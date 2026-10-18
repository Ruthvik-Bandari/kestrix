# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""M1: LoRA supervised fine-tuning of the B2 base model (plan sections 12 and 14).

Trains on the ``train`` SFT examples only, and reports evaluation loss on ``development``. The loss
is computed on completion tokens; prompt tokens are masked. Everything the plan asks a run to
record is written to ``training_manifest.json`` next to the adapter:

- seed, effective batch size and gradient accumulation;
- the sequence limit, and how many examples it truncated;
- optimizer settings and checkpoint steps;
- loss history, peak GPU memory and throughput;
- the base model revision and the SHA-256 of the training and development data.

GPU job only. It needs the ``gpu`` dependency group (torch, transformers, peft).
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .b2 import MODEL_REPO, MODEL_REVISION


@dataclass(frozen=True)
class TrainConfig:
    seed: int = 1
    epochs: int = 3
    learning_rate: float = 2e-4
    weight_decay: float = 0.0
    warmup_ratio: float = 0.05
    micro_batch: int = 1
    grad_accumulation: int = 8
    max_tokens: int = 4096  # plan: pilot 2k-4k context windows and inspect truncation
    lora_r: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    target_modules: tuple[str, ...] = ("q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj")
    checkpoint_every: int = 0  # optimizer steps; 0 keeps only the final adapter
    max_steps: int = 0  # >0 for smoke runs that measure memory and throughput


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _model(snapshot: Path, cfg: TrainConfig) -> tuple[Any, Any, bool]:
    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(snapshot, local_files_only=True, trust_remote_code=False)
    bf16 = bool(torch.cuda.is_bf16_supported())
    model: Any = AutoModelForCausalLM.from_pretrained(
        snapshot,
        local_files_only=True,
        trust_remote_code=False,
        torch_dtype=torch.bfloat16 if bf16 else torch.float16,
        device_map="auto",
    )
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()
    lora = LoraConfig(
        r=cfg.lora_r,
        lora_alpha=cfg.lora_alpha,
        lora_dropout=cfg.lora_dropout,
        target_modules=list(cfg.target_modules),
        task_type="CAUSAL_LM",
    )
    return get_peft_model(model, lora), tokenizer, bf16


def encode(tokenizer: Any, ex: dict[str, Any], max_tokens: int) -> tuple[list[int], list[int], bool]:
    """Token ids and labels (prompt masked with -100); cuts the prompt from the left when too long."""
    prompt = tokenizer.apply_chat_template(
        [{"role": "user", "content": ex["prompt"]}], tokenize=False, add_generation_prompt=True
    )
    p_ids = tokenizer(prompt, add_special_tokens=False)["input_ids"]
    c_ids = tokenizer(ex["completion"] + tokenizer.eos_token, add_special_tokens=False)["input_ids"]
    ids, labels = p_ids + c_ids, [-100] * len(p_ids) + c_ids
    if len(ids) <= max_tokens:
        return ids, labels, False
    return ids[-max_tokens:], labels[-max_tokens:], True


def train(snapshot: Path, train_path: Path, dev_path: Path, out: Path, cfg: TrainConfig) -> dict[str, Any]:
    import torch
    from transformers import get_cosine_schedule_with_warmup

    random.seed(cfg.seed)
    torch.manual_seed(cfg.seed)
    model, tokenizer, bf16 = _model(snapshot, cfg)
    train_enc = [encode(tokenizer, e, cfg.max_tokens) for e in _load(train_path)]
    dev_enc = [encode(tokenizer, e, cfg.max_tokens) for e in _load(dev_path)]
    trainable = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(trainable, lr=cfg.learning_rate, weight_decay=cfg.weight_decay)
    total = cfg.max_steps or math.ceil(len(train_enc) / (cfg.micro_batch * cfg.grad_accumulation)) * cfg.epochs
    sched = get_cosine_schedule_with_warmup(opt, int(cfg.warmup_ratio * total), total)

    def loss_of(ids: list[int], labels: list[int]) -> Any:
        x = torch.tensor([ids], device=model.device)
        return model(input_ids=x, labels=torch.tensor([labels], device=model.device)).loss

    def dev_loss() -> float:
        model.eval()
        with torch.no_grad():
            losses = [float(loss_of(ids, labels)) for ids, labels, _ in dev_enc]
        model.train()
        return round(sum(losses) / len(losses), 5) if losses else float("nan")

    torch.cuda.reset_peak_memory_stats()
    history, step, tokens, started = [], 0, 0, time.time()
    model.train()
    for epoch in range(cfg.epochs):
        order = random.sample(range(len(train_enc)), len(train_enc))
        for i, idx in enumerate(order, 1):
            ids, labels, _ = train_enc[idx]
            (loss_of(ids, labels) / cfg.grad_accumulation).backward()
            tokens += len(ids)
            if i % cfg.grad_accumulation and i != len(order):
                continue
            torch.nn.utils.clip_grad_norm_(trainable, 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            step += 1
            if cfg.checkpoint_every and step % cfg.checkpoint_every == 0:
                model.save_pretrained(out / f"checkpoint-{step}")
            if cfg.max_steps and step >= cfg.max_steps:
                break
        history.append({"epoch": epoch + 1, "step": step, "dev_loss": dev_loss()})
        if cfg.max_steps and step >= cfg.max_steps:
            break
    elapsed = time.time() - started
    out.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(out)
    manifest = {
        "schema_version": 1,
        "base_model": f"{MODEL_REPO}@{MODEL_REVISION}",
        "config": asdict(cfg),
        "precision": "bf16" if bf16 else "fp16",
        "effective_batch": cfg.micro_batch * cfg.grad_accumulation,
        "optimizer": {"name": "AdamW", "lr": cfg.learning_rate, "weight_decay": cfg.weight_decay, "schedule": "cosine"},
        "train_examples": len(train_enc),
        "dev_examples": len(dev_enc),
        "truncated_examples": sum(t for *_, t in train_enc + dev_enc),
        "optimizer_steps": step,
        "history": history,
        "peak_gpu_memory_gb": round(torch.cuda.max_memory_allocated() / 1024**3, 2),
        "tokens_per_second": round(tokens / elapsed, 1) if elapsed else None,
        "elapsed_seconds": round(elapsed, 1),
        "gpu": torch.cuda.get_device_name(0),
        "data_sha256": {"train": _sha256(train_path), "development": _sha256(dev_path)},
    }
    (out / "training_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
