# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""Learned vulnerability ranker, slice C6 of ADR 0005: data assembly, teacher and student training.

Research only (not in the wheel); the torch code runs as cluster GPU jobs and is imported lazily.

**Data** (``work/split-v2.jsonl``, or ``work/split.jsonl`` before the extension, plus
``work/negatives.jsonl``). One example is a function and a label:

* ``vulnerable``: the before-fix version of a labelled record (label 1, its CWEs);
* ``patched``: its after-fix version (label 0);
* ``negative``: a sampled ``negative_unchanged`` function, ``neg_ratio`` per vulnerable record
  (seeded by ``data_seed``, so every training seed sees the same data).

Training code reads only ``train`` and ``dev`` (``require_trainable``); ``dev`` is used for early
stopping and thresholds only. ``test`` and ``test_extension`` are read by ``evaluate.py`` alone,
under ``--locked``. The ``filtered`` view drops the records of the audit strata below 0.80 label
accuracy (``filters.excluded_ids`` of ``reports/split-manifest-v2.json``).

**Teacher**: Qwen2.5-Coder-7B-Instruct with LoRA (bf16, no quantization, gradient checkpointing). The
prompt asks for ``{"vulnerable": bool, "cwe": "CWE-xxx" | null}`` and the assistant turn is opened
with ``{"vulnerable":``. The vulnerability score is the logit difference of the next tokens
`` true`` and `` false`` (the language-model head at that position), trained with binary cross
entropy. Why this and not a new classification head: at step 0 the score *is* the zero-shot model,
so the zero-shot baseline and the fine-tuned teacher are the same scorer before and after training,
and the 2-way softmax over the pretrained head starts from the model's prior instead of a random
head (1.5k positives are few). The loss is a proper scoring rule on that logit, so
``sigmoid(score)`` is a probability estimate; ``evaluate.py`` still fits Platt scaling on dev and
reports calibration error before and after. A small linear CWE head on the same hidden state ranks
the training set's most frequent CWEs (top-1/top-3 for true positives).

**Student**: UniXcoder-base (Apache-2.0) with a vulnerability head and a CWE head, trained only on
the permissive-license pool, on the hard labels and the teacher's soft labels (mean teacher logit
over the given teacher runs, temperature ``temperature``). Exported as a plain PyTorch state dict
(fp32) and an int8 dynamically quantized one (``Linear`` layers int8, other tensors fp16).

Every run writes ``runs/<run-id>/run.json`` (config, data SHA-256, base revision, git SHA),
``log.jsonl`` (loss, dev PR-AUC, timings) and checkpoints.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import os
import random
import sys
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TEACHER_REPO = "Qwen/Qwen2.5-Coder-7B-Instruct"
TEACHER_REVISION = "c03e6d358207e414f1eca0bb1891e29f1db0e242"
STUDENT_REPO = "microsoft/unixcoder-base"
STUDENT_REVISION = "5604afdc964f6c53782a6813140ade5216b99006"
TRAINABLE = frozenset({"train", "dev"})
HELD_OUT = frozenset({"test", "test_extension"})
VIEWS = ("full", "filtered")
DATA_SEED = "kestrixvul-train-v1"
ANSWER_PREFIX = '{"vulnerable":'
ANSWERS = (" true", " false")
OTHER_CWE = "other"
TRUNCATED = "\n... (truncated)"
SYSTEM = "You are a security code reviewer. You answer with one JSON object and nothing else."


class DataError(RuntimeError):
    """A manifest or input file the run needs is missing or inconsistent."""


class HeldOutSplitError(RuntimeError):
    """Training code asked for a held-out split."""


# --- data -----------------------------------------------------------------------------------


def require_trainable(splits: tuple[str, ...]) -> None:
    held = sorted(set(splits) - TRAINABLE)
    if held:
        raise HeldOutSplitError(f"training code never reads {held}; only evaluate.py --locked reads held-out splits")


def manifest_path(root: Path) -> Path:
    for name in ("split-v2.jsonl", "split.jsonl"):
        path = root / "work" / name
        if path.is_file():
            return path
    raise DataError(
        f"no split manifest under {root / 'work'}: expected split-v2.jsonl (hpc/vul_extend.sbatch split) "
        "or split.jsonl (hpc/vul_build.sbatch split)"
    )


def stream_rows(path: Path, allowed: frozenset[str]) -> Iterator[dict[str, Any]]:
    """Rows of a split-tagged JSONL file whose ``split`` is in ``allowed``; others are dropped on read."""
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                if row.get("split") in allowed:
                    yield row


def read_records(root: Path, splits: tuple[str, ...]) -> list[dict[str, Any]]:
    require_trainable(splits)
    return list(stream_rows(manifest_path(root), frozenset(splits)))


def negatives_path(root: Path) -> Path:
    path = root / "work" / "negatives.jsonl"
    if not path.is_file():
        raise DataError(f"{path} is missing (kestrixvul negatives, run by hpc/vul_extend.sbatch split)")
    return path


def read_negatives(root: Path, splits: tuple[str, ...]) -> list[dict[str, Any]]:
    require_trainable(splits)
    return list(stream_rows(negatives_path(root), frozenset(splits)))


def read_filters(root: Path) -> dict[str, Any]:
    """``filters`` of split manifest v2 (excluded and audit-confirmed ids per split); {} before v2."""
    path = root / "reports" / "split-manifest-v2.json"
    if not path.is_file():
        return {}
    filters: dict[str, Any] = json.loads(path.read_text(encoding="utf-8")).get("filters", {})
    return filters


def normalize_cwe(cwe: str) -> str | None:
    """``CWE-078`` -> ``CWE-78``; NVD placeholders (``NVD-CWE-Other``, ``noinfo``) -> None."""
    head, _, number = cwe.strip().upper().partition("-")
    if head != "CWE" or not number.isdigit():
        return None
    return f"CWE-{int(number)}"


def seeded_key(seed: str, key: str) -> str:
    return hashlib.sha256(f"{seed}\x1f{key}".encode()).hexdigest()


def context_window(file_text: str, code: str, max_chars: int) -> tuple[str, str]:
    """File text just before and just after the function, at most ``max_chars`` in total."""
    start = file_text.find(code)
    if start < 0 or max_chars <= 0:
        return "", ""
    half = max_chars // 2
    before = file_text[:start][-half:]
    after = file_text[start + len(code) :][: max_chars - len(before)]
    return before, after


def _example(row: dict[str, Any], role: str, code: str) -> dict[str, Any]:
    cwes = sorted({c for c in (normalize_cwe(x) for x in row.get("cwes", [])) if c}) if role == "vulnerable" else []
    return {
        "id": f"{row['id']}:{role[0]}",
        "record_id": row["id"],
        "role": role,
        "label": 1 if role == "vulnerable" else 0,
        "cwes": cwes,
        "code": code,
        "language": row["language"],
        "repo": row["repo"],
        "path": row.get("path", ""),
        "function": row.get("function", ""),
        "license_class": row.get("license_class", "unknown"),
        "file_text": row.get("file_text"),
    }


def examples_from(
    records: list[dict[str, Any]],
    negatives: list[dict[str, Any]],
    *,
    neg_ratio: float | None,
    seed: str = DATA_SEED,
    excluded: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Vulnerable and patched examples of ``records`` (minus ``excluded`` ids) plus negatives.

    ``neg_ratio``: negatives per vulnerable record, drawn in a seeded order; None keeps them all.
    """
    kept = sorted((r for r in records if r["id"] not in excluded), key=lambda r: r["id"])
    out = []
    for r in kept:
        out.append(_example(r, "vulnerable", r["vulnerable"]))
        if r.get("patched"):
            out.append(_example(r, "patched", r["patched"]))
    pool = sorted(negatives, key=lambda n: seeded_key(seed, n["id"]))
    if neg_ratio is not None:
        pool = pool[: round(neg_ratio * len(kept))]
    out += [_example(n, "negative", n["code"]) for n in pool]
    return sorted(out, key=lambda e: e["id"])


def subsample(examples: list[dict[str, Any]], limit: int, seed: str = DATA_SEED) -> list[dict[str, Any]]:
    if not limit or limit >= len(examples):
        return examples
    chosen = sorted(examples, key=lambda e: seeded_key(seed, e["id"]))[:limit]
    return sorted(chosen, key=lambda e: e["id"])


def license_classes(root: Path, rows: list[dict[str, Any]]) -> None:
    """Fill ``license_class`` of rows that lack it (negatives) from ``licenses/licenses.csv``."""
    from .licenses import classify, license_of
    from .split import _licenses

    table = _licenses(root)
    for row in rows:
        if "license_class" not in row:
            row["license_class"] = classify(license_of(row, table))


def assemble(
    root: Path,
    split: str,
    *,
    neg_ratio: float | None,
    seed: str = DATA_SEED,
    view: str = "full",
    permissive_only: bool = False,
    limit: int = 0,
) -> list[dict[str, Any]]:
    """The examples of one trainable split (see the module docstring)."""
    require_trainable((split,))
    if view not in VIEWS:
        raise DataError(f"unknown view {view!r}; expected one of {VIEWS}")
    records = read_records(root, (split,))
    negatives = read_negatives(root, (split,)) if neg_ratio != 0 else []
    excluded: frozenset[str] = frozenset()
    if view == "filtered":
        excluded = frozenset(read_filters(root).get("excluded_ids", {}).get(split, []))
    if permissive_only:
        license_classes(root, negatives)
        records = [r for r in records if r.get("license_class") == "permissive"]
        negatives = [n for n in negatives if n["license_class"] == "permissive"]
    examples = examples_from(records, negatives, neg_ratio=neg_ratio, seed=seed, excluded=excluded)
    return subsample(examples, limit, seed)


def ids_sha256(examples: list[dict[str, Any]]) -> str:
    return hashlib.sha256("".join(e["id"] + "\n" for e in sorted(examples, key=lambda e: e["id"])).encode()).hexdigest()


def cwe_vocab(examples: list[dict[str, Any]], top: int) -> list[str]:
    """The ``top`` most frequent CWEs of the vulnerable examples (ties by id), then ``other``."""
    counts = Counter(c for e in examples if e["label"] for c in e["cwes"])
    return [c for c, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]] + [OTHER_CWE]


def cwe_target(example: dict[str, Any], vocab: list[str]) -> int:
    """Index of the example's first in-vocabulary CWE, ``other`` if none; -1 for non-vulnerable examples."""
    if not example["label"]:
        return -1
    for c in example["cwes"]:
        if c in vocab:
            return vocab.index(c)
    return vocab.index(OTHER_CWE)


def make_batches(lengths: list[int], size: int, rng: random.Random, chunk: int = 50) -> list[list[int]]:
    """Shuffled micro-batches of similar length: shuffle, sort within chunks of ``size * chunk``, shuffle batches."""
    order = list(range(len(lengths)))
    rng.shuffle(order)
    batches: list[list[int]] = []
    for s in range(0, len(order), size * chunk):
        block = sorted(order[s : s + size * chunk], key=lambda i: lengths[i])
        batches += [block[j : j + size] for j in range(0, len(block), size)]
    rng.shuffle(batches)
    return batches


def prompt(example: dict[str, Any], code: str, context_chars: int = 0) -> str:
    lang = example["language"]
    parts = [f"Language: {lang}", f"File: {example['path']}", f"Function: {example['function']}"]
    if example.get("file_text") and context_chars:
        before, after = context_window(example["file_text"], example["code"], context_chars)
        if before:
            parts.append(f"File context before the function (truncated):\n```{lang}\n{before}\n```")
        if after:
            parts.append(f"File context after the function (truncated):\n```{lang}\n{after}\n```")
    parts.append(f"Function code:\n```{lang}\n{code}\n```")
    parts.append(
        'Does this function contain a security vulnerability? Answer with JSON only: {"vulnerable": true or false, '
        '"cwe": "CWE-<id>" or null}.'
    )
    return "\n\n".join(parts)


# --- run bookkeeping -------------------------------------------------------------------------


def git_sha() -> str:
    """The code version: ``KESTRIX_GIT_SHA``, else the ``GIT_SHA`` file the sync writes, else unknown."""
    if os.environ.get("KESTRIX_GIT_SHA"):
        return os.environ["KESTRIX_GIT_SHA"]
    marker = Path(__file__).resolve().parents[2] / "GIT_SHA"
    return marker.read_text().strip() if marker.is_file() else "unknown"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def write_json(path: Path, obj: object) -> None:
    write_private(path, json.dumps(obj, indent=2, sort_keys=True) + "\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    write_private(path, "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class RunLog:
    """Appends one JSON line per event to ``log.jsonl`` and echoes it to the job log."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.started = time.time()

    def __call__(self, event: str, **fields: Any) -> None:
        line = json.dumps({"event": event, "elapsed_s": round(time.time() - self.started, 1), **fields})
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        print(line, flush=True)


def data_hashes(root: Path, splits: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    manifest = manifest_path(root)
    return {
        "manifest": manifest.name,
        "manifest_sha256": file_sha256(manifest),
        "negatives_sha256": file_sha256(negatives_path(root)),
        "examples": {name: {"n": len(ex), "ids_sha256": ids_sha256(ex)} for name, ex in splits.items()},
    }


def new_run_dir(root: Path, run_id: str) -> Path:
    run = root / "runs" / run_id
    if (run / "run.json").is_file():
        raise DataError(f"{run} already holds a run; pick another --run-id")
    run.mkdir(parents=True, exist_ok=True, mode=0o700)
    return run


def snapshot_dir(models: Path, repo: str, revision: str) -> Path:
    path = models / f"{repo.rsplit('/', maxsplit=1)[-1]}@{revision}"
    if not (path / "MANIFEST.sha256").is_file():
        raise DataError(f"model snapshot {path} is missing; fetch it on the transfer node first")
    return path


# --- teacher (torch) -------------------------------------------------------------------------


@dataclass(frozen=True)
class TeacherConfig:
    seed: int = 1
    epochs: int = 2
    learning_rate: float = 1e-4
    weight_decay: float = 0.0
    warmup_ratio: float = 0.05
    micro_batch: int = 4
    grad_accumulation: int = 4
    max_tokens: int = 4096
    context_chars: int = 4000
    lora_r: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    neg_ratio: float = 3.0
    dev_neg_ratio: float = 5.0  # dev subsample used for early stopping; evaluate.py uses all dev negatives
    soft_neg_ratio: float = 8.0  # negatives per vulnerable record in the permissive pool scored for the student
    view: str = "full"
    top_cwes: int = 25
    cwe_weight: float = 0.2
    eval_every: int = 200  # optimizer steps between dev evaluations (and at the end)
    patience: int = 3  # dev evaluations without improvement before stopping
    log_every: int = 10
    score_batch: int = 8
    max_steps: int = 0  # >0: smoke runs
    limit: int = 0  # >0: at most this many train examples (smoke)
    dev_limit: int = 0  # >0: at most this many dev examples (smoke)


TARGET_MODULES = ("q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj")


def answer_ids(tokenizer: Any) -> tuple[int, int]:
    ids = [tokenizer.encode(a, add_special_tokens=False) for a in ANSWERS]
    if any(len(i) != 1 for i in ids) or ids[0] == ids[1]:
        raise DataError(f"the answer tokens {ANSWERS} are not two distinct single tokens: {ids}")
    return ids[0][0], ids[1][0]


def encode_teacher(
    tokenizer: Any, example: dict[str, Any], max_tokens: int, context_chars: int
) -> tuple[list[int], bool]:
    """Chat-formatted prompt plus the opened answer; the function code is cut when it does not fit."""

    def ids_for(code: str, ctx: int) -> list[int]:
        messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt(example, code, ctx)}]
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True) + ANSWER_PREFIX
        return list(tokenizer(text, add_special_tokens=False)["input_ids"])

    ids = ids_for(example["code"], context_chars)
    if len(ids) <= max_tokens:
        return ids, False
    ids = ids_for(example["code"], 0)
    if len(ids) <= max_tokens:
        return ids, True
    code_ids = tokenizer(example["code"], add_special_tokens=False)["input_ids"]
    keep = max(16, len(code_ids) - (len(ids) - max_tokens) - 32)
    ids = ids_for(tokenizer.decode(code_ids[:keep]) + TRUNCATED, 0)
    return (ids if len(ids) <= max_tokens else ids[-max_tokens:]), True


def load_teacher(snapshot: Path, cfg: TeacherConfig | None) -> tuple[Any, Any]:
    """(model, tokenizer) in bf16 on the GPU; with ``cfg``, LoRA adapters and gradient checkpointing."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(snapshot, local_files_only=True, trust_remote_code=False)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    model: Any = AutoModelForCausalLM.from_pretrained(
        snapshot,
        local_files_only=True,
        trust_remote_code=False,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        attn_implementation="sdpa",
    )
    model.config.use_cache = False
    if cfg is not None:
        from peft import LoraConfig, get_peft_model

        model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
        lora = LoraConfig(
            r=cfg.lora_r,
            lora_alpha=cfg.lora_alpha,
            lora_dropout=cfg.lora_dropout,
            target_modules=list(TARGET_MODULES),
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, lora)
    return model, tokenizer


def _causal_lm(model: Any) -> Any:
    return model.get_base_model() if hasattr(model, "get_base_model") else model


def _hidden(lm: Any, batch: list[list[int]], pad_id: int) -> Any:
    """Last-layer hidden state at each sequence's last token (right padding)."""
    import torch

    device = lm.lm_head.weight.device
    width = max(len(x) for x in batch)
    ids = torch.full((len(batch), width), pad_id, dtype=torch.long)
    mask = torch.zeros((len(batch), width), dtype=torch.long)
    for i, x in enumerate(batch):
        ids[i, : len(x)] = torch.tensor(x)
        mask[i, : len(x)] = 1
    out = lm.model(input_ids=ids.to(device), attention_mask=mask.to(device))
    last = torch.tensor([len(x) - 1 for x in batch], device=device)
    return out.last_hidden_state[torch.arange(len(batch), device=device), last]


def _vuln_logit(lm: Any, hidden: Any, answers: tuple[int, int]) -> Any:
    weight = lm.lm_head.weight[list(answers)]
    pair = hidden @ weight.T
    return (pair[:, 0] - pair[:, 1]).float()


def score_teacher(
    model: Any,
    tokenizer: Any,
    head: Any,
    vocab: list[str],
    examples: list[dict[str, Any]],
    max_tokens: int,
    context_chars: int,
    batch: int,
) -> list[dict[str, Any]]:
    """{id, logit, cwes} per example; ``head`` None (zero-shot) gives no CWE ranking."""
    import torch

    lm = _causal_lm(model)
    answers = answer_ids(tokenizer)
    encoded = [encode_teacher(tokenizer, e, max_tokens, context_chars)[0] for e in examples]
    order = sorted(range(len(encoded)), key=lambda i: len(encoded[i]))
    out: list[dict[str, Any]] = [{} for _ in examples]
    model.eval()
    with torch.no_grad():
        for s in range(0, len(order), batch):
            idx = order[s : s + batch]
            hidden = _hidden(lm, [encoded[i] for i in idx], tokenizer.pad_token_id)
            logits = _vuln_logit(lm, hidden, answers).tolist()
            probs = torch.softmax(head(hidden.float()), -1).tolist() if head is not None else None
            for j, i in enumerate(idx):
                cwes: list[str] = []
                if probs is not None:
                    ranked = sorted(range(len(vocab)), key=lambda k: -probs[j][k])
                    cwes = [vocab[k] for k in ranked if vocab[k] != OTHER_CWE][:5]
                out[i] = {"id": examples[i]["id"], "logit": float(logits[j]), "cwes": cwes}
    return out


def _dev_pr_auc(scored: list[dict[str, Any]], examples: list[dict[str, Any]]) -> float | None:
    from .evaluate import average_precision

    return average_precision([s["logit"] for s in scored], [e["label"] for e in examples])


def train_teacher(root: Path, snapshot: Path, run: Path, cfg: TeacherConfig) -> dict[str, Any]:
    import torch
    from peft import set_peft_model_state_dict
    from safetensors.torch import load_file
    from transformers import get_cosine_schedule_with_warmup

    log = RunLog(run / "log.jsonl")
    random.seed(cfg.seed)
    torch.manual_seed(cfg.seed)
    rng = random.Random(cfg.seed)
    train_ex = assemble(root, "train", neg_ratio=cfg.neg_ratio, view=cfg.view, limit=cfg.limit)
    dev_ex = assemble(root, "dev", neg_ratio=cfg.dev_neg_ratio, view=cfg.view, limit=cfg.dev_limit)
    pool = assemble(root, "train", neg_ratio=cfg.soft_neg_ratio, view=cfg.view, permissive_only=True, limit=cfg.limit)
    vocab = cwe_vocab(train_ex, cfg.top_cwes)
    meta: dict[str, Any] = {
        "schema_version": 1,
        "kind": "teacher",
        "run_id": run.name,
        "status": "running",
        "config": asdict(cfg),
        "base_model": f"{TEACHER_REPO}@{TEACHER_REVISION}",
        "scoring": "logit(' true') - logit(' false') after the opened answer '{\"vulnerable\":'; LoRA on "
        + ",".join(TARGET_MODULES),
        "precision": "bf16",
        "git_sha": git_sha(),
        "data": data_hashes(root, {"train": train_ex, "dev": dev_ex, "student_pool": pool}),
        "label_counts": {
            "train": dict(Counter(e["role"] for e in train_ex)),
            "dev": dict(Counter(e["role"] for e in dev_ex)),
            "student_pool": dict(Counter(e["role"] for e in pool)),
        },
        "cwe_vocab": vocab,
    }
    write_json(run / "run.json", meta)
    log("data", **meta["label_counts"])

    model, tokenizer = load_teacher(snapshot, cfg)
    lm = _causal_lm(model)
    answers = answer_ids(tokenizer)
    device = lm.lm_head.weight.device
    head = torch.nn.Linear(lm.config.hidden_size, len(vocab)).to(device)
    encoded = [encode_teacher(tokenizer, e, cfg.max_tokens, cfg.context_chars) for e in train_ex]
    labels = [float(e["label"]) for e in train_ex]
    targets = [cwe_target(e, vocab) for e in train_ex]
    log(
        "encoded",
        truncated=sum(t for _, t in encoded),
        mean_tokens=round(sum(len(i) for i, _ in encoded) / len(encoded), 1),
    )
    params = [p for p in model.parameters() if p.requires_grad] + list(head.parameters())
    opt = torch.optim.AdamW(params, lr=cfg.learning_rate, weight_decay=cfg.weight_decay)
    per_epoch = math.ceil(math.ceil(len(encoded) / cfg.micro_batch) / cfg.grad_accumulation)
    total = cfg.max_steps or per_epoch * cfg.epochs
    sched = get_cosine_schedule_with_warmup(opt, int(cfg.warmup_ratio * total), total)
    bce = torch.nn.BCEWithLogitsLoss()
    ce = torch.nn.CrossEntropyLoss()

    best: dict[str, Any] = {"step": None, "dev_pr_auc": None}
    evals_without_gain = 0

    def dev_eval(step: int) -> bool:
        """Score dev, keep the best checkpoint; True when early stopping should stop the run."""
        nonlocal evals_without_gain
        t0 = time.time()
        scored = score_teacher(
            model, tokenizer, head, vocab, dev_ex, cfg.max_tokens, cfg.context_chars, cfg.score_batch
        )
        auc = _dev_pr_auc(scored, dev_ex)
        model.train()
        log("dev", step=step, dev_pr_auc=auc, n=len(dev_ex), seconds=round(time.time() - t0, 1))
        if best["step"] is None or (auc is not None and (best["dev_pr_auc"] is None or auc > best["dev_pr_auc"])):
            best.update(step=step, dev_pr_auc=auc)
            model.save_pretrained(run / "best")
            torch.save(head.state_dict(), run / "best" / "cwe_head.pt")
            evals_without_gain = 0
            return False
        evals_without_gain += 1
        return evals_without_gain >= cfg.patience

    torch.cuda.reset_peak_memory_stats()
    step, seen_tokens, started, last_eval, stop = 0, 0, time.time(), -1, False
    window: list[float] = []
    model.train()
    for epoch in range(cfg.epochs):
        batches = make_batches([len(i) for i, _ in encoded], cfg.micro_batch, rng)
        for bi, batch in enumerate(batches, 1):
            hidden = _hidden(lm, [encoded[i][0] for i in batch], tokenizer.pad_token_id)
            logit = _vuln_logit(lm, hidden, answers)
            loss = bce(logit, torch.tensor([labels[i] for i in batch], device=device))
            pos = [j for j, i in enumerate(batch) if targets[i] >= 0]
            if pos:
                cwe_logits = head(hidden[pos].float())
                loss = loss + cfg.cwe_weight * ce(
                    cwe_logits, torch.tensor([targets[batch[j]] for j in pos], device=device)
                )
            (loss / cfg.grad_accumulation).backward()
            window.append(float(loss))
            seen_tokens += sum(len(encoded[i][0]) for i in batch)
            if bi % cfg.grad_accumulation and bi != len(batches):
                continue
            torch.nn.utils.clip_grad_norm_(params, 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            step += 1
            if step % cfg.log_every == 0:
                elapsed = time.time() - started
                log(
                    "train",
                    epoch=epoch + 1,
                    step=step,
                    loss=round(sum(window) / len(window), 5),
                    lr=sched.get_last_lr()[0],
                    tokens_per_s=round(seen_tokens / elapsed, 1),
                )
                window = []
            if cfg.eval_every and step % cfg.eval_every == 0:
                last_eval = step
                stop = dev_eval(step)
            if stop or (cfg.max_steps and step >= cfg.max_steps):
                break
        if stop or (cfg.max_steps and step >= cfg.max_steps):
            break
    if last_eval != step:
        dev_eval(step)
    elapsed = time.time() - started
    model.save_pretrained(run / "last")
    torch.save(head.state_dict(), run / "last" / "cwe_head.pt")
    if best["step"] is not None and best["step"] != step:
        set_peft_model_state_dict(model, load_file(str(run / "best" / "adapter_model.safetensors")))
        head.load_state_dict(torch.load(run / "best" / "cwe_head.pt", weights_only=True))
    t0 = time.time()
    soft = score_teacher(model, tokenizer, head, vocab, pool, cfg.max_tokens, cfg.context_chars, cfg.score_batch)
    write_jsonl(run / "soft_labels.jsonl", soft)
    log("soft_labels", n=len(soft), seconds=round(time.time() - t0, 1))
    meta |= {
        "status": "done",
        "optimizer_steps": step,
        "effective_batch": cfg.micro_batch * cfg.grad_accumulation,
        "best": best,
        "train_seconds": round(elapsed, 1),
        "tokens_per_second": round(seen_tokens / elapsed, 1) if elapsed else None,
        "peak_gpu_memory_gb": round(torch.cuda.max_memory_allocated() / 1024**3, 2),
        "gpu": torch.cuda.get_device_name(0),
        "truncated_train_examples": sum(t for _, t in encoded),
        "soft_labels": {"n": len(soft), "ids_sha256": ids_sha256(pool)},
    }
    write_json(run / "run.json", meta)
    return meta


# --- student (torch) -------------------------------------------------------------------------


@dataclass(frozen=True)
class StudentConfig:
    seed: int = 1
    epochs: int = 5
    learning_rate: float = 5e-5
    weight_decay: float = 0.01
    warmup_ratio: float = 0.06
    batch: int = 32
    max_tokens: int = 512
    alpha: float = 0.5  # weight of the hard-label loss; 1 - alpha goes to the teacher's soft labels
    temperature: float = 2.0
    cwe_weight: float = 0.2
    dev_neg_ratio: float = 5.0
    eval_every: int = 0  # 0: once per epoch
    patience: int = 2
    log_every: int = 20
    max_steps: int = 0
    dev_limit: int = 0


def student_text(example: dict[str, Any]) -> str:
    return f"{example['language']} {example['path']} {example['function']}\n{example['code']}"


def student_module(encoder: Any, n_cwe: int) -> Any:
    """UniXcoder encoder + dropout + vulnerability and CWE heads on the first token."""
    import torch

    class Student(torch.nn.Module):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__()
            size = encoder.config.hidden_size
            self.encoder = encoder
            self.dropout = torch.nn.Dropout(0.1)
            self.vuln = torch.nn.Linear(size, 1)
            self.cwe = torch.nn.Linear(size, n_cwe)

        def forward(self, input_ids: Any, attention_mask: Any) -> tuple[Any, Any]:
            first = self.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state[:, 0]
            first = self.dropout(first)
            return self.vuln(first).squeeze(-1), self.cwe(first)

    return Student()


def build_student(snapshot: Path, n_cwe: int, *, pretrained: bool) -> tuple[Any, Any]:
    from transformers import AutoConfig, AutoModel, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(snapshot, local_files_only=True, trust_remote_code=False)
    if pretrained:
        encoder = AutoModel.from_pretrained(
            snapshot, local_files_only=True, trust_remote_code=False, add_pooling_layer=False
        )
    else:
        config = AutoConfig.from_pretrained(snapshot, local_files_only=True, trust_remote_code=False)
        encoder = AutoModel.from_config(config, add_pooling_layer=False)
    return student_module(encoder, n_cwe), tokenizer


def quantize_int8(model: Any) -> Any:
    import torch

    return torch.ao.quantization.quantize_dynamic(model.cpu().float().eval(), {torch.nn.Linear}, dtype=torch.qint8)


def int8_state(model: Any) -> dict[str, Any]:
    """State dict of the int8 model with its remaining float tensors (embeddings, norms) in fp16."""
    return {k: _cast(v, half=True) for k, v in model.state_dict().items()}


def _cast(value: Any, *, half: bool) -> Any:
    import torch

    # A quantized state dict also holds non-tensor entries (packed params, torch.dtype objects whose
    # is_floating_point is a bool attribute, not a method); only float tensors are cast.
    if isinstance(value, torch.Tensor) and value.is_floating_point():
        return value.half() if half else value.float()
    return value


def load_student(run: Path, snapshot: Path, *, int8: bool) -> tuple[Any, Any]:
    """(model, tokenizer) from a finished student run: fp32 (``student_fp32.pt``) or int8 (CPU)."""
    import torch

    meta = json.loads((run / "run.json").read_text())
    model, tokenizer = build_student(snapshot, len(meta["cwe_vocab"]), pretrained=False)
    if int8:
        model = quantize_int8(model)
        state = torch.load(run / "student_int8.pt", weights_only=True, map_location="cpu")
        state = {k: _cast(v, half=False) for k, v in state.items()}
    else:
        state = torch.load(run / "student_fp32.pt", weights_only=True, map_location="cpu")
    model.load_state_dict(state)
    return model.eval(), tokenizer


def _student_batch(tokenizer: Any, examples: list[dict[str, Any]], max_tokens: int, device: Any) -> tuple[Any, Any]:
    enc = tokenizer(
        [student_text(e) for e in examples], truncation=True, max_length=max_tokens, padding=True, return_tensors="pt"
    )
    return enc["input_ids"].to(device), enc["attention_mask"].to(device)


def score_student(
    model: Any,
    tokenizer: Any,
    vocab: list[str],
    examples: list[dict[str, Any]],
    max_tokens: int,
    batch: int,
    device: Any,
) -> list[dict[str, Any]]:
    import torch

    out: list[dict[str, Any]] = [{} for _ in examples]
    order = sorted(range(len(examples)), key=lambda i: len(examples[i]["code"]))
    model.eval()
    with torch.no_grad():
        for s in range(0, len(order), batch):
            idx = order[s : s + batch]
            ids, mask = _student_batch(tokenizer, [examples[i] for i in idx], max_tokens, device)
            with torch.autocast(device_type=device.type, dtype=torch.bfloat16, enabled=device.type == "cuda"):
                logit, cwe_logits = model(ids, mask)
            probs = torch.softmax(cwe_logits.float(), -1).tolist()
            for j, i in enumerate(idx):
                ranked = sorted(range(len(vocab)), key=lambda k: -probs[j][k])
                cwes = [vocab[k] for k in ranked if vocab[k] != OTHER_CWE][:5]
                out[i] = {"id": examples[i]["id"], "logit": float(logit[j]), "cwes": cwes}
    return out


def teacher_soft_labels(root: Path, runs: list[str]) -> tuple[dict[str, float], dict[str, Any]]:
    """Mean teacher logit per example id over finished teacher runs that scored the same pool."""
    metas = []
    for run_id in runs:
        path = root / "runs" / run_id
        meta = json.loads((path / "run.json").read_text())
        if meta.get("kind") != "teacher" or meta.get("status") != "done":
            raise DataError(f"{run_id} is not a finished teacher run")
        metas.append((path, meta))
    pools = {m["soft_labels"]["ids_sha256"] for _, m in metas}
    if len(pools) != 1:
        raise DataError("the teacher runs scored different student pools")
    sums: dict[str, float] = {}
    for path, _ in metas:
        for row in read_jsonl(path / "soft_labels.jsonl"):
            sums[row["id"]] = sums.get(row["id"], 0.0) + row["logit"] / len(metas)
    return sums, metas[0][1]


def train_student(root: Path, snapshot: Path, run: Path, teacher_runs: list[str], cfg: StudentConfig) -> dict[str, Any]:
    import torch
    from transformers import get_linear_schedule_with_warmup

    log = RunLog(run / "log.jsonl")
    random.seed(cfg.seed)
    torch.manual_seed(cfg.seed)
    rng = random.Random(cfg.seed)
    soft, teacher_meta = teacher_soft_labels(root, teacher_runs)
    tcfg = teacher_meta["config"]
    pool = assemble(
        root, "train", neg_ratio=tcfg["soft_neg_ratio"], view=tcfg["view"], permissive_only=True, limit=tcfg["limit"]
    )
    if ids_sha256(pool) != teacher_meta["soft_labels"]["ids_sha256"]:
        raise DataError("the permissive train pool differs from the one the teacher scored; rerun the teacher")
    if any(e["license_class"] != "permissive" for e in pool):
        raise DataError("a non-permissive example reached the student pool")
    dev_ex = assemble(root, "dev", neg_ratio=cfg.dev_neg_ratio, view=tcfg["view"], limit=cfg.dev_limit)
    vocab = cwe_vocab(pool, teacher_meta["config"]["top_cwes"])
    meta: dict[str, Any] = {
        "schema_version": 1,
        "kind": "student",
        "run_id": run.name,
        "status": "running",
        "config": asdict(cfg),
        "base_model": f"{STUDENT_REPO}@{STUDENT_REVISION}",
        "base_license": "Apache-2.0 (Hugging Face license tag and model card, checked 2026-10-20)",
        "teacher_runs": teacher_runs,
        "training_pool": "permissive-license train examples only (licenses/licenses.csv, SPDX class 'permissive')",
        "git_sha": git_sha(),
        "data": data_hashes(root, {"train": pool, "dev": dev_ex}),
        "label_counts": {
            "train": dict(Counter(e["role"] for e in pool)),
            "dev": dict(Counter(e["role"] for e in dev_ex)),
        },
        "cwe_vocab": vocab,
    }
    write_json(run / "run.json", meta)
    log("data", **meta["label_counts"])
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model, tokenizer = build_student(snapshot, len(vocab), pretrained=True)
    model.to(device)
    targets = [cwe_target(e, vocab) for e in pool]
    opt = torch.optim.AdamW(model.parameters(), lr=cfg.learning_rate, weight_decay=cfg.weight_decay)
    per_epoch = math.ceil(len(pool) / cfg.batch)
    total = cfg.max_steps or per_epoch * cfg.epochs
    sched = get_linear_schedule_with_warmup(opt, int(cfg.warmup_ratio * total), total)
    bce = torch.nn.BCEWithLogitsLoss()
    ce = torch.nn.CrossEntropyLoss()
    t = cfg.temperature
    best: dict[str, Any] = {"step": None, "dev_pr_auc": None}
    misses = 0

    def dev_eval(step: int) -> bool:
        nonlocal misses
        t0 = time.time()
        scored = score_student(model, tokenizer, vocab, dev_ex, cfg.max_tokens, 64, device)
        auc = _dev_pr_auc(scored, dev_ex)
        model.train()
        log("dev", step=step, dev_pr_auc=auc, n=len(dev_ex), seconds=round(time.time() - t0, 1))
        if best["step"] is None or (auc is not None and (best["dev_pr_auc"] is None or auc > best["dev_pr_auc"])):
            best.update(step=step, dev_pr_auc=auc)
            torch.save({k: v.detach().cpu() for k, v in model.state_dict().items()}, run / "student_fp32.pt")
            misses = 0
            return False
        misses += 1
        return misses >= cfg.patience

    step, started, stop, last_eval = 0, time.time(), False, -1
    window: list[float] = []
    model.train()
    for epoch in range(cfg.epochs):
        for batch in make_batches([len(e["code"]) for e in pool], cfg.batch, rng):
            ids, mask = _student_batch(tokenizer, [pool[i] for i in batch], cfg.max_tokens, device)
            hard = torch.tensor([float(pool[i]["label"]) for i in batch], device=device)
            teacher = torch.tensor([soft[pool[i]["id"]] for i in batch], device=device)
            with torch.autocast(device_type=device.type, dtype=torch.bfloat16, enabled=device.type == "cuda"):
                logit, cwe_logits = model(ids, mask)
            logit = logit.float()
            loss = cfg.alpha * bce(logit, hard) + (1 - cfg.alpha) * t * t * bce(logit / t, torch.sigmoid(teacher / t))
            pos = [j for j, i in enumerate(batch) if targets[i] >= 0]
            if pos:
                gold = torch.tensor([targets[batch[j]] for j in pos], device=device)
                loss = loss + cfg.cwe_weight * ce(cwe_logits[pos].float(), gold)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            step += 1
            window.append(float(loss))
            if step % cfg.log_every == 0:
                log(
                    "train",
                    epoch=epoch + 1,
                    step=step,
                    loss=round(sum(window) / len(window), 5),
                    lr=sched.get_last_lr()[0],
                )
                window = []
            if cfg.eval_every and step % cfg.eval_every == 0:
                last_eval = step
                stop = dev_eval(step)
            if stop or (cfg.max_steps and step >= cfg.max_steps):
                break
        if not cfg.eval_every and not stop and last_eval != step:
            last_eval = step
            stop = dev_eval(step)
        if stop or (cfg.max_steps and step >= cfg.max_steps):
            break
    if last_eval != step:
        dev_eval(step)
    elapsed = time.time() - started
    model.load_state_dict(torch.load(run / "student_fp32.pt", weights_only=True, map_location="cpu"))
    torch.save(int8_state(quantize_int8(model)), run / "student_int8.pt")
    meta |= {
        "status": "done",
        "optimizer_steps": step,
        "best": best,
        "train_seconds": round(elapsed, 1),
        "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "exports": {
            name: {"bytes": (run / name).stat().st_size, "sha256": file_sha256(run / name)}
            for name in ("student_fp32.pt", "student_int8.pt")
        },
    }
    write_json(run / "run.json", meta)
    log("exported", **meta["exports"])
    return meta


# --- command line ----------------------------------------------------------------------------


def _add_config(parser: argparse.ArgumentParser, cls: type[TeacherConfig] | type[StudentConfig]) -> None:
    for f in dataclasses.fields(cls):
        default = f.default
        parser.add_argument(f"--{f.name.replace('_', '-')}", type=type(default), default=default)


def _config(args: argparse.Namespace, cls: type[Any]) -> Any:
    return cls(**{f.name: getattr(args, f.name) for f in dataclasses.fields(cls)})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m kestrixvul.train", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="kind", required=True)
    for kind, cls in (("teacher", TeacherConfig), ("student", StudentConfig)):
        p = sub.add_parser(kind)
        p.add_argument("--root", type=Path, required=True, help="the vul data root, e.g. /scratch/$USER/kestrix/vul")
        p.add_argument("--models", type=Path, help="model snapshots (default: <root>/../models)")
        p.add_argument("--run-id", help="default: <kind>-seed<seed>-<SLURM_JOB_ID or time>")
        if kind == "student":
            p.add_argument("--teacher-run", action="append", required=True, help="finished teacher run id (repeatable)")
        _add_config(p, cls)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root: Path = args.root.resolve()
    repo = Path(__file__).resolve().parents[2]
    if (repo / ".git").exists() and root.is_relative_to(repo):
        print("--root must be outside the repository working tree", file=sys.stderr)
        return 2
    models = (args.models or root.parent / "models").resolve()
    os.umask(0o077)
    try:
        if args.kind == "teacher":
            tcfg: TeacherConfig = _config(args, TeacherConfig)
            snapshot = snapshot_dir(models, TEACHER_REPO, TEACHER_REVISION)
            manifest_path(root)
            run = new_run_dir(
                root, args.run_id or f"teacher-seed{tcfg.seed}-{os.environ.get('SLURM_JOB_ID', int(time.time()))}"
            )
            meta = train_teacher(root, snapshot, run, tcfg)
        else:
            scfg: StudentConfig = _config(args, StudentConfig)
            snapshot = snapshot_dir(models, STUDENT_REPO, STUDENT_REVISION)
            manifest_path(root)
            run = new_run_dir(
                root, args.run_id or f"student-seed{scfg.seed}-{os.environ.get('SLURM_JOB_ID', int(time.time()))}"
            )
            meta = train_student(root, snapshot, run, args.teacher_run, scfg)
    except (DataError, HeldOutSplitError, OSError) as exc:
        print(f"train {args.kind}: FAILED {exc}", file=sys.stderr)
        return 1
    print(f"train {args.kind}: done {run} best={meta['best']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
