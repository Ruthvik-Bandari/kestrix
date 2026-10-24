# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
"""The label-audit reviewers: two open-weight Apache-2.0 code models on one H200 (``research/hpc/vul/vul_audit.sbatch``).

* ``ai-a``: Qwen2.5-Coder-32B-Instruct; ``ai-b``: IBM Granite-34B-Code-Instruct-8k. Each judges every
  packet of ``audit/packets.jsonl`` independently from the same written criteria
  (``prompts/vul_audit_reviewer.txt``), in bf16 with greedy decoding.
* ``ai-c``: the stronger model (Qwen, 32k context) with a different prompt
  (``prompts/vul_audit_adjudicator.txt``) that also shows both earlier verdicts, for every packet the two
  reviewers disagree on.

Packets are cut to each model's context (Granite has 8k tokens): advisory, before, after and diff each get a
share of the budget and a ``[truncated]`` marker. Replies are parsed as one JSON object; anything else
becomes ``unclear`` with the reason ``unparseable reply``. Reviews are appended to
``<folder>/reviews/{a,b,adj}-<model>.jsonl`` (0600), so a rerun resumes. Models load offline from
``/scratch/$USER/kestrix/models/<name>@<revision>`` (``research/hpc/vul/fetch_vul_audit_models.sh``), never with
``trust_remote_code``. Record content is untrusted data: the models only classify it.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import PATCH, VERDICTS, read_jsonl

PROMPTS = Path(__file__).parent / "prompts"
MAX_NEW_TOKENS = 200
CHARS_PER_TOKEN = 3.2  # conservative for code; the prompt is cut by characters, then checked in tokens
REASON_CHARS = 200


@dataclass(frozen=True)
class Reviewer:
    name: str  # ai-a, ai-b
    key: str  # file prefix: a, b
    repo: str
    revision: str
    context_tokens: int

    @property
    def slug(self) -> str:
        return self.repo.rsplit("/", 1)[-1]


REVIEWERS = (
    Reviewer("ai-a", "a", "Qwen/Qwen2.5-Coder-32B-Instruct", "381fc969f78efac66bc87ff7ddeadb7e73c218a7", 32768),
    Reviewer("ai-b", "b", "ibm-granite/granite-34b-code-instruct-8k", "4bdfb589ebd261be0942a00dd239175d9d65bc47", 8192),
)
ADJUDICATOR = REVIEWERS[0]


def load_prompt(name: str) -> str:
    """A prompt template without its SPDX header lines."""
    lines = (PROMPTS / name).read_text(encoding="utf-8").splitlines(keepends=True)
    return "".join(line for line in lines if not line.startswith("# SPDX-"))


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "\n[truncated]"


def render(
    packet: dict[str, Any], template: str, budget_chars: int, reviews: list[dict[str, Any]] | None = None
) -> str:
    """The prompt for one packet, its parts cut to ``budget_chars`` in total."""
    advisory = (
        "\n\n".join(f"[{a['id']}]\n{a['text']}" for a in packet["advisories"]) or "(none; SVEN pair, judge by the CWE)"
    )
    parts = {
        "advisory": _cut(advisory, int(budget_chars * 0.15)),
        "before": _cut(packet["before"], int(budget_chars * 0.3)),
        "after": _cut(packet["after"] or "(function deleted by the fix)", int(budget_chars * 0.25)),
        "diff": _cut(packet["diff"], int(budget_chars * 0.3)),
    }
    earlier = ""
    for i, r in enumerate(reviews or [], start=1):
        earlier += f"Review {i}: verdict={r['verdict']} patch={r['patch']} reason={r['reason']}\n"
    return template.format(
        language=packet["language"],
        path=packet["path"],
        function=packet["function"],
        cwes=", ".join(packet["cwes"]) or "unknown",
        reviews=earlier.strip(),
        **parts,
    )


JSON_OBJECT = re.compile(r"\{[^{}]*\}", re.DOTALL)


def parse(reply: str) -> dict[str, str]:
    """The last JSON object in the reply with valid fields, else an ``unclear`` verdict."""
    for match in reversed(JSON_OBJECT.findall(reply)):
        try:
            obj = json.loads(match)
        except json.JSONDecodeError:
            continue
        verdict, patch = str(obj.get("verdict", "")).strip(), str(obj.get("patch", "unclear")).strip()
        if verdict in VERDICTS:
            reason = " ".join(str(obj.get("reason", "")).split())[:REASON_CHARS] or "no reason given"
            return {"verdict": verdict, "patch": patch if patch in PATCH else "unclear", "reason": reason}
    return {"verdict": "unclear", "patch": "unclear", "reason": "unparseable reply"}


Generate = Callable[[str], str]


@dataclass
class Loaded:
    generate: Generate
    unload: Callable[[], None]


def review_all(
    packets: list[dict[str, Any]],
    out: Path,
    generate: Generate,
    template: str,
    budget_chars: int,
    *,
    reviews_for: dict[str, list[dict[str, Any]]] | None = None,
) -> int:
    """Append one review per packet not yet in ``out``; return how many were added."""
    done = {r["id"] for r in read_jsonl(out)}
    added = 0
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        for p in packets:
            if p["id"] in done:
                continue
            prompt = render(p, template, budget_chars, reviews_for[p["id"]] if reviews_for else None)
            fh.write(json.dumps({"id": p["id"], **parse(generate(prompt))}, sort_keys=True) + "\n")
            fh.flush()
            added += 1
    return added


def disputed(a: Path, b: Path) -> dict[str, list[dict[str, Any]]]:
    """{id: [review a, review b]} for packets whose two verdicts differ."""
    ra = {r["id"]: r for r in read_jsonl(a)}
    rb = {r["id"]: r for r in read_jsonl(b)}
    return {i: [ra[i], rb[i]] for i in sorted(set(ra) & set(rb)) if ra[i]["verdict"] != rb[i]["verdict"]}


def model_dir(models: Path, reviewer: Reviewer) -> Path:
    path = models / f"{reviewer.slug}@{reviewer.revision}"
    if not (path / "MANIFEST.sha256").exists():
        raise FileNotFoundError(f"{path} is not downloaded (run research/hpc/vul/fetch_vul_audit_models.sh)")
    return path


def load_generator(path: Path, context_tokens: int) -> Loaded:  # pragma: no cover - needs a GPU
    import gc

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(
        path, local_files_only=True, torch_dtype=torch.bfloat16, device_map="cuda", trust_remote_code=False
    )
    model.eval()
    held = {"model": model}
    del model

    def generate(prompt: str) -> str:
        model = held["model"]
        messages = [{"role": "user", "content": prompt}]
        ids = tokenizer.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt")
        if ids.shape[-1] > context_tokens - MAX_NEW_TOKENS:  # cut by characters was not enough: keep the head
            ids = ids[:, : context_tokens - MAX_NEW_TOKENS]
        with torch.no_grad():
            out = model.generate(
                ids.to(model.device),
                max_new_tokens=MAX_NEW_TOKENS,
                do_sample=False,
                pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
            )
        return str(tokenizer.decode(out[0, ids.shape[-1] :], skip_special_tokens=True))

    def unload() -> None:
        held.clear()
        gc.collect()
        torch.cuda.empty_cache()

    return Loaded(generate, unload)


def run(folder: Path, models: Path, *, limit: int | None = None) -> dict[str, Any]:  # pragma: no cover - GPU job
    """Both reviews, then the adjudication of disagreements; returns timing and counts."""
    packets = read_jsonl(folder / "packets.jsonl")[:limit] if limit else read_jsonl(folder / "packets.jsonl")
    reviews = folder / "reviews"
    reviews.mkdir(parents=True, exist_ok=True, mode=0o700)
    reviewer_prompt = load_prompt("vul_audit_reviewer.txt")
    adjudicator_prompt = load_prompt("vul_audit_adjudicator.txt")
    report: dict[str, Any] = {"packets": len(packets), "reviewers": {}}
    files = {r.key: reviews / f"{r.key}-{r.slug}.jsonl" for r in REVIEWERS}
    for reviewer in (REVIEWERS[1], REVIEWERS[0]):  # Granite first, so Qwen stays loaded for the adjudication
        start = time.monotonic()
        loaded = load_generator(model_dir(models, reviewer), reviewer.context_tokens)
        budget = int((reviewer.context_tokens - MAX_NEW_TOKENS - 700) * CHARS_PER_TOKEN)
        added = review_all(packets, files[reviewer.key], loaded.generate, reviewer_prompt, budget)
        report["reviewers"][reviewer.name] = {
            "model": reviewer.repo,
            "revision": reviewer.revision,
            "added": added,
            "seconds": round(time.monotonic() - start),
        }
        if reviewer is ADJUDICATOR:
            start = time.monotonic()
            disputes = disputed(files["a"], files["b"])
            out = reviews / f"adj-{reviewer.slug}.jsonl"
            todo = [p for p in packets if p["id"] in disputes]
            added = review_all(todo, out, loaded.generate, adjudicator_prompt, budget, reviews_for=disputes)
            report["reviewers"]["ai-c"] = {
                "model": reviewer.repo,
                "revision": reviewer.revision,
                "disputes": len(disputes),
                "added": added,
                "seconds": round(time.monotonic() - start),
            }
        loaded.unload()
    return report
