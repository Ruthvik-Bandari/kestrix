"""Local Hugging Face inference for B2 (cluster GPU job only; needs the ``gpu`` dependency group).

The model loads from a local snapshot fetched on the transfer node at a pinned revision, with
``local_files_only`` and ``trust_remote_code=False``, so nothing is downloaded and no repository
code runs at inference time. Decoding is greedy, which makes it deterministic for a given model,
prompt and hardware.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .b2 import Model

MAX_NEW_TOKENS = 768


def load(snapshot: Path, adapter: Path | None = None) -> Model:
    """``adapter``: an M1 LoRA adapter directory to apply on top of the base snapshot."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(snapshot, local_files_only=True, trust_remote_code=False)
    dtype = torch.bfloat16 if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else torch.float16
    model: Any = AutoModelForCausalLM.from_pretrained(
        snapshot, local_files_only=True, trust_remote_code=False, torch_dtype=dtype, device_map="auto"
    )
    if adapter is not None:
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, adapter, is_trainable=False)
    model.eval()

    def complete(prompt: str) -> str:
        messages = [{"role": "user", "content": prompt}]
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(text, return_tensors="pt").to(model.device)
        with torch.no_grad():
            output = model.generate(
                **inputs, max_new_tokens=MAX_NEW_TOKENS, do_sample=False, pad_token_id=tokenizer.eos_token_id
            )
        return str(tokenizer.decode(output[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True))

    return complete
