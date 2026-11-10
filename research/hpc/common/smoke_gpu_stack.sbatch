#!/bin/bash -l
# SPDX-FileCopyrightText: 2026 Ruthvik Bandari
# SPDX-License-Identifier: Apache-2.0
# Checks the `gpu` dependency group on a V100 (sm_70, driver 545) after a torch or transformers bump:
# CUDA works, fp16 matmul runs, and transformers 5 tokenizes a chat and generates on the GPU.
# Offline: the tokenizer and the model are built in the job, nothing is downloaded.
#   ssh explorer 'cd ~/kestrix && bash research/hpc/common/setup_env.sh gpu'   # on explorer-xfer if it downloads
#   ssh explorer 'cd ~/kestrix && sbatch research/hpc/common/smoke_gpu_stack.sbatch'
#SBATCH --job-name=kestrix-gpu-stack
#SBATCH --account=aai6610.202610
#SBATCH --partition=gpu-short
#SBATCH --gres=gpu:v100-sxm2:1
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=00:15:00
#SBATCH --output=/scratch/%u/kestrix/logs/%x-%j.out
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH" HF_HUB_OFFLINE=1
source "$(dirname "$0")/gpu_env.sh" 2>/dev/null || source research/hpc/common/gpu_env.sh
nvidia-smi --query-gpu=name,driver_version --format=csv,noheader
uv run --no-sync python - <<'EOF'
import torch
import transformers
from tokenizers import Tokenizer, models, pre_tokenizers
from transformers import LlamaConfig, LlamaForCausalLM, PreTrainedTokenizerFast

print("torch", torch.__version__, "cuda", torch.version.cuda, "transformers", transformers.__version__)
assert torch.cuda.is_available(), "CUDA not available"
cap = torch.cuda.get_device_capability(0)
print("device", torch.cuda.get_device_name(0), "capability", cap)
assert f"sm_{cap[0]}{cap[1]}" in torch.cuda.get_arch_list(), f"no kernels for sm_{cap[0]}{cap[1]}"
a = torch.randn(512, 512, device="cuda", dtype=torch.float16)
assert torch.isfinite(a @ a).all()

vocab = {t: i for i, t in enumerate(["<unk>", "<eos>", "user", "assistant", ":", "hello", "world"])}
raw = Tokenizer(models.WordLevel(vocab, unk_token="<unk>"))
raw.pre_tokenizer = pre_tokenizers.Whitespace()
tok = PreTrainedTokenizerFast(tokenizer_object=raw, unk_token="<unk>", eos_token="<eos>", pad_token="<eos>")
tok.chat_template = "{% for m in messages %}{{ m['role'] }} : {{ m['content'] }} {% endfor %}assistant :"
messages = [{"role": "user", "content": "hello world"}]
# The call in kestrixvul.audit_llm: transformers 5 returns a BatchEncoding unless return_dict=False.
ids = tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt", return_dict=False)
assert isinstance(ids, torch.Tensor) and ids.dim() == 2, type(ids)
text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
assert isinstance(text, str), type(text)

cfg = LlamaConfig(vocab_size=len(vocab), hidden_size=64, intermediate_size=128, num_hidden_layers=2,
                  num_attention_heads=4, num_key_value_heads=4, max_position_embeddings=64)
model = LlamaForCausalLM(cfg).to("cuda", dtype=torch.float16).eval()
with torch.no_grad():
    out = model.generate(ids.to("cuda"), max_new_tokens=4, min_new_tokens=4, do_sample=False, pad_token_id=tok.pad_token_id)
assert out.shape[-1] == ids.shape[-1] + 4, out.shape
print("OK: gpu stack works on this device")
EOF
