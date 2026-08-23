"""
complexity_model.py — loads our trained char-level GPT (from ../out-complexity-char)
and exposes a simple analyze_code() function that returns a clean, parsed
prediction instead of raw continuing text.
"""
import os
import pickle
import re
from contextlib import nullcontext

import torch

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from model import GPTConfig, GPT

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "out-complexity-char")
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
DTYPE = "bfloat16" if torch.cuda.is_available() and torch.cuda.is_bf16_supported() else "float16"


class ComplexityModel:
    def __init__(self):
        ckpt_path = os.path.join(OUT_DIR, "ckpt.pt")
        checkpoint = torch.load(ckpt_path, map_location=DEVICE, weights_only=False)
        gptconf = GPTConfig(**checkpoint["model_args"])
        self.model = GPT(gptconf)

        state_dict = checkpoint["model"]
        unwanted_prefix = "_orig_mod."
        for k, v in list(state_dict.items()):
            if k.startswith(unwanted_prefix):
                state_dict[k[len(unwanted_prefix):]] = state_dict.pop(k)
        self.model.load_state_dict(state_dict)
        self.model.eval()
        self.model.to(DEVICE)

        # load the char-level vocab
        meta_path = os.path.join(
            os.path.dirname(__file__), "..", "data", "complexity_char", "meta.pkl"
        )
        with open(meta_path, "rb") as f:
            meta = pickle.load(f)
        self.stoi, self.itos = meta["stoi"], meta["itos"]

        ptdtype = {"float32": torch.float32, "bfloat16": torch.bfloat16, "float16": torch.float16}[DTYPE]
        device_type = "cuda" if "cuda" in DEVICE else "cpu"
        self.ctx = (
            nullcontext()
            if device_type == "cpu"
            else torch.amp.autocast(device_type=device_type, dtype=ptdtype)
        )

    def encode(self, s: str):
        return [self.stoi[c] for c in s if c in self.stoi]

    def decode(self, ids) -> str:
        return "".join(self.itos[i] for i in ids)

    def generate_raw(self, prompt: str, max_new_tokens=200, temperature=0.6, top_k=100) -> str:
        ids = self.encode(prompt)
        x = torch.tensor(ids, dtype=torch.long, device=DEVICE)[None, ...]
        with torch.no_grad():
            with self.ctx:
                y = self.model.generate(x, max_new_tokens, temperature=temperature, top_k=top_k)
        full = self.decode(y[0].tolist())
        return full[len(prompt):]  # just the newly generated part


def build_prompt(code: str, language: str, few_shot_example: dict | None = None) -> str:
    """
    Build the prompt in the exact shape the model was trained on. If a
    few_shot_example is given (from retrieval), it's shown first as a
    worked example, then the new code, matching the same format so the
    model can pattern-match off it (see conversation notes: this is
    few-shot grounding, not true instruction-following RAG).
    """
    parts = []
    if few_shot_example:
        parts.append(few_shot_example["full_text"].strip())
        parts.append("")
    parts.append(f"Language: {language}")
    parts.append("Code:")
    parts.append(code.strip())
    parts.append("Expected Output:")
    return "\n".join(parts)


def parse_output(raw_generated: str) -> dict:
    """
    Crop the model's raw continuation at the first END EXAMPLE, and pull out
    the Time/Space/Reason fields. Returns a dict; any field the model didn't
    produce cleanly comes back as None so the UI can show that honestly
    instead of guessing.
    """
    end_idx = raw_generated.find("END EXAMPLE")
    cropped = raw_generated[:end_idx].strip() if end_idx != -1 else raw_generated.strip()

    time_match = re.search(r"Time Complexity:\s*(\S+)", cropped)
    space_match = re.search(r"Space Complexity:\s*(\S+)", cropped)
    reason_match = re.search(r"Reason:\s*\n?(.*)", cropped, re.DOTALL)

    return {
        "time_complexity": time_match.group(1) if time_match else None,
        "space_complexity": space_match.group(1) if space_match else None,
        "reason": reason_match.group(1).strip() if reason_match else None,
        "raw_cropped": cropped,
    }


_model_instance = None


def get_model() -> ComplexityModel:
    global _model_instance
    if _model_instance is None:
        _model_instance = ComplexityModel()
    return _model_instance


def analyze_code(code: str, language: str, few_shot_example: dict | None = None) -> dict:
    model = get_model()
    prompt = build_prompt(code, language, few_shot_example)
    raw = model.generate_raw(prompt, max_new_tokens=200)
    parsed = parse_output(raw)
    parsed["prompt_used"] = prompt
    return parsed
