"""Download the BGE-small ONNX model into models/ for baking into the image."""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

REPO = "BAAI/bge-small-en-v1.5"
BASE = f"https://huggingface.co/{REPO}/resolve/main"
FILES = {
    "model.onnx": f"{BASE}/onnx/model.onnx",
    "tokenizer.json": f"{BASE}/tokenizer.json",
}


def main() -> int:
    dest = Path("models/bge-small-en-v1.5")
    dest.mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        target = dest / name
        if target.exists():
            print(f"present: {target}")
            continue
        print(f"downloading {url}")
        urllib.request.urlretrieve(url, target)
    print(f"model ready in {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
