"""Fetch Llama Prompt Guard into data/prompt_guard/.

You must accept Meta's licence first — the download is gated and will 403 or
404 until you do. Either route works:

  Kaggle   https://www.kaggle.com/models/metaresearch/llama-3.1-prompt-guard
           accept the licence, then create an API token
           (kaggle.com/settings -> Create New Token) and save the downloaded
           kaggle.json to ~/.kaggle/kaggle.json

  HuggingFace  accept the licence on the model page, then
               huggingface-cli login

    python -m scripts.download_guard
"""
import shutil
import sys
from pathlib import Path

DEST = Path("data/prompt_guard")

KAGGLE_SLUGS = [
    "metaresearch/llama-3.1-prompt-guard/transformers/prompt-guard-86m",
    "metaresearch/llama-3.1-prompt-guard/pyTorch/prompt-guard-86m",
    "metaresearch/llama-3.1-prompt-guard/transformers/llama-prompt-guard-2-86m",
]
HF_REPOS = ["meta-llama/Llama-Prompt-Guard-2-86M", "meta-llama/Prompt-Guard-86M"]


def try_kaggle() -> Path | None:
    try:
        import kagglehub
    except ImportError:
        return None
    for slug in KAGGLE_SLUGS:
        try:
            p = Path(kagglehub.model_download(slug))
            print(f"  kaggle: got {slug}")
            return p
        except Exception as e:
            print(f"  kaggle: {slug} -> {type(e).__name__}")
    return None


def try_hf() -> Path | None:
    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        return None
    for repo in HF_REPOS:
        try:
            p = Path(snapshot_download(repo))
            print(f"  hf: got {repo}")
            return p
        except Exception as e:
            print(f"  hf: {repo} -> {type(e).__name__}")
    return None


def main():
    if (DEST / "config.json").exists():
        print(f"already present at {DEST}")
        return

    print("fetching Prompt Guard...")
    src = try_kaggle() or try_hf()
    if src is None:
        print("\nCould not download. The model is licence-gated — accept the "
              "licence and authenticate, then re-run. See this file's docstring.",
              file=sys.stderr)
        raise SystemExit(1)

    DEST.parent.mkdir(parents=True, exist_ok=True)
    if DEST.exists():
        shutil.rmtree(DEST)
    shutil.copytree(src, DEST)
    print(f"\ninstalled to {DEST}")
    print("next: python -m scripts.run_guard_baseline")


if __name__ == "__main__":
    main()
