#!/usr/bin/env python3
"""
==============================================================================
OpenRouter Free Models Catalog Refresher (ATI V2)
Description: Dynamically queries OpenRouter API for live, zero-cost models,
             filters out deprecated/paid/media-only models and known prompt-leakers,
             and updates OPENROUTER_MODELS in backend/llm.py.
==============================================================================
"""

import os
import sys
import re
import json
import argparse
import urllib.request
import urllib.error

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
LLM_PY_PATH = os.path.join(ROOT_DIR, "backend", "llm.py")
ENV_PATH = os.path.join(ROOT_DIR, ".env")

# Models excluded due to proven failure in production (prompt leaks, non-text, or parameter crashes)
BLACKLISTED_MODELS = {
    "nvidia/nemotron-3.5-lightning:free",  # 74.5% prompt leak rate in empirical DB audit
    "google/lyria-3-pro-preview",         # Audio/music generation preview
    "google/lyria-3-clip-preview",        # Audio clip generation preview
}

# Preferred ranking order for high-quality threat intelligence & PoC extraction
PREFERRED_ORDER = [
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "particle-ai/particle-1:free",
    "google/gemma-4-31b-it:free",
    "google/gemma-4-26b-a4b-it:free",
    "nvidia/nemotron-3.5-super-vl:free",
    "dots-studio/dots-3-note-preview:free",
    "liquid/lfm-3-1.7b:free",
    "openrouter/free"
]


def load_openrouter_api_key():
    """Extracts first valid OpenRouter API key from .env without external dependencies."""
    if not os.path.exists(ENV_PATH):
        return None

    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("OPENROUTER_API_KEY") and "=" in line:
                val = line.split("=", 1)[1].strip()
                # Strip leading/trailing quotes
                if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                    val = val[1:-1].strip()
                keys = [k.strip().strip('"').strip("'") for k in val.split(",") if k.strip()]
                if keys:
                    return keys[0]
    return None


def fetch_openrouter_models(api_key=None, verbose=False):
    """Fetches the full models list from OpenRouter API."""
    url = "https://openrouter.ai/api/v1/models"
    headers = {
        "User-Agent": "ATI-V2-Model-Refresher/1.0"
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    if verbose:
        print(f"[*] Querying OpenRouter API: {url}")

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read().decode("utf-8")
            json_data = json.loads(data)
            return json_data.get("data", [])
    except Exception as e:
        print(f"[!] Error querying OpenRouter API: {e}", file=sys.stderr)
        return []


def filter_and_rank_free_models(models, verbose=False):
    """Filters free text/reasoning models and ranks them by quality."""
    free_models = []

    for m in models:
        m_id = m.get("id", "")
        pricing = m.get("pricing", {})
        prompt_price = pricing.get("prompt", "0")
        comp_price = pricing.get("completion", "0")

        is_free_id = m_id.endswith(":free") or m_id == "openrouter/free"
        is_free_price = (prompt_price == "0" or prompt_price == 0) and (comp_price == "0" or comp_price == 0)

        if not (is_free_id or is_free_price):
            continue

        if m_id in BLACKLISTED_MODELS:
            if verbose:
                print(f"[-] Excluding blacklisted model: {m_id}")
            continue

        # Check description and name for audio/image-only models
        desc = (m.get("description") or "").lower()
        name = (m.get("name") or "").lower()
        if "music generation" in desc or "music generation" in name or "audio generation" in desc:
            if verbose:
                print(f"[-] Excluding non-text/audio model: {m_id}")
            continue

        free_models.append({
            "id": m_id,
            "name": m.get("name", m_id),
            "context_length": m.get("context_length", 0),
            "description": (m.get("description") or "")[:120]
        })

    # Sort based on PREFERRED_ORDER, with unlisted free models appended at the end
    def sort_key(item):
        m_id = item["id"]
        if m_id in PREFERRED_ORDER:
            return PREFERRED_ORDER.index(m_id)
        return len(PREFERRED_ORDER) + 1

    ranked = sorted(free_models, key=sort_key)

    # Ensure openrouter/free meta-router is included as safety fallback
    if not any(m["id"] == "openrouter/free" for m in ranked):
        ranked.append({
            "id": "openrouter/free",
            "name": "Free Models Router",
            "context_length": 200000,
            "description": "Dynamic auto-router fallback across available free models"
        })

    return ranked


def update_llm_py(model_ids, dry_run=False, verbose=False):
    """Safely updates OPENROUTER_MODELS list in backend/llm.py."""
    if not os.path.exists(LLM_PY_PATH):
        print(f"[!] Error: {LLM_PY_PATH} not found!", file=sys.stderr)
        return False

    with open(LLM_PY_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = r'(OPENROUTER_MODELS\s*=\s*\[)([^\]]*?)(\])'
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        print("[!] Could not locate OPENROUTER_MODELS definition in backend/llm.py", file=sys.stderr)
        return False

    formatted_list = "OPENROUTER_MODELS = [\n"
    for m in model_ids:
        formatted_list += f'    "{m}",\n'
    formatted_list = formatted_list.rstrip(",\n") + "\n]"

    new_content = content[:match.start()] + formatted_list + content[match.end():]

    if dry_run:
        print("\n[DRY RUN] Generated OPENROUTER_MODELS block:")
        print(formatted_list)
        return True

    with open(LLM_PY_PATH, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"\n[+] Successfully updated {LLM_PY_PATH} with {len(model_ids)} active free models.")
    return True


def main():
    parser = argparse.ArgumentParser(description="Refresh OpenRouter Free Models in ATI V2")
    parser.add_argument("--dry-run", action="store_true", help="Preview models and changes without writing to backend/llm.py")
    parser.add_argument("--verbose", action="store_true", help="Print verbose details of each model")
    args = parser.parse_args()

    print("=" * 65)
    print(" 🚀 OpenRouter Free Models Refresher for ATI V2")
    print("=" * 65)

    api_key = load_openrouter_api_key()
    if api_key:
        print(f"[*] Loaded OpenRouter API Key (...{api_key[-6:]})")
    else:
        print("[*] No API Key found in .env; querying public models catalog...")

    models = fetch_openrouter_models(api_key, verbose=args.verbose)
    if not models:
        print("[!] No models returned from OpenRouter API. Exiting.")
        sys.exit(1)

    print(f"[*] Retrieved {len(models)} total models from OpenRouter.")
    ranked_models = filter_and_rank_free_models(models, verbose=args.verbose)

    print(f"\n[*] Found {len(ranked_models)} active free models:")
    for i, m in enumerate(ranked_models, 1):
        print(f"  {i:2d}. {m['id']:<45} (ctx: {m['context_length']:,} tokens)")
        if args.verbose:
            print(f"      Name: {m['name']}")
            print(f"      Desc: {m['description']}...")

    model_ids = [m["id"] for m in ranked_models]
    update_llm_py(model_ids, dry_run=args.dry_run, verbose=args.verbose)
    print("=" * 65)


if __name__ == "__main__":
    main()
