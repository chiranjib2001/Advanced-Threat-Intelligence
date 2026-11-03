# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Multi-Provider Free LLM Cascade with Dynamic Cooldown & Telemetry
# Providers: GroqCloud, Cerebras, OpenRouter Free, Google Gemini, Mistral, Local Ollama
# ==============================================================================
import os
import time
import logging
import random
import re
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOGS_DIR = os.path.join(ROOT_DIR, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

logger = logging.getLogger('ai_engine')
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler(os.path.join(LOGS_DIR, 'cve_analyzer.log'), encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s'))
    logger.addHandler(fh)

api_logger = logging.getLogger('api_call_logger')
api_logger.setLevel(logging.INFO)
if not api_logger.handlers:
    ap_fh = logging.FileHandler(os.path.join(LOGS_DIR, 'apicall.log'), encoding='utf-8')
    ap_fh.setFormatter(logging.Formatter('%(asctime)s - [API] - %(message)s'))
    api_logger.addHandler(ap_fh)

# --- DYNAMIC GETTERS FOR ALL FREE PROVIDERS ---
def _parse_keys(env_var: str) -> list:
    load_dotenv(override=True)
    raw = os.getenv(env_var, "")
    return [k.strip() for k in raw.split(",") if k.strip()]

def get_groq_keys(): return _parse_keys("GROQ_API_KEYS")
def get_cerebras_keys(): return _parse_keys("CEREBRAS_API_KEYS")
def get_openrouter_keys(): return _parse_keys("OPENROUTER_API_KEY")
def get_gemini_keys(): return _parse_keys("GEMINI_API_KEYS")
def get_mistral_keys(): return _parse_keys("MISTRAL_API_KEYS")
def get_ollama_url(): return os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1").strip()

# --- MODEL POOLS ---
GROQ_MODELS = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "qwen/qwen3.8-27b",
    "qwen/qwen3.6-27b",
    "groq/compound",
    "groq/compound-mini"
]

CEREBRAS_MODELS = [
    "gpt-oss-120b",
    "qwen-3.8-27b",
    "gemma-4-31b"
]

OPENROUTER_MODELS = [
    "nvidia/nemotron-3.5-lightning:free",
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "liquid/lfm-2.5-2.6b:free",
    "nex-agi/nex-n2.5-mini:free",
    "cohere/north-mini-code:free",
    "poolside/laguna-s-2.1:free",
    "thinkingmachines/inkling:free"
]

GEMINI_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-flash-latest",
    "gemini-2.5-pro",
    "gemini-pro-latest"
]

MISTRAL_MODELS = [
    "codestral-latest",
    "mistral-small-latest"
]

KEYWORD_LIST = [
    "Ransomware",
    "Lateral Movement",
    "Zero-Click",
    "Default Credentials",
    "Privilege Escalation",
    "Unauthenticated RCE",
    "Data Exfiltration"
]

# --- DYNAMIC KEY COOLDOWN SCHEDULER & TELEMETRY ---
# Tracks key_str -> reactivate_timestamp. If 429 occurs, skips key until reactivate_timestamp.
_key_cooldowns = {}

def _is_cooling_down(key: str) -> bool:
    reactivate_at = _key_cooldowns.get(key, 0)
    return time.time() < reactivate_at

def _set_cooldown(key: str, seconds: float = 60.0):
    _key_cooldowns[key] = time.time() + seconds

def _get_cooldown_remaining(key: str) -> float:
    return max(0.0, _key_cooldowns.get(key, 0) - time.time())

# Telemetry registry for System Gateway UI
_telemetry = {
    "groq": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None},
    "cerebras": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None},
    "openrouter": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None},
    "gemini": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None},
    "mistral": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None},
    "ollama": {"requests": 0, "success": 0, "failures": 0, "latencies": [], "last_model": None}
}

def _mask_key(key: str) -> str:
    if not key: return "None"
    return f"...{key[-6:]}" if len(key) > 6 else "******"

def _record_telemetry(provider: str, success: bool, latency: float, model: str):
    if provider in _telemetry:
        t = _telemetry[provider]
        t["requests"] += 1
        if success:
            t["success"] += 1
            t["latencies"].append(round(latency, 2))
            if len(t["latencies"]) > 20:
                t["latencies"].pop(0)
            t["last_model"] = model
        else:
            t["failures"] += 1


def _call_llm_chat(messages, max_tokens=1000, temperature=0.1, custom_models=None):
    """
    Multi-Provider Free LLM Execution Engine:
    Cascades across available zero-cost providers in order:
    1. GroqCloud (Ultra-fast LPU inference)
    2. Cerebras Cloud (High-speed free tier)
    3. OpenRouter Free Pool (nemotron, gemma-4, minimax, glm-5.2)
    4. Google Gemini AI Studio (gemini-2.5-flash, gemini-pro)
    5. Mistral AI (codestral, mistral-small)
    6. Local Ollama (100% offline fallback)
    """
    providers_order = [
        ("groq", get_groq_keys(), "https://api.groq.com/openai/v1", GROQ_MODELS, 12.0),
        ("gemini", get_gemini_keys(), "https://generativelanguage.googleapis.com/v1beta/openai/", GEMINI_MODELS, 18.0),
        ("mistral", get_mistral_keys(), "https://api.mistral.ai/v1", MISTRAL_MODELS, 12.0),
        ("cerebras", get_cerebras_keys(), "https://api.cerebras.ai/v1", CEREBRAS_MODELS, 6.0),
        ("openrouter", get_openrouter_keys(), "https://openrouter.ai/api/v1", OPENROUTER_MODELS, 10.0)
    ]

    for p_name, keys, base_url, default_models, timeout_sec in providers_order:
        if not keys:
            continue

        models_to_try = [m for m in (custom_models if custom_models else default_models) if not (p_name != "gemini" and m.startswith("gemini-"))]
        for model in models_to_try:
            for key in keys:
                if _is_cooling_down(key):
                    rem = round(_get_cooldown_remaining(key), 1)
                    api_logger.info(f"[{p_name.upper()}] Key {_mask_key(key)} cooling down ({rem}s remaining) -> Skipping call")
                    continue

                masked = _mask_key(key)
                req_tag = f"[{p_name.upper()}] [Model: '{model}'] [Key: {masked}]"
                api_logger.info(f"{req_tag} -> Sending completion request...")
                t_start = time.time()

                try:
                    client = OpenAI(base_url=base_url, api_key=key, timeout=timeout_sec, max_retries=0)
                    response = client.chat.completions.create(
                        model=model,
                        messages=messages,
                        max_tokens=max_tokens,
                        temperature=temperature
                    )
                    latency = time.time() - t_start
                    raw_content = response.choices[0].message.content if response.choices and response.choices[0].message else ""
                    reply = (raw_content or "").strip()

                    if reply:
                        _record_telemetry(p_name, True, latency, model)
                        success_msg = f"{req_tag} -> SUCCESS in {latency:.2f}s! ({len(reply)} chars)"
                        api_logger.info(success_msg)
                        logger.info(success_msg)
                        return reply, f"{p_name.capitalize()} ({model})"

                except Exception as e:
                    latency = time.time() - t_start
                    _record_telemetry(p_name, False, latency, model)
                    err_str = str(e)

                    # Dynamic key cooldown on rate limit (429), payment required (402), or quota exhaustion
                    if "402" in err_str or "payment" in err_str.lower() or "billing" in err_str.lower():
                        _set_cooldown(key, 86400.0)
                        logger.warning(f"{req_tag} -> Payment required / quota exhausted (402). Placing key in cooldown for 24h.")
                    elif "429" in err_str or "rate limit" in err_str.lower() or "free-models-per-day" in err_str:
                        cooldown_time = 86400.0 if "free-models-per-day" in err_str else 60.0
                        _set_cooldown(key, cooldown_time)
                        logger.warning(f"{req_tag} -> Rate limit triggered. Placing key in cooldown for {cooldown_time}s.")
                    elif "timeout" in err_str.lower() or "timed out" in err_str.lower():
                        if p_name == "openrouter":
                            _set_cooldown(key, 300.0)

                    err_snippet = err_str[:160].replace("\n", " ")
                    fail_msg = f"{req_tag} -> FAILED in {latency:.2f}s: {err_snippet}"
                    api_logger.warning(fail_msg)
                    logger.warning(fail_msg)
                    time.sleep(0.2)
                    continue

    # Provider 6: Local Ollama (Offline Fallback)
    ollama_url = get_ollama_url()
    try:
        t_start = time.time()
        client = OpenAI(base_url=ollama_url, api_key="ollama", timeout=12.0)
        response = client.chat.completions.create(
            model="llama3.2",
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature
        )
        latency = time.time() - t_start
        raw_content = response.choices[0].message.content if response.choices and response.choices[0].message else ""
        reply = (raw_content or "").strip()
        if reply:
            _record_telemetry("ollama", True, latency, "llama3.2")
            return reply, "Local Ollama (llama3.2)"
    except Exception:
        pass

    logger.error("CRITICAL: All configured LLM providers exhausted after full cascade.")
    api_logger.error("CRITICAL: All configured LLM providers exhausted after full cascade.")
    return None, "Failed (All Models Offline)"


def ai_link_classifier(text_content, url=None, thread_models=None):
    """
    3-Way Threat Intel Classifier with Fast-Path Heuristic Pre-Filtering:
    1. Checks URL against known exploit signatures or runnable shell/command patterns -> 'POC' (<1ms, 0 AI tokens)
    2. Checks URL against known vendor advisory portals (Microsoft, Cisco, Siemens, etc.) -> 'VENDOR_FIX' (<1ms, 0 AI tokens)
    3. Analyzes GitHub code vs commit/PR vs advisory paths (<1ms)
    4. Ambiguous Links Only: Dispatches to Multi-Provider AI Engine
    Returns: 'POC', 'VENDOR_FIX', or 'INFO'
    """
    from backend import scraper

    # Heuristic Rule 0: Product version / release tag check
    if url and scraper.is_product_release_url(url):
        return "VULN_VERSION"

    # Heuristic Rule 1: Research Blog with embedded PoC or pure PoC
    is_blog = bool(url and scraper.is_blog_url(url, text_content))
    has_poc_command = bool(scraper.match_exploit_command_signatures(text_content) or (url and scraper.is_known_exploit_url(url)))

    if is_blog and has_poc_command:
        return "BLOG_POC"
    if has_poc_command:
        return "POC"

    # Heuristic Rule 2: Official vendor security bulletin match
    if url and scraper.is_known_advisory_url(url):
        return "VENDOR_FIX"

    # Heuristic Rule 3: GitHub smart path inspection
    if url and "github.com" in url.lower():
        u_lower = url.lower()
        if any(p in u_lower for p in ["/releases/tag/", "/releases/download/", "/archive/refs/tags/", "/releases", "/tags"]):
            return "VULN_VERSION"
        if "/commit/" in u_lower or "/pull/" in u_lower or "/security/advisories/" in u_lower:
            return "VENDOR_FIX"
        if any(u_lower.endswith(ext) for ext in [".py", ".c", ".cpp", ".go", ".sh", ".rb", ".pl"]):
            return "POC"
        if "/issues/" in u_lower:
            return "INFO"

    if is_blog:
        return "BLOG"

    if not text_content or len(text_content.strip()) < 25:
        return "INFO"

    # Fast AI fallback for ambiguous text
    prompt = """You are an expert threat intelligence classifier. Read the text extracted from a security webpage.
Classify this content into EXACTLY one of these categories:
1. 'POC' - Working Proof of Concept code, exploit payload, or weaponization steps.
2. 'BLOG_POC' - Security research writeup or blog containing working PoC commands or code.
3. 'BLOG' - General security research writeup or article without runnable exploit commands.
4. 'VULN_VERSION' - Product version release, download archive, or package distribution.
5. 'VENDOR_FIX' - Official vendor security advisory, patch notification, or mitigation guide.
6. 'INFO' - General CVE discussion, news snippet, or bug tracker.
Output EXACTLY and ONLY one word: 'POC', 'BLOG_POC', 'BLOG', 'VULN_VERSION', 'VENDOR_FIX', or 'INFO'."""

    truncated_text = text_content[:4000]
    messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": f"Text:\n{truncated_text}"}
    ]

    reply, model_used = _call_llm_chat(messages, max_tokens=15, temperature=0.0, custom_models=thread_models)
    if reply:
        clean = reply.strip().upper()
        if "BLOG_POC" in clean or ("BLOG" in clean and "POC" in clean):
            return "BLOG_POC"
        elif "POC" in clean:
            return "POC"
        elif "BLOG" in clean:
            return "BLOG"
        elif "VERSION" in clean or "RELEASE" in clean:
            return "VULN_VERSION"
        elif "VENDOR" in clean or "FIX" in clean or "PATCH" in clean:
            return "VENDOR_FIX"
        else:
            return "INFO"
    return "INFO"


def ai_poc_detector(text_content, url=None, thread_models=None):
    """Backwards-compatible wrapper: returns True if classified as POC."""
    return ai_link_classifier(text_content, url=url, thread_models=thread_models) == "POC"


def ai_select_best_poc_links(cve_id: str, candidate_urls: list, max_select: int = 3, thread_models=None) -> list:
    """
    Given a list of 5+ outbound candidate URLs extracted from a page,
    uses the LLM to identify the top candidate links most likely to contain
    functional PoC exploit code, technical recreation steps, or raw scripts.
    Falls back to heuristic ranking if LLM is unavailable.
    """
    if not candidate_urls:
        return []
    if len(candidate_urls) <= max_select:
        return candidate_urls

    def heuristic_score(u):
        u_low = u.lower()
        score = 0
        if any(k in u_low for k in ['exploit', 'poc', 'payload', 'advisory/poc', 'cve-']): score += 10
        if any(k in u_low for k in ['github.com', 'gitlab.com', 'gist.github.com']): score += 8
        if any(u_low.endswith(ext) for ext in ['.py', '.sh', '.c', '.go', '.rb', '.pl']): score += 10
        if any(k in u_low for k in ['raw.githubusercontent.com', 'pastebin.com', 'rentry.co']): score += 9
        if any(k in u_low for k in ['/blog/', '/research/', '/writeup/', '/disclosures/']): score += 5
        if any(k in u_low for k in ['support.', 'help.', 'docs.', 'forum.', 'community.', 'legal', 'privacy', 'twitter.com', 'linkedin.com']): score -= 10
        return score

    sorted_candidates = sorted(candidate_urls, key=heuristic_score, reverse=True)

    prompt = f"""You are a cyber threat intelligence specialist analyzing {cve_id}.
From the following candidate URLs extracted from a security disclosure, select up to {max_select} URLs that are MOST LIKELY to contain a Proof of Concept (PoC), weaponized exploit script, GitHub repository, or technical recreation steps.

Candidate URLs:
{chr(10).join(sorted_candidates[:15])}

Output ONLY the selected URLs, exactly one URL per line, with no other commentary or markdown."""

    messages = [
        {"role": "system", "content": "You are a precise link selector for security exploit researchers. Select only the top URLs most likely to contain actual PoC exploit code or reproduction steps."},
        {"role": "user", "content": prompt}
    ]

    try:
        reply, model_used = _call_llm_chat(messages, max_tokens=150, temperature=0.0, custom_models=thread_models)
        if reply and not reply.startswith("API Offline") and not model_used.startswith("Failed"):
            chosen = []
            for line in reply.splitlines():
                line = line.strip().strip("-*• ")
                for cand in candidate_urls:
                    if cand in line or line in cand:
                        if cand not in chosen:
                            chosen.append(cand)
                            break
            if chosen:
                logger.info(f"AI selected {len(chosen)} candidate PoC links for {cve_id} via {model_used}: {chosen}")
                return chosen[:max_select]
    except Exception as e:
        logger.warning(f"AI link selection error for {cve_id}: {e}")

    return sorted_candidates[:max_select]


def analyze_individual_cve(cve_id, combined_text_data, thread_models=None):
    """
    Extracts structured intelligence with strict XML schema for a single CVE.
    Returns: summary, action, poc, vendor, product, keywords, model_used
    """
    logger.info(f"AI Analyzing {cve_id} via Multi-Provider Cascade...")

    strict_prompt = f"""You are a precise cybersecurity analyst. You MUST output your response EXACTLY using the following XML tags. Do NOT add any conversational text outside these tags.

<summary>Provide a 5 to 6 line summary of the threat.</summary>
<action>Provide a 1 line recommended action.</action>
<poc>Include the exact HTML/JS/Python PoC code, ADD recreation steps, OR malicious one-liner URLs here. Do not overlook simple URL payloads. If absolutely none exist, write 'None'.</poc>
<vendor>Vendor Name or 'Unknown'</vendor>
<product>Product Name or 'Unknown'</product>
<keywords>Comma-separated keywords from this exact list: {', '.join(KEYWORD_LIST)}</keywords>"""

    messages = [
        {"role": "system", "content": strict_prompt},
        {"role": "user", "content": f"Data for {cve_id}:\n{combined_text_data}"}
    ]

    raw_text, model_used = _call_llm_chat(messages, max_tokens=1500, temperature=0.1, custom_models=thread_models)

    if not raw_text:
        return "API Offline or Rate Limited.", "Try again later.", "None", "Unknown", "Unknown", "None", "Failed (All Models Offline)"

    def extract_tag(text, tag):
        match = re.search(rf'<{tag}>(.*?)</{tag}>', text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        known_tags = "summary|action|poc|vendor|product|keywords"
        match_fallback = re.search(rf'<{tag}>(.*?)(?=<(?:{known_tags})\b|$)', text, flags=re.IGNORECASE | re.DOTALL)
        if match_fallback:
            val = match_fallback.group(1).strip()
            val = re.sub(r'</\w+>', '', val).strip()
            if val:
                return val
        return None

    s = extract_tag(raw_text, 'summary')
    a = extract_tag(raw_text, 'action')
    p = extract_tag(raw_text, 'poc')
    v = extract_tag(raw_text, 'vendor')
    pr = extract_tag(raw_text, 'product')
    kw = extract_tag(raw_text, 'keywords')

    if p:
        p = p.replace('```html', '').replace('```python', '').replace('```', '').strip()

    if s and a and p and v and pr and kw:
        logger.info(f"[SUCCESS] Successfully analyzed {cve_id} using: {model_used}")
        return s, a, p, v, pr, kw, model_used

    # Robust fallback for partial tags
    fallback_summary = s
    if not fallback_summary:
        cleaned_text = re.sub(r'<[^>]+>', ' ', raw_text)
        fallback_summary = ' '.join(cleaned_text.split())[:350]
        if not fallback_summary:
            fallback_summary = "Analysis details extracted from threat feeds."

    return (
        fallback_summary,
        (a or "Review manually and apply vendor patches."),
        (p or "None"),
        (v or "Unknown"),
        (pr or "Unknown"),
        (kw or "None"),
        model_used
    )


def analyze_cve_batch(cve_items, thread_models=None):
    """
    High-throughput batch CVE analyzer: combines 2 to 4 CVEs into a single LLM request.
    Reduces API calls by up to 75%, avoiding free-tier rate limits and accelerating pipeline execution.
    cve_items: list of (cve_id, combined_text) tuples.
    Returns: dict {cve_id: (summary, action, poc, vendor, product, keywords, model_used)}
    """
    if not cve_items:
        return {}

    if len(cve_items) == 1:
        cid, txt = cve_items[0]
        return {cid.strip().upper(): analyze_individual_cve(cid, txt, thread_models=thread_models)}

    # Auto-chunk large batches into safe sub-batches of 3 to prevent token exhaustion
    if len(cve_items) > 3:
        import concurrent.futures
        results = {}
        sub_batches = [cve_items[i:i + 3] for i in range(0, len(cve_items), 3)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(sub_batches))) as executor:
            futures = [executor.submit(analyze_cve_batch, sb, thread_models=thread_models) for sb in sub_batches]
            for f in concurrent.futures.as_completed(futures):
                try:
                    results.update(f.result())
                except Exception as e:
                    logger.error(f"Error in batch sub-worker: {e}")
        return results

    cve_ids_str = ", ".join([cid for cid, _ in cve_items])
    logger.info(f"AI Batch Analyzing {len(cve_items)} CVEs ({cve_ids_str}) in single prompt...")

    batch_prompt = f"""You are a precise cybersecurity analyst. You MUST analyze EACH vulnerability in the provided list.
For EACH vulnerability, output your response EXACTLY using the following XML structure:

<cve id="CVE-ID">
<summary>5 to 6 line summary of the threat.</summary>
<action>1 line recommended action.</action>
<poc>Exact PoC code, recreation steps, or malicious URLs. If none, write 'None'.</poc>
<vendor>Vendor Name or 'Unknown'</vendor>
<product>Product Name or 'Unknown'</product>
<keywords>Comma-separated keywords from this exact list: {', '.join(KEYWORD_LIST)}</keywords>
</cve>

Do NOT add any conversational text outside these tags."""

    user_payload = "\n\n" + ("=" * 40) + "\n\n"
    user_payload = user_payload.join([f"=== Vulnerability: {cid} ===\n{(txt or '')[:2500]}" for cid, txt in cve_items])

    messages = [
        {"role": "system", "content": batch_prompt},
        {"role": "user", "content": user_payload}
    ]

    tokens_budget = min(4000, 1000 * len(cve_items))
    raw_text, model_used = _call_llm_chat(messages, max_tokens=tokens_budget, temperature=0.1, custom_models=thread_models)

    results = {}
    if not raw_text:
        # Graceful non-blocking fallback if providers are rate-limited/offline
        for cid, txt in cve_items:
            clean_cid = cid.strip().upper()
            results[clean_cid] = (
                "Active threat telemetry indexed. Automatic deep AI analysis temporarily offline or rate-limited; full evidence preserved in database.",
                "Review proof links and exploit reproduction steps in Sources tab.",
                "None",
                "Unknown",
                "Unknown",
                "In-The-Wild, OSINT",
                model_used or "Failed (Rate Limited)"
            )
        return results

    # Parse each <cve id="...">...</cve> block
    cve_blocks = re.findall(r'<cve\s+id=[\'"]([^\'"]+)[\'"]>(.*?)</cve>', raw_text, flags=re.IGNORECASE | re.DOTALL)
    parsed_ids = set()

    for cid_match, block in cve_blocks:
        clean_cid = cid_match.strip().upper()
        parsed_ids.add(clean_cid)

        def extract_tag(text, tag):
            m = re.search(rf'<{tag}>(.*?)</{tag}>', text, flags=re.IGNORECASE | re.DOTALL)
            return m.group(1).strip() if m else None

        s = extract_tag(block, 'summary')
        a = extract_tag(block, 'action')
        p = extract_tag(block, 'poc')
        v = extract_tag(block, 'vendor')
        pr = extract_tag(block, 'product')
        kw = extract_tag(block, 'keywords')

        if p:
            p = p.replace('```html', '').replace('```python', '').replace('```', '').strip()

        results[clean_cid] = (
            s or "Analysis details extracted from threat feeds.",
            a or "Review manually and apply vendor patches.",
            p or "None",
            v or "Unknown",
            pr or "Unknown",
            kw or "None",
            model_used
        )

    # Any CVE in the batch that failed to parse individually falls back to analyze_individual_cve
    for cid, txt in cve_items:
        clean_cid = cid.strip().upper()
        if clean_cid not in parsed_ids:
            results[clean_cid] = analyze_individual_cve(cid, txt, thread_models=thread_models)

    return results


def generate_priority_summary(cve_summaries_list):
    """Generates an executive CISO briefing across a batch of analyzed CVEs."""
    if not cve_summaries_list:
        return "No vulnerabilities were identified."

    messages = [
        {"role": "system", "content": "You are a Chief Information Security Officer (CISO). Write a concise, 1-paragraph executive summary highlighting the most dangerous threats in the provided list."},
        {"role": "user", "content": f"Vulnerabilities:\n{chr(10).join(cve_summaries_list)}"}
    ]

    summary, model_used = _call_llm_chat(messages, max_tokens=600, temperature=0.2)
    return summary or "Executive summary could not be generated due to upstream model availability."


def get_llm_status():
    """Returns telemetry of available AI providers, keys, response times, and model lists."""
    groq_keys = get_groq_keys()
    cerebras_keys = get_cerebras_keys()
    openrouter_keys = get_openrouter_keys()
    gemini_keys = get_gemini_keys()
    mistral_keys = get_mistral_keys()

    def _avg_latency(p_name):
        l = _telemetry.get(p_name, {}).get("latencies", [])
        return round(sum(l) / len(l), 2) if l else None

    return {
        "providers": {
            "groq": {
                "name": "GroqCloud (LPU)",
                "configured": bool(groq_keys),
                "keys_count": len(groq_keys),
                "models": GROQ_MODELS,
                "avg_latency_sec": _avg_latency("groq"),
                "success_count": _telemetry["groq"]["success"],
                "failures_count": _telemetry["groq"]["failures"]
            },
            "cerebras": {
                "name": "Cerebras Cloud",
                "configured": bool(cerebras_keys),
                "keys_count": len(cerebras_keys),
                "models": CEREBRAS_MODELS,
                "avg_latency_sec": _avg_latency("cerebras"),
                "success_count": _telemetry["cerebras"]["success"],
                "failures_count": _telemetry["cerebras"]["failures"]
            },
            "openrouter": {
                "name": "OpenRouter Free",
                "configured": bool(openrouter_keys),
                "keys_count": len(openrouter_keys),
                "models": OPENROUTER_MODELS,
                "avg_latency_sec": _avg_latency("openrouter"),
                "success_count": _telemetry["openrouter"]["success"],
                "failures_count": _telemetry["openrouter"]["failures"]
            },
            "gemini": {
                "name": "Google Gemini",
                "configured": bool(gemini_keys),
                "keys_count": len(gemini_keys),
                "models": GEMINI_MODELS,
                "avg_latency_sec": _avg_latency("gemini"),
                "success_count": _telemetry["gemini"]["success"],
                "failures_count": _telemetry["gemini"]["failures"]
            },
            "mistral": {
                "name": "Mistral AI",
                "configured": bool(mistral_keys),
                "keys_count": len(mistral_keys),
                "models": MISTRAL_MODELS,
                "avg_latency_sec": _avg_latency("mistral"),
                "success_count": _telemetry["mistral"]["success"],
                "failures_count": _telemetry["mistral"]["failures"]
            }
        },
        "total_active_keys": len(groq_keys) + len(cerebras_keys) + len(openrouter_keys) + len(gemini_keys) + len(mistral_keys)
    }
