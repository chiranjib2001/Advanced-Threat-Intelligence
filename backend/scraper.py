# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Web Scraper, Exploit Command Matcher & 3-Level Chain Harvester
# ==============================================================================
import os
import re
import json
import urllib.parse
import requests
from bs4 import BeautifulSoup

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(ROOT_DIR, "data")
TEMP_DIR = os.path.join(ROOT_DIR, "execution_temp")
if not os.path.exists(TEMP_DIR):
    os.makedirs(TEMP_DIR, exist_ok=True)

# Load signature dictionaries
EXPLOIT_SIGNATURES = []
ADVISORY_SIGNATURES = []

def _load_signatures():
    global EXPLOIT_SIGNATURES, ADVISORY_SIGNATURES
    exploit_file = os.path.join(DATA_DIR, "known_exploit_links_url.txt")
    if os.path.exists(exploit_file):
        with open(exploit_file, "r", encoding="utf-8") as f:
            EXPLOIT_SIGNATURES = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

    advisory_file = os.path.join(DATA_DIR, "known_advisory_links_url.txt")
    if os.path.exists(advisory_file):
        with open(advisory_file, "r", encoding="utf-8") as f:
            ADVISORY_SIGNATURES = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

_load_signatures()

# High-confidence command and payload trigger strings
COMMAND_PAYLOAD_PATTERNS = [
    # Shell & execution triggers
    r"/bin/sh\b", r"/bin/bash\b", r"/dev/tcp/", r"/dev/null\b", r"bash\s+-i\b",
    r"cmd\.exe\b", r"powershell(\.exe)?\s+(-enc|-e|-w|bypass)", r"wscript\.shell",
    r"\beval\(", r"\bexec\(", r"\bsystem\(", r"\bpopen\(",
    # Network & delivery commands
    r"\bcurl\s+.*http", r"\bwget\s+.*http", r"\bnc\s+-lvnp\b", r"\bnc\s+-e\b",
    r"\bncat\b", r"\bssh\s+.*@", r"\bPOST\s+/[^\s]+\s+HTTP/1\.[01]", r"\bGET\s+/[^\s]+\s+HTTP/1\.[01]",
    # Injection & exploit signatures
    r"UNION\s+SELECT\b", r"'\s+OR\s+'1'='1", r"\.\./\.\./", r"\{\{7\*7\}\}",
    r"\$\{jndi:(ldap|rmi|dns):", r"<script[\s>]", r"document\.cookie",
    # Script headers & payload builders
    r"#!/usr/bin/env\s+python", r"import\s+requests", r"import\s+socket",
    r"urllib\.request", r"sys\.argv\[", r"payload\s*=", r"exploit\s*\("
]
COMPILED_COMMAND_REGEX = re.compile("|".join(COMMAND_PAYLOAD_PATTERNS), re.IGNORECASE)


def match_exploit_command_signatures(text: str) -> bool:
    """Returns True if text contains runnable shell, network, or exploit payload commands."""
    if not text or len(text.strip()) < 15:
        return False
    return bool(COMPILED_COMMAND_REGEX.search(text))


def is_known_exploit_url(url: str) -> bool:
    """Checks URL against known exploit repositories and path signatures."""
    if not url: return False
    u = url.lower()
    return any(sig in u for sig in EXPLOIT_SIGNATURES)


def is_known_advisory_url(url: str) -> bool:
    """Checks URL against known vendor advisory and official bulletin portals."""
    if not url: return False
    u = url.lower()
    return any(sig in u for sig in ADVISORY_SIGNATURES)


def scrape_url_text(url, max_chars=10000, max_download_bytes=1048576, return_raw_html=False):
    """
    Fetches web content cleanly.
    Returns:
      If return_raw_html=False: extracted text or None if fetch failed (no error strings saved to DB).
      If return_raw_html=True: tuple (text, html_text) or (None, None) on failure.
    """
    if not url or not isinstance(url, str) or not url.strip().startswith(("http://", "https://")):
        return (None, None) if return_raw_html else None

    url = url.strip()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10, stream=True)
        response.raise_for_status()

        content_type = response.headers.get("Content-Type", "").lower()
        if content_type and not any(t in content_type for t in ["text/", "json", "xml"]):
            return (None, None) if return_raw_html else None

        raw_bytes = bytearray()
        for chunk in response.iter_content(chunk_size=16384):
            raw_bytes.extend(chunk)
            if len(raw_bytes) >= max_download_bytes:
                break

        encoding = response.encoding or 'utf-8'
        html_text = raw_bytes.decode(encoding, errors='replace')

        soup = BeautifulSoup(html_text, 'html.parser')
        for unwanted in soup(["script", "style", "noscript", "header", "footer", "nav", "aside", "svg", "iframe"]):
            unwanted.decompose()

        text = soup.get_text(separator=' ', strip=True)
        text = ' '.join(text.split())
        cleaned_text = text[:max_chars] if text else None

        if return_raw_html:
            return cleaned_text, html_text
        return cleaned_text

    except Exception:
        # Return None on failure so caller does not pollute database or LLM prompt with error strings
        return (None, None) if return_raw_html else None


def extract_outbound_links(html_text: str, base_url: str) -> list:
    """
    Extracts high-value outbound links from a web page.
    If base_url is a known vendor advisory, prunes corporate navigation and ONLY follows
    links pointing to GitHub, GitLab, Gists, Pastebin, Exploit-DB, or technical blogs.
    """
    if not html_text:
        return []

    soup = BeautifulSoup(html_text, 'html.parser')
    extracted = []
    base_is_vendor = is_known_advisory_url(base_url)

    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            continue

        resolved_url = urllib.parse.urljoin(base_url, href).split('#')[0].rstrip('/')
        if not resolved_url.startswith(('http://', 'https://')):
            continue

        # Pruning rule: If base URL is a vendor advisory, only follow external technical/code repositories
        if base_is_vendor:
            url_lower = resolved_url.lower()
            is_external_tech = any(k in url_lower for k in [
                'github.com', 'gitlab.com', 'gist.github.com', 'pastebin.com',
                'rentry.co', 'exploit-db.com', 'packetstormsecurity.com', 'seclists.org',
                '.py', '.sh', '.c', '.go', 'raw.githubusercontent.com'
            ])
            if not is_external_tech:
                continue

        if resolved_url != base_url and resolved_url not in extracted:
            extracted.append(resolved_url)
            if len(extracted) >= 12: # Safe limit per page to avoid spider traps
                break

    return extracted


def execute_chain_link_crawl(cve_id: str, lv0_url: str, max_depth: int = 3, parent_id: int = None) -> list:
    """
    Recursively crawls a reference link from Level 0 up to Level 3.
    Buffers intermediate text chunks to execution_temp/ to keep process RAM footprint near zero.
    Returns a list of discovered chain records:
      [{'url': ..., 'depth': ..., 'text': ..., 'is_poc': ..., 'parent_id': ...}]
    """
    cve_id = cve_id.strip().upper()
    temp_file = os.path.join(TEMP_DIR, f"{cve_id}_chain.json")
    results = []

    def crawl_level(current_url, current_depth, p_id):
        if current_depth > max_depth or not current_url:
            return

        text_content, raw_html = scrape_url_text(current_url, return_raw_html=True)
        if not text_content:
            return

        is_poc = 0
        if is_known_exploit_url(current_url) or match_exploit_command_signatures(text_content):
            is_poc = 1

        record = {
            "cve_id": cve_id,
            "url": current_url,
            "depth_level": current_depth,
            "parent_source_id": p_id,
            "is_poc": is_poc,
            "text": text_content[:4000]
        }
        results.append(record)

        # Write buffered chunk to disk to keep RAM usage minimal
        try:
            with open(temp_file, "a", encoding="utf-8") as tf:
                tf.write(json.dumps({"url": current_url, "depth": current_depth, "is_poc": is_poc}) + "\n")
        except Exception:
            pass

        # If we found an explicit exploit payload, or if we have reached max depth, stop further expansion
        if is_poc == 1 or current_depth >= max_depth:
            return

        # Extract sub-links for next level (Level 1, 2, or 3)
        sublinks = extract_outbound_links(raw_html, current_url)
        for s_url in sublinks[:6]: # Cap breadth per branch
            crawl_level(s_url, current_depth + 1, p_id)

    crawl_level(lv0_url, 0, parent_id)
    return results
