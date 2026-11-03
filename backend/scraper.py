# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Web Scraper & Fast-Path Link Classifier (5-Level Parallel Chain Engine)
# ==============================================================================
import os
import re
import json
import requests
import urllib.parse
import concurrent.futures
import warnings
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning, MarkupResemblesLocatorWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

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

# High-confidence command, container escape, and payload trigger strings
COMMAND_PAYLOAD_PATTERNS = [
    # Shell & execution triggers
    r"/bin/sh\b", r"/bin/bash\b", r"/dev/tcp/", r"/dev/null\b", r"bash\s+-i\b",
    r"cmd\.exe\b", r"powershell(\.exe)?\s+(-enc|-e|-w|bypass)", r"wscript\.shell",
    r"\beval\(", r"\bexec\(", r"\bsystem\(", r"\bpopen\(",
    # Container / VM / Sandbox escape and symlink patterns
    r"\bln\s+-s\b", r"\bmkdir\s+.*&&", r"\brm\s+-rf?\b", r"\bexec\s+\d+\s*<",
    r"\bsymlink\b", r"\bguest-to-host\b", r"\bhypervisor\s+escape\b", r"\bsandbox\s+escape\b",
    r"\bbash:\s*mkdir\b", r"\bchmod\s+[+0-7]", r"\bmount\s+-o\b", r"\bchroot\b",
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

RAW_URL_REGEX = re.compile(r'https?://[^\s<>"\')]+', re.IGNORECASE)
MD_LINK_REGEX = re.compile(r'\[([^\]]+)\]\((https?://[^\s\)]+)\)', re.IGNORECASE)


def match_exploit_command_signatures(text: str) -> bool:
    """Returns True if text contains runnable shell, container escape, network, or exploit payload commands."""
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
    for sig in ADVISORY_SIGNATURES:
        if not sig:
            continue
        if ".*" in sig:
            reg = re.escape(sig).replace(r"\.\*", ".*")
            if re.search(reg, u):
                return True
        elif sig in u:
            return True
    if any(p in u for p in [
        "/security-advisories", "/security/security-announcements", 
        "/security-announcements", "/security/advisories", 
        "/security-bulletin", "/security-bulletins", 
        "/security/notices", "/security_advisories",
        "/security-update", "/security-updates",
        "access.redhat.com/security", "ubuntu.com/security",
        "msrc.microsoft.com", "portal.msrc.microsoft.com",
        "nvd.nist.gov/vuln/detail", "cve.mitre.org/cgi-bin/cvename.cgi",
        "cve.org/cverecord"
    ]):
        return True
    return False


def is_product_release_url(url: str) -> bool:
    """Detects if a URL is a product release tag, archive download, or repository version distribution."""
    if not url: return False
    u = url.lower()
    release_patterns = [
        '/releases/tag/', '/releases/download/', '/archive/refs/tags/',
        '/archive/refs/heads/', '/releases', '/tags/', '/tags',
        'pypi.org/project/', 'npmjs.com/package/', 'hub.docker.com/r/'
    ]
    return any(p in u for p in release_patterns)


def is_blog_url(url: str, text: str = "") -> bool:
    """Detects if a URL or its extracted content is a security research blog or technical writeup."""
    if not url: return False
    u = url.lower()
    blog_domains = ['medium.com', 'substack.com', 'dev.to', 'blogger.com', 'wordpress.com', 'accomplish.ai']
    blog_paths = ['/blog/', '/posts/', '/post/', '/research/', '/writeup/', '/writeups/', '/security-research/', '/disclosures/', '/disclosure/', '/articles/']
    if any(d in u for d in blog_domains) or any(p in u for p in blog_paths):
        return True
    if text:
        t_low = text[:600].lower()
        if any(k in t_low for k in ['research disclosure', 'security advisory writeup', 'technical disclosure', 'accomplish blog', 'researcher reported', 'writeup', 'root cause analysis']):
            return True
    return False


def extract_links_from_text(text: str) -> list:
    """Extracts both raw HTTP(S) links and markdown-formatted URLs from text."""
    if not text: return []
    links = []
    # Markdown links [title](url)
    for match in MD_LINK_REGEX.findall(text):
        u = match[1].strip().rstrip('.,;:)')
        if u.startswith(('http://', 'https://')) and u not in links:
            links.append(u)
    # Raw URLs
    for match in RAW_URL_REGEX.findall(text):
        u = match.strip().rstrip('.,;:)')
        if u.startswith(('http://', 'https://')) and u not in links:
            links.append(u)
    return links


def query_wayback_cdx_snapshot(url: str, timeout: int = 5):
    """
    Automated Live CDX HTTP Lookup:
    Queries the Internet Archive Wayback Machine CDX API to locate the latest
    valid HTTP 200 snapshot timestamp for a target URL that returned 404 or was deleted.
    Returns the replay snapshot URL (with raw /id_ mode to bypass toolbars) or None.
    """
    if not url or not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return None
    if any(h in url.lower() for h in ["localhost", "127.0.0.1", "web.archive.org"]):
        return None

    cdx_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": url,
        "output": "json",
        "fl": "timestamp,original,statuscode",
        "filter": "statuscode:200",
        "limit": 1
    }
    try:
        res = requests.get(cdx_url, params=params, timeout=timeout)
        if res.status_code == 200:
            rows = res.json()
            if len(rows) > 1:
                ts, orig = rows[1][0], rows[1][1]
                # 'id_' suffix serves raw historical payload without Wayback toolbar injections
                return f"https://web.archive.org/web/{ts}id_/{orig}"
    except Exception as e:
        logger.debug(f"[Wayback CDX] Lookup failed for {url}: {e}")
    return None


def scrape_url_text(url, max_chars=10000, max_download_bytes=1048576, return_raw_html=False):
    """
    Fetches web content cleanly, following redirects.
    Includes Automated Live CDX HTTP Retry: If a target URL returns 404/410,
    the crawler queries the Wayback Machine CDX API to recover the archived snapshot.
    Returns:
      If return_raw_html=False: extracted text or None if fetch failed.
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
        response = requests.get(url, headers=headers, timeout=10, stream=True, allow_redirects=True)
        
        # --- Automated Live CDX HTTP Retry Hook ---
        if response.status_code in (404, 410):
            logger.info(f"[Wayback CDX] HTTP {response.status_code} on {url}. Triggering Automated Live CDX HTTP Retry...")
            archived_url = query_wayback_cdx_snapshot(url)
            if archived_url:
                logger.info(f"[Wayback CDX] Resurrected archived snapshot: {archived_url}")
                response = requests.get(archived_url, headers=headers, timeout=12, stream=True, allow_redirects=True)

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

        # If response has no HTML/XML tags (e.g. raw script, plain text URL, or single path), bypass bs4
        if "<" not in html_text:
            cleaned_text = ' '.join(html_text.split())[:max_chars] if html_text.strip() else None
            if return_raw_html:
                return cleaned_text, html_text
            return cleaned_text

        is_xml = html_text.lstrip().startswith("<?xml") or "xml" in content_type
        parser = "xml" if is_xml else "html.parser"
        try:
            soup = BeautifulSoup(html_text, parser)
        except Exception:
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
        return (None, None) if return_raw_html else None


def extract_outbound_links(html_text: str, base_url: str) -> list:
    """
    Extracts high-value outbound links from a web page.
    Prunes social share traps, telemetry trackers, and generic legal pages.
    """
    # If no markup tags, cannot contain <a href> links
    if not html_text or not isinstance(html_text, str) or "<" not in html_text:
        return []

    is_xml = html_text.lstrip().startswith("<?xml")
    parser = "xml" if is_xml else "html.parser"
    try:
        soup = BeautifulSoup(html_text, parser)
    except Exception:
        soup = BeautifulSoup(html_text, 'html.parser')
    extracted = []
    # Pruning rule: If base URL is a vendor advisory, do not crawl sublinks
    if is_known_advisory_url(base_url):
        return []

    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            continue

        resolved_url = urllib.parse.urljoin(base_url, href).split('#')[0].rstrip('/')
        if not resolved_url.startswith(('http://', 'https://')):
            continue

        url_lower = resolved_url.lower()
        if any(ign in url_lower for ign in ignored_domains):
            continue

        # Exclude any destination links that are known vendor advisories or product releases
        if is_known_advisory_url(resolved_url) or is_product_release_url(resolved_url):
            continue

        if resolved_url != base_url and resolved_url not in extracted:
            extracted.append(resolved_url)
            if len(extracted) >= 30: # Page extraction pool limit
                break

    return extracted


def classify_scraped_link(url: str, text_content: str = "") -> dict:
    """
    Evaluates a URL and its extracted text to determine threat status, PoC flag, and blog tag.
    Returns:
      {
        'is_poc': 0 or 1,
        'is_blog': bool,
        'is_release': bool,
        'status': 'poc' | 'blog_poc' | 'blog' | 'vuln_version' | 'vendor_fix' | 'info'
      }
    """
    u_lower = (url or "").lower()
    is_release = is_product_release_url(url)
    is_poc = 0
    is_blog = is_blog_url(url, text_content)
    is_adv = is_known_advisory_url(url) or ("/security/advisories" in u_lower)

    # Release / Tag URLs are product versions, NOT PoCs
    if is_release:
        return {
            "is_poc": 0,
            "is_blog": False,
            "is_release": True,
            "status": "vuln_version"
        }

    # Official vendor security advisory portals are vendor_fix unless URL is an explicit exploit repo
    if is_adv and not is_known_exploit_url(url):
        return {
            "is_poc": 0,
            "is_blog": is_blog,
            "is_release": False,
            "status": "vendor_fix"
        }

    # Match exploit signatures in URL or runnable command payloads in content
    if is_known_exploit_url(url) or match_exploit_command_signatures(text_content):
        is_poc = 1

    if is_blog and is_poc:
        status = "blog_poc"
    elif is_poc:
        status = "poc"
    elif is_blog:
        status = "blog"
    elif is_adv:
        status = "vendor_fix"
    else:
        status = "info"

    return {
        "is_poc": is_poc,
        "is_blog": is_blog,
        "is_release": False,
        "status": status
    }


def execute_chain_link_crawl(cve_id: str, seed_urls, max_depth: int = 2, max_workers: int = 6, parent_id: int = None, stop_on_poc: bool = True, max_total_urls: int = 20) -> list:
    """
    Recursively crawls outbound links up to max_depth (default 2) concurrently.
    - Level 0: Primary seed references (NVD disclosures / OSINT posts)
    - Level 1: Outbound links on those pages (writeups, advisories, repos)
    - Level 2: Sub-links within Level 1 (raw payloads, exploit scripts, gists)
    
    Optimizations:
    - Early PoC Exit: Stops crawling immediately once a verified weaponized PoC is found.
    - AI Link Selector: If a page has 5+ sublinks, uses LLM to select the top 2-3 most likely PoC candidates.
    - Advisory Exclusion: Prunes vendor advisory portals from deep recursion unless they link to code repos.
    - Hard URL Ceiling: Caps crawl to max_total_urls (default 20) to guarantee fast termination.
    """
    cve_id = cve_id.strip().upper()
    temp_file = os.path.join(TEMP_DIR, f"{cve_id}_chain.json")

    # Normalize seeds
    if isinstance(seed_urls, str):
        seeds = extract_links_from_text(seed_urls) if "http" in seed_urls else [seed_urls]
    elif isinstance(seed_urls, (list, set)):
        seeds = list(seed_urls)
    else:
        seeds = []

    if not seeds:
        return []

    visited = set()
    results = []
    poc_found = False

    # Queue contains tuples of (url, current_depth, parent_id)
    # Seeds start at depth 1 (Level 1 from NIST or OSINT disclosures)
    # Sublinks are depth 2 (Level 2 onwards)
    current_level_queue = [
        (u.rstrip('/'), 1, parent_id) for u in seeds
        if u and not is_known_advisory_url(u) and not is_product_release_url(u)
    ]

    def _process_single_url(item):
        url, depth, p_id = item
        if not url:
            return None

        text_content, raw_html = scrape_url_text(url, return_raw_html=True)
        if not text_content:
            return None

        eval_res = classify_scraped_link(url, text_content)
        sublinks = []

        # Only extract sublinks if PoC not already found, not at max depth, and not a vendor advisory
        if depth < max_depth and raw_html and not eval_res["is_release"] and not eval_res["is_poc"] and not is_known_advisory_url(url):
            raw_sublinks = extract_outbound_links(raw_html, url)
            sublinks = [s for s in raw_sublinks if not is_known_advisory_url(s) and not is_product_release_url(s)]

            # If 5+ sublinks, use LLM to pick the top 3 most likely to have PoC
            if len(sublinks) >= 5:
                try:
                    from backend.llm import ai_select_best_poc_links
                    sublinks = ai_select_best_poc_links(cve_id, sublinks, max_select=3)
                except Exception:
                    sublinks = sublinks[:3]
            elif len(sublinks) > 3:
                sublinks = sublinks[:3]

        record = {
            "cve_id": cve_id,
            "url": url,
            "depth_level": depth,
            "parent_source_id": p_id,
            "is_poc": eval_res["is_poc"],
            "is_blog": eval_res["is_blog"],
            "exploit_status": eval_res["status"],
            "text": text_content[:4000]
        }
        return record, sublinks

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for current_depth in range(1, max_depth + 1):
            if not current_level_queue or poc_found or len(results) >= max_total_urls:
                break

            try:
                import main
                if getattr(main, 'scan_stop_event', None) and main.scan_stop_event.is_set():
                    break
            except Exception:
                pass

            # Filter out visited
            unique_items = []
            for item in current_level_queue:
                if item[0] not in visited and len(visited) < max_total_urls:
                    visited.add(item[0])
                    unique_items.append(item)

            if not unique_items:
                break

            futures = [executor.submit(_process_single_url, it) for it in unique_items]
            next_level_queue = []

            for fut in concurrent.futures.as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        record, sublinks = res
                        results.append(record)

                        try:
                            with open(temp_file, "a", encoding="utf-8") as tf:
                                tf.write(json.dumps({
                                    "url": record["url"],
                                    "depth": record["depth_level"],
                                    "is_poc": record["is_poc"],
                                    "status": record["exploit_status"]
                                }) + "\n")
                        except Exception:
                            pass

                        # Early exit: If PoC found, stop crawl immediately for this CVE
                        if stop_on_poc and record["is_poc"] == 1:
                            poc_found = True
                            print(f"   [!] 🎯 PoC identified for {cve_id} at {record['url']}! Terminating crawl early.")
                            break

                        if len(results) >= max_total_urls:
                            break

                        # Queue sublinks if not reached max depth and PoC not found
                        if not poc_found and current_depth < max_depth and sublinks:
                            for s_url in sublinks:
                                s_clean = s_url.rstrip('/')
                                if s_clean not in visited and len(visited) < max_total_urls:
                                    next_level_queue.append((s_clean, current_depth + 1, parent_id))
                except Exception:
                    pass

            if poc_found or len(results) >= max_total_urls:
                break

            current_level_queue = next_level_queue

    return results
