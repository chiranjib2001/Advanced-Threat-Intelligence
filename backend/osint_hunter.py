# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Real-Time Multi-Source OSINT Threat Hunter (15-Day Unified Engine)
# Sources: HackerNews, Reddit Security, X (Twitter), CISA KEV, Security Media, Dark Web Dorks
# ==============================================================================
import os
import requests
import re
import concurrent.futures
import logging
import xml.etree.ElementTree as ET
import time
import urllib.parse
from collections import Counter
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
import warnings
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning, MarkupResemblesLocatorWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOGS_DIR = os.path.join(ROOT_DIR, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

logger = logging.getLogger('osint_hunter')
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(logging.FileHandler(os.path.join(LOGS_DIR, 'cve_analyzer.log'), encoding='utf-8'))

api_logger = logging.getLogger('api_call_logger')
api_logger.setLevel(logging.INFO)
if not api_logger.handlers:
    api_handler = logging.FileHandler(os.path.join(LOGS_DIR, 'apicall.log'), encoding='utf-8')
    api_handler.setFormatter(logging.Formatter('%(asctime)s - [API] - %(message)s'))
    api_logger.addHandler(api_handler)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

class TrendingResults(dict):
    """
    Subclasses dict so trending[cve_id] -> count works seamlessly
    for existing pipeline logic, while providing .platform_stats, .source_details, and .comparative_metrics.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.platform_stats = {
            "HackerNews": 0,
            "Reddit": 0,
            "X (Twitter)": 0,
            "CISA KEV": 0,
            "Security Media": 0,
            "Dark Web & Underground": 0,
            "Telegram Threat Radar": 0
        }
        self.source_details = {}  # cve_id -> list of record dicts
        self.comparative_metrics = {
            "cisa_only_count": 0,
            "osint_only_count": 0,
            "correlated_both_count": 0,
            "cisa_vs_osint_series": []
        }

def _has_poc_keywords(text: str) -> bool:
    t = text.lower()
    return any(k in t for k in ['poc', 'exploit', 'weaponiz', 'payload', 'rce', '0-day', 'zero-day', 'reproduce', 'recreation', 'proof of concept'])

def _is_within_days(date_str: str, days_back: int) -> bool:
    if not date_str:
        return True
    try:
        if 'T' in date_str:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        else:
            dt = parsedate_to_datetime(date_str)
        cutoff = datetime.now(dt.tzinfo) - timedelta(days=days_back)
        return dt >= cutoff
    except Exception:
        return True

# ------------------------------------------------------------------------------
# 1. HackerNews (Algolia API - 15-Day Lookback)
# ------------------------------------------------------------------------------
def fetch_hackernews_cves(days_back: int = 15):
    """Scrapes HackerNews via Algolia API for CVE discussions across the last 15 days."""
    logger.info(f"[OSINT] Scraping HackerNews (Last {days_back} Days)...")
    records = []
    ts = int((datetime.now() - timedelta(days=days_back)).timestamp())
    for q in ["CVE-20", "CVE-19"]:
        for page in [0, 1]:
            url = "https://hn.algolia.com/api/v1/search_by_date"
            params = {
                "query": q,
                "tags": "(story,comment)",
                "numericFilters": f"created_at_i>{ts}",
                "hitsPerPage": 100,
                "page": page
            }
            api_logger.info(f"GET Request -> HackerNews API: {url}?query={q}&page={page}")
            try:
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    hits = response.json().get("hits", [])
                    if not hits:
                        break
                    for hit in hits:
                        title = hit.get("title") or hit.get("story_title") or "HackerNews Discussion"
                        comment_text = hit.get("comment_text") or ""
                        story_text = hit.get("story_text") or ""
                        raw_text = f"{title} {comment_text} {story_text}"
                        
                        link = hit.get("story_url") or hit.get("url")
                        if not link and hit.get("objectID"):
                            link = f"https://news.ycombinator.com/item?id={hit['objectID']}"
                        elif not link:
                            link = "https://news.ycombinator.com"
                            
                        matches = CVE_PATTERN.findall(raw_text)
                        is_poc = _has_poc_keywords(raw_text)
                        for cve in matches:
                            records.append({
                                "cve_id": cve.upper(),
                                "platform": "HackerNews",
                                "url": link,
                                "title": title[:100],
                                "snippet": (comment_text[:200] or story_text[:200] or title[:200]),
                                "is_poc": is_poc
                            })
                else:
                    break
            except Exception as e:
                logger.error(f"[OSINT] HackerNews fetch failed for query {q}: {e}")
                break
                
    logger.info(f"[OSINT] HackerNews CVE mentions harvested: {len(records)}")
    return records

# ------------------------------------------------------------------------------
# 2. Reddit Security Subreddits (15-Day Window)
# ------------------------------------------------------------------------------
def fetch_reddit_cves(days_back: int = 15):
    """Scrapes curated security subreddits (blueteamsec, netsec, cybersecurity, redteamsec)."""
    logger.info(f"[OSINT] Scraping Curated Security Subreddits (Last {days_back} Days)...")
    records = []
    headers = {
        "User-Agent": "ATI-Threat-Hunter-Radar/2.0 (Security Intelligence Research by /u/threat_hunter_bot)",
        "Accept": "application/atom+xml, application/xml, text/xml"
    }
    subreddits = ["blueteamsec", "netsec", "cybersecurity", "redteamsec"]
    cutoff = datetime.now() - timedelta(days=days_back)
    
    for sub in subreddits:
        url = f"https://www.reddit.com/r/{sub}/.rss"
        api_logger.info(f"GET Request -> Reddit RSS: {url}")
        try:
            response = requests.get(url, headers=headers, timeout=8)
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.content)
                    entries = root.findall('{http://www.w3.org/2005/Atom}entry')
                    for entry in entries:
                        updated_str = entry.findtext('{http://www.w3.org/2005/Atom}updated') or ''
                        if updated_str:
                            try:
                                dt = datetime.fromisoformat(updated_str.replace('Z', '+00:00'))
                                if dt.replace(tzinfo=None) < cutoff:
                                    continue
                            except Exception:
                                pass

                        title = entry.findtext('{http://www.w3.org/2005/Atom}title') or ''
                        content = entry.findtext('{http://www.w3.org/2005/Atom}content') or ''
                        link_elem = entry.find('{http://www.w3.org/2005/Atom}link')
                        link = link_elem.get('href') if link_elem is not None else f"https://reddit.com/r/{sub}"
                        
                        full_text = f"{title} {content}"
                        matches = CVE_PATTERN.findall(full_text)
                        is_poc = _has_poc_keywords(full_text)
                        for cve in matches:
                            records.append({
                                "cve_id": cve.upper(),
                                "platform": "Reddit",
                                "url": link,
                                "title": f"r/{sub}: {title[:90]}",
                                "snippet": content[:200],
                                "is_poc": is_poc
                            })
                except Exception as parse_err:
                    logger.warning(f"[OSINT] Failed parsing Atom XML for r/{sub}: {parse_err}")
            elif response.status_code in (403, 429):
                logger.warning(f"[OSINT] Reddit r/{sub} rate-limited/blocked (HTTP {response.status_code}).")
            else:
                logger.warning(f"[OSINT] Reddit r/{sub} returned HTTP {response.status_code}")
        except Exception as e:
            logger.error(f"[OSINT] Reddit r/{sub} fetch failed: {e}")
            
        time.sleep(0.8)
        
    logger.info(f"[OSINT] Reddit CVE mentions harvested: {len(records)}")
    return records

# ------------------------------------------------------------------------------
# 3. X (formerly Twitter) Threat Radar Stream (15-Day Lookback)
# ------------------------------------------------------------------------------
def fetch_twitter_x_cves(days_back: int = 15):
    """Scrapes real-time X (formerly Twitter) threat discussions using the Google News syndicated stream."""
    logger.info(f"[OSINT] Scraping X (formerly Twitter) Threat Radar Stream (Last {days_back} Days)...")
    records = []
    url = f"https://news.google.com/rss/search?q=CVE+(site:x.com+OR+site:twitter.com+OR+twitter)&hl=en-US&gl=US&ceid=US:en"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    api_logger.info(f"GET Request -> X (Twitter) Stream: {url}")
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            items = root.findall('.//item')
            for item in items:
                pub_date = item.findtext('pubDate') or ''
                if not _is_within_days(pub_date, days_back):
                    continue

                title = item.findtext('title') or ''
                link = item.findtext('link') or 'https://x.com'
                desc = item.findtext('description') or ''
                
                full_text = f"{title} {desc}"
                matches = CVE_PATTERN.findall(full_text)
                is_poc = _has_poc_keywords(full_text)
                for cve in matches:
                    records.append({
                        "cve_id": cve.upper(),
                        "platform": "X (Twitter)",
                        "url": link,
                        "title": title[:100],
                        "snippet": desc[:200],
                        "is_poc": is_poc
                    })
    except Exception as e:
        logger.error(f"[OSINT] X (Twitter) stream fetch failed: {e}")
        
    logger.info(f"[OSINT] X (Twitter) CVE mentions harvested: {len(records)}")
    return records

# ------------------------------------------------------------------------------
# 4. CISA KEV (First-Class 15-Day Catalog Ingestion)
# ------------------------------------------------------------------------------
def fetch_cisa_15d_cves(days_back: int = 15):
    """
    Ingests CISA KEV entries added in the last 15 days as a first-class intelligence stream.
    Queries the local database or official CISA feed for recent additions.
    """
    logger.info(f"[OSINT] Ingesting Official CISA KEV Additions (Last {days_back} Days)...")
    records = []
    try:
        from backend import db_manager
        conn = db_manager.get_db_connection()
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
        cursor.execute("""
            SELECT cve_id, cisa_date_added, affected_vendor, affected_product, cisa_required_action, ransomware_campaign
            FROM cve_main
            WHERE is_cisa_kev = 1 AND cisa_date_added >= ?
            ORDER BY cisa_date_added DESC
        """, (cutoff,))
        rows = cursor.fetchall()
        for r in rows:
            cve_id = r["cve_id"].upper()
            vendor = r["affected_vendor"] or "Unknown Vendor"
            prod = r["affected_product"] or "Product"
            date_added = r["cisa_date_added"]
            ransomware = f" | Attributed: {r['ransomware_campaign']}" if r["ransomware_campaign"] else ""
            
            records.append({
                "cve_id": cve_id,
                "platform": "CISA KEV",
                "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}",
                "title": f"CISA KEV Cataloged ({date_added}): {vendor} {prod}",
                "snippet": f"Officially mandated remediation: {r['cisa_required_action'] or 'Apply updates per vendor instructions'}{ransomware}",
                "is_poc": False,
                "in_cisa": True
            })
        conn.close()
    except Exception as e:
        logger.error(f"[OSINT] Failed fetching CISA 15-day KEV records: {e}")
        
    logger.info(f"[OSINT] CISA KEV 15-Day additions harvested: {len(records)}")
    return records

# ------------------------------------------------------------------------------
# 5. Security Media Feeds (The Hacker News, BleepingComputer, Dark Reading)
# ------------------------------------------------------------------------------
def fetch_security_media_cves(days_back: int = 15):
    """
    Ingests technical vulnerability disclosures from high-reputation cybersecurity journalism:
    - The Hacker News (THN)
    - BleepingComputer
    - Dark Reading
    """
    logger.info(f"[OSINT] Scraping Security Media Feeds (Last {days_back} Days)...")
    records = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ATI-Threat-Hunter-Bot/2.0"}
    
    feeds = [
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
        ("Dark Reading", "https://www.darkreading.com/rss.xml")
    ]
    
    for name, url in feeds:
        api_logger.info(f"GET Request -> Media RSS: {url}")
        try:
            response = requests.get(url, headers=headers, timeout=8)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                for item in root.findall('.//item'):
                    pub_date = item.findtext('pubDate') or ''
                    if not _is_within_days(pub_date, days_back):
                        continue

                    title = item.findtext('title') or ''
                    link = item.findtext('link') or url
                    desc = item.findtext('description') or ''
                    full_text = f"{title} {desc}"
                    
                    matches = CVE_PATTERN.findall(full_text)
                    is_poc = _has_poc_keywords(full_text)
                    for cve in matches:
                        records.append({
                            "cve_id": cve.upper(),
                            "platform": "Security Media",
                            "url": link,
                            "title": f"[{name}] {title[:90]}",
                            "snippet": desc[:200],
                            "is_poc": is_poc
                        })
        except Exception as e:
            logger.error(f"[OSINT] Security media feed {name} failed: {e}")
            
    logger.info(f"[OSINT] Security Media CVE mentions harvested: {len(records)}")
    return records

# ------------------------------------------------------------------------------
# 6. Dark Web & Targeted Google Dorking Engine (Optimized with when:15d)
# ------------------------------------------------------------------------------
def fetch_darkweb_and_dork_cves(days_back: int = 15):
    """
    Executes targeted Google Dorking queries with explicit recency constraint (when:{days_back}d)
    to index active underground zero-day chatter, ransomware leak announcements, and paste drops:
    - Dark Web & Ransomware Leaks: ("dark web" OR "darkweb" OR "ransomware") (CVE-202 OR CVE-2025 OR CVE-2026) when:{days_back}d
    - Weaponized Code & Drops: site:github.com CVE (poc OR exploit) when:{days_back}d
    - Active Wild Threats: ("dark web" OR "ransomware" OR "exploit") CVE when:{days_back}d
    - Pastebin / Underground Drop Sites: (site:pastebin.com OR site:rentry.co) (CVE-202 OR CVE-2025 OR CVE-2026)
    """
    logger.info(f"[OSINT] Scraping Dark Web & Exploit Dork Feeds (Last {days_back} Days)...")
    records = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ATI-Threat-Hunter-Bot/2.0"}
    
    dork_queries = [
        f'("dark web" OR "darkweb" OR "ransomware") (CVE-202 OR CVE-2025 OR CVE-2026) (leak OR exploit OR forum OR broker) when:{days_back}d',
        f'("dark web" OR "darkweb" OR "ransomware" OR "leak" OR "broker") ("CVE-") when:{days_back}d',
        f'site:github.com CVE (poc OR exploit) when:{days_back}d',
        f'("dark web" OR "ransomware" OR "exploit") CVE when:{days_back}d',
        f'(site:pastebin.com OR site:rentry.co) (CVE-202 OR CVE-2025 OR CVE-2026)',
        f'(site:pastebin.com OR site:rentry.co) ("CVE-") when:{days_back}d'
    ]
    
    for dork in dork_queries:
        encoded_q = urllib.parse.quote(dork)
        url = f"https://news.google.com/rss/search?q={encoded_q}&hl=en-US&gl=US&ceid=US:en"
        api_logger.info(f"GET Request -> Dark Web Dork: {url}")
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                for item in root.findall('.//item'):
                    pub_date = item.findtext('pubDate') or ''
                    if not _is_within_days(pub_date, days_back):
                        continue

                    title = item.findtext('title') or ''
                    link = item.findtext('link') or 'https://google.com'
                    desc = item.findtext('description') or ''
                    full_text = f"{title} {desc}"
                    
                    matches = CVE_PATTERN.findall(full_text)
                    is_poc = _has_poc_keywords(full_text) or "github.com" in full_text.lower() or "poc" in full_text.lower()
                    for cve in matches:
                        records.append({
                            "cve_id": cve.upper(),
                            "platform": "Dark Web & Underground",
                            "url": link,
                            "title": f"[DarkWeb/Leak] {title[:85]}",
                            "snippet": desc[:200],
                            "is_poc": is_poc
                        })
        except Exception as e:
            logger.error(f"[OSINT] Dark web dork query failed: {e}")
            
    logger.info(f"[OSINT] Dark Web & Dork mentions harvested: {len(records)}")
    return records


# ------------------------------------------------------------------------------
# 7. Telegram Threat Radar (Zero-Credential Public Web Preview Stream)
# ------------------------------------------------------------------------------
def fetch_telegram_public_cves(days_back: int = 15):
    """
    Monitors high-reputation cybersecurity threat and exploit disclosure Telegram channels
    via zero-credential web previews (https://t.me/s/{channel}).
    Harvests newly disclosed CVEs, proof links, and exploit discussions without API keys.
    """
    logger.info(f"[OSINT] Scraping Telegram Threat Radar (Last {days_back} Days)...")
    records = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close"
    }
    
    channels = ["RedPacketSecurity", "vxunderground"]
    
    for ch in channels:
        url = f"https://t.me/s/{ch}"
        api_logger.info(f"GET Request -> Telegram Threat Radar: {url}")
        soup = None
        for attempt in range(2):
            try:
                resp = requests.get(url, headers=headers, timeout=8)
                if resp.status_code == 200:
                    is_xml = resp.text.lstrip().startswith("<?xml")
                    parser = "xml" if is_xml else "html.parser"
                    try:
                        soup = BeautifulSoup(resp.text, parser)
                    except Exception:
                        soup = BeautifulSoup(resp.text, "html.parser")
                    break
            except Exception as e:
                if attempt == 1:
                    logger.error(f"[OSINT] Telegram channel @{ch} fetch failed after retry: {e}")
                time.sleep(0.5)

        if not soup:
            continue

        try:
            messages = soup.find_all("div", class_="tgme_widget_message_wrap")
            for msg in messages:
                time_tag = msg.find("time")
                post_date = time_tag.get("datetime") if time_tag else ""
                if post_date and not _is_within_days(post_date, days_back):
                    continue
                    
                text_div = msg.find("div", class_="tgme_widget_message_text")
                if not text_div:
                    continue
                text = text_div.get_text(separator=" ", strip=True)
                
                matches = CVE_PATTERN.findall(text)
                if not matches:
                    continue
                    
                link_tag = msg.find("a", class_="tgme_widget_message_date")
                msg_link = link_tag.get("href") if link_tag else url
                is_poc = _has_poc_keywords(text)
                
                clean_cves = set([c.upper() for c in matches])
                for cve in clean_cves:
                    records.append({
                        "cve_id": cve,
                        "platform": "Telegram Threat Radar",
                        "url": msg_link,
                        "title": f"[@{ch}] {text[:80]}",
                        "snippet": text[:200],
                        "is_poc": is_poc
                    })
        except Exception as e:
            logger.error(f"[OSINT] Telegram parsing error for @{ch}: {e}")
            
    logger.info(f"[OSINT] Telegram Threat Radar mentions harvested: {len(records)}")
    return records


# ------------------------------------------------------------------------------
# 8. Clearweb Ransomware Mirrors (Zero-Tor Leak Feeds: Ransomwatch & Ransomware.live)
# ------------------------------------------------------------------------------
def fetch_ransomware_mirrors_cves(days_back: int = 15):
    """
    Ingests clearweb mirrors of ransomware leak sites (Ransomwatch and Ransomware.live)
    without Tor overhead. Identifies actively exploited CVEs attributed to ransomware gangs.
    """
    logger.info(f"[OSINT] Scraping Clearweb Ransomware Mirrors (Last {days_back} Days)...")
    records = []
    headers = {"User-Agent": "ATI-Threat-Hunter-Bot/2.0"}

    # 1. Ransomwatch Posts Feed
    rw_url = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    api_logger.info(f"GET Request -> Ransomwatch Feed: {rw_url}")
    try:
        res = requests.get(rw_url, headers=headers, timeout=8)
        if res.status_code == 200:
            posts = res.json()
            for p in posts[:200]:
                post_title = p.get("post_title") or ""
                group_name = p.get("group_name") or "Ransomware Cartel"
                discovered = p.get("discovered") or ""
                if discovered and not _is_within_days(discovered, days_back):
                    continue
                matches = CVE_PATTERN.findall(post_title)
                for cve in matches:
                    records.append({
                        "cve_id": cve.upper(),
                        "platform": "Dark Web & Underground",
                        "url": f"https://ransomwatch.telemetry.ltd/#/group/{group_name}",
                        "title": f"[{group_name} Leak] {post_title[:80]}",
                        "snippet": f"Attributed to {group_name}. Discovered: {discovered}",
                        "is_poc": _has_poc_keywords(post_title)
                    })
    except Exception as e:
        logger.warning(f"[OSINT] Ransomwatch feed fetch error: {e}")

    # 2. Ransomware.live Recent Victims
    rl_url = "https://api.ransomware.live/v2/recentvictims"
    api_logger.info(f"GET Request -> Ransomware.live Feed: {rl_url}")
    try:
        res = requests.get(rl_url, headers=headers, timeout=8)
        if res.status_code == 200:
            victims = res.json()
            if isinstance(victims, list):
                for v in victims[:150]:
                    v_title = f"{v.get('victim','')}: {v.get('description','')}"
                    group = v.get("group_name") or "Ransomware Gang"
                    pub = v.get("published") or ""
                    if pub and not _is_within_days(pub, days_back):
                        continue
                    matches = CVE_PATTERN.findall(v_title)
                    for cve in matches:
                        records.append({
                            "cve_id": cve.upper(),
                            "platform": "Dark Web & Underground",
                            "url": v.get("screenshot_url") or "https://www.ransomware.live",
                            "title": f"[{group} Extortion] {v.get('victim','Victim')[:75]}",
                            "snippet": v_title[:200],
                            "is_poc": False
                        })
    except Exception as e:
        logger.warning(f"[OSINT] Ransomware.live fetch error: {e}")

    logger.info(f"[OSINT] Ransomware mirror mentions harvested: {len(records)}")
    return records


# ------------------------------------------------------------------------------
# Master Ingestion Aggregator & Comparative Analytics
# ------------------------------------------------------------------------------
def get_trending_cves_from_socials(min_mentions: int = 1, days_back: int = 15):
    """
    Parallel multi-source harvester across 8 intelligence streams:
    1. HackerNews (15 Days)
    2. Reddit Security (15 Days)
    3. X (Twitter) Threat Radar (15 Days)
    4. CISA KEV (First-Class Ingestion, 15 Days)
    5. Security Media (THN, BleepingComputer, Dark Reading)
    6. Dark Web & Underground Google Dorking Engine (with when:15d)
    7. Telegram Threat Radar (Zero-Credential Public Streams)
    8. Clearweb Ransomware Mirrors (Ransomwatch & Ransomware.live)
    """
    print(f"\n[*] Phase 2: Ingesting 15-Day Threat Intelligence Across 8 Multi-Source Streams...")
    print(f"[*] Streams: HackerNews, Reddit, X (Twitter), CISA KEV, Security Media, Dark Web Dorks, Telegram, Ransomware Mirrors")
    print(f"[*] Lookback Scope: Last {days_back} days (since {(datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%d')})...")
    
    all_records = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_hn = executor.submit(fetch_hackernews_cves, days_back)
        future_rs = executor.submit(fetch_reddit_cves, days_back)
        future_tx = executor.submit(fetch_twitter_x_cves, days_back)
        future_cisa = executor.submit(fetch_cisa_15d_cves, days_back)
        future_media = executor.submit(fetch_security_media_cves, days_back)
        future_dark = executor.submit(fetch_darkweb_and_dork_cves, days_back)
        future_tg = executor.submit(fetch_telegram_public_cves, days_back)
        future_rw = executor.submit(fetch_ransomware_mirrors_cves, days_back)
        
        all_records.extend(future_hn.result())
        all_records.extend(future_rs.result())
        all_records.extend(future_tx.result())
        all_records.extend(future_cisa.result())
        all_records.extend(future_media.result())
        all_records.extend(future_dark.result())
        all_records.extend(future_tg.result())
        all_records.extend(future_rw.result())
        
    cve_counts = Counter([r["cve_id"] for r in all_records])
    platform_counts = Counter([r["platform"] for r in all_records])
    
    source_details = {}
    cisa_cves = set()
    osint_cves = set()
    
    for r in all_records:
        cve = r["cve_id"]
        if cve not in source_details:
            source_details[cve] = []
        source_details[cve].append(r)
        
        if r["platform"] == "CISA KEV":
            cisa_cves.add(cve)
        else:
            osint_cves.add(cve)
            
    results = TrendingResults()
    results.platform_stats = {
        "HackerNews": platform_counts.get("HackerNews", 0),
        "Reddit": platform_counts.get("Reddit", 0),
        "X (Twitter)": platform_counts.get("X (Twitter)", 0),
        "CISA KEV": platform_counts.get("CISA KEV", 0),
        "Security Media": platform_counts.get("Security Media", 0),
        "Dark Web & Underground": platform_counts.get("Dark Web & Underground", 0),
        "Telegram Threat Radar": platform_counts.get("Telegram Threat Radar", 0)
    }
    results.source_details = source_details
    
    for cve, count in cve_counts.items():
        if count >= min_mentions:
            results[cve] = count
            
    # Build Comparative Metrics for CISA vs OSINT Bar Graph
    correlated_both = cisa_cves.intersection(osint_cves)
    cisa_only = cisa_cves - osint_cves
    osint_only = osint_cves - cisa_cves
    
    cisa_vs_osint_series = []
    for cve, count in sorted(results.items(), key=lambda x: x[1], reverse=True)[:35]:
        cve_records = source_details.get(cve, [])
        platforms = list(set([r["platform"] for r in cve_records]))
        in_cisa = 1 if cve in cisa_cves else 0
        osint_score = sum(1 for r in cve_records if r["platform"] != "CISA KEV")
        
        cisa_vs_osint_series.append({
            "cve_id": cve,
            "in_cisa": in_cisa,
            "osint_mentions": osint_score,
            "total_signals": count,
            "platforms": platforms,
            "is_correlated": 1 if (in_cisa and osint_score > 0) else 0
        })
        
    results.comparative_metrics = {
        "cisa_only_count": len(cisa_only),
        "osint_only_count": len(osint_only),
        "correlated_both_count": len(correlated_both),
        "cisa_vs_osint_series": cisa_vs_osint_series
    }
    
    # Terminal Summary Output
    print(f"\n[+] 15-Day Multi-Source Threat Leaderboard ({len(results)} Unique CVEs Detected):")
    print(f"    -> [HackerNews]: {results.platform_stats['HackerNews']} | [Reddit]: {results.platform_stats['Reddit']} | [X (Twitter)]: {results.platform_stats['X (Twitter)']}")
    print(f"    -> [CISA KEV (15d)]: {results.platform_stats['CISA KEV']} | [Security Media]: {results.platform_stats['Security Media']}")
    print(f"    -> [Dark Web / Leaks]: {results.platform_stats['Dark Web & Underground']} | [Telegram Radar]: {results.platform_stats['Telegram Threat Radar']}")
    print(f"    -> Correlation Breakdown: Correlated (Both): {len(correlated_both)} | OSINT Early Warnings: {len(osint_only)} | CISA-Only: {len(cisa_only)}")
    
    logger.info(f"[OSINT 15D] Total {len(results)} CVEs. Platforms: {results.platform_stats}. Correlation: Both={len(correlated_both)}, OSINT={len(osint_only)}, CISA={len(cisa_only)}")
    
    for cve, count in sorted(results.items(), key=lambda x: x[1], reverse=True)[:25]:
        platforms = list(set([r["platform"] for r in source_details.get(cve, [])]))
        has_poc = any(r.get("is_poc") for r in source_details.get(cve, []))
        in_c = " [CISA KEV]" if cve in cisa_cves else ""
        poc_flag = " [!] Unverified PoC/Exploit" if has_poc else ""
        line = f"    -> {cve}: {count} signal(s) from {', '.join(platforms)}{in_c}{poc_flag}"
        print(line)
        logger.info(f"[OSINT Signal] {line.strip()}")
        
    return results
