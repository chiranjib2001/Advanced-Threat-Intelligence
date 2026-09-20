# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Zero-Cost Parallel IoC Enrichment & Exposure Engine
# Data Feeds: abuse.ch ThreatFox, MalwareBazaar, URLhaus, Shodan InternetDB
# ==============================================================================
import os
import re
import csv
import json
import io
import uuid
import ipaddress
import logging
import requests
from datetime import datetime
import concurrent.futures
from typing import List, Dict, Any, Optional

from . import db_manager

# Logging setup
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOGS_DIR = os.path.join(ROOT_DIR, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

logger = logging.getLogger('ioc_engine')
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler(os.path.join(LOGS_DIR, 'cve_analyzer.log'), encoding='utf-8')
    fh.setFormatter(logging.Formatter('%(asctime)s - [IOC] - %(message)s'))
    logger.addHandler(fh)

api_logger = logging.getLogger('api_call_logger')
api_logger.setLevel(logging.INFO)
if not api_logger.handlers:
    ap_fh = logging.FileHandler(os.path.join(LOGS_DIR, 'apicall.log'), encoding='utf-8')
    ap_fh.setFormatter(logging.Formatter('%(asctime)s - [API] - %(message)s'))
    api_logger.addHandler(ap_fh)

# --- Zero-Cost API Endpoints ---
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
URLHAUS_TAG_URL = "https://urlhaus-api.abuse.ch/v1/tag/{}/"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{}"

REQUEST_TIMEOUT = 8

# Common private IP prefixes to ignore in regex extraction
PRIVATE_IP_REGEX = re.compile(r'^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|0\.|255\.)')


# ==============================================================================
# 1. FEED QUERIES (100% FREE & KEYLESS)
# ==============================================================================

def query_threatfox(cve_id: str) -> List[Dict[str, Any]]:
    """Fetches C2 IPs, domains, and payload URLs from abuse.ch ThreatFox."""
    iocs = []
    payload = {"query": "search_ioc", "search_term": cve_id.strip().upper()}
    api_logger.info(f"POST Request -> ThreatFox API: {THREATFOX_API_URL} | Search: {cve_id}")
    try:
        res = requests.post(THREATFOX_API_URL, json=payload, timeout=REQUEST_TIMEOUT)
        if res.status_code == 200:
            data = res.json()
            if data.get("query_status") == "ok":
                for item in data.get("data", []):
                    ioc_val = item.get("ioc")
                    ioc_raw_type = item.get("ioc_type", "").lower()
                    ioc_type = 'ip' if 'ip' in ioc_raw_type else ('domain' if 'domain' in ioc_raw_type else ('url' if 'url' in ioc_raw_type else 'hash'))
                    malware = item.get("malware_printable") or item.get("malware")
                    confidence = item.get("confidence_level", 80)
                    first_seen = item.get("first_seen")
                    
                    iocs.append({
                        "ioc_type": ioc_type,
                        "ioc_value": ioc_val,
                        "threat_actor": item.get("threat_type_desc") or None,
                        "malware_family": malware,
                        "source_feed": "ThreatFox",
                        "confidence": confidence,
                        "first_seen": first_seen,
                        "details": f"Threat Type: {item.get('threat_type')}"
                    })
    except Exception as e:
        logger.warning(f"ThreatFox query failed for {cve_id}: {e}")
    return iocs


def query_malwarebazaar(cve_id: str) -> List[Dict[str, Any]]:
    """Fetches real malware sample hashes (SHA256, MD5) from abuse.ch MalwareBazaar."""
    iocs = []
    tag = cve_id.strip().lower()
    payload = {"query": "get_taginfo", "tag": tag, "limit": 10}
    api_logger.info(f"POST Request -> MalwareBazaar API: {MALWAREBAZAAR_API_URL} | Tag: {tag}")
    try:
        res = requests.post(MALWAREBAZAAR_API_URL, data=payload, timeout=REQUEST_TIMEOUT)
        if res.status_code == 200:
            data = res.json()
            if data.get("query_status") == "ok":
                for item in data.get("data", []):
                    sha256 = item.get("sha256_hash")
                    md5 = item.get("md5_hash")
                    signature = item.get("signature")
                    file_type = item.get("file_type")
                    first_seen = item.get("first_seen")

                    if sha256:
                        iocs.append({
                            "ioc_type": "sha256",
                            "ioc_value": sha256,
                            "threat_actor": None,
                            "malware_family": signature,
                            "source_feed": "MalwareBazaar",
                            "confidence": 95,
                            "first_seen": first_seen,
                            "details": f"File Type: {file_type} | Signature: {signature}"
                        })
                    if md5:
                        iocs.append({
                            "ioc_type": "md5",
                            "ioc_value": md5,
                            "threat_actor": None,
                            "malware_family": signature,
                            "source_feed": "MalwareBazaar",
                            "confidence": 90,
                            "first_seen": first_seen,
                            "details": f"File Type: {file_type}"
                        })
    except Exception as e:
        logger.warning(f"MalwareBazaar query failed for {cve_id}: {e}")
    return iocs


def query_urlhaus(cve_id: str) -> List[Dict[str, Any]]:
    """Fetches live weaponized payload drop URLs from abuse.ch URLhaus."""
    iocs = []
    tag = cve_id.strip().lower()
    url = URLHAUS_TAG_URL.format(tag)
    api_logger.info(f"GET Request -> URLhaus API: {url}")
    try:
        res = requests.get(url, timeout=REQUEST_TIMEOUT)
        if res.status_code == 200:
            data = res.json()
            if data.get("query_status") == "ok":
                for item in data.get("urls", [])[:10]:
                    payload_url = item.get("url")
                    threat = item.get("threat")
                    status = item.get("url_status")
                    first_seen = item.get("date_added")
                    
                    if payload_url:
                        iocs.append({
                            "ioc_type": "url",
                            "ioc_value": payload_url,
                            "threat_actor": None,
                            "malware_family": threat,
                            "source_feed": "URLhaus",
                            "confidence": 85,
                            "first_seen": first_seen,
                            "details": f"URL Status: {status} | Threat: {threat}"
                        })
    except Exception as e:
        logger.warning(f"URLhaus query failed for {cve_id}: {e}")
    return iocs


def query_shodan_internetdb(ip: str) -> Optional[Dict[str, Any]]:
    """
    Validates Internet Exposure of an IP via Shodan InternetDB (100% Free, No API Key).
    Returns open ports, hostnames, and known exposed vulnerabilities.
    """
    if not ip or PRIVATE_IP_REGEX.match(ip):
        return None
    
    url = SHODAN_INTERNETDB_URL.format(ip.strip())
    api_logger.info(f"GET Request -> Shodan InternetDB: {url}")
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            return {
                "ip": data.get("ip"),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "cpes": data.get("cpes", []),
                "vulns": data.get("vulns", []),
                "tags": data.get("tags", [])
            }
    except Exception:
        pass
    return None


def extract_regex_iocs(cve_id: str, raw_text: Optional[str]) -> List[Dict[str, Any]]:
    """Extracts SHA256/MD5 hashes, public IPv4s, and C2 URLs from raw PoC text."""
    if not raw_text or len(raw_text) < 10:
        return []

    iocs = []
    seen = set()

    # 1. Extract SHA256
    for h in re.findall(r'\b[a-fA-F0-9]{64}\b', raw_text):
        if h.lower() not in seen:
            seen.add(h.lower())
            iocs.append({
                "ioc_type": "sha256",
                "ioc_value": h.lower(),
                "threat_actor": None,
                "malware_family": None,
                "source_feed": "PoC Scrape",
                "confidence": 75,
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "details": "Extracted from public exploit payload"
            })

    # 2. Extract MD5 (32 hex characters)
    for md in re.findall(r'\b[a-fA-F0-9]{32}\b', raw_text):
        if md.lower() not in seen:
            seen.add(md.lower())
            iocs.append({
                "ioc_type": "md5",
                "ioc_value": md.lower(),
                "threat_actor": None,
                "malware_family": None,
                "source_feed": "PoC Scrape",
                "confidence": 70,
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "details": "Extracted MD5 hash from exploit payload"
            })

    # 3. Extract Validated Public IPv4
    for ip in re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_text):
        try:
            ip_obj = ipaddress.ip_address(ip)
            if (ip_obj.version == 4 and 
                not ip_obj.is_private and 
                not ip_obj.is_loopback and 
                not ip_obj.is_reserved and 
                not ip_obj.is_multicast and 
                not ip_obj.is_link_local and 
                ip not in seen):
                seen.add(ip)
                iocs.append({
                    "ioc_type": "ip",
                    "ioc_value": ip,
                    "threat_actor": None,
                    "malware_family": None,
                    "source_feed": "PoC Scrape",
                    "confidence": 70,
                    "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "details": "Observed in PoC payload script"
                })
        except ValueError:
            continue

    return iocs


# ==============================================================================
# 2. PARALLEL ORCHESTRATION & PERSISTENCE
# ==============================================================================

def parallel_enrich_cve(cve_id: str, raw_poc_text: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Runs multi-source threat intel queries concurrently using a ThreadPoolExecutor.
    Correlates with Shodan InternetDB and saves unique IoCs to SQLite.
    """
    cve_id = cve_id.strip().upper()
    all_iocs = []

    # Parallel Feed Execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        f_tf = executor.submit(query_threatfox, cve_id)
        f_mb = executor.submit(query_malwarebazaar, cve_id)
        f_uh = executor.submit(query_urlhaus, cve_id)
        f_rx = executor.submit(extract_regex_iocs, cve_id, raw_poc_text)

        for future in (f_tf, f_mb, f_uh, f_rx):
            try:
                res = future.result()
                if res:
                    all_iocs.extend(res)
            except Exception as e:
                logger.error(f"Error during parallel IoC enrichment: {e}")

    # Validate IP exposure with Shodan InternetDB concurrently
    ip_iocs = [ioc for ioc in all_iocs if ioc.get("ioc_type") == "ip"]
    if ip_iocs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as shodan_exec:
            future_to_ioc = {shodan_exec.submit(query_shodan_internetdb, ioc["ioc_value"]): ioc for ioc in ip_iocs[:4]}
            for fut in concurrent.futures.as_completed(future_to_ioc):
                ioc_ref = future_to_ioc[fut]
                shodan_res = fut.result()
                if shodan_res and shodan_res.get("ports"):
                    ports_str = ",".join(map(str, shodan_res["ports"][:6]))
                    ioc_ref["details"] = f"{ioc_ref.get('details', '')} | Shodan Open Ports: [{ports_str}]"
                    ioc_ref["confidence"] = min(100, ioc_ref.get("confidence", 70) + 15)

    # Persist to SQLite Database
    if all_iocs:
        conn = db_manager.get_db_connection()
        cursor = conn.cursor()
        
        discovered_malware = []
        for ioc in all_iocs:
            cursor.execute('''
                INSERT INTO cve_iocs (cve_id, ioc_type, ioc_value, threat_actor, malware_family, source_feed, confidence, first_seen, details)
                SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM cve_iocs WHERE cve_id = ? AND ioc_value = ? AND ioc_type = ?
                )
            ''', (
                cve_id, ioc["ioc_type"], ioc["ioc_value"], ioc.get("threat_actor"),
                ioc.get("malware_family"), ioc.get("source_feed"), ioc.get("confidence", 80),
                ioc.get("first_seen") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ioc.get("details"), cve_id, ioc["ioc_value"], ioc["ioc_type"]
            ))

            if ioc.get("malware_family") and ioc["malware_family"] not in discovered_malware:
                discovered_malware.append(ioc["malware_family"])

        if discovered_malware:
            KNOWN_RANSOMWARE = ["ransomware", "locker", "crypt", "ryuk", "conti", "blackcat", "alphv", "hive", "clop", "revil", "darkside", "babuk", "phobos", "dharma", "akira", "play", "bianlian"]
            ransomware_hits = [m for m in discovered_malware if any(k in m.lower() for k in KNOWN_RANSOMWARE)]
            if ransomware_hits:
                cursor.execute('UPDATE cve_main SET ransomware_campaign = ? WHERE cve_id = ? AND (ransomware_campaign IS NULL OR ransomware_campaign = "")', (", ".join(ransomware_hits), cve_id))

        conn.commit()
        conn.close()

    return all_iocs


def get_cve_iocs(cve_id: str) -> List[Dict[str, Any]]:
    """Retrieves all stored IoCs for a specific CVE."""
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve_iocs WHERE cve_id = ? ORDER BY confidence DESC, id DESC", (cve_id.strip().upper(),))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# ==============================================================================
# 3. EXPORT HELPERS (CSV & STIX 2.1)
# ==============================================================================

def export_iocs_csv(cve_id: Optional[str] = None) -> str:
    """Generates a CSV string containing all validated IoCs."""
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    if cve_id:
        cursor.execute("SELECT * FROM cve_iocs WHERE cve_id = ? ORDER BY cve_id, confidence DESC", (cve_id.strip().upper(),))
    else:
        cursor.execute("SELECT * FROM cve_iocs ORDER BY cve_id, confidence DESC")
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["CVE ID", "Indicator Type", "Indicator Value", "Threat Actor", "Malware Family", "Source Feed", "Confidence Score", "First Seen", "Details"])
    for r in rows:
        writer.writerow([r["cve_id"], r["ioc_type"], r["ioc_value"], r["threat_actor"], r["malware_family"], r["source_feed"], r["confidence"], r["first_seen"], r["details"]])
    return output.getvalue()


def export_iocs_stix(cve_id: Optional[str] = None) -> Dict[str, Any]:
    """Generates a standard STIX 2.1 JSON bundle of IoCs for SIEM/EDR ingestion."""
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    if cve_id:
        cursor.execute("SELECT * FROM cve_iocs WHERE cve_id = ?", (cve_id.strip().upper(),))
    else:
        cursor.execute("SELECT * FROM cve_iocs")
    rows = cursor.fetchall()
    conn.close()

    stix_objects = []
    for r in rows:
        pattern = f"[{r['ioc_type']} = '{r['ioc_value']}']"
        if r['ioc_type'] == 'ip':
            pattern = f"[ipv4-addr:value = '{r['ioc_value']}']"
        elif r['ioc_type'] == 'domain':
            pattern = f"[domain-name:value = '{r['ioc_value']}']"
        elif r['ioc_type'] == 'sha256':
            pattern = f"[file:hashes.'SHA-256' = '{r['ioc_value']}']"
        elif r['ioc_type'] == 'md5':
            pattern = f"[file:hashes.'MD5' = '{r['ioc_value']}']"
        elif r['ioc_type'] == 'url':
            pattern = f"[url:value = '{r['ioc_value']}']"

        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z",
            "name": f"{r['cve_id']} - {r['ioc_type'].upper()}",
            "description": r["details"] or f"Indicator associated with {r['cve_id']}",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "confidence": r["confidence"],
            "external_references": [
                {"source_name": r["source_feed"] or "ATI V2", "external_id": r["cve_id"]}
            ]
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": stix_objects
    }
