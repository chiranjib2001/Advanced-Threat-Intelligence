# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Ingestion Engine for NIST NVD 2.0, CISA KEV & FIRST.org EPSS
# ==============================================================================
import os
import time
import threading
import concurrent.futures
import requests
import logging
from datetime import datetime, timedelta
from dotenv import load_dotenv
from backend import db_manager

load_dotenv()

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOGS_DIR = os.path.join(ROOT_DIR, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

# Dedicated API Logger to logs/apicall.log
api_logger = logging.getLogger('api_call_logger')
api_logger.setLevel(logging.INFO)
if not api_logger.handlers:
    api_handler = logging.FileHandler(os.path.join(LOGS_DIR, 'apicall.log'), encoding='utf-8')
    api_handler.setFormatter(logging.Formatter('%(asctime)s - [API] - %(message)s'))
    api_logger.addHandler(api_handler)

NIST_API_KEY = os.getenv("NIST_API_KEY", "")
NIST_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NIST_HEADERS = {"apiKey": NIST_API_KEY} if NIST_API_KEY else {}

def fetch_cisa_kev():
    print("[*] Fetching latest CISA KEV catalog & Ransomware attribution...")
    api_logger.info(f"GET Request -> CISA KEV: {CISA_KEV_URL}")
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        conn = db_manager.get_db_connection()
        cursor = conn.cursor()
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue
            cve_id = cve_id.strip().upper()
            description = vuln.get("shortDescription")
            date_added = vuln.get("dateAdded")
            due_date = vuln.get("dueDate")
            req_action = vuln.get("requiredAction")
            ransomware_use = vuln.get("knownRansomwareCampaignUse")
            vuln_name = vuln.get("vulnerabilityName")
            vendor = vuln.get("vendorProject") or "Unknown"
            product = vuln.get("product") or "Unknown"
            cwes = vuln.get("cwes", [])
            cwe_str = ", ".join(cwes) if isinstance(cwes, list) else str(cwes or "")

            # Ensure row is stored in cve_main so CISA KEV CVEs are available in DB even before deep NIST scan
            cursor.execute('''
                INSERT INTO cve_main (
                    cve_id, published_date, affected_vendor, affected_product,
                    cwe, is_cisa_kev, cisa_date_added, cisa_due_date, cisa_required_action,
                    ransomware_campaign, severity
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 'High')
                ON CONFLICT(cve_id) DO UPDATE SET
                    is_cisa_kev = 1,
                    cisa_date_added = COALESCE(excluded.cisa_date_added, cve_main.cisa_date_added),
                    cisa_due_date = COALESCE(excluded.cisa_due_date, cve_main.cisa_due_date),
                    cisa_required_action = COALESCE(excluded.cisa_required_action, cve_main.cisa_required_action),
                    affected_vendor = CASE 
                        WHEN cve_main.affected_vendor IS NULL OR cve_main.affected_vendor = 'Unknown' THEN excluded.affected_vendor 
                        ELSE cve_main.affected_vendor 
                    END,
                    affected_product = CASE 
                        WHEN cve_main.affected_product IS NULL OR cve_main.affected_product = 'Unknown' THEN excluded.affected_product 
                        ELSE cve_main.affected_product 
                    END,
                    cwe = COALESCE(cve_main.cwe, excluded.cwe),
                    ransomware_campaign = CASE 
                        WHEN excluded.ransomware_campaign IS NOT NULL THEN excluded.ransomware_campaign 
                        ELSE cve_main.ransomware_campaign 
                    END
            ''', (
                cve_id,
                date_added,
                vendor,
                product,
                cwe_str,
                date_added,
                due_date,
                req_action,
                'Known Ransomware Linked' if ransomware_use == 'Known' else None
            ))

            cursor.execute('''
                INSERT INTO cve_sources (cve_id, source_name, url, details, is_poc_link)
                SELECT ?, 'CISA KEV', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', ?, 1
                WHERE NOT EXISTS (SELECT 1 FROM cve_sources WHERE cve_id = ? AND source_name = 'CISA KEV')
            ''', (cve_id, f"{vuln_name or ''} - {description or ''}".strip(' -'), cve_id))

            # If linked to known ransomware campaigns, insert into cve_iocs
            if ransomware_use == "Known":
                cursor.execute('''
                    INSERT INTO cve_iocs (cve_id, ioc_type, ioc_value, threat_actor, source_feed, confidence, details)
                    SELECT ?, 'ransomware', 'Known Ransomware Campaign Use', 'Ransomware Operator', 'CISA KEV', 100, ?
                    WHERE NOT EXISTS (
                        SELECT 1 FROM cve_iocs WHERE cve_id = ? AND ioc_type = 'ransomware'
                    )
                ''', (cve_id, f"Due Date: {due_date} | Action: {req_action}", cve_id))

        conn.commit()
        conn.close()
        print(f"[+] CISA KEV catalog & ransomware telemetry merged successfully.")
    except Exception as e:
        api_logger.error(f"Failed CISA KEV fetch: {e}")
        print(f"[-] Error fetching CISA KEV: {e}")

def check_cisa_for_cve(cve_id: str) -> bool:
    """
    Checks if a specific CVE is cataloged in the CISA Known Exploited Vulnerabilities feed.
    Enriches cve_main and cve_iocs if matched.
    """
    cve_id = cve_id.strip().upper()
    print(f"[*] Checking CISA KEV catalog status for {cve_id}...")
    api_logger.info(f"GET Request -> Checking CISA KEV for {cve_id}")
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for vuln in data.get("vulnerabilities", []):
                if vuln.get("cveID", "").upper() == cve_id:
                    description = vuln.get("shortDescription")
                    date_added = vuln.get("dateAdded")
                    due_date = vuln.get("dueDate")
                    req_action = vuln.get("requiredAction")
                    ransomware_use = vuln.get("knownRansomwareCampaignUse")
                    vuln_name = vuln.get("vulnerabilityName")

                    conn = db_manager.get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE cve_main 
                        SET is_cisa_kev = 1,
                            cisa_date_added = COALESCE(?, cisa_date_added),
                            cisa_due_date = ?,
                            cisa_required_action = ?,
                            ransomware_campaign = CASE 
                                WHEN ? = 'Known' THEN 'Known Ransomware Linked' 
                                ELSE ransomware_campaign 
                            END
                        WHERE cve_id = ?
                    ''', (date_added, due_date, req_action, ransomware_use, cve_id))

                    cursor.execute('''
                        INSERT INTO cve_sources (cve_id, source_name, url, details, is_poc_link)
                        SELECT ?, 'CISA KEV', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', ?, 1
                        WHERE NOT EXISTS (SELECT 1 FROM cve_sources WHERE cve_id = ? AND source_name = 'CISA KEV')
                    ''', (cve_id, f"{vuln_name or ''} - {description or ''}".strip(' -'), cve_id))

                    if ransomware_use == "Known":
                        cursor.execute('''
                            INSERT INTO cve_iocs (cve_id, ioc_type, ioc_value, threat_actor, source_feed, confidence, details)
                            SELECT ?, 'ransomware', 'Known Ransomware Campaign Use', 'Ransomware Operator', 'CISA KEV', 100, ?
                            WHERE NOT EXISTS (
                                SELECT 1 FROM cve_iocs WHERE cve_id = ? AND ioc_type = 'ransomware'
                            )
                        ''', (cve_id, f"Due Date: {due_date} | Action: {req_action}", cve_id))

                    conn.commit()
                    conn.close()
                    print(f" [!] 🚨 {cve_id} is CONFIRMED in CISA KEV! (Due Date: {due_date})")
                    return True
        print(f" [+] {cve_id} is not listed in active CISA KEV catalog.")
    except Exception as e:
        api_logger.error(f"Failed single CISA check for {cve_id}: {e}")
    return False

def safe_get(url, params=None, max_retries=3):
    wait_seconds = 1 if NIST_API_KEY else 6
    api_logger.info(f"GET Request -> NIST API: {url} | Params: {params}")
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, params=params, headers=NIST_HEADERS, timeout=60)
            if response.status_code == 200: return response
            if response.status_code in (403, 429, 500, 502, 503, 504) and attempt < max_retries:
                api_logger.warning(f"NIST API Rate Limit/Error ({response.status_code}). Retrying in {wait_seconds * attempt}s...")
                time.sleep(wait_seconds * attempt)
                continue
            response.raise_for_status()
        except requests.RequestException as e:
            if attempt < max_retries: time.sleep(wait_seconds * attempt)
            else: 
                api_logger.error(f"NIST API Fetch failed after {max_retries} attempts: {e}")
                return None

def fetch_epss(cve_id):
    """Fetches EPSS probability for a single CVE from FIRST.org. Returns float or None if unavailable (NA)."""
    cve_id = cve_id.strip().upper()
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    api_logger.info(f"GET Request -> FIRST.org EPSS: {url}")
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            items = data.get("data", [])
            if items and items[0].get("epss") is not None:
                return float(items[0]["epss"])
    except Exception as e:
        api_logger.error(f"EPSS Fetch failed for {cve_id}: {e}")
    return None

def fetch_epss_batch(cve_ids):
    """Fetches EPSS probabilities for a batch of CVEs (up to 50 at once) from FIRST.org."""
    results = {}
    if not cve_ids:
        return results

    clean_ids = [c.strip().upper() for c in cve_ids if c and isinstance(c, str)]
    chunk_size = 50
    for i in range(0, len(clean_ids), chunk_size):
        chunk = clean_ids[i:i + chunk_size]
        query_str = ",".join(chunk)
        url = f"https://api.first.org/data/v1/epss?cve={query_str}"
        api_logger.info(f"GET Batch Request -> FIRST.org EPSS ({len(chunk)} CVEs)")
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", []):
                    cid = item.get("cve", "").upper()
                    if cid and item.get("epss") is not None:
                        try:
                            results[cid] = float(item["epss"])
                        except (ValueError, TypeError):
                            results[cid] = None
        except Exception as e:
            api_logger.error(f"EPSS batch fetch error for chunk: {e}")

    for cid in clean_ids:
        if cid not in results:
            results[cid] = None
    return results

def enrich_epss_parallel(cve_ids, run_in_background=True):
    """
    Enriches CVEs with EPSS scores from FIRST.org in a parallel background thread.
    Updates SQLite asynchronously so scraping and AI analysis are not blocked.
    """
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]

    clean_cves = list(set([c.strip().upper() for c in cve_ids if c and isinstance(c, str)]))
    if not clean_cves:
        return None

    def worker():
        print(f"[*] [EPSS Engine] Fetching EPSS scores in parallel for {len(clean_cves)} CVEs...")
        scores = fetch_epss_batch(clean_cves)
        if scores:
            try:
                conn = db_manager.get_db_connection()
                cursor = conn.cursor()
                updated_count = 0
                for cid, score in scores.items():
                    if score is not None:
                        cursor.execute('UPDATE cve_main SET epss_score = ? WHERE cve_id = ?', (score, cid))
                        updated_count += 1
                conn.commit()
                conn.close()
                print(f"[+] [EPSS Engine] Background update complete: {updated_count}/{len(clean_cves)} EPSS scores populated.")
            except Exception as e:
                api_logger.error(f"[EPSS Engine] Database update error: {e}")

    if run_in_background:
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        return t
    else:
        worker()
        return None

def format_epss(score):
    """Standard formatter: returns 'NA' if score is None or unavailable, otherwise 'XX.X%'."""
    if score is None:
        return "NA"
    try:
        val = float(score)
        return f"{val * 100:.1f}%"
    except (ValueError, TypeError):
        return "NA"

def extract_vendor_product(cve_obj):
    for config in cve_obj.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe_str = match.get("criteria", "")
                if cpe_str.startswith("cpe:2.3:"):
                    parts = cpe_str.split(":")
                    if len(parts) >= 5: return parts[3].capitalize(), parts[4].capitalize()
    return "Unknown", "Unknown"

def process_nist_vulns(vulns, cursor, require_network=True):
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id or cve.get("vulnStatus", "").lower() == "rejected": continue
        
        published = cve.get("published")
        last_modified = cve.get("lastModified")
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
                
        cvss_score = 0.0
        cvss_vector = "UNKNOWN"
        severity = "Unknown"
        attack_vector = "UNKNOWN"
        metrics = cve.get("metrics", {})
        
        if "cvssMetricV31" in metrics or "cvssMetricV30" in metrics:
            metric_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "UNKNOWN")
                severity = cvss_data.get("baseSeverity", "Unknown").capitalize()
                attack_vector = cvss_data.get("attackVector", "UNKNOWN").upper()

        # Fallback to CVSS v4.0 if and only if CVSS v3 is absent
        if cvss_score == 0.0 and "cvssMetricV40" in metrics:
            metric_list = metrics.get("cvssMetricV40", [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "UNKNOWN")
                severity = cvss_data.get("baseSeverity", "Unknown").capitalize()
                attack_vector = cvss_data.get("attackVector", "UNKNOWN").upper()

        # Fallback to CVSS v2.0 if and only if CVSS v3 and v4 are absent
        if cvss_score == 0.0 and "cvssMetricV2" in metrics:
            metric_list = metrics.get("cvssMetricV2", [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "UNKNOWN")
                severity = metric_list[0].get("baseSeverity", "Unknown").capitalize()
                attack_vector = cvss_data.get("accessVector", "UNKNOWN").upper()
                
        if require_network and attack_vector != "NETWORK": continue
        
        vendor, product = extract_vendor_product(cve)
        epss = None  # None represents NA initially; populated concurrently by enrich_epss_parallel

        cursor.execute('''
            INSERT INTO cve_main (cve_id, published_date, updated_date, cvss_v3_score, cvss_vector, epss_score, severity, affected_vendor, affected_product)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                cvss_v3_score = CASE WHEN excluded.cvss_v3_score > 0 THEN excluded.cvss_v3_score ELSE COALESCE(cve_main.cvss_v3_score, excluded.cvss_v3_score) END,
                cvss_vector = CASE WHEN excluded.cvss_vector != 'UNKNOWN' THEN excluded.cvss_vector ELSE cve_main.cvss_vector END,
                severity = CASE WHEN excluded.severity != 'Unknown' THEN excluded.severity ELSE cve_main.severity END,
                published_date = COALESCE(excluded.published_date, cve_main.published_date),
                updated_date = COALESCE(excluded.updated_date, cve_main.updated_date),
                affected_vendor = CASE 
                    WHEN cve_main.affected_vendor IS NULL OR cve_main.affected_vendor = 'Unknown' THEN excluded.affected_vendor 
                    ELSE cve_main.affected_vendor 
                END,
                affected_product = CASE 
                    WHEN cve_main.affected_product IS NULL OR cve_main.affected_product = 'Unknown' THEN excluded.affected_product 
                    ELSE cve_main.affected_product 
                END
        ''', (cve_id, published, last_modified, cvss_score, cvss_vector, epss, severity, vendor, product))
        
        cursor.execute('UPDATE cve_main SET cvss_vector = ? WHERE cve_id = ? AND (cvss_vector IS NULL OR cvss_vector = "UNKNOWN")', (cvss_vector, cve_id))

        cursor.execute('''
            INSERT INTO cve_sources (cve_id, source_name, url, details, is_poc_link)
            SELECT ?, 'NVD Description', ?, ?, 0
            WHERE NOT EXISTS (SELECT 1 FROM cve_sources WHERE cve_id = ? AND source_name = 'NVD Description')
        ''', (cve_id, f"https://nvd.nist.gov/vuln/detail/{cve_id}", description, cve_id))
        
        if description:
            cursor.execute('''
                UPDATE cve_sources SET details = ? 
                WHERE cve_id = ? AND source_name = 'NVD Description'
            ''', (description, cve_id))
        
        # Ingest all reference URLs from NIST with strict deduplication per CVE
        for ref in cve.get("references", []):
            raw_url = (ref.get("url") or "").strip()
            if not raw_url:
                continue
            clean_url = raw_url.rstrip('/')
            tags = " ".join(ref.get("tags", [])).lower()
            url_lower = raw_url.lower()

            is_release = any(p in url_lower for p in ["/releases/tag/", "/releases/download/", "/archive/refs/tags/", "/releases", "/tags/", "/tags"])
            is_commit_or_advisory = any(p in url_lower for p in ["/commit/", "/pull/", "/security/advisories/", "cisa.gov", "advisory", "bulletin"])

            if is_release:
                is_poc = 0
                source_name = "Vulnerable/Fixed Product Version"
                status = "vuln_version"
            elif is_commit_or_advisory:
                is_poc = 0
                source_name = "Vendor Advisory / Patch"
                status = "vendor_fix"
            elif "exploit" in tags or "poc" in tags or any(url_lower.endswith(ext) for ext in [".py", ".sh", ".c", ".go", ".rb", ".pl"]):
                is_poc = 1
                source_name = "External Reference (PoC)"
                status = "poc"
            else:
                is_poc = 0
                source_name = "External Reference"
                status = "info"

            cursor.execute('''
                INSERT INTO cve_sources (cve_id, source_name, url, is_poc_link, exploit_status)
                SELECT ?, ?, ?, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM cve_sources WHERE cve_id = ? AND (url = ? OR url = ? OR rtrim(url, '/') = ?)
                )
            ''', (cve_id, source_name, raw_url, is_poc, status, cve_id, raw_url, clean_url, clean_url))

def fetch_single_cve(cve_id, force_refetch=False):
    cve_id = cve_id.strip().upper()
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    
    # Check existing data in local DB
    cursor.execute('''
        SELECT m.cvss_v3_score, m.cvss_vector,
               (SELECT COUNT(*) FROM cve_sources s WHERE s.cve_id = m.cve_id AND s.source_name = 'NVD Description') as has_nvd_desc
        FROM cve_main m
        WHERE m.cve_id = ?
    ''', (cve_id,))
    row = cursor.fetchone()

    has_full_nist = bool(row and (row['cvss_v3_score'] is not None or row['has_nvd_desc'] > 0))

    if not force_refetch and has_full_nist:
        print(f"[*] {cve_id} already has complete NIST data in local database. Skipping NIST API fetch.")
        conn.close()
        return

    if force_refetch:
        print(f"[*] Live re-analysis requested for {cve_id}: Querying NIST NVD 2.0 API for latest updates...")
    elif row:
        print(f"[*] {cve_id} exists from CISA KEV, but missing full NIST technical details. Fetching from NIST...")
    else:
        print(f"[*] Fetching specific CVE: {cve_id} from NIST...")

    try:
        response = safe_get(NIST_BASE_URL, params={"cveId": cve_id})
        if response and response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                process_nist_vulns(vulns, cursor, require_network=False)
                conn.commit()
                print(f"[+] Successfully fetched/updated {cve_id} from NIST.")
            else:
                print(f"[-] No vulnerability records found in NIST for {cve_id}.")
                if row:
                    print(f"[*] Retaining and utilizing existing local data for {cve_id}.")
        else:
            print(f"[-] NIST API query returned non-200 or timed out for {cve_id}.")
            if row:
                print(f"[*] Falling back to existing local database record for {cve_id}.")
    except Exception as e:
        api_logger.error(f"NIST API Fetch exception for {cve_id}: {e}")
        print(f"[-] NIST API error ({e}).")
        if row:
            print(f"[*] NIST API unavailable. Falling back to existing local data for {cve_id}.")
    finally:
        conn.close()

def fetch_nist_cves(start_dt=None, end_dt=None):
    if not end_dt: end_dt = datetime.now()
    if not start_dt: start_dt = end_dt - timedelta(days=3)
    print(f"\n[*] Fetching NIST CVEs (NETWORK ONLY) from {start_dt.date()} to {end_dt.date()}...")
    
    # NIST NVD API 2.0 enforces a max range of 120 days per query.
    # Automatically slice ranges > 90 days into safe consecutive windows.
    slices = []
    curr_start = start_dt
    while curr_start < end_dt:
        curr_end = min(curr_start + timedelta(days=90), end_dt)
        slices.append((curr_start, curr_end))
        curr_start = curr_end + timedelta(seconds=1)

    conn = db_manager.get_db_connection()
    cursor = conn.cursor()

    for slice_idx, (s_dt, e_dt) in enumerate(slices, 1):
        if len(slices) > 1:
            print(f" [*] Processing NIST Window {slice_idx}/{len(slices)}: {s_dt.date()} to {e_dt.date()}...")
        start_str = s_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_str = e_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        start_index = 0
        
        while True:
            try:
                import main
                if getattr(main, 'scan_stop_event', None) and main.scan_stop_event.is_set():
                    print("[*] Scan pause requested. Stopping NIST data fetch.")
                    break
            except Exception:
                pass

            params = {"pubStartDate": start_str, "pubEndDate": end_str, "resultsPerPage": 2000, "startIndex": start_index}
            response = safe_get(NIST_BASE_URL, params=params)
            if not response: break
            
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            returned = len(vulns)
            print(f" -> Fetched {start_index + returned} / {data.get('totalResults', 0)} records...")
            
            if returned == 0: break
            process_nist_vulns(vulns, cursor, require_network=True)
            conn.commit()
            
            start_index += returned
            if start_index >= data.get("totalResults", 0): break
            time.sleep(1 if NIST_API_KEY else 6)

    conn.close()
    print("[+] NIST fetching complete.")
