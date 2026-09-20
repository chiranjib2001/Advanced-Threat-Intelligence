# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: IoT, SCADA, ICS & OT Hardware Vulnerability Collector
# ==============================================================================
import time
from datetime import datetime, timedelta
from backend import db_manager, collect

IOT_OT_KEYWORDS = ["IoT", "SCADA", "PLC", "ICS", "firmware", "HMI", "sensor", "RTU", "router"]

def fetch_iot_ot_cves(start_dt=None, end_dt=None):
    if not end_dt: end_dt = datetime.now()
    if not start_dt: start_dt = end_dt - timedelta(days=3)
    
    # Auto-slice date ranges > 90 days to respect NIST limits
    slices = []
    curr_start = start_dt
    while curr_start < end_dt:
        curr_end = min(curr_start + timedelta(days=90), end_dt)
        slices.append((curr_start, curr_end))
        curr_start = curr_end + timedelta(seconds=1)

    print(f"\n[*] Fetching IoT/OT specific CVEs from {start_dt.date()} to {end_dt.date()}...")
    
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    
    for slice_idx, (s_dt, e_dt) in enumerate(slices, 1):
        if len(slices) > 1:
            print(f" [*] Processing IoT/OT Window {slice_idx}/{len(slices)}: {s_dt.date()} to {e_dt.date()}...")
        start_str = s_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_str = e_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for keyword in IOT_OT_KEYWORDS:
            print(f" -> Querying NIST for keyword: '{keyword}'")
            start_index = 0
            while True:
                params = {
                    "pubStartDate": start_str, "pubEndDate": end_str,
                    "keywordSearch": keyword, "resultsPerPage": 2000, "startIndex": start_index
                }
                response = collect.safe_get(collect.NIST_BASE_URL, params=params)
                if not response: break
                
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                returned = len(vulns)
                if returned == 0: break
                
                # Ingest full technical metrics, CVSS, and reference URLs into cve_sources
                collect.process_nist_vulns(vulns, cursor, require_network=False)

                cve_ids_in_batch = []
                for item in vulns:
                    cve = item.get("cve", {})
                    cid = cve.get("id")
                    if cid and cve.get("vulnStatus", "").lower() != "rejected":
                        cve_ids_in_batch.append(cid)
                        cursor.execute('UPDATE cve_main SET is_iot_ot = 1 WHERE cve_id = ?', (cid,))
                
                conn.commit()

                # Batch EPSS enrichment (50 CVEs per API call) instead of 100 blocking calls
                if cve_ids_in_batch:
                    scores = collect.fetch_epss_batch(cve_ids_in_batch)
                    for cid, score in scores.items():
                        if score is not None:
                            cursor.execute('UPDATE cve_main SET epss_score = ? WHERE cve_id = ?', (score, cid))
                    conn.commit()
                    
                start_index += returned
                if start_index >= data.get("totalResults", 0): break
                time.sleep(1 if collect.NIST_API_KEY else 6)
                
    conn.close()
    print("[+] IoT/OT fetching sequence complete.")
