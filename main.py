# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Automated CVE Threat Intel & OSINT Orchestrator (CLI & GUI Launcher)
# ==============================================================================
import os
import sys
import time
import argparse
import logging
import random
import concurrent.futures
import threading
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Fix Windows console UTF-8 encoding for emojis
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

load_dotenv()

# Setup logging to logs/ directory
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
LOGS_DIR = os.path.join(ROOT_DIR, "logs")
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOGS_DIR, 'cve_analyzer.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

# Backend Engine Imports
from backend import db_manager, collect, iot_ot_cve, exploit_finder, osint_hunter, report, scraper, llm, ioc_engine, enrich_engine


def run_single_cve(cve_id, run_exploit_hunt=False, force_nist_refetch=False, progress_prefix=None):
    print("=" * 60)
    print(f" Targeted Analysis: {cve_id}")
    print("=" * 60)
    db_manager.init_db()
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    collect.fetch_single_cve(cve_id, force_refetch=force_nist_refetch)
    
    # Launch parallel EPSS fetch in background while scraping and AI analysis run
    epss_thread = collect.enrich_epss_parallel(cve_id, run_in_background=True)
    
    # Verify CISA KEV & Ransomware Catalog Status
    collect.check_cisa_for_cve(cve_id)
    
    if run_exploit_hunt:
        print(f"[*] Hunting for known weaponized exploits (Nuclei/Metasploit)...")
        exploit_finder.run_exploit_hunt(cve_id)
    
    print("\n[*] Scraping and Deep-Scanning Reference Links...")
    url_cache = {} 
    has_found_poc = False
    
    cursor.execute('SELECT id, url, is_poc_link FROM cve_sources WHERE cve_id = ? AND details IS NULL AND url != ""', (cve_id,))
    for row in cursor.fetchall():
        raw_url = row['url']
        clean_url = raw_url.rstrip('/') 
        
        if clean_url in url_cache:
            text_content, is_poc, classification = url_cache[clean_url]
            print(f"   [~] Reusing cached scan for duplicate link: {clean_url[:50]}...")
        else:
            text_content = scraper.scrape_url_text(raw_url)
            is_poc = row['is_poc_link']
            classification = llm.ai_link_classifier(text_content, url=raw_url)
            print(f"   [AI Classifier] -> {classification} for: {raw_url[:50]}...")
            if classification == "POC":
                is_poc = 1
                has_found_poc = True
                
            url_cache[clean_url] = (text_content, is_poc, classification)
            
        cursor.execute('UPDATE cve_sources SET details = ?, is_poc_link = ?, exploit_status = ? WHERE id = ?', (text_content, is_poc, classification.lower(), row['id']))
    
    if has_found_poc:
        cursor.execute('UPDATE cve_main SET has_public_poc = 1 WHERE cve_id = ?', (cve_id,))
    conn.commit()
    
    print(f"\n[*] Sending {cve_id} to Multi-Provider AI Engine for analysis...")
    cursor.execute('SELECT source_name, details FROM cve_sources WHERE cve_id = ? AND details IS NOT NULL', (cve_id,))
    combined_text = f"CVE ID: {cve_id}\n\n"
    for src in cursor.fetchall():
        combined_text += f"--- Source: {src['source_name']} ---\n{src['details']}\n\n"
        
    summary, action, poc, ai_vendor, ai_product, keywords, ai_model = llm.analyze_individual_cve(cve_id, combined_text)
    
    if summary and not ai_model.startswith("Failed") and summary != "API Offline or Rate Limited.":
        cursor.execute('''
            INSERT OR REPLACE INTO cve_analysis (cve_id, ai_summary, recommended_action, poc_recreation_steps, keywords, is_analyzed)
            VALUES (?, ?, ?, ?, ?, 1)
        ''', (cve_id, summary, action, poc, keywords))
        
        if ai_vendor.lower() != "unknown" or ai_product.lower() != "unknown":
            cursor.execute('UPDATE cve_main SET affected_vendor = ?, affected_product = ? WHERE cve_id = ?', (ai_vendor, ai_product, cve_id))
        conn.commit()
    else:
        print(f" [-] AI analysis skipped/rate-limited for {cve_id}; not marking as analyzed.")

    print(f"\n[*] Running Zero-Cost Parallel Threat Enrichment (ThreatFox / MalwareBazaar / URLhaus / Shodan)...")
    discovered_iocs = ioc_engine.parallel_enrich_cve(cve_id, raw_poc_text=poc or combined_text)
    if discovered_iocs:
        print(f" [+] Discovered and verified {len(discovered_iocs)} Indicators of Compromise (IoCs).")
    
    # Wait for parallel EPSS fetch to conclude before reporting
    if epss_thread:
        epss_thread.join(timeout=3.0)
        
    cursor.execute('SELECT severity, cvss_v3_score, cvss_vector, epss_score, affected_vendor, affected_product FROM cve_main WHERE cve_id = ?', (cve_id,))
    cve_data = cursor.fetchone()
    severity = cve_data['severity'] if cve_data and cve_data['severity'] else "Unknown"
    cvss_score = cve_data['cvss_v3_score'] if cve_data and cve_data['cvss_v3_score'] else 0.0
    cvss_vector = cve_data['cvss_vector'] if cve_data and cve_data['cvss_vector'] else "Unknown"
    epss_display = collect.format_epss(cve_data['epss_score'] if cve_data else None)
    vendor = cve_data['affected_vendor'] if cve_data else "Unknown"
    product = cve_data['affected_product'] if cve_data else "Unknown"
    
    cursor.execute('SELECT url FROM cve_sources WHERE cve_id = ? AND is_poc_link = 1 AND url != ""', (cve_id,))
    poc_links = cursor.fetchall()
    links_text = "\n".join([f"- {row['url']}" for row in poc_links]) if poc_links else "- No explicit public exploit links identified."
    
    markdown_body = f"""🚨 **Targeted Threat Intel: {cve_id}** 🚨\n
**Severity:** {severity} | **CVSS:** {cvss_score} ({cvss_vector}) | **EPSS:** {epss_display}\n
**Product:** {vendor} {product}\n
**Keywords:** {keywords}\n
---\n
🧠 **AI Summary (via {ai_model}):** {summary}\n
✅ **Action Required:** {action}\n
🛠️ **PoC / Recreation Steps:**\n```\n{poc}\n```\n
🔗 **Exploit & Reference Links:**\n{links_text}"""
    
    report.send_webhook(markdown_body, progress_prefix=progress_prefix)
    prefix = f" [{progress_prefix}]" if progress_prefix else " [+]"
    print(f"{prefix} Finished & Alerted: {cve_id}")
    conn.close()


def run_pipeline(start_date, end_date, count_limit=None, fetch_cisa=False, is_iot_ot=False, all_severity=False, run_exploit_hunt=False, is_trending=False):
    print("=" * 60)
    print(" Automated Threat Intel Pipeline")
    if is_trending:
        print(" 🚨 MODE: ACTIVE WEEK EXPLOITS (STRUCTURED THREATS) 🚨")
    print(f" Target Dates: {start_date.date()} to {end_date.date()}")
    if is_iot_ot: print(" Scope: IoT / OT / ICS Hardware Focus")
    if all_severity: print(" Scope: ALL Severities (Including Medium & Low)")
    if count_limit: print(f" Limit: Top {count_limit} vulnerabilities")
    print("=" * 60)
    
    db_manager.init_db()
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    
    if is_iot_ot:
        print("[*] Phase 1: Fetching NIST Data (IoT/OT Focus)...")
        iot_ot_cve.fetch_iot_ot_cves(start_dt=start_date, end_dt=end_date)
    else:
        print("[*] Phase 1: Fetching NIST Data...")
        collect.fetch_nist_cves(start_dt=start_date, end_dt=end_date)
        
    if fetch_cisa or is_trending:
        print("[*] Phase 1b: Fetching CISA KEV Data...")
        collect.fetch_cisa_kev()
        
    start_iso = start_date.strftime('%Y-%m-%dT00:00:00.000Z')
    end_iso = end_date.strftime('%Y-%m-%dT23:59:59.000Z')
    start_cisa = start_date.strftime('%Y-%m-%d')
    end_cisa = end_date.strftime('%Y-%m-%d')

    if fetch_cisa or is_trending:
        # Strictly filter CISA CVEs by cisa_date_added to ensure out-of-range CISA CVEs are not processed
        target_query = '''
            SELECT m.cve_id FROM cve_main m
            LEFT JOIN cve_analysis a ON m.cve_id = a.cve_id
            WHERE ((m.published_date >= ? AND m.published_date <= ?) OR (m.is_cisa_kev = 1 AND m.cisa_date_added >= ? AND m.cisa_date_added <= ?))
            AND (a.is_analyzed IS NULL OR a.is_analyzed = 0)
        '''
        params = [start_iso, end_iso, start_cisa, end_cisa]
    else:
        target_query = '''
            SELECT m.cve_id FROM cve_main m
            LEFT JOIN cve_analysis a ON m.cve_id = a.cve_id
            WHERE m.published_date >= ? AND m.published_date <= ?
            AND (a.is_analyzed IS NULL OR a.is_analyzed = 0)
        '''
        params = [start_iso, end_iso]
    
    if is_trending:
        target_query += " AND (m.epss_score > 0.05 OR m.is_cisa_kev = 1 OR m.has_public_poc = 1)"
    elif not all_severity:
        target_query += " AND (m.severity = 'Critical' OR m.severity = 'High')"
        
    if is_iot_ot:
        target_query += " AND m.is_iot_ot = 1"
        
    target_query += " ORDER BY m.cvss_v3_score DESC, m.epss_score DESC"
    
    if count_limit:
        target_query += " LIMIT ?"
        params.append(count_limit)
        
    cursor.execute(target_query, tuple(params))
    target_cves = [row['cve_id'] for row in cursor.fetchall()]
    total_targets = len(target_cves)
    
    severity_tag = "Trending CVEs" if is_trending else ("CVEs" if all_severity else "High/Critical CVEs")
    print(f"\n[*] Identified {total_targets} unanalyzed {severity_tag} for processing.")
    
    if total_targets > 0:
        # Ensure all target CVEs possess full NIST technical enrichment (e.g. if ingested via CISA KEV)
        for cve in target_cves:
            collect.fetch_single_cve(cve, force_refetch=False)

        # Launch parallel EPSS enrichment for all target CVEs while scraping and AI runs
        collect.enrich_epss_parallel(target_cves, run_in_background=True)
        
        if run_exploit_hunt:
            print("\n[*] Phase 1.5: Hunting for Exploit Modules (Nuclei/Metasploit/Trickest)...")
            for cve in target_cves:
                exploit_finder.run_exploit_hunt(cve)
                
        print("\n[*] Phase 2: Scraping and AI-Scanning ALL Web Data for Target CVEs...")
        placeholders = ','.join('?' for _ in target_cves)
        
        cursor.execute(f'''
            SELECT id, cve_id, url, is_poc_link FROM cve_sources
            WHERE cve_id IN ({placeholders}) AND details IS NULL AND url != ''
        ''', target_cves)
        
        url_rows = cursor.fetchall()
        url_cache = {}
        unique_urls = list(set([r['url'] for r in url_rows if r['url']]))

        if unique_urls:
            print(f" [*] Concurrently scraping & classifying {len(unique_urls)} unique reference links...")
            def _scrape_classify_worker(u):
                txt = scraper.scrape_url_text(u)
                cls = llm.ai_link_classifier(txt, url=u)
                return u.rstrip('/'), (txt, 1 if cls == "POC" else 0, cls)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as sc_exec:
                for clean_u, res in sc_exec.map(_scrape_classify_worker, unique_urls):
                    url_cache[clean_u] = res

        for row in url_rows:
            clean_url = row['url'].rstrip('/')
            text_content, is_poc, classification = url_cache.get(clean_url, (None, row['is_poc_link'], 'info'))
            if row['is_poc_link']:
                is_poc = 1
            cursor.execute('UPDATE cve_sources SET details = ?, is_poc_link = ?, exploit_status = ? WHERE id = ?', (text_content, is_poc, classification.lower(), row['id']))
            if is_poc:
                cursor.execute('UPDATE cve_main SET has_public_poc = 1 WHERE cve_id = ?', (row['cve_id'],))
        conn.commit()
        conn.close()
        
        total_targets = len(target_cves)
        print(f"\n[*] Phase 3: CONCURRENT Multi-Provider AI Analysis ({total_targets} threats)...")
        completed_count = 0
        progress_lock = threading.Lock()

        def analyze_worker(cve_id):
            nonlocal completed_count
            thread_conn = db_manager.get_db_connection()
            thread_cursor = thread_conn.cursor()
            try:
                thread_cursor.execute('SELECT source_name, details FROM cve_sources WHERE cve_id = ? AND details IS NOT NULL', (cve_id,))
                combined_text = f"CVE ID: {cve_id}\n\n"
                for src in thread_cursor.fetchall():
                    combined_text += f"--- Source: {src['source_name']} ---\n{src['details']}\n\n"
                    
                summary, action, poc, ai_vendor, ai_product, keywords, ai_model = llm.analyze_individual_cve(cve_id, combined_text)
                
                if summary and not ai_model.startswith("Failed") and summary != "API Offline or Rate Limited.":
                    thread_cursor.execute('''
                        INSERT OR REPLACE INTO cve_analysis (cve_id, ai_summary, recommended_action, poc_recreation_steps, keywords, is_analyzed)
                        VALUES (?, ?, ?, ?, ?, 1)
                    ''', (cve_id, summary, action, poc, keywords))
                    
                    if ai_vendor.lower() != "unknown" or ai_product.lower() != "unknown":
                        thread_cursor.execute('UPDATE cve_main SET affected_vendor = ?, affected_product = ? WHERE cve_id = ?', (ai_vendor, ai_product, cve_id))
                    thread_conn.commit()

                    # Run Zero-Cost Parallel IoC Enrichment
                    try:
                        ioc_engine.parallel_enrich_cve(cve_id, raw_poc_text=poc)
                    except Exception as _e:
                        logging.warning(f"IoC enrichment failed for {cve_id}: {_e}")
                    
                    thread_cursor.execute('SELECT severity, cvss_v3_score, cvss_vector, epss_score, affected_vendor, affected_product FROM cve_main WHERE cve_id = ?', (cve_id,))
                    cve_data = thread_cursor.fetchone()
                    severity = cve_data['severity'] if cve_data and cve_data['severity'] else "Unknown"
                    cvss_score = cve_data['cvss_v3_score'] if cve_data and cve_data['cvss_v3_score'] else 0.0
                    cvss_vector = cve_data['cvss_vector'] if cve_data and cve_data['cvss_vector'] else "Unknown"
                    epss_display = collect.format_epss(cve_data['epss_score'] if cve_data else None)
                    vendor = cve_data['affected_vendor'] if cve_data else "Unknown"
                    product = cve_data['affected_product'] if cve_data else "Unknown"
                    
                    thread_cursor.execute('SELECT url FROM cve_sources WHERE cve_id = ? AND is_poc_link = 1 AND url != ""', (cve_id,))
                    poc_links = thread_cursor.fetchall()
                    links_text = "\n".join([f"- {row['url']}" for row in poc_links]) if poc_links else "- No public exploits identified."
                    
                    short_summary = summary[:400] + "..." if len(summary) > 400 else summary
                    
                    chunk_markdown = f"""🚨 **Real-Time Alert: {cve_id}** 🚨\n
**Severity:** {severity} | **CVSS:** {cvss_score} ({cvss_vector}) | **EPSS:** {epss_display}\n
**Product:** {vendor} {product}\n
**Keywords:** {keywords}\n
---\n
🧠 **AI Summary (via {ai_model}):** {short_summary}\n
✅ **Action:** {action}\n
🛠️ **PoC / Recreation Steps:**\n```\n{poc}\n```\n
🔗 **Exploit Links:**\n{links_text}"""
                    
                    with progress_lock:
                        completed_count += 1
                        progress_tag = f"{completed_count}/{total_targets}"

                    report.send_webhook(chunk_markdown, progress_prefix=progress_tag)
                    print(f" [{progress_tag}] Finished & Alerted: {cve_id}")
                else:
                    with progress_lock:
                        completed_count += 1
                        progress_tag = f"{completed_count}/{total_targets}"
                    print(f" [{progress_tag}] AI analysis skipped/rate-limited: {cve_id}")
            except Exception as e:
                with progress_lock:
                    completed_count += 1
                    progress_tag = f"{completed_count}/{total_targets}"
                logging.error(f"[THREAD ERROR] [{progress_tag}] Failed processing {cve_id}: {e}")
            finally:
                thread_conn.close()
                
        time.sleep(1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            executor.map(analyze_worker, target_cves)
    else:
        conn.close()
            
    print("\n[*] Phase 4: Report Generation...")
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    report_query = '''
        SELECT m.cve_id, m.severity, m.affected_vendor, m.affected_product, a.ai_summary, a.recommended_action 
        FROM cve_main m JOIN cve_analysis a ON m.cve_id = a.cve_id
        WHERE m.published_date >= ? AND m.published_date <= ?
    '''
    if is_trending:
        report_query += " AND (m.epss_score > 0.05 OR m.is_cisa_kev = 1 OR m.has_public_poc = 1)"
    elif not all_severity:
        report_query += " AND (m.severity = 'Critical' OR m.severity = 'High')"
        
    if is_iot_ot:
        report_query += " AND m.is_iot_ot = 1"
        
    report_query += " ORDER BY m.epss_score DESC, m.cvss_v3_score DESC"
    cursor.execute(report_query, (start_date.strftime('%Y-%m-%dT00:00:00.000Z'), end_date.strftime('%Y-%m-%dT23:59:59.000Z')))
    analyzed_data = cursor.fetchall()
    
    if analyzed_data:
        master_summary = llm.generate_priority_summary([f"{r['cve_id']}: {r['ai_summary']}" for r in analyzed_data])
        master_markdown = f"📊 Pipeline Complete ({start_date.date()} to {end_date.date()}) 📊\n\n🎯 Executive Summary:\n{master_summary}\n\n"
        scope_text = "Trending vulnerabilities" if is_trending else ("IoT & OT vulnerabilities" if is_iot_ot else "vulnerabilities")
        master_markdown += f"Successfully analyzed {len(analyzed_data)} {scope_text}. Full HTML report saved locally."
    else:
        scope = "Trending threats" if is_trending else ("IoT/OT" if is_iot_ot else "Network attack vector")
        master_summary = f"No vulnerabilities found for {scope} matching severity criteria in this timeframe."
        master_markdown = f"✅ Pipeline Complete: {master_summary}"
        
    report.send_webhook(master_markdown)
    subj, html = report.generate_report(start_date=start_date, end_date=end_date, executive_summary_text=master_summary, all_severity=True, scope="analyzed")
    report_file_path = os.path.join(ROOT_DIR, "report_output.html")
    with open(report_file_path, "w", encoding="utf-8") as f:
        f.write(html)
    conn.close()


if __name__ == "__main__":
    print("=" * 60)
    print(" 🛡️ Automated Threat Intel Analyzer 🛡️")
    print(" Credit: Created with love by Chiranjib and Team")
    print("=" * 60)
    parser = argparse.ArgumentParser(description="Automated CVE Threat Intel Analyzer")
    parser.add_argument("--start", type=str, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end", type=str, help="End date (YYYY-MM-DD)")
    parser.add_argument("--cve", type=str, help="Analyze a specific CVE (e.g., CVE-2024-1234)")
    parser.add_argument("--count", type=int, help="Limit analysis to the top N worst vulnerabilities")
    parser.add_argument("--cisa", action="store_true", help="Include CISA Known Exploited Vulnerabilities catalog fetch")
    parser.add_argument("--iotot", action="store_true", help="Filter strictly for IoT, ICS, and OT hardware vulnerabilities")
    parser.add_argument("--all-severity", action="store_true", help="Analyze all severities, bypassing the Critical/High filter")
    parser.add_argument("--exploit-find", action="store_true", help="Actively search Nuclei, Metasploit, and GitHub for PoCs")
    
    parser.add_argument("--active-week-exploits", action="store_true", help="Find STRUCTURED Trending CVEs (EPSS > 5%%, CISA KEV, or Public PoCs) from the last 7 days.")
    parser.add_argument("--in-wild-osint", action="store_true", help="Find UNSTRUCTURED Trending CVEs by scraping HackerNews/Reddit, regardless of publish date.")
    parser.add_argument("--enrich-db", action="store_true", help="Launch interactive on-demand database maintenance and technical/AI enrichment (Press 'q' to stop)")
    
    # === GUI & Web Server Flags ===
    parser.add_argument("--gui", "--web", "--server", dest="gui", action="store_true", help="Launch the full-stack Web GUI & API Server (FastAPI + Cyber Command Center UI)")
    parser.add_argument("--port", type=int, default=8000, help="Web server port (default: 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Web server host (default: 127.0.0.1)")
    args = parser.parse_args()
    
    if args.gui:
        import uvicorn
        import webbrowser
        print(f"\n[*] Launching ATI V2 Cyber Command Center Web GUI at http://{args.host}:{args.port} ...")
        try:
            threading.Timer(1.2, lambda: webbrowser.open(f"http://{args.host}:{args.port}")).start()
        except Exception:
            pass
        uvicorn.run("backend.server:app", host=args.host, port=args.port, reload=False)

    elif args.cve:
        run_single_cve(args.cve, run_exploit_hunt=args.exploit_find, force_nist_refetch=True)
        
    elif args.in_wild_osint:
        print("\n🚨 MODE: IN-WILD OSINT & CISA EXPLOIT THREAT HUNTING 🚨")
        print("[*] Phase 1: Ingesting CISA Known Exploited Vulnerabilities (KEV) Catalog...")
        collect.fetch_cisa_kev()

        print("\n[*] Phase 2: Ingesting 15-Day Threat Intelligence Across 6 Multi-Source Streams...")
        trending_cves_dict = osint_hunter.get_trending_cves_from_socials(min_mentions=1, days_back=15)
        
        db_manager.init_db()
        conn = db_manager.get_db_connection()
        cursor = conn.cursor()
        target_cves = []

        if trending_cves_dict:
            print("\n[*] Storing OSINT-identified CVEs and proof links in local database...")
            source_details = getattr(trending_cves_dict, "source_details", {})
            for cve_id, mentions in trending_cves_dict.items():
                collect.fetch_single_cve(cve_id) 
                records = source_details.get(cve_id, [])
                platforms = list(set([r["platform"] for r in records]))
                platforms_str = ", ".join(platforms) if platforms else "Social Chatter"
                
                cursor.execute('''UPDATE cve_main SET osint_mention_count = ?, is_exploited_in_wild = 1, osint_sources = ? WHERE cve_id = ?''', (mentions, platforms_str, cve_id))
                
                # Store unverified internet proof links in cve_sources
                for rec in records:
                    cursor.execute('SELECT id FROM cve_sources WHERE cve_id = ? AND url = ?', (cve_id, rec["url"]))
                    if not cursor.fetchone():
                        cursor.execute('''
                            INSERT INTO cve_sources (cve_id, source_name, url, is_poc_link, details, exploit_status)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            cve_id,
                            f"OSINT: {rec['platform']}",
                            rec["url"],
                            1 if rec.get("is_poc") else 0,
                            f"{rec['title']} (Unverified Internet Chatter)",
                            "unverified_osint_poc" if rec.get("is_poc") else "unverified_osint_chatter"
                        ))
                conn.commit()
                target_cves.append(cve_id)
        else:
            print("[-] Social chatter below viral threshold. Correlating with CISA KEV & active wild threats...")
            now = datetime.now()
            thirty_days_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d")
            month_prefix = now.strftime("%Y-%m")
            print(f"[*] Fallback Scope: Strictly filtering CISA KEV from the last 1 month (since {thirty_days_ago})...")

            limit = args.count
            if not limit:
                limit = 15
                print(f"[*] Applying default safety limit: Prioritizing Top {limit} most recent CISA KEV (latest month / week) & high-risk threats...")

            cursor.execute('''
                SELECT m.cve_id FROM cve_main m
                LEFT JOIN cve_analysis a ON m.cve_id = a.cve_id
                WHERE (m.is_cisa_kev = 1 OR m.is_exploited_in_wild = 1 OR m.epss_score > 0.05 OR m.has_public_poc = 1)
                AND (m.cisa_date_added >= ? OR m.cisa_date_added LIKE ? OR m.published_date >= ?)
                AND (a.is_analyzed IS NULL OR a.is_analyzed = 0)
                ORDER BY 
                    CASE WHEN m.cisa_date_added IS NOT NULL AND m.cisa_date_added != '' THEN m.cisa_date_added ELSE '1970-01-01' END DESC,
                    m.is_cisa_kev DESC, 
                    m.epss_score DESC, 
                    m.cvss_v3_score DESC
                LIMIT ?
            ''', (thirty_days_ago, f"{month_prefix}%", thirty_days_ago, limit))
            target_cves = [r["cve_id"] for r in cursor.fetchall()]

            if not target_cves:
                cursor.execute('''
                    SELECT m.cve_id FROM cve_main m
                    WHERE (m.is_cisa_kev = 1 OR m.is_exploited_in_wild = 1 OR m.epss_score > 0.05 OR m.has_public_poc = 1)
                    AND (m.cisa_date_added >= ? OR m.cisa_date_added LIKE ? OR m.published_date >= ?)
                    ORDER BY 
                        CASE WHEN m.cisa_date_added IS NOT NULL AND m.cisa_date_added != '' THEN m.cisa_date_added ELSE '1970-01-01' END DESC,
                        m.is_cisa_kev DESC, 
                        m.epss_score DESC, 
                        m.cvss_v3_score DESC
                    LIMIT ?
                ''', (thirty_days_ago, f"{month_prefix}%", thirty_days_ago, limit))
                target_cves = [r["cve_id"] for r in cursor.fetchall()]

        conn.close()

        total_targets = len(target_cves)
        print(f"\n[*] Processing {total_targets} Active In-The-Wild & CISA Threats (Concurrent Pool)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            def _in_wild_worker(item):
                idx, cid = item
                progress_tag = f"{idx}/{total_targets}"
                if args.exploit_find:
                    exploit_finder.run_exploit_hunt(cid)
                run_single_cve(cid, run_exploit_hunt=False, progress_prefix=progress_tag)
            executor.map(_in_wild_worker, list(enumerate(target_cves, 1)))

    elif args.enrich_db:
        print("\n[*] Launching Interactive On-Demand Database Enrichment Engine...")
        print("[!] Interactive Control: Press 'q' + Enter (or Ctrl+C) at any time to stop cleanly.\n")

        def _keyboard_listener():
            try:
                while not enrich_engine.stop_event.is_set():
                    user_cmd = input()
                    if user_cmd.strip().lower() == 'q':
                        enrich_engine.request_stop()
                        break
            except Exception:
                enrich_engine.request_stop()

        t_key = threading.Thread(target=_keyboard_listener, daemon=True)
        t_key.start()
        enrich_engine.enrich_database(max_items=args.count)

    elif args.active_week_exploits:
        if args.start or args.end:
            print("\n⚠️  DISCLAIMER: The --start and --end flags are IGNORED when using --active-week-exploits.")
        print("⚠️  DISCLAIMER: This mode aggressively scans external databases for weaponization. It may take considerable time due to rate limiting and web scraping.\n")
        
        end_dt = datetime.now()
        start_dt = end_dt - timedelta(days=7)
        run_pipeline(start_dt, end_dt, count_limit=args.count, fetch_cisa=True, is_iot_ot=args.iotot, all_severity=args.all_severity, run_exploit_hunt=True, is_trending=True)
        
    else:
        end_dt = datetime.strptime(args.end, "%Y-%m-%d") if args.end else datetime.now()
        start_dt = datetime.strptime(args.start, "%Y-%m-%d") if args.start else end_dt - timedelta(days=2)
        run_pipeline(start_dt, end_dt, count_limit=args.count, fetch_cisa=args.cisa, is_iot_ot=args.iotot, all_severity=args.all_severity, run_exploit_hunt=args.exploit_find)