# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: FastAPI Backend & REST API Server for ATI V2
# ==============================================================================
import os
import sys
import time
import io
import logging
import threading
import queue
import sqlite3
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, BackgroundTasks, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import warnings
try:
    from bs4 import XMLParsedAsHTMLWarning, MarkupResemblesLocatorWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
    warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
except ImportError:
    pass

try:
    from backend import db_manager, collect, iot_ot_cve, exploit_finder, osint_hunter, report, ioc_engine, llm, enrich_engine, vuln_version_finder, scraper
except ImportError:
    from . import db_manager, collect, iot_ot_cve, exploit_finder, osint_hunter, report, ioc_engine, llm, enrich_engine, vuln_version_finder, scraper

STATIC_DIR = os.path.join(ROOT_DIR, "static")
LOGS_DIR = os.path.join(ROOT_DIR, "logs")

# Initialize DB on startup
db_manager.init_db()

app = FastAPI(
    title="ATI V2 - Threat Intelligence Platform",
    description="Automated CVE Threat Intel, OSINT & Exploit Hunting API",
    version="2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_no_cache_header(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# Global Scan Execution State
scan_state = {
    "is_running": False,
    "current_task": "Idle",
    "started_at": None,
    "log_history": [],
}
scan_subscribers = []
scan_lock = threading.Lock()


class StreamCapture(io.StringIO):
    """Custom stream to capture stdout/stderr in real-time and broadcast to SSE listeners."""
    def __init__(self, original_stream):
        super().__init__()
        self.original_stream = original_stream

    def write(self, s):
        self.original_stream.write(s)
        self.original_stream.flush()
        if s.strip():
            with scan_lock:
                timestamp = datetime.now().strftime("%H:%M:%S")
                clean_line = f"[{timestamp}] {s.strip()}"
                scan_state["log_history"].append(clean_line)
                if len(scan_state["log_history"]) > 2000:
                    scan_state["log_history"].pop(0)
                    
                for q in scan_subscribers:
                    try:
                        q.put_nowait(clean_line)
                    except Exception:
                        pass
        return len(s)


class ScanRequest(BaseModel):
    mode: str = "custom"  # 'single', 'osint', 'weekly', 'iotot', 'custom'
    cve_id: Optional[str] = None
    exploit_find: bool = True
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    count: Optional[int] = None
    limit_enabled: bool = False
    cisa: bool = False
    iotot: bool = False
    all_severity: bool = False
    active_week_exploits: bool = False
    in_wild_osint: bool = False


class CisaEnrichRequest(BaseModel):
    severity_scope: str = "medium_plus"  # 'medium_plus' or 'all'
    time_scope: str = "this_month"        # 'this_month' or 'all'
    limit: Optional[int] = None


class EnrichDbRequest(BaseModel):
    enrich_technical: bool = True
    enrich_epss: bool = True
    enrich_ai: bool = True
    enrich_exploits: bool = False
    max_items: Optional[int] = None


class AssetCreateRequest(BaseModel):
    asset_name: str
    asset_type: str = "Server"
    vendor: str
    product: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    ip_address: Optional[str] = None
    domain_name: Optional[str] = None
    criticality: str = "High"
    owner_department: Optional[str] = None
    notes: Optional[str] = None


def execute_pipeline_task(req: ScanRequest):
    global scan_state
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    capture = StreamCapture(old_stdout)
    sys.stdout = capture
    sys.stderr = capture
    
    import main

    # Strict count enforcement: Only apply limit if limit_enabled is explicitly True
    effective_count = req.count if (req.limit_enabled and req.count is not None) else None

    try:
        with scan_lock:
            scan_state["is_running"] = True
            scan_state["current_task"] = req.mode.upper()
            scan_state["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            scan_state["log_history"].clear()

        print(f"🎯 Launching ATI V2 Threat Hunt: Mode = {req.mode.upper()}...")
        
        if req.mode == "single" and req.cve_id:
            cve_id = req.cve_id.strip().upper()
            main.run_single_cve(cve_id, run_exploit_hunt=req.exploit_find, force_nist_refetch=True)
            
        elif req.mode == "osint" or (req.mode == "custom" and req.in_wild_osint):
            print("\n🚨 MODE: IN-WILD OSINT & CISA EXPLOIT THREAT HUNTING 🚨")
            print("[*] Phase 1: Ingesting CISA Known Exploited Vulnerabilities (KEV) Catalog...")
            collect.fetch_cisa_kev()

            print("\n[*] Phase 2: Ingesting 15-Day Threat Intelligence Across 6 Multi-Source Streams...")
            trending = osint_hunter.get_trending_cves_from_socials(min_mentions=1, days_back=15)
            
            conn = db_manager.get_db_connection()
            cursor = conn.cursor()
            target_cves = []

            if trending:
                source_details = getattr(trending, "source_details", {})
                trending_items = list(trending.items())
                if effective_count:
                    trending_items = trending_items[:effective_count]
                for cve_id, count in trending_items:
                    if getattr(main, "scan_stop_event", None) and main.scan_stop_event.is_set():
                        print("[*] Scan pause/cancellation requested. Stopping OSINT processing.")
                        break

                    collect.fetch_single_cve(cve_id)
                    records = source_details.get(cve_id, [])
                    platforms = list(set([r["platform"] for r in records]))
                    platforms_str = ", ".join(platforms) if platforms else "Social Chatter"
                    cursor.execute('UPDATE cve_main SET osint_mention_count = ?, is_exploited_in_wild = 1, osint_sources = ? WHERE cve_id = ?', (count, platforms_str, cve_id))
                    
                    seed_links = set()
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
                        seed_links.add(rec["url"])
                        # Extract any embedded links in title or snippet text
                        text_to_scan = f"{rec.get('title', '')} {rec.get('snippet', '')}"
                        for emb_url in scraper.extract_links_from_text(text_to_scan):
                            seed_links.add(emb_url)

                    # Also include Level 1 reference links from NIST (excluding known advisories & product releases)
                    cursor.execute('SELECT url FROM cve_sources WHERE cve_id = ? AND url != ""', (cve_id,))
                    for s_row in cursor.fetchall():
                        u = s_row['url']
                        if u and not scraper.is_known_advisory_url(u) and not scraper.is_product_release_url(u):
                            seed_links.add(u)

                    # Execute high-speed Level-2 parallel crawl with early PoC exit & AI link selection
                    if seed_links:
                        print(f"   [*] Rapid Crawling OSINT links for {cve_id} (Level 2 Fast Engine with PoC Early-Exit)...")
                        chain_results = scraper.execute_chain_link_crawl(
                            cve_id, list(seed_links), max_depth=2, max_workers=6, stop_on_poc=True, max_total_urls=15
                        )
                        for cr in chain_results:
                            c_url = cr["url"]
                            c_poc = cr["is_poc"]
                            c_stat = cr["exploit_status"]
                            c_text = cr.get("text", "")[:300]
                            if c_stat == "blog_poc":
                                s_name = "OSINT Research Blog (PoC)"
                            elif c_stat == "poc":
                                s_name = "OSINT Discovered PoC"
                            elif c_stat == "blog":
                                s_name = "OSINT Research Blog"
                            elif c_stat == "vuln_version":
                                s_name = "Vulnerable/Fixed Product Version"
                            elif c_stat == "vendor_fix":
                                s_name = "Vendor Advisory"
                            else:
                                s_name = f"OSINT Reference (L{cr['depth_level']})"

                            cursor.execute('''
                                INSERT INTO cve_sources (cve_id, source_name, url, is_poc_link, details, exploit_status)
                                SELECT ?, ?, ?, ?, ?, ?
                                WHERE NOT EXISTS (
                                    SELECT 1 FROM cve_sources WHERE cve_id = ? AND (url = ? OR rtrim(url, '/') = ?)
                                )
                            ''', (cve_id, s_name, c_url, c_poc, c_text, c_stat, cve_id, c_url, c_url.rstrip('/')))

                            if c_poc == 1:
                                cursor.execute('UPDATE cve_main SET has_public_poc = 1 WHERE cve_id = ?', (cve_id,))

                    # Save immediate OSINT intelligence record so mentions are instantly accessible
                    cursor.execute('''
                        INSERT OR IGNORE INTO cve_analysis (cve_id, ai_summary, recommended_action, poc_recreation_steps, keywords, is_analyzed)
                        VALUES (?, ?, ?, ?, ?, 0)
                    ''', (
                        cve_id,
                        f"Active OSINT chatter detected across {platforms_str} ({count} mention(s)). Verified proof links and PoC candidates indexed. Full AI deep-dive available on-demand.",
                        "Review extracted source links and verify edge exposure. Apply vendor patches if PoC is confirmed.",
                        "Proof of concept and reproduction links logged in Sources drawer.",
                        "OSINT, In-The-Wild, Social Chatter"
                    ))

                    conn.commit()
                    target_cves.append(cve_id)
            else:
                print("[-] Social chatter below viral threshold. Correlating with CISA KEV & active wild threats...")
                now = datetime.now()
                thirty_days_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d")
                month_prefix = now.strftime("%Y-%m")
                print(f"[*] Fallback Scope: Strictly filtering CISA KEV from the last 1 month (since {thirty_days_ago})...")

                limit = effective_count
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

            total_targets = len(target_cves)
            if req.exploit_find and total_targets > 0:
                print(f"\n[*] Pre-hunting exploit modules in parallel for {total_targets} CVEs...")
                exploit_finder.batch_exploit_hunt(target_cves, max_workers=12)

            # Deep AI analysis on top viral/PoC threats via fast 3-CVE batching
            priority_targets = []
            for cid in target_cves:
                cursor.execute('SELECT has_public_poc FROM cve_main WHERE cve_id = ?', (cid,))
                p_row = cursor.fetchone()
                if p_row and p_row['has_public_poc']:
                    priority_targets.append(cid)

            if not priority_targets and target_cves:
                priority_targets = target_cves[:3] # Top 3 viral mentions
            elif len(priority_targets) > 6:
                # Prioritize top 6 verified PoC threats for immediate AI synthesis;
                # all remaining threats are fully indexed and can be deep-analyzed on demand
                priority_targets = priority_targets[:6]

            if priority_targets:
                print(f"\n[*] Concurrently AI-analyzing {len(priority_targets)} top priority viral/PoC threats (via Multi-CVE Batch)...")
                batch_items = []
                for cid in priority_targets:
                    cursor.execute('SELECT source_name, details FROM cve_sources WHERE cve_id = ? AND details IS NOT NULL', (cid,))
                    c_txt = f"CVE ID: {cid}\n\n"
                    for src in cursor.fetchall():
                        c_txt += f"--- Source: {src['source_name']} ---\n{src['details']}\n\n"
                    batch_items.append((cid, c_txt))

                batch_results = llm.analyze_cve_batch(batch_items)
                for cid in priority_targets:
                    res = batch_results.get(cid.strip().upper())
                    if res and not res[6].startswith("Failed") and res[0] != "API Offline or Rate Limited.":
                        s, a, p, v, pr, kw, m = res
                        cursor.execute('''
                            INSERT OR REPLACE INTO cve_analysis (cve_id, ai_summary, recommended_action, poc_recreation_steps, keywords, is_analyzed)
                            VALUES (?, ?, ?, ?, ?, 1)
                        ''', (cid, s, a, p, kw))
                        conn.commit()
                        print(f" [+] Deep AI analysis saved for priority threat: {cid}")

            conn.close()
            print(f"\n[+] OSINT Threat Hunt Complete! Indexed {len(target_cves)} in-the-wild threats.")
                
        elif req.mode == "weekly" or (req.mode == "custom" and req.active_week_exploits):
            end_dt = datetime.now()
            start_dt = end_dt - timedelta(days=7)
            main.run_pipeline(start_dt, end_dt, count_limit=effective_count, fetch_cisa=True, is_iot_ot=req.iotot, all_severity=req.all_severity, run_exploit_hunt=True, is_trending=True)
            
        elif req.mode == "iotot":
            end_dt = datetime.strptime(req.end_date, "%Y-%m-%d") if req.end_date else datetime.now()
            start_dt = datetime.strptime(req.start_date, "%Y-%m-%d") if req.start_date else end_dt - timedelta(days=3)
            main.run_pipeline(start_dt, end_dt, count_limit=effective_count, fetch_cisa=req.cisa, is_iot_ot=True, all_severity=True, run_exploit_hunt=req.exploit_find)
            
        elif req.mode == "date_audit":
            end_dt = datetime.strptime(req.end_date, "%Y-%m-%d") if req.end_date else datetime.now()
            start_dt = datetime.strptime(req.start_date, "%Y-%m-%d") if req.start_date else end_dt - timedelta(days=2)
            main.run_pipeline(start_dt, end_dt, count_limit=effective_count, fetch_cisa=True, is_iot_ot=False, all_severity=req.all_severity, run_exploit_hunt=req.exploit_find)
            
        else: # custom
            if req.cve_id and req.cve_id.strip():
                main.run_single_cve(req.cve_id.strip().upper(), run_exploit_hunt=req.exploit_find, force_nist_refetch=True)
            else:
                end_dt = datetime.strptime(req.end_date, "%Y-%m-%d") if req.end_date else datetime.now()
                start_dt = datetime.strptime(req.start_date, "%Y-%m-%d") if req.start_date else end_dt - timedelta(days=2)
                main.run_pipeline(start_dt, end_dt, count_limit=effective_count, fetch_cisa=req.cisa, is_iot_ot=req.iotot, all_severity=req.all_severity, run_exploit_hunt=req.exploit_find)

        print("\n✅ Threat Hunt pipeline completed successfully!")

    except Exception as e:
        print(f"\n❌ Error during scan execution: {e}")
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        with scan_lock:
            scan_state["is_running"] = False
            scan_state["current_task"] = "Completed"


def execute_cisa_enrichment_task(req: CisaEnrichRequest):
    global scan_state
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    capture = StreamCapture(old_stdout)
    sys.stdout = capture
    sys.stderr = capture

    try:
        with scan_lock:
            scan_state["is_running"] = True
            scan_state["current_task"] = "CISA_ENRICH"
            scan_state["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            scan_state["log_history"].clear()

        print("=" * 60)
        print("⚡ CISA DATABASE TECHNICAL ENRICHMENT PIPELINE")
        print(f" Target Scope: {req.severity_scope.upper()} | Timeframe: {req.time_scope.upper()}")
        print(" Policy: NIST NVD 2.0 & EPSS Ingestion ONLY - ZERO AI TOKENS")
        print("=" * 60)

        # 1. Sync latest CISA catalog into local DB
        print("\n[*] Phase 1: Ingesting latest CISA KEV catalog feed into database...")
        collect.fetch_cisa_kev()

        # 2. Select CISA records based on user scope
        conn = db_manager.get_db_connection()
        cursor = conn.cursor()

        now = datetime.now()
        month_prefix = now.strftime("%Y-%m")
        thirty_days_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d")

        conditions = ["m.is_cisa_kev = 1"]
        params = []

        if req.time_scope == "this_month":
            conditions.append("(m.cisa_date_added >= ? OR m.cisa_date_added LIKE ?)")
            params.extend([thirty_days_ago, f"{month_prefix}%"])

        if req.severity_scope == "medium_plus":
            conditions.append("(m.severity IN ('Critical', 'High', 'Medium') OR m.cvss_v3_score >= 4.0 OR m.cvss_v3_score IS NULL OR m.severity IS NULL OR m.severity = 'Unknown')")

        where_sql = " WHERE " + " AND ".join(conditions)
        query = f'''
            SELECT m.cve_id, m.cisa_date_added, m.cvss_v3_score, m.affected_vendor, m.affected_product
            FROM cve_main m
            {where_sql}
            ORDER BY 
                CASE WHEN m.cisa_date_added IS NOT NULL AND m.cisa_date_added != '' THEN m.cisa_date_added ELSE '1970-01-01' END DESC,
                m.cve_id DESC
        '''
        if req.limit:
            query += " LIMIT ?"
            params.append(req.limit)

        cursor.execute(query, tuple(params))
        target_rows = cursor.fetchall()
        conn.close()

        total_targets = len(target_rows)
        print(f"\n[*] Identified {total_targets} CISA KEV vulnerabilities for technical enrichment.")

        if total_targets > 0:
            target_cve_ids = [r["cve_id"] for r in target_rows]

            # Ingest NIST details for each CVE (fetch_single_cve skips if already complete)
            print("\n[*] Phase 2: Ingesting NIST NVD 2.0 technical metrics (CVSS, vector, CWE, vendor/product, references)...")
            for idx, cve_id in enumerate(target_cve_ids, 1):
                print(f"[{idx}/{total_targets}] Fetching technical telemetry for {cve_id}...")
                collect.fetch_single_cve(cve_id, force_refetch=False)

            # Parallel EPSS score enrichment
            print(f"\n[*] Phase 3: Enriching EPSS probabilities in parallel for {len(target_cve_ids)} CVEs...")
            collect.enrich_epss_parallel(target_cve_ids, run_in_background=False)

            print(f"\n✅ CISA Database Technical Enrichment completed successfully for {total_targets} CVEs!")
            print("[*] All technical metrics (CVSS, vector, CWE, vendor/product, references, EPSS) updated.")
        else:
            print("\n[-] No CISA KEV vulnerabilities matched the selected filter criteria.")

    except Exception as e:
        print(f"\n❌ Error during CISA enrichment execution: {e}")
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        with scan_lock:
            scan_state["is_running"] = False
            scan_state["current_task"] = "Completed"


def execute_enrich_task(req: EnrichDbRequest):
    global scan_state
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    capture = StreamCapture(old_stdout)
    sys.stdout = capture
    sys.stderr = capture

    try:
        with scan_lock:
            scan_state["is_running"] = True
            scan_state["current_task"] = "ENRICH_DB"
            scan_state["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            scan_state["log_history"].clear()

        enrich_engine.enrich_database(
            enrich_technical=req.enrich_technical,
            enrich_epss=req.enrich_epss,
            enrich_ai=req.enrich_ai,
            enrich_exploits=req.enrich_exploits,
            max_items=req.max_items
        )
    except Exception as e:
        print(f"\n❌ Error during database enrichment execution: {e}")
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        with scan_lock:
            scan_state["is_running"] = False
            scan_state["current_task"] = "Completed"


# ==============================================================================
# REST API Endpoints
# ==============================================================================

@app.get("/api/stats")
def get_dashboard_stats():
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()

    stats = {}
    cursor.execute("SELECT COUNT(*) as count FROM cve_main")
    stats["total_cves"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_main WHERE severity = 'Critical'")
    stats["critical_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_main WHERE severity = 'High'")
    stats["high_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_main WHERE severity = 'Medium'")
    stats["medium_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_main WHERE severity = 'Low'")
    stats["low_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_main WHERE is_cisa_kev = 1")
    stats["cisa_kev_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_main WHERE has_public_poc = 1")
    stats["public_poc_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_main WHERE has_nuclei = 1")
    stats["nuclei_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_main WHERE has_metasploit = 1")
    stats["metasploit_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_main WHERE is_iot_ot = 1")
    stats["iot_ot_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_main WHERE osint_mention_count > 0 OR is_exploited_in_wild = 1")
    stats["osint_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_analysis WHERE is_analyzed = 1")
    stats["analyzed_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM cve_iocs")
    stats["total_iocs_count"] = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(DISTINCT cve_id) as count FROM cve_main WHERE ransomware_campaign IS NOT NULL AND ransomware_campaign != ''")
    stats["ransomware_count"] = cursor.fetchone()["count"]

    cursor.execute("""
        SELECT m.cve_id, m.severity, m.cvss_v3_score, m.epss_score, m.affected_vendor, m.affected_product,
               m.is_cisa_kev, m.has_public_poc, m.has_nuclei, m.has_metasploit, m.is_iot_ot,
               a.ai_summary, a.recommended_action, a.keywords
        FROM cve_main m
        LEFT JOIN cve_analysis a ON m.cve_id = a.cve_id
        ORDER BY m.cvss_v3_score DESC, m.epss_score DESC
        LIMIT 5
    """)
    stats["top_threats"] = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT keywords FROM cve_analysis WHERE keywords IS NOT NULL AND keywords != 'None'")
    all_keywords = []
    for row in cursor.fetchall():
        for kw in str(row["keywords"]).split(","):
            kw_clean = kw.strip()
            if kw_clean and kw_clean != "None":
                all_keywords.append(kw_clean)
    
    from collections import Counter
    stats["keyword_distribution"] = dict(Counter(all_keywords).most_common(8))

    conn.close()
    return stats


@app.get("/api/cves")
def list_cves(
    search: Optional[str] = None,
    severity: Optional[str] = None,
    is_cisa_kev: Optional[bool] = None,
    has_public_poc: Optional[bool] = None,
    has_nuclei: Optional[bool] = None,
    has_metasploit: Optional[bool] = None,
    is_iot_ot: Optional[bool] = None,
    is_osint: Optional[bool] = None,
    is_analyzed: Optional[bool] = None,
    has_iocs: Optional[bool] = None,
    keyword: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    sort_by: str = "cvss_v3_score",
    sort_order: str = "desc"
):
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()

    conditions = []
    params = []

    if search:
        s = f"%{search}%"
        conditions.append("(m.cve_id LIKE ? OR m.affected_vendor LIKE ? OR m.affected_product LIKE ? OR a.ai_summary LIKE ?)")
        params.extend([s, s, s, s])

    if severity and severity.lower() != "all":
        conditions.append("m.severity = ?")
        params.append(severity.capitalize())

    if is_cisa_kev is not None:
        conditions.append("m.is_cisa_kev = ?")
        params.append(1 if is_cisa_kev else 0)

    if has_public_poc is not None:
        conditions.append("m.has_public_poc = ?")
        params.append(1 if has_public_poc else 0)

    if has_nuclei is not None:
        conditions.append("m.has_nuclei = ?")
        params.append(1 if has_nuclei else 0)

    if has_metasploit is not None:
        conditions.append("m.has_metasploit = ?")
        params.append(1 if has_metasploit else 0)

    if is_iot_ot is not None:
        conditions.append("m.is_iot_ot = ?")
        params.append(1 if is_iot_ot else 0)

    if is_osint is not None:
        conditions.append("(m.osint_mention_count > 0 OR m.is_exploited_in_wild = 1)")

    if is_analyzed is not None:
        if is_analyzed:
            conditions.append("a.is_analyzed = 1")
        else:
            conditions.append("(a.is_analyzed IS NULL OR a.is_analyzed = 0)")

    if has_iocs is not None:
        if has_iocs:
            conditions.append("m.cve_id IN (SELECT DISTINCT cve_id FROM cve_iocs)")
        else:
            conditions.append("m.cve_id NOT IN (SELECT DISTINCT cve_id FROM cve_iocs)")

    if keyword:
        conditions.append("a.keywords LIKE ?")
        params.append(f"%{keyword}%")

    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

    allowed_sort_fields = {
        "cvss_v3_score": "m.cvss_v3_score",
        "epss_score": "m.epss_score",
        "published_date": "m.published_date",
        "cve_id": "m.cve_id",
        "osint_mention_count": "m.osint_mention_count"
    }
    sort_field = allowed_sort_fields.get(sort_by, "m.cvss_v3_score")
    order = "ASC" if sort_order.lower() == "asc" else "DESC"

    count_query = f"SELECT COUNT(*) as total FROM cve_main m LEFT JOIN cve_analysis a ON m.cve_id = a.cve_id {where_clause}"
    cursor.execute(count_query, tuple(params))
    total = cursor.fetchone()["total"]

    offset = (page - 1) * limit
    data_query = f"""
        SELECT m.cve_id, m.published_date, m.updated_date, m.cvss_v3_score, m.cvss_vector, m.epss_score,
               m.severity, m.affected_vendor, m.affected_product, m.is_cisa_kev, m.cisa_date_added, m.cisa_due_date,
               m.cisa_required_action, m.ransomware_campaign, m.has_public_poc,
               m.has_nuclei, m.has_metasploit, m.is_iot_ot, m.osint_mention_count, m.is_exploited_in_wild,
               (SELECT COUNT(*) FROM cve_iocs i WHERE i.cve_id = m.cve_id) as ioc_count,
               a.ai_summary, a.recommended_action, a.keywords, a.is_analyzed
        FROM cve_main m
        LEFT JOIN cve_analysis a ON m.cve_id = a.cve_id
        {where_clause}
        ORDER BY {sort_field} {order}
        LIMIT ? OFFSET ?
    """
    cursor.execute(data_query, tuple(params + [limit, offset]))
    items = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": (total + limit - 1) // limit if limit else 1,
        "items": items
    }


@app.get("/api/cves/{cve_id}")
def get_cve_detail(cve_id: str):
    cve_id = cve_id.strip().upper()
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM cve_main WHERE cve_id = ?", (cve_id,))
    main_row = cursor.fetchone()
    if not main_row:
        conn.close()
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in local database.")

    main_data = dict(main_row)

    cursor.execute("SELECT * FROM cve_analysis WHERE cve_id = ?", (cve_id,))
    analysis_row = cursor.fetchone()
    main_data["analysis"] = dict(analysis_row) if analysis_row else None

    cursor.execute("SELECT id, source_name, url, is_poc_link, exploit_status, details FROM cve_sources WHERE cve_id = ?", (cve_id,))
    main_data["sources"] = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT id, ioc_type, ioc_value, threat_actor, malware_family, source_feed, confidence, first_seen, details FROM cve_iocs WHERE cve_id = ? ORDER BY confidence DESC, id DESC", (cve_id,))
    main_data["iocs"] = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return main_data


@app.get("/api/cves/{cve_id}/iocs")
def get_cve_iocs_endpoint(cve_id: str):
    return {"cve_id": cve_id.strip().upper(), "iocs": ioc_engine.get_cve_iocs(cve_id)}


@app.get("/api/iocs/export")
def export_iocs(format: str = "csv", cve_id: Optional[str] = None):
    if format.lower() == "stix":
        return ioc_engine.export_iocs_stix(cve_id)
    csv_content = ioc_engine.export_iocs_csv(cve_id)
    from fastapi.responses import Response
    filename = f"iocs_{cve_id.lower()}.csv" if cve_id else "all_threat_iocs.csv"
    return Response(content=csv_content, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.post("/api/cves/{cve_id}/analyze")
def trigger_cve_analysis(cve_id: str, background_tasks: BackgroundTasks):
    cve_id = cve_id.strip().upper()
    if scan_state["is_running"]:
        raise HTTPException(status_code=409, detail="Another scan or analysis pipeline is already running.")

    req = ScanRequest(mode="single", cve_id=cve_id, exploit_find=True)
    background_tasks.add_task(execute_pipeline_task, req)
    return {"status": "started", "message": f"Targeted analysis started for {cve_id}"}


@app.get("/api/cves/{cve_id}/vuln-version")
@app.post("/api/cves/{cve_id}/vuln-version")
def get_or_find_vulnerable_versions(cve_id: str):
    cve_id = cve_id.strip().upper()
    try:
        data = vuln_version_finder.find_vulnerable_versions(cve_id)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed finding vulnerable versions for {cve_id}: {e}")


@app.post("/api/scan")
def launch_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if scan_state["is_running"]:
        raise HTTPException(status_code=409, detail="A scan is already active. Please wait or monitor logs.")

    background_tasks.add_task(execute_pipeline_task, req)
    return {"status": "started", "mode": req.mode, "message": f"Scan pipeline '{req.mode}' initiated."}


@app.post("/api/scan/stop")
def stop_scan_endpoint():
    try:
        import main
        main.scan_stop_event.set()
    except Exception:
        pass
    return {
        "status": "stopping",
        "message": "Graceful pause/stop signal dispatched to Threat Hunt Pipeline. Current batch will complete and progress is safely saved in database."
    }


@app.post("/api/cisa/enrich")
def launch_cisa_enrich(req: CisaEnrichRequest, background_tasks: BackgroundTasks):
    if scan_state["is_running"]:
        raise HTTPException(status_code=409, detail="Another scan or enrichment pipeline is already running. Please wait.")

    background_tasks.add_task(execute_cisa_enrichment_task, req)
    return {
        "status": "started",
        "severity_scope": req.severity_scope,
        "time_scope": req.time_scope,
        "message": f"CISA technical database enrichment ({req.severity_scope}, {req.time_scope}) initiated without AI."
    }


@app.post("/api/enrich-db")
def launch_enrich_db(background_tasks: BackgroundTasks, req: Optional[EnrichDbRequest] = None):
    if scan_state["is_running"] or enrich_engine.enrichment_state["is_running"]:
        raise HTTPException(status_code=409, detail="A scan or enrichment pipeline is already active. Please wait or stop the running task.")

    effective_req = req or EnrichDbRequest()
    background_tasks.add_task(execute_enrich_task, effective_req)
    return {
        "status": "started",
        "message": "On-demand Database & Threat Enrichment initiated. Stream live logs via /api/scan/stream."
    }


@app.post("/api/enrich-db/stop")
def stop_enrich_db():
    enrich_engine.request_stop()
    return {
        "status": "stopping",
        "message": "Graceful stop signal dispatched to Enrichment Engine. Completing current item and terminating..."
    }


@app.get("/api/enrich-db/status")
def get_enrich_db_status():
    return enrich_engine.get_enrichment_status()


# ==============================================================================
# Owned Assets Management & Inventory Endpoints (Future Correlation Ready)
# ==============================================================================

@app.get("/api/assets")
def list_assets(search: Optional[str] = None):
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    query = """
        SELECT a.*, 
               (SELECT COUNT(*) FROM asset_cve_matches m WHERE m.asset_id = a.asset_id) as match_count,
               (SELECT COUNT(*) FROM asset_cve_matches m JOIN cve_main c ON m.cve_id = c.cve_id WHERE m.asset_id = a.asset_id AND (c.has_public_poc = 1 OR c.is_cisa_kev = 1)) as high_risk_match_count
        FROM owned_assets a
    """
    params = []
    if search:
        s = f"%{search}%"
        query += " WHERE a.asset_name LIKE ? OR a.vendor LIKE ? OR a.product LIKE ? OR a.ip_address LIKE ?"
        params.extend([s, s, s, s])
    query += " ORDER BY a.asset_id DESC"
    cursor.execute(query, tuple(params))
    assets = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"total": len(assets), "assets": assets}


@app.post("/api/assets")
def create_asset(req: AssetCreateRequest):
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO owned_assets (asset_name, asset_type, vendor, product, version, cpe, ip_address, domain_name, criticality, owner_department, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (req.asset_name, req.asset_type, req.vendor, req.product, req.version, req.cpe, req.ip_address, req.domain_name, req.criticality, req.owner_department, req.notes))
    asset_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"status": "created", "asset_id": asset_id, "message": f"Asset '{req.asset_name}' registered successfully."}


@app.delete("/api/assets/{asset_id}")
def delete_asset(asset_id: int):
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM asset_cve_matches WHERE asset_id = ?", (asset_id,))
    cursor.execute("DELETE FROM owned_assets WHERE asset_id = ?", (asset_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return {"status": "deleted", "asset_id": asset_id}


@app.get("/api/assets/{asset_id}/matches")
def get_asset_matches(asset_id: int):
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT m.match_id, m.match_type, m.is_mitigated, m.mitigation_notes, m.matched_at,
               c.cve_id, c.severity, c.cvss_v3_score, c.epss_score, c.has_public_poc, c.is_cisa_kev,
               a.ai_summary
        FROM asset_cve_matches m
        JOIN cve_main c ON m.cve_id = c.cve_id
        LEFT JOIN cve_analysis a ON c.cve_id = a.cve_id
        WHERE m.asset_id = ?
        ORDER BY c.cvss_v3_score DESC
    """, (asset_id,))
    matches = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"asset_id": asset_id, "matches": matches, "total_matches": len(matches)}


@app.get("/api/scan/status")
def get_scan_status():
    with scan_lock:
        return {
            "is_running": scan_state["is_running"],
            "current_task": scan_state["current_task"],
            "started_at": scan_state["started_at"],
            "log_count": len(scan_state["log_history"])
        }


@app.get("/api/scan/stream")
def stream_scan_logs():
    def event_generator():
        client_queue = queue.Queue()
        with scan_lock:
            scan_subscribers.append(client_queue)
            for line in scan_state["log_history"][-40:]:
                client_queue.put_nowait(line)

        try:
            while True:
                try:
                    line = client_queue.get(timeout=1.0)
                    yield f"data: {line}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        except GeneratorExit:
            with scan_lock:
                if client_queue in scan_subscribers:
                    scan_subscribers.remove(client_queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/osint/trending")
def get_osint_trending():
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    cutoff_15d = (datetime.now() - timedelta(days=15)).strftime("%Y-%m-%d")

    cursor.execute("""
        SELECT m.cve_id, m.osint_mention_count, m.severity, m.cvss_v3_score, m.epss_score,
               m.affected_vendor, m.affected_product, m.has_public_poc, m.osint_sources,
               m.is_cisa_kev, m.cisa_date_added, a.ai_summary
        FROM cve_main m
        LEFT JOIN cve_analysis a ON m.cve_id = a.cve_id
        WHERE m.osint_mention_count > 0 OR m.is_exploited_in_wild = 1 OR (m.is_cisa_kev = 1 AND m.cisa_date_added >= ?)
        ORDER BY m.osint_mention_count DESC, m.cvss_v3_score DESC
        LIMIT 60
    """, (cutoff_15d,))
    rows = cursor.fetchall()

    items = []
    platform_breakdown = {
        "HackerNews": 0,
        "Reddit": 0,
        "X (Twitter)": 0,
        "CISA KEV": 0,
        "Security Media": 0,
        "Dark Web & Underground": 0,
        "Telegram Threat Radar": 0
    }
    cluster_points = []
    cisa_cves = set()
    osint_cves = set()

    for row in rows:
        d = dict(row)
        cve_id = d["cve_id"]

        cursor.execute("""
            SELECT source_name, url, is_poc_link, details, exploit_status
            FROM cve_sources
            WHERE cve_id = ? AND (source_name LIKE 'OSINT:%' OR source_name = 'CISA KEV')
        """, (cve_id,))
        source_links = [dict(r) for r in cursor.fetchall()]
        d["sources"] = source_links

        osint_src = (d.get("osint_sources") or "").lower()
        source_names_lower = " ".join([s.get("source_name", "").lower() for s in source_links])
        combined_src = f"{osint_src} {source_names_lower}"

        has_hn = "hackernews" in combined_src or "hn" in combined_src
        has_reddit = "reddit" in combined_src
        has_twitter = "x (twitter)" in combined_src or "twitter" in combined_src
        has_media = "security media" in combined_src or "media" in combined_src
        has_darkweb = "dark web" in combined_src or "leak" in combined_src or "underground" in combined_src
        has_telegram = "telegram" in combined_src
        is_cisa = bool(d.get("is_cisa_kev") == 1 or "cisa" in combined_src)

        d["platforms"] = []
        mentions = d.get("osint_mention_count") or 1

        if is_cisa:
            d["platforms"].append("CISA KEV")
            platform_breakdown["CISA KEV"] += 1
            cisa_cves.add(cve_id)

        if has_hn:
            d["platforms"].append("HackerNews")
            platform_breakdown["HackerNews"] += mentions
            osint_cves.add(cve_id)
        if has_reddit:
            d["platforms"].append("Reddit")
            platform_breakdown["Reddit"] += mentions
            osint_cves.add(cve_id)
        if has_twitter:
            d["platforms"].append("X (Twitter)")
            platform_breakdown["X (Twitter)"] += mentions
            osint_cves.add(cve_id)
        if has_media:
            d["platforms"].append("Security Media")
            platform_breakdown["Security Media"] += mentions
            osint_cves.add(cve_id)
        if has_darkweb:
            d["platforms"].append("Dark Web & Underground")
            platform_breakdown["Dark Web & Underground"] += mentions
            osint_cves.add(cve_id)
        if has_telegram:
            d["platforms"].append("Telegram Threat Radar")
            platform_breakdown["Telegram Threat Radar"] += mentions
            osint_cves.add(cve_id)

        if not d["platforms"]:
            d["platforms"] = ["HackerNews"]
            platform_breakdown["HackerNews"] += mentions
            osint_cves.add(cve_id)

        d["in_cisa"] = 1 if is_cisa else 0
        d["is_correlated"] = 1 if (is_cisa and len([p for p in d["platforms"] if p != "CISA KEV"]) > 0) else 0

        d["has_unverified_poc"] = any(s.get("exploit_status") == "unverified_osint_poc" or s.get("is_poc_link") == 1 for s in source_links) or d.get("has_public_poc") == 1

        cvss = d["cvss_v3_score"] if d["cvss_v3_score"] is not None else 6.5
        epss = d.get("epss_score") or 0.05

        cluster_points.append({
            "cve_id": cve_id,
            "x": round(float(cvss), 1),
            "y": int(mentions),
            "r": max(6, min(24, int(float(epss) * 35) + 6)),
            "severity": d["severity"] or "Medium",
            "vendor": d["affected_vendor"] or "Unknown",
            "epss": round(float(epss) * 100, 2),
            "platforms": d["platforms"],
            "has_poc": d["has_unverified_poc"],
            "in_cisa": d["in_cisa"],
            "is_correlated": d["is_correlated"]
        })

        items.append(d)

    conn.close()

    correlated_both = cisa_cves.intersection(osint_cves)
    cisa_only = cisa_cves - osint_cves
    osint_only = osint_cves - cisa_cves

    cisa_vs_osint_series = []
    for it in items[:30]:
        cisa_vs_osint_series.append({
            "cve_id": it["cve_id"],
            "in_cisa": it["in_cisa"],
            "osint_mentions": max(1, sum(1 for p in it["platforms"] if p != "CISA KEV") * (it.get("osint_mention_count") or 1)),
            "severity": it.get("severity") or "Medium",
            "vendor": it.get("affected_vendor") or "Unknown",
            "is_correlated": it["is_correlated"]
        })

    return {
        "items": items,
        "platform_breakdown": platform_breakdown,
        "comparative_metrics": {
            "cisa_only_count": len(cisa_only),
            "osint_only_count": len(osint_only),
            "correlated_both_count": len(correlated_both),
            "cisa_vs_osint_series": cisa_vs_osint_series
        },
        "cluster_points": cluster_points,
        "kpis": {
            "total_threats": len(items),
            "cisa_count": len(cisa_cves),
            "hackernews_count": platform_breakdown["HackerNews"],
            "reddit_count": platform_breakdown["Reddit"],
            "twitter_count": platform_breakdown["X (Twitter)"],
            "media_count": platform_breakdown["Security Media"],
            "darkweb_count": platform_breakdown["Dark Web & Underground"],
            "telegram_count": platform_breakdown.get("Telegram Threat Radar", 0),
            "correlated_count": len(correlated_both)
        }
    }


@app.get("/api/reports/html", response_class=HTMLResponse)
def get_html_report(refresh: Optional[bool] = False, scope: Optional[str] = "analyzed"):
    report_file = os.path.join(ROOT_DIR, "report_output.html")
    if refresh or not os.path.exists(report_file):
        from backend import report as report_gen
        subj, html_content = report_gen.generate_report(scope=scope or "analyzed")
        return html_content

    with open(report_file, "r", encoding="utf-8") as f:
        return f.read()


@app.post("/api/reports/regenerate")
def regenerate_html_report(scope: Optional[str] = "analyzed"):
    from backend import report as report_gen
    subj, html_content = report_gen.generate_report(scope=scope or "analyzed")
    conn = db_manager.get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM cve_analysis WHERE is_analyzed = 1")
    total_analyzed = c.fetchone()[0]
    conn.close()
    return {
        "status": "success",
        "message": f"Executive threat report regenerated successfully.",
        "total_analyzed": total_analyzed,
        "subject": subj
    }


@app.get("/api/reports/stats")
def get_reports_stats():
    conn = db_manager.get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT COUNT(a.cve_id) as total_analyzed,
               SUM(CASE WHEN m.severity = 'Critical' THEN 1 ELSE 0 END) as critical_count,
               SUM(CASE WHEN m.severity = 'High' THEN 1 ELSE 0 END) as high_count,
               SUM(CASE WHEN m.has_public_poc = 1 THEN 1 ELSE 0 END) as poc_count,
               SUM(CASE WHEN m.is_cisa_kev = 1 THEN 1 ELSE 0 END) as cisa_count,
               SUM(CASE WHEN m.is_iot_ot = 1 THEN 1 ELSE 0 END) as iot_count
        FROM cve_analysis a
        JOIN cve_main m ON a.cve_id = m.cve_id
        WHERE a.is_analyzed = 1
    """)
    row = dict(c.fetchone())
    conn.close()

    report_file = os.path.join(ROOT_DIR, "report_output.html")
    mtime = os.path.getmtime(report_file) if os.path.exists(report_file) else None
    last_mod = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S UTC") if mtime else "Not yet generated"
    row["last_generated"] = last_mod
    return row


class ExportPDFRequest(BaseModel):
    export_type: Optional[str] = "full"


@app.post("/api/export-pdf")
async def trigger_pdf_export(req: Optional[ExportPDFRequest] = None):
    exp_type = req.export_type if req and req.export_type else "full"
    try:
        import subprocess
        x_script = os.path.join(ROOT_DIR, "x.py")
        if not os.path.exists(x_script):
            raise HTTPException(status_code=404, detail="Standalone documentation script x.py not found in root.")
        
        await asyncio.to_thread(subprocess.run, [sys.executable, x_script, "--type", exp_type], check=True, cwd=ROOT_DIR)
        
        now = datetime.now()
        date_stamp = now.strftime("%d-%b-%Y").upper()
        if exp_type == "report":
            filename = f"ATI_Threat_Dossier_v2_{date_stamp}.pdf"
        else:
            suffix = f"_{exp_type.upper()}" if exp_type != "full" else ""
            filename = f"AutomatedATI_v2{suffix}_{date_stamp}.pdf"

        return {
            "status": "success",
            "filename": filename,
            "export_type": exp_type,
            "download_url": f"/api/download/{filename}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed generating PDF: {e}")


@app.get("/api/download/{filename}")
def download_file(filename: str):
    safe_filename = os.path.basename(filename)
    full_path = os.path.join(ROOT_DIR, safe_filename)
    if os.path.exists(full_path) and safe_filename.endswith(".pdf"):
        return FileResponse(full_path, media_type="application/pdf", filename=safe_filename)
    raise HTTPException(status_code=404, detail="Requested file does not exist.")


@app.get("/api/system")
def get_system_info():
    llm_telemetry = llm.get_llm_status()
    has_webhook = bool(os.getenv("WEBHOOK_URL"))
    has_nist_key = bool(os.getenv("NIST_API_KEY"))
    has_github_token = bool(os.getenv("GITHUB_TOKEN"))

    providers = llm_telemetry.get("providers", {})
    groq_keys = providers.get("groq", {}).get("keys_count", 0)
    cerebras_keys = providers.get("cerebras", {}).get("keys_count", 0)
    openrouter_keys = providers.get("openrouter", {}).get("keys_count", 0)
    gemini_keys = providers.get("gemini", {}).get("keys_count", 0)
    mistral_keys = providers.get("mistral", {}).get("keys_count", 0)

    fallback_models = []
    for p_data in providers.values():
        fallback_models.extend(p_data.get("models", []))

    return {
        "platform": "ATI V2 Threat Intel Command Center",
        "version": "2.0.0",
        "status": "Online",
        "llm_providers": {
            "gemini_keys": gemini_keys,
            "openrouter_keys": openrouter_keys,
            "groq_keys": groq_keys,
            "cerebras_keys": cerebras_keys,
            "mistral_keys": mistral_keys
        },
        "llm_telemetry": providers,
        "total_active_keys": llm_telemetry.get("total_active_keys", 0),
        "openrouter_keys_count": openrouter_keys + gemini_keys,
        "has_webhook": has_webhook,
        "has_nist_key": has_nist_key,
        "has_github_token": has_github_token,
        "fallback_models": fallback_models,
        "database_path": db_manager.DB_PATH,
        "database_size_kb": round(os.path.getsize(db_manager.DB_PATH) / 1024, 2) if os.path.exists(db_manager.DB_PATH) else 0
    }


@app.get("/api/logs/{log_name}")
def get_log_tail(log_name: str, lines: int = Query(60, ge=1, le=500)):
    allowed_logs = {
        "analyzer": "cve_analyzer.log",
        "apicall": "apicall.log",
        "exploit": "exploitfinder.log"
    }
    filename = allowed_logs.get(log_name)
    if not filename:
        return {"log": log_name, "content": "Log file not recognized."}

    target_file = os.path.join(LOGS_DIR, filename)
    if not os.path.exists(target_file):
        return {"log": filename, "content": "Log file is currently empty."}

    try:
        with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
            all_lines = f.readlines()
            tail_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
            return {
                "log": filename,
                "total_lines": len(all_lines),
                "content": "".join(tail_lines)
            }
    except Exception as e:
        return {"log": filename, "content": f"Error reading log: {e}"}


# Mount Static Frontend
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
def root_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>ATI V2 Static UI loading...</h1>"


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    favicon_path = os.path.join(STATIC_DIR, "favicon.ico")
    if os.path.exists(favicon_path):
        return FileResponse(favicon_path, media_type="image/x-icon")
    return HTMLResponse(status_code=404)


if __name__ == "__main__":
    import uvicorn
    print("[*] Starting ATI V2 Web Server on http://127.0.0.1:8000...")
    uvicorn.run("backend.server:app", host="127.0.0.1", port=8000, reload=True)
