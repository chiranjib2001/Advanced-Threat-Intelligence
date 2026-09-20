# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Prioritized Interactive HTML Threat Report Generator & MS Teams Alerting
# ==============================================================================
import os
import sys
import re
import requests
import logging
import html
from datetime import datetime, timedelta
from dotenv import load_dotenv

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend import db_manager

load_dotenv()


def sanitize_text(val):
    if not val:
        return ""
    s = str(val)
    s = re.sub(r'</?[a-zA-Z0-9_\-]+[^>]*>', ' ', s)
    s = s.replace('&lt;', '<').replace('&gt;', '>')
    s = re.sub(r'<[^>]+>', ' ', s)
    return ' '.join(s.split()).strip()


def generate_report(start_date=None, end_date=None, executive_summary_text=None, all_severity=True, scope="analyzed"):
    logging.info(f"Generating Prioritized Interactive Report (scope={scope})...")
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    now = datetime.now()

    if start_date is None or end_date is None or scope == "analyzed":
        scope = "analyzed"
        start_str = (now - timedelta(days=30)).strftime('%Y-%m-%d')
        end_str = now.strftime('%Y-%m-%d')
        timeframe_label = "All System Analyzed Telemetry"

        query = '''
            SELECT m.cve_id, m.severity, m.cvss_v3_score, m.cvss_vector, m.epss_score,
                   m.affected_vendor, m.affected_product, m.is_cisa_kev, m.cisa_date_added, m.has_public_poc,
                   m.has_nuclei, m.has_metasploit, m.is_iot_ot, m.osint_mention_count,
                   a.ai_summary, a.recommended_action, a.poc_recreation_steps, a.keywords,
                   COALESCE(a.is_analyzed, 0) as is_analyzed
            FROM cve_main m 
            JOIN cve_analysis a ON m.cve_id = a.cve_id 
            WHERE a.is_analyzed = 1
        '''
        # In analyzed scope, include all analyzed threats across all severities so report matches database count

        query += '''
            ORDER BY 
                CASE 
                    WHEN a.is_analyzed = 1 AND m.has_public_poc = 1 THEN 1
                    WHEN a.is_analyzed = 1 THEN 2
                    ELSE 3 
                END ASC,
                CASE m.severity 
                    WHEN 'Critical' THEN 1 
                    WHEN 'High' THEN 2 
                    WHEN 'Medium' THEN 3 
                    WHEN 'Low' THEN 4 
                    ELSE 5 
                END ASC,
                m.cvss_v3_score DESC,
                m.epss_score DESC
        '''
        cursor.execute(query)
        tracked_cves = [dict(row) for row in cursor.fetchall()]

        # Fallback if no analyzed records exist yet
        if not tracked_cves:
            query = '''
                SELECT m.cve_id, m.severity, m.cvss_v3_score, m.cvss_vector, m.epss_score,
                       m.affected_vendor, m.affected_product, m.is_cisa_kev, m.cisa_date_added, m.has_public_poc,
                       m.has_nuclei, m.has_metasploit, m.is_iot_ot, m.osint_mention_count,
                       a.ai_summary, a.recommended_action, a.poc_recreation_steps, a.keywords,
                       COALESCE(a.is_analyzed, 0) as is_analyzed
                FROM cve_main m 
                LEFT JOIN cve_analysis a ON m.cve_id = a.cve_id 
                ORDER BY m.is_cisa_kev DESC, m.cvss_v3_score DESC 
                LIMIT 50
            '''
            cursor.execute(query)
            tracked_cves = [dict(row) for row in cursor.fetchall()]
    else:
        start_str = start_date.strftime('%Y-%m-%d')
        end_str = end_date.strftime('%Y-%m-%d')
        timeframe_label = f"{start_str} to {end_str}"

        query = '''
            SELECT m.cve_id, m.severity, m.cvss_v3_score, m.cvss_vector, m.epss_score,
                   m.affected_vendor, m.affected_product, m.is_cisa_kev, m.cisa_date_added, m.has_public_poc,
                   m.has_nuclei, m.has_metasploit, m.is_iot_ot, m.osint_mention_count,
                   a.ai_summary, a.recommended_action, a.poc_recreation_steps, a.keywords,
                   COALESCE(a.is_analyzed, 0) as is_analyzed
            FROM cve_main m 
            LEFT JOIN cve_analysis a ON m.cve_id = a.cve_id 
            WHERE m.published_date >= ? AND m.published_date <= ?
        '''
        if not all_severity:
            query += " AND (m.severity = 'Critical' OR m.severity = 'High')"

        query += '''
            ORDER BY 
                CASE 
                    WHEN a.is_analyzed = 1 AND m.has_public_poc = 1 THEN 1
                    WHEN a.is_analyzed = 1 THEN 2
                    ELSE 3 
                END ASC,
                CASE m.severity 
                    WHEN 'Critical' THEN 1 
                    WHEN 'High' THEN 2 
                    WHEN 'Medium' THEN 3 
                    WHEN 'Low' THEN 4 
                    ELSE 5 
                END ASC,
                m.cvss_v3_score DESC,
                m.epss_score DESC
        '''
        cursor.execute(query, (f"{start_str}T00:00:00.000Z", f"{end_str}T23:59:59.000Z"))
        tracked_cves = [dict(row) for row in cursor.fetchall()]

    # Fetch IoC mappings for tracked CVEs
    cursor.execute("SELECT cve_id, ioc_type, ioc_value, threat_actor, malware_family, source_feed, confidence FROM cve_iocs")
    ioc_map = {}
    for ir in cursor.fetchall():
        cid = ir["cve_id"]
        if cid not in ioc_map:
            ioc_map[cid] = []
        ioc_map[cid].append(dict(ir))

    conn.close()

    total_cves = len(tracked_cves)
    critical_count = sum(1 for r in tracked_cves if r['severity'] == 'Critical')
    high_count = sum(1 for r in tracked_cves if r['severity'] == 'High')
    poc_count = sum(1 for r in tracked_cves if r['has_public_poc'] == 1)
    iot_count = sum(1 for r in tracked_cves if r['is_iot_ot'] == 1)
    cisa_count = sum(1 for r in tracked_cves if r['is_cisa_kev'] == 1)
    analyzed_count = sum(1 for r in tracked_cves if r['is_analyzed'] == 1)

    generated_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    if not executive_summary_text:
        executive_summary_text = (
            f"This Executive Threat Intelligence Briefing synthesizes active technical telemetry for "
            f"<strong>{total_cves}</strong> prioritized vulnerabilities analyzed by the ATI V2 engine. "
            f"The analyzed threat posture identifies <strong>{critical_count}</strong> Critical and "
            f"<strong>{high_count}</strong> High severity vulnerabilities, with <strong>{cisa_count}</strong> "
            f"active in-the-wild exploitation mandates cataloged by CISA KEV and <strong>{poc_count}</strong> "
            f"weaponized proof-of-concept exploits. Priority remediation is recommended for remote code "
            f"execution (RCE), authentication bypass, and edge gateway vectors affecting enterprise infrastructure."
        )

    # Build rows HTML
    rows_html = ""
    for r in tracked_cves:
        cve_id = html.escape(str(r.get('cve_id') or ''))
        sev = html.escape(str(r.get('severity') or 'Unknown'))
        
        raw_v = r.get('affected_vendor') or 'Unknown'
        clean_v = raw_v.splitlines()[0].split('<')[0].strip() if raw_v else 'Unknown'
        vendor = html.escape(sanitize_text(clean_v) or 'Unknown')

        raw_p = r.get('affected_product') or 'Unknown'
        clean_p = raw_p.splitlines()[0].split('<')[0].strip() if raw_p else 'Unknown'
        prod = html.escape(sanitize_text(clean_p) or 'Unknown')

        cvss = r.get('cvss_v3_score') or 0.0
        if r.get('epss_score') is not None:
            epss_val = float(r['epss_score']) * 100
            epss_display = f"{epss_val:.1f}%"
            epss_width = min(100, epss_val * 2.5)
        else:
            epss_display = "NA"
            epss_width = 0
        
        is_analyzed = 1 if r.get('is_analyzed') else 0
        has_poc = 1 if r.get('has_public_poc') else 0
        is_iot = 1 if r.get('is_iot_ot') else 0
        is_cisa = 1 if r.get('is_cisa_kev') else 0
        
        raw_summary = r.get('ai_summary') or "Analysis pending in database..."
        summary = sanitize_text(raw_summary) or "Analysis pending in database..."

        raw_action = r.get('recommended_action') or "Review vulnerability details and apply vendor security updates."
        action = sanitize_text(raw_action) or "Review and apply vendor security updates."

        poc_steps = r.get('poc_recreation_steps') or ""
        keywords = sanitize_text(r.get('keywords') or "")

        # Badges HTML
        badges_html = ""
        if has_poc:
            badges_html += '<span class="badge badge-poc">🔥 PoC Available</span> '
        if is_cisa:
            cisa_dt = r['cisa_date_added'] if ('cisa_date_added' in r.keys() and r['cisa_date_added']) else ''
            cisa_tag = f" ({cisa_dt})" if cisa_dt else ""
            badges_html += f'<span class="badge badge-cisa" title="Active Exploitation Cataloged by CISA">🛡️ CISA KEV{cisa_tag}</span> '
        if is_iot:
            badges_html += '<span class="badge badge-iot">🏭 IoT/OT</span> '
        if is_analyzed:
            badges_html += '<span class="badge badge-ai">⚡ AI Analyzed</span> '

        # PoC Box HTML
        poc_box_html = ""
        if poc_steps and poc_steps != "None" and poc_steps != "None identified":
            poc_id = f"poc-{cve_id.replace('-', '_')}"
            safe_poc = html.escape(poc_steps)
            poc_box_html = f"""
            <div class="poc-toggle-wrapper">
                <button class="btn-toggle-poc" onclick="togglePoC('{poc_id}')">View PoC / Recreation Steps</button>
                <div id="{poc_id}" class="poc-drawer" style="display:none;">
                    <button class="btn-copy-poc" onclick="copyPoCText(this, '{poc_id}-code')">Copy Payload</button>
                    <pre id="{poc_id}-code" class="poc-code"><code>{safe_poc}</code></pre>
                </div>
            </div>
            """

        # Keyword tags
        keyword_tags_html = ""
        if keywords and keywords != "None":
            for kw in keywords.split(","):
                kw_clean = html.escape(kw.strip())
                if kw_clean and kw_clean != "None":
                    keyword_tags_html += f'<span class="tag-keyword">{kw_clean}</span> '

        # IoC Box HTML
        iocs_list = ioc_map.get(str(r['cve_id']), [])
        iocs_box_html = ""
        if iocs_list:
            ioc_pills = "".join([f'<span class="ioc-pill" title="{html.escape(i.get("source_feed","Feed"))} ({i.get("confidence",80)}% Conf)"><strong>{html.escape(i.get("ioc_type","").upper())}:</strong> <code>{html.escape(str(i.get("ioc_value","")))}</code></span> ' for i in iocs_list[:4]])
            iocs_box_html = f'<div class="ioc-row-box"><span class="ioc-row-title">🛡️ Verified IoCs ({len(iocs_list)}):</span> {ioc_pills}</div>'

        # Severity class
        sev_class = f"sev-{sev.lower()}"

        # Safe search string: lowercased, whitespace-collapsed, and HTML-attribute escaped
        search_terms = f"{cve_id} {vendor} {prod} {sev} {keywords} {summary} {action}".lower()
        clean_search = " ".join(search_terms.split())
        safe_data_search = html.escape(clean_search, quote=True)

        rows_html += f"""
        <tr class="cve-row" 
            data-severity="{sev.lower()}" 
            data-analyzed="{is_analyzed}" 
            data-poc="{has_poc}" 
            data-iotot="{is_iot}" 
            data-cisa="{is_cisa}"
            data-search="{safe_data_search}">
            <td>
                <div class="cve-header-cell">
                    <span class="cve-badge-id">{cve_id}</span>
                    <span class="sev-badge {sev_class}">{sev} {cvss}</span>
                </div>
                <div class="epss-bar-wrapper" title="EPSS Exploit Probability: {epss_display}">
                    <div class="epss-label">EPSS: <strong>{epss_display}</strong></div>
                    <div class="epss-track"><div class="epss-fill" style="width: {epss_width}%;"></div></div>
                </div>
                <div class="item-badges">{badges_html}</div>
            </td>
            <td>
                <div class="vendor-prod"><strong>{vendor}</strong> / {prod}</div>
                <div class="cve-summary">{html.escape(summary)}</div>
                {poc_box_html}
                {iocs_box_html}
            </td>
            <td>
                <div class="action-box">
                    <div class="action-title">Action Required:</div>
                    <div class="action-text">{html.escape(action)}</div>
                </div>
                <div class="keyword-container">{keyword_tags_html}</div>
            </td>
        </tr>
        """

    scope_title = "All Severities" if all_severity else "Critical & High Severity"

    # Full Standalone HTML with Embedded CSS & JavaScript
    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ATI V2 - Threat Intelligence Briefing ({start_str} to {end_str})</title>
<style>
:root {{
    --bg-main: #0B0F19;
    --bg-card: #111827;
    --bg-card-hover: #1A2234;
    --border-color: #1F293D;
    --text-primary: #F3F4F6;
    --text-muted: #9CA3AF;
    --accent-cyan: #06B6D4;
    --accent-blue: #3B82F6;
    --sev-crit: #EF4444;
    --sev-high: #F97316;
    --sev-med: #F59E0B;
    --sev-low: #10B981;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-primary);
    line-height: 1.5;
    padding: 24px;
}}
.report-container {{
    max-width: 1400px;
    margin: 0 auto;
}}
header.report-header {{
    background: linear-gradient(135deg, #111827 0%, #1E293B 100%);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 24px 32px;
    margin-bottom: 24px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
}}
.header-top {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
    margin-bottom: 16px;
}}
.header-title h1 {{
    font-size: 24px;
    font-weight: 800;
    letter-spacing: -0.5px;
    display: flex;
    align-items: center;
    gap: 10px;
}}
.header-title p {{
    color: var(--text-muted);
    font-size: 14px;
    margin-top: 4px;
}}
.header-actions {{
    display: flex;
    gap: 10px;
}}
.btn-action {{
    background-color: #1F293D;
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    padding: 8px 16px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
}}
.btn-action:hover {{
    background-color: var(--accent-blue);
    border-color: var(--accent-blue);
}}
/* Executive Summary Box */
.exec-summary-box {{
    background: rgba(6, 182, 212, 0.06);
    border-left: 4px solid var(--accent-cyan);
    border-radius: 0 8px 8px 0;
    padding: 16px 20px;
    margin-top: 16px;
}}
.exec-summary-box h3 {{
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--accent-cyan);
    margin-bottom: 6px;
}}
.exec-summary-box p {{
    font-size: 14px;
    color: #E2E8F0;
    line-height: 1.6;
}}
/* KPI Metrics Bar */
.kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}}
.kpi-card {{
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 16px 20px;
}}
.kpi-card .kpi-label {{
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    color: var(--text-muted);
}}
.kpi-card .kpi-val {{
    font-size: 26px;
    font-weight: 800;
    margin-top: 4px;
}}
.kpi-crit .kpi-val {{ color: var(--sev-crit); }}
.kpi-poc .kpi-val {{ color: #F59E0B; }}
.kpi-ai .kpi-val {{ color: var(--accent-cyan); }}
.kpi-iot .kpi-val {{ color: #A855F7; }}

/* Filter Control Bar */
.filter-bar {{
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 20px;
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    align-items: center;
    justify-content: space-between;
}}
.search-input-wrapper {{
    flex: 1;
    min-width: 260px;
}}
.search-input {{
    width: 100%;
    background: #0B0F19;
    border: 1px solid var(--border-color);
    padding: 10px 14px;
    border-radius: 6px;
    color: #fff;
    font-size: 14px;
}}
.search-input:focus {{
    outline: none;
    border-color: var(--accent-cyan);
}}
.filter-chips {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}}
.filter-chip {{
    background: #1F293D;
    color: var(--text-muted);
    border: 1px solid transparent;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
}}
.filter-chip:hover {{ color: #fff; }}
.filter-chip.active {{
    background: rgba(6, 182, 212, 0.15);
    color: var(--accent-cyan);
    border-color: var(--accent-cyan);
}}
.select-severity {{
    background: #0B0F19;
    color: #fff;
    border: 1px solid var(--border-color);
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 13px;
}}

/* Table Layout */
.table-container {{
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    overflow: hidden;
    box-shadow: 0 4px 16px rgba(0,0,0,0.3);
}}
table.threat-table {{
    width: 100%;
    border-collapse: collapse;
    text-align: left;
}}
table.threat-table th {{
    background-color: #161F30;
    padding: 14px 18px;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border-color);
}}
table.threat-table td {{
    padding: 18px;
    border-bottom: 1px solid var(--border-color);
    vertical-align: top;
    font-size: 14px;
}}
table.threat-table tr:hover {{
    background-color: var(--bg-card-hover);
}}
.cve-header-cell {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
}}
.cve-badge-id {{
    font-family: monospace;
    font-weight: 700;
    font-size: 14px;
    color: #fff;
}}
.sev-badge {{
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    padding: 2px 8px;
    border-radius: 4px;
}}
.sev-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--sev-crit); border: 1px solid rgba(239, 68, 68, 0.4); }}
.sev-high {{ background: rgba(249, 115, 22, 0.2); color: var(--sev-high); border: 1px solid rgba(249, 115, 22, 0.4); }}
.sev-medium {{ background: rgba(245, 158, 11, 0.2); color: var(--sev-med); border: 1px solid rgba(245, 158, 11, 0.4); }}
.sev-low {{ background: rgba(16, 185, 129, 0.2); color: var(--sev-low); border: 1px solid rgba(16, 185, 129, 0.4); }}
.sev-unknown {{ background: #374151; color: #9CA3AF; }}

.epss-bar-wrapper {{
    margin: 8px 0;
}}
.epss-label {{
    font-size: 11px;
    color: var(--text-muted);
    margin-bottom: 3px;
}}
.epss-track {{
    height: 5px;
    width: 120px;
    background: #1F293D;
    border-radius: 3px;
    overflow: hidden;
}}
.epss-fill {{
    height: 100%;
    background: linear-gradient(90deg, #3B82F6, #EF4444);
}}

.item-badges {{
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 6px;
}}
.badge {{
    font-size: 10px;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 4px;
}}
.badge-poc {{ background: rgba(245, 158, 11, 0.2); color: #F59E0B; border: 1px solid rgba(245, 158, 11, 0.3); }}
.badge-cisa {{ background: rgba(239, 68, 68, 0.2); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); }}
.badge-iot {{ background: rgba(168, 85, 247, 0.2); color: #C084FC; border: 1px solid rgba(168, 85, 247, 0.3); }}
.badge-ai {{ background: rgba(6, 182, 212, 0.2); color: #22D3EE; border: 1px solid rgba(6, 182, 212, 0.3); }}

.vendor-prod {{
    font-size: 13px;
    color: #94A3B8;
    margin-bottom: 6px;
}}
.cve-summary {{
    color: #E2E8F0;
    line-height: 1.5;
    margin-bottom: 8px;
}}

.action-box {{
    background: rgba(16, 185, 129, 0.08);
    border-left: 3px solid #10B981;
    padding: 10px 14px;
    border-radius: 0 6px 6px 0;
    margin-bottom: 8px;
}}
.action-title {{
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    color: #34D399;
    margin-bottom: 2px;
}}
.action-text {{
    font-size: 13px;
    color: #E2E8F0;
}}

.poc-toggle-wrapper {{ margin-top: 10px; }}
.btn-toggle-poc {{
    background: #1E293B;
    border: 1px solid #334155;
    color: #F59E0B;
    padding: 5px 10px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
}}
.poc-drawer {{
    position: relative;
    background: #080C14;
    border: 1px solid #1F293D;
    border-radius: 6px;
    padding: 12px;
    margin-top: 8px;
}}
.btn-copy-poc {{
    position: absolute;
    top: 8px;
    right: 8px;
    background: #1E293B;
    border: 1px solid #334155;
    color: #fff;
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 4px;
    cursor: pointer;
}}
.poc-code {{
    font-family: monospace;
    font-size: 12px;
    color: #A5F3FC;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
}}

.tag-keyword {{
    display: inline-block;
    background: #1E293B;
    color: #CBD5E1;
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 4px;
    margin-right: 4px;
    margin-top: 4px;
}}

/* IoC Row Box */
.ioc-row-box {{
    background: rgba(6, 182, 212, 0.05);
    border: 1px solid rgba(6, 182, 212, 0.2);
    border-radius: 6px;
    padding: 8px 10px;
    margin-top: 8px;
    font-size: 12px;
}}
.ioc-row-title {{
    font-size: 11px;
    font-weight: 700;
    color: var(--accent-cyan);
    margin-right: 6px;
    text-transform: uppercase;
}}
.ioc-pill {{
    display: inline-block;
    background: #0D1321;
    border: 1px solid #1F293D;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
    margin: 2px 3px;
}}
.ioc-pill code {{
    color: #38BDF8;
    font-family: monospace;
}}
.empty-placeholder {{
    text-align: center;
    padding: 40px;
    color: var(--text-muted);
    display: none;
}}
@media print {{
    body {{ background: #fff; color: #000; padding: 0; }}
    .btn-action, .filter-bar, .btn-toggle-poc, .btn-copy-poc {{ display: none !important; }}
    .poc-drawer {{ display: block !important; }}
    table.threat-table td, table.threat-table th {{ border: 1px solid #ccc; color: #000; }}
}}
</style>
</head>
<body>

<div class="report-container">
    <header class="report-header">
        <div class="header-top">
            <div class="header-title">
                <h1>🛡️ Automated Threat Intel Dossier</h1>
                <p>Scope: <strong>{timeframe_label}</strong> &bull; Severities: <strong>{scope_title}</strong> &bull; Generated: {generated_time}</p>
            </div>
            <div class="header-actions">
                <button class="btn-action" onclick="window.print()">🖨️ Print / Save PDF</button>
                <button class="btn-action" onclick="exportTableToCSV()">📥 Export CSV</button>
            </div>
        </div>
        <div class="exec-summary-box">
            <h3>CISO Executive Threat Intelligence Briefing</h3>
            <p>{executive_summary_text}</p>
        </div>
    </header>

    <!-- KPI Metrics -->
    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-label">Total in Report</div>
            <div class="kpi-val" id="kpi-total">{total_cves}</div>
        </div>
        <div class="kpi-card kpi-crit">
            <div class="kpi-label">Critical Severity</div>
            <div class="kpi-val" id="kpi-crit">{critical_count}</div>
        </div>
        <div class="kpi-card kpi-poc">
            <div class="kpi-label">Weaponized PoCs</div>
            <div class="kpi-val" id="kpi-poc">{poc_count}</div>
        </div>
        <div class="kpi-card kpi-ai">
            <div class="kpi-label">AI Analyzed Threats</div>
            <div class="kpi-val" id="kpi-ai">{analyzed_count}</div>
        </div>
        <div class="kpi-card kpi-iot">
            <div class="kpi-label">IoT / OT Hardware</div>
            <div class="kpi-val" id="kpi-iot">{iot_count}</div>
        </div>
    </div>

    <!-- Filter Bar -->
    <div class="filter-bar">
        <div class="search-input-wrapper">
            <input type="text" id="reportSearch" class="search-input" placeholder="🔍 Search CVE ID, vendor, product, keywords, summary..." oninput="applyFilters()">
        </div>
        <div class="filter-chips">
            <button class="filter-chip active" data-filter="all" onclick="setChipFilter('all', this)">All ({total_cves})</button>
            <button class="filter-chip" data-filter="analyzed" onclick="setChipFilter('analyzed', this)">⚡ AI Analyzed ({analyzed_count})</button>
            <button class="filter-chip" data-filter="poc" onclick="setChipFilter('poc', this)">🔥 Has PoC ({poc_count})</button>
            <button class="filter-chip" data-filter="iotot" onclick="setChipFilter('iotot', this)">🏭 IoT/OT ({iot_count})</button>
            <button class="filter-chip" data-filter="cisa" onclick="setChipFilter('cisa', this)">🛡️ CISA KEV ({cisa_count})</button>
        </div>
        <div>
            <select id="severitySelect" class="select-severity" onchange="applyFilters()">
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
        </div>
    </div>

    <!-- Threat Intel Table -->
    <div class="table-container">
        <table class="threat-table" id="threatTable">
            <thead>
                <tr>
                    <th style="width: 25%;">Threat & Scoring</th>
                    <th style="width: 45%;">Intelligence Analysis & PoC</th>
                    <th style="width: 30%;">Mitigation & Attack Vectors</th>
                </tr>
            </thead>
            <tbody>
                {rows_html if rows_html else '<tr><td colspan="3" style="text-align:center; padding: 30px;">No vulnerabilities found matching criteria.</td></tr>'}
            </tbody>
        </table>
        <div id="noResults" class="empty-placeholder">No vulnerabilities match your current search or filter criteria.</div>
    </div>
</div>

<script>
let currentChip = 'all';

function setChipFilter(filterType, element) {{
    currentChip = filterType;
    document.querySelectorAll('.filter-chip').forEach(el => el.classList.remove('active'));
    element.classList.add('active');
    applyFilters();
}}

function applyFilters() {{
    const query = document.getElementById('reportSearch').value.toLowerCase().trim();
    const severity = document.getElementById('severitySelect').value.toLowerCase();
    const rows = document.querySelectorAll('.cve-row');
    let visibleCount = 0;

    rows.forEach(row => {{
        const rowSearch = row.getAttribute('data-search') || '';
        const rowSev = row.getAttribute('data-severity') || '';
        const rowAnalyzed = row.getAttribute('data-analyzed') === '1';
        const rowPoC = row.getAttribute('data-poc') === '1';
        const rowIoT = row.getAttribute('data-iotot') === '1';
        const rowCISA = row.getAttribute('data-cisa') === '1';

        let matchesSearch = !query || rowSearch.includes(query);
        let matchesSev = severity === 'all' || rowSev === severity;
        let matchesChip = true;

        if (currentChip === 'analyzed') matchesChip = rowAnalyzed;
        else if (currentChip === 'poc') matchesChip = rowPoC;
        else if (currentChip === 'iotot') matchesChip = rowIoT;
        else if (currentChip === 'cisa') matchesChip = rowCISA;

        if (matchesSearch && matchesSev && matchesChip) {{
            row.style.display = '';
            visibleCount++;
        }} else {{
            row.style.display = 'none';
        }}
    }});

    document.getElementById('noResults').style.display = visibleCount === 0 ? 'block' : 'none';
    document.getElementById('kpi-total').innerText = visibleCount;
}}

function togglePoC(drawerId) {{
    const drawer = document.getElementById(drawerId);
    if (drawer) {{
        drawer.style.display = drawer.style.display === 'none' ? 'block' : 'none';
    }}
}}

function copyPoCText(btn, codeId) {{
    const codeEl = document.getElementById(codeId);
    if (codeEl) {{
        navigator.clipboard.writeText(codeEl.innerText).then(() => {{
            const old = btn.innerText;
            btn.innerText = 'Copied!';
            setTimeout(() => {{ btn.innerText = old; }}, 1500);
        }});
    }}
}}

function exportTableToCSV() {{
    let csv = [];
    const rows = document.querySelectorAll("table tr");
    for (let i = 0; i < rows.length; i++) {{
        if (rows[i].style.display !== 'none') {{
            let row = [], cols = rows[i].querySelectorAll("td, th");
            for (let j = 0; j < cols.length; j++) {{
                let data = cols[j].innerText.replace(/(\\r\\n|\\n|\\r)/gm, " ").replace(/(\\s\\s+)/g, " ");
                data = data.replace(/"/g, '""');
                row.push('"' + data + '"');
            }}
            csv.push(row.join(","));
        }}
    }}
    const csvFile = new Blob([csv.join("\\n")], {{type: "text/csv"}});
    const downloadLink = document.createElement("a");
    downloadLink.download = "ATI_Threat_Report_{start_str}.csv";
    downloadLink.href = window.URL.createObjectURL(csvFile);
    downloadLink.style.display = "none";
    document.body.appendChild(downloadLink);
    downloadLink.click();
}}
</script>
</body>
</html>
"""
    report_file_path = os.path.join(ROOT_DIR, "report_output.html")
    try:
        with open(report_file_path, "w", encoding="utf-8") as f:
            f.write(html_body)
        logging.info(f"Saved executive HTML report to {report_file_path}")
    except Exception as e:
        logging.error(f"Failed to write report_output.html: {e}")

    subject = f"Threat Intel: {total_cves} Vulnerabilities ({start_str})"
    return subject, html_body


def send_webhook(markdown_text, progress_prefix=None):
    webhook_url = os.getenv("WEBHOOK_URL")
    prefix_success = f"[{progress_prefix}] " if progress_prefix else "[+] "
    prefix_fail = f"[{progress_prefix}] " if progress_prefix else "[-] "
    if not webhook_url:
        logging.warning("Skipping webhook: WEBHOOK_URL missing in .env file.")
        return       
    logging.info("Sending payload to webhook...")
    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": markdown_text,
                            "wrap": True
                        }
                    ]
                }
            }
        ]
    }
    
    try:
        response = requests.post(
            webhook_url, 
            json=payload, 
            headers={"Content-Type": "application/json"}, 
            timeout=10
        )
        if response.ok:
            print(f"{prefix_success}Webhook message sent successfully!")
        else:
            print(f"{prefix_fail}Webhook Failed: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"{prefix_fail}Webhook Exception: {e}")
