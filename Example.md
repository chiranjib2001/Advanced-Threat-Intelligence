# 🛠️ ATI V2 - Operational CLI Playbooks & Examples

This document provides curated CLI execution playbooks and usage scenarios for the **Automated Threat Intelligence & OSINT Analyzer (ATI V2)**.

---

## 📌 CLI Reference Overview

Run `python main.py -h` at any time to inspect all available runtime flags and sub-engines:

```bash
python main.py -h
```

```text
usage: main.py [-h] [--start START] [--end END] [--cve CVE] [--count COUNT]
               [--cisa] [--iotot] [--all-severity] [--exploit-find]
               [--active-week-exploits] [--in-wild-osint] [--enrich-db]
               [--gui] [--port PORT] [--host HOST]

Automated CVE Threat Intel Analyzer

options:
  -h, --help            show this help message and exit
  --start START         Start date (YYYY-MM-DD)
  --end END             End date (YYYY-MM-DD)
  --cve CVE             Analyze a specific CVE (e.g., CVE-2024-1234)
  --count COUNT         Limit analysis to the top N worst vulnerabilities
  --cisa                Include CISA Known Exploited Vulnerabilities catalog fetch
  --iotot               Filter strictly for IoT, ICS, and OT hardware vulnerabilities
  --all-severity        Analyze all severities, bypassing the Critical/High filter
  --exploit-find        Actively search Nuclei, Metasploit, and GitHub for PoCs
  --active-week-exploits
                        Find STRUCTURED Trending CVEs (EPSS > 5%, CISA KEV, or Public PoCs) from the last 7 days.
  --in-wild-osint       Find UNSTRUCTURED Trending CVEs by scraping HackerNews/Reddit, regardless of publish date.
  --enrich-db           Launch interactive on-demand database maintenance and technical/AI enrichment
  --gui, --web, --server
                        Launch the full-stack Web GUI & API Server (FastAPI + Cyber Command Center UI)
  --port PORT           Web server port (default: 8000)
  --host HOST           Web server host (default: 127.0.0.1)
```

---

## 🎯 Operational Playbooks

### 1. The Tactical Deep-Dive (Targeted Analyst Mode)

Use this when an alert fires, a specific vulnerability makes the news, or you need immediate deep-dive context on a single threat.

```bash
python main.py --cve CVE-2026-36960 --exploit-find
```

#### Sample Execution Output
```text
============================================================
 Targeted Analysis: CVE-2026-36960
============================================================
Initializing database schema...
Database successfully created/verified at: data\cve_database.db
[*] CVE-2026-36960 already exists in local database. Skipping NIST API fetch.
[*] Hunting for known weaponized exploits (Nuclei/Metasploit)...
[*] Scraping and Deep-Scanning Reference Links...
[*] Sending CVE-2026-36960 to AI for final analysis...
[+] Webhook message sent successfully!
```

**What this scan accomplishes:**
- **Bypasses Date Filters:** Hyper-focuses on the specified CVE identifier.
- **Active Exploit Hunting:** Searches GitHub, Trickest, ProjectDiscovery Nuclei, and Metasploit for weaponized exploits.
- **Deep Link Scanning:** Recursively scans advisory links up to 3 levels deep to detect malicious payloads and command one-liners.
- **Formatted Alerting:** Dispatches a structured alert (including CVSS, EPSS score, and PoC recreation steps) to your configured webhook.

---

### 2. The "Ahead of the Curve" Hunt (Unstructured OSINT)

Use this to catch zero-days or older vulnerabilities that have suddenly surged in discussion before official government feeds update.

```bash
python main.py --in-wild-osint
```

**What this scan accomplishes:**
- **Social Threat Scraping:** Concurrently queries HackerNews and Reddit (`r/netsec`, `r/cybersecurity`, `r/blueteamsec`, `r/redteamsec`).
- **Trend Identification:** Aggregates mention velocity to surface what the InfoSec community is actively discussing.
- **Force-Processing:** If an older CVE suddenly goes viral, ATI V2 automatically pulls NIST records, hunts for new exploits, and routes it through the AI analysis pipeline.

---

### 3. The Executive Threat Briefing (Structured Intel)

Ideal for automated weekly cron jobs or preparing threat briefings for leadership and SOC managers.

```bash
python main.py --active-week-exploits --count 5
```

**What this scan accomplishes:**
- **Strict 7-Day Lookback:** Automatically isolates the scan window to the preceding 7 days.
- **High-Signal Triage:** Filters out low-priority noise by strictly analyzing vulnerabilities with EPSS probability > 5%, presence on CISA KEV, or verified public PoCs.
- **Top-N Limiter:** Focuses resource usage on the top 5 highest-risk vulnerabilities, generating a concise, actionable executive summary.

---

### 4. The Hardware & Infrastructure Sweep (IoT / OT Focus)

Use this when assessing risk for industrial control systems, manufacturing networks, SCADA infrastructure, or edge devices.

```bash
python main.py --iotot --all-severity --count 10
```

#### Sample Execution Output
```text
============================================================
 Automated Threat Intel Pipeline
 Scope: IoT / OT / ICS Hardware Focus
 Scope: ALL Severities (Including Medium & Low)
 Limit: Top 10 vulnerabilities
============================================================
Initializing database schema...
Database successfully created/verified at: data\cve_database.db
[*] Phase 1: Fetching NIST Data (IoT/OT Focus)...
 -> Querying NIST for keyword: 'IoT'
 -> Querying NIST for keyword: 'SCADA'
 -> Querying NIST for keyword: 'PLC'
 -> Querying NIST for keyword: 'ICS'
 -> Querying NIST for keyword: 'firmware'
 -> Querying NIST for keyword: 'HMI'
 -> Querying NIST for keyword: 'sensor'
 -> Querying NIST for keyword: 'RTU'
 -> Querying NIST for keyword: 'router'
[+] IoT/OT fetching sequence complete.
[*] Identified 10 unanalyzed CVEs for processing.
[*] Phase 2: Scraping and AI-Scanning ALL Web Data for Target CVEs...
[*] Phase 3: CONCURRENT AI Analysis...
[*] Phase 4: Report Generation...
[+] Webhook message sent successfully!
```

**What this scan accomplishes:**
- **Keyword Targeting:** Automatically injects ICS/SCADA/IoT hardware keywords (`SCADA`, `PLC`, `ICS`, `firmware`, `RTU`, `router`) into the query pipeline.
- **Bypassing Severity Gates:** Evaluates Medium and Low severity chainable hardware flaws that could lead to physical process compromise.
- **Inventory Flagging:** Flags matching CVEs with `is_iot_ot = 1` for IoT asset correlation.

---

### 5. The "Patch Tuesday" Historical Sweep

Use this for thorough historical auditing, such as sweeping an entire bi-weekly patch cycle with full exploit discovery and CISA catalog cross-referencing.

```bash
python main.py --start 2026-05-01 --end 2026-05-14 --count 10 --exploit-find --cisa
```

**What this scan accomplishes:**
- **Custom Date Range:** Queries NIST NVD for all network-accessible vulnerabilities published between the start and end dates.
- **CISA Synchronization:** Synchronizes the latest CISA Known Exploited Vulnerabilities catalog.
- **Mass Exploit Discovery:** Triggers `--exploit-find` across all top targets to hunt for active GitHub and Metasploit PoCs before AI synthesis.
