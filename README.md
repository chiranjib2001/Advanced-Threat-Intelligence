# 🛡️ Automated Threat Intel & OSINT Analyzer (ATI V2)

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL%20Mode-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success)]()

**ATI V2** is an end-to-end, zero-cost Cyber Threat Intelligence (CTI) and vulnerability triage platform. It continuously harvests, classifies, enriches, and alerts on emerging vulnerabilities (CVEs) across official feeds, weaponized exploit repositories, clearweb ransomware trackers, and social threat channels.

Features a dual-mode interface: a rich **Cyber Command Center Web GUI** with real-time SSE telemetry and a scriptable **CLI** for automated security operations and CI/CD pipelines.

---

## ⚡ Key Capabilities

- **Official Vulnerability Ingestion**:
  - **NIST NVD 2.0 API**: Automatic 90-day window slicing with backfill and resilient rate-limiting.
  - **CISA KEV Catalog**: Persistent synchronization of confirmed actively exploited vulnerabilities.
  - **FIRST.org EPSS**: Parallel, non-blocking batch scoring for exploit probability estimation.
- **Weaponized Exploit Hunting**:
  - Dual-mode discovery across **ProjectDiscovery Nuclei templates**, **Metasploit modules**, **Trickest CVE PoCs**, and public **GitHub** code repositories.
  - **3-Level Deep Link Harvester (LV0 → LV3)**: Recursively parses vendor advisories down to weaponized scripts (`.py`, `.sh`), detecting execution strings while pruning vendor patch portals.
- **8-Stream OSINT & Ransomware Intelligence**:
  - Real-time zero-cost monitoring across HackerNews, Reddit (`r/netsec`, `r/blueteamsec`, `r/redteamsec`, `r/cybersecurity`), syndicated threat feeds, and security newsrooms.
  - Clearweb mirrors of dark web ransomware leak sites (**Ransomwatch** and **Ransomware.live**) with zero Tor overhead.
- **Multi-Provider AI Intelligence Cascades**:
  - Zero-cost inference cascade across **GroqCloud** (LPU), **Cerebras Cloud**, **OpenRouter**, **Google Gemini**, **Mistral AI**, and local offline **Ollama**.
  - Intelligent API cooldown scheduler with automatic HTTP 429 backoff and multi-key rotation.
- **Owned Assets Triangulation**:
  - Internal asset inventory (`owned_assets`) correlated against active CVEs and detected PoCs.
- **Alerting & Briefings**:
  - Automated webhook dispatch (Slack, Microsoft Teams Adaptive Cards, Discord).
  - Standalone executive HTML threat briefings and PDF dossier generation.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10 or higher
- Git

### 2. Installation
```bash
# Clone the repository
git clone <your-repository-url>
cd ATI-V2

# (Optional) Create and activate a virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment
Copy `.env.example` to `.env` and configure your API keys:
```bash
cp .env.example .env
```
> **Note:** All external AI providers are optional or support free tiers. Local offline inference via [Ollama](https://ollama.ai/) is supported out-of-the-box (`http://localhost:11434/v1`).

### 4. Launch Cyber Command Center (Web GUI)
```bash
python main.py --gui
```
Open your browser at `http://127.0.0.1:8000` to access the Cyber Command Center dashboard.

### 5. CLI Execution Examples
```bash
# Targeted CVE Deep-Dive with Active Exploit Hunting
python main.py --cve CVE-2024-38077 --exploit-find

# Find trending vulnerabilities from the last 7 days with public PoCs or CISA KEV
python main.py --active-week-exploits

# Run unstructured OSINT hunt across HackerNews, Reddit, and Ransomware feeds
python main.py --in-wild-osint

# Filter strictly for IoT, SCADA, and OT hardware vulnerabilities
python main.py --iotot --count 20
```

For more CLI recipes and scenarios, see [`Example.md`](Example.md).

---

## 📁 Repository Structure

```text
├── backend/
│   ├── collect.py         # NIST NVD 2.0, CISA KEV & EPSS collectors
│   ├── db_manager.py      # SQLite WAL connection handler & schema initialization
│   ├── enrich_engine.py   # Technical and AI threat backfill & batch maintenance
│   ├── exploit_finder.py  # Nuclei, Metasploit, Trickest & GitHub PoC hunter
│   ├── ioc_engine.py      # Indicators of Compromise extraction & validation
│   ├── iot_ot_cve.py      # Hardware / OT / ICS specific taxonomy filters
│   ├── llm.py             # Multi-provider AI cascade, model pools & key scheduler
│   ├── osint_hunter.py    # 8-Stream OSINT & Ransomware leak site crawler
│   ├── report.py          # HTML briefing builder & webhook notifier
│   ├── scraper.py         # Deep link crawler & fast-path heuristic URL classifier
│   └── server.py          # FastAPI application & Server-Sent Events (SSE) telemetry
├── data/
│   ├── known_advisory_links_url.txt  # Curated ICS/vendor advisory signatures
│   └── known_exploit_links_url.txt   # Known exploit repository signatures
├── static/
│   ├── app.js             # Command Center frontend application logic
│   ├── index.html         # Web GUI layout
│   └── style.css          # Glassmorphism dark cyber theme styles
├── .env.example           # Environment variables template
├── .gitignore             # Git exclusion rules for secrets, DBs, and logs
├── documentation.md       # Comprehensive 900+ line technical architecture manual
├── Example.md             # Curated CLI operational playbooks and output logs
├── flows.md               # Algorithmic & deep link crawl mermaid flowcharts
├── main.py                # Unified CLI entrypoint & web launcher
├── requirements.txt       # Python package dependencies
└── x.py                   # Standalone PDF documentation & threat dossier bundler
```

---

## 📖 Extended Documentation

- **Full Architecture & Sub-engine Guide**: [`documentation.md`](documentation.md)
- **Crawl & Intelligence Flow Diagrams**: [`flows.md`](flows.md)
- **Operational CLI Playbooks**: [`Example.md`](Example.md)

---

## 🔒 Security & Privacy Notice

- **Zero Hardcoded Secrets**: This project does not store or track credentials. Always keep your `.env` private and never commit sensitive keys.
- **Heuristic Safe Crawling**: Crawling mechanisms adhere to depth bounds (max depth 3) to prevent spider traps and respect non-exploit boundaries.
