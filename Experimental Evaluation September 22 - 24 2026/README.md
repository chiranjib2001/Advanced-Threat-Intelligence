# Experimental Evaluation Benchmark Dataset (September 22–24, 2026)

## 1. Overview and Scope

This directory contains the primary empirical evaluation dataset and verification artifacts supporting the quantitative findings presented in the accepted manuscript (`ATI Final.pdf` / `review_paper.pdf`). 

The evaluation was executed in two synchronized experimental phases:
- **Phase A (48-Hour Live Ingestion & Exploit Mining Benchmark):** Live monitoring over the **September 22 to September 24, 2026** disclosure window, ingesting freshly published CVEs from NIST NVD 2.0 and CISA KEV feeds.
- **Phase B (Multi-Stream OSINT Early-Warning Lead Times):** Tracking pre-exploitation chatter across an 8-stream harvester over a rolling 15-day lookback window against official federal CISA KEV publication dates.
- **Deep Crawling Traversal Benchmark:** Traversal log evaluation across 364 distinct crawl chains containing 23,206 links parsed across 17,376 unique URLs, evaluating crawl depths from Level 0 to Level 5.

---

## 2. Directory Contents

| File Name | Format | Description |
| :--- | :---: | :--- |
| `evaluation_dataset.db` | SQLite 3 | Master relational evaluation database containing tables `cve_main`, `cve_sources`, `cve_analysis`, `cve_iocs`, and benchmark summary tables. |
| `verify_evaluation_metrics.py` | Python 3 | Standalone verification script that connects to `evaluation_dataset.db`, executes SQL validation queries, and prints the exact tables reported in the paper. |
| `table_2_phase_a_benchmark.csv` | CSV | Tabular metrics for the Phase A 48-hour scheduled disclosure run (137 ingested, 71 prioritized, 49 PoCs, 38 release tags suppressed, 44 Docker testbeds). |
| `table_3_phase_b_osint_lead_times.csv` | CSV | Evaluated in-the-wild threat telemetry for the 6 highlighted CVEs, detailing OSINT discovery date ($t_{osint}$), CISA date ($t_{cisa}$), and lead time ($\Delta t_{cisa}$). |
| `table_4_crawl_depth_progression.csv` | CSV | Crawl depth progression telemetry across 364 crawl chains (Levels 0 to 5), links visited, PoC yield, median latency, and unique CVE coverage. |
| `table_5_ablation_study.csv` | CSV | Empirical ablation study results evaluating the quantitative impact of removing individual architectural modules. |

---

## 3. Database Schema

The `evaluation_dataset.db` file contains the following relational schema:

```
┌─────────────────────────────────┐       1 : N       ┌─────────────────────────────────┐
│            cve_main             │──────────────────<│           cve_sources           │
├─────────────────────────────────┤                   ├─────────────────────────────────┤
│ • cve_id (TEXT PRIMARY KEY)     │                   │ • id (INTEGER PRIMARY KEY)      │
│ • published_date (DATETIME)     │                   │ • cve_id (TEXT FK)              │
│ • cvss_v3_score, epss_score     │                   │ • source_name, url              │
│ • severity, cwe                 │                   │ • is_poc_link (BOOLEAN)         │
│ • affected_vendor, product      │                   │ • exploit_status (6 Classes)    │
│ • is_cisa_kev, cisa_date_added  │                   │ • depth_level (Level 0 to 5)    │
│ • has_public_poc, has_nuclei    │                   │ • parent_source_id              │
│ • osint_mention_count           │                   └─────────────────────────────────┘
│ • osint_sources                 │
└─────────────────────────────────┘
                │
                │ 1 : N
                ▼
┌─────────────────────────────────┐                   ┌─────────────────────────────────┐
│            cve_iocs             │                   │          cve_analysis           │
├─────────────────────────────────┤                   ├─────────────────────────────────┤
│ • id (INTEGER PRIMARY KEY)      │                   │ • cve_id (TEXT PRIMARY KEY FK)  │
│ • cve_id (TEXT FK)              │                   │ • ai_summary                    │
│ • ioc_type, ioc_value           │                   │ • recommended_action            │
│ • threat_actor, malware_family  │                   │ • poc_recreation_steps          │
│ • source_feed, confidence       │                   │ • keywords, is_analyzed         │
└─────────────────────────────────┘                   └─────────────────────────────────┘
```

---

## 4. One-Click Verification Instructions

To reproduce all quantitative metrics reported in the paper:

```bash
# Navigate to the evaluation directory
cd "Experimental Evaluation September 22 - 24 2026"

# Run the automated verification script
python verify_evaluation_metrics.py
```

### Direct SQLite Query Examples:

#### 1. Verify Table 2 (Phase A Operational Metrics):
```sql
SELECT metric_name, observed_count, percentage_rate, operational_significance 
FROM benchmark_phase_a;
```

#### 2. Verify Table 3 (OSINT Lead Times vs. CISA KEV):
```sql
SELECT cve_id, target_software, osint_discovery_date, cisa_kev_listing_date, defensive_lead_time_days, mention_count 
FROM benchmark_phase_b_osint 
ORDER BY defensive_lead_time_days DESC;
```

#### 3. Verify Table 4 (Crawl Depth Progression across 364 Chains):
```sql
SELECT depth_level, unique_urls_visited, cumulative_links_parsed, pocs_at_depth, 
       cumulative_pocs || ' (' || cumulative_yield_pct || '%)' AS cumulative_yield, 
       median_latency_s || ' s' AS median_latency, 
       unique_cves_with_poc, actual_coverage_pct || '%' AS actual_coverage 
FROM benchmark_crawl_depth 
ORDER BY depth_level ASC;
```

---

## 5. Ethical Considerations & Forensic Integrity

- **No Malware Droppers:** All unverified external links circulating on social platforms and raw repositories are tagged as `unverified_osint_poc` with `is_poc_link = 0`, ensuring they cannot be automatically executed.
- **Non-Invasive Queries:** All crawling telemetry respects `robots.txt` boundaries, outbound domain limits ($B_{max} = 20$), and streams content in 1 MB chunks to prevent denial-of-service.
- **Forensic Hash Integrity:** SHA-256 hashes of all harvested scripts and manifests are preserved for independent provenance verification.
