# ==============================================================================
# Author: Created with love by Chiranjib and Team
# Description: Vulnerable Software Version Finder & Lab Reproduction Engine
# Supports: NIST CPE, GitHub Releases/Tags, Wayback Machine, Package Registries
# ==============================================================================
import os
import re
import json
import logging
import urllib.parse
import requests
from typing import Dict, Any, List, Optional
from backend import db_manager, collect

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(ROOT_DIR, "data")
LOGS_DIR = os.path.join(ROOT_DIR, "logs")

logger = logging.getLogger("vuln_version_finder")
logger.setLevel(logging.INFO)
if not logger.handlers:
    logger.addHandler(logging.FileHandler(os.path.join(LOGS_DIR, "cve_analyzer.log"), encoding="utf-8"))

ARCHIVE_SOURCES_PATH = os.path.join(DATA_DIR, "software_archive_sources.json")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {
    "User-Agent": "ATI-V2-Threat-Intel/2.0"
}


def load_archive_catalog() -> dict:
    """Loads the software archive and registry source templates from data/software_archive_sources.json."""
    if os.path.exists(ARCHIVE_SOURCES_PATH):
        try:
            with open(ARCHIVE_SOURCES_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load software_archive_sources.json: {e}")
    return {"archive_repositories": []}


def parse_version_tuple(v_str: str) -> tuple:
    """
    Parses a version string into a comparable tuple where stable releases rank
    higher than release candidates (e.g. 0.39.0 > 0.39.0-rc6).
    """
    if not v_str:
        return (-1, 0, 0, -1, 0)
    
    clean = re.sub(r'^(v|version[-_])', '', str(v_str).strip(), flags=re.IGNORECASE)
    # Check if pre-release
    is_pre = bool(re.search(r'[-_](rc|beta|alpha|dev|preview|pre)\d*', clean, re.IGNORECASE))
    pre_num = 0
    m_pre = re.search(r'[-_](?:rc|beta|alpha|dev|preview|pre)(\d+)', clean, re.IGNORECASE)
    if m_pre:
        pre_num = int(m_pre.group(1))

    # Strip pre-release tag to get base numbers
    base = re.split(r'[-_]', clean)[0]
    num_parts = [int(p) for p in re.findall(r'\d+', base)]
    while len(num_parts) < 3:
        num_parts.append(0)

    # (major, minor, patch, 1 if stable else 0, pre_release_num)
    return (num_parts[0], num_parts[1], num_parts[2], 0 if is_pre else 1, pre_num)


def query_wayback_cdx_snapshot(target_url: str, timeout: int = 4) -> str:
    """
    Automated Live CDX HTTP Retry:
    Queries the Internet Archive CDX server API to find the exact latest HTTP 200
    snapshot timestamp for historical software installer packages, download mirrors,
    or repository releases that have returned 404.
    Returns the direct historical replay URL or falls back to the calendar view.
    """
    if not target_url:
        return ""
    if any(h in target_url.lower() for h in ["localhost", "127.0.0.1", "web.archive.org"]):
        return target_url

    cdx_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": target_url,
        "output": "json",
        "fl": "timestamp,original,statuscode",
        "filter": "statuscode:200",
        "limit": 1
    }
    try:
        res = requests.get(cdx_url, params=params, timeout=timeout)
        if res.status_code == 200:
            rows = res.json()
            if len(rows) > 1:
                ts, orig = rows[1][0], rows[1][1]
                logger.info(f"[Wayback CDX] Resolved live archive snapshot for {target_url} -> {ts}")
                return f"https://web.archive.org/web/{ts}/{orig}"
    except Exception as e:
        logger.debug(f"[Wayback CDX] Live lookup failed for {target_url}: {e}")

    # Fallback to general Wayback calendar lookup
    return f"https://web.archive.org/web/*/{target_url}"


# Maintain backwards compatibility
query_wayback_machine_snapshot = query_wayback_cdx_snapshot


def extract_cpe_version_bounds(cve_id: str) -> Dict[str, Any]:
    """
    Fetches raw NIST NVD 2.0 configuration data to extract exact vulnerable version bounds:
    versionStartIncluding, versionEndExcluding, criteria, etc.
    """
    cve_id = cve_id.strip().upper()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    result = {
        "vendor": "Unknown",
        "product": "Unknown",
        "vulnerable_range": None,
        "fixed_version": None,
        "raw_cpe_matches": []
    }

    try:
        headers = {}
        if collect.NIST_API_KEY:
            headers["apiKey"] = collect.NIST_API_KEY

        res = requests.get(url, headers=headers, timeout=12)
        if res.status_code == 200:
            data = res.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve = vulns[0].get("cve", {})
                configs = cve.get("configurations", [])
                for conf in configs:
                    for node in conf.get("nodes", []):
                        for m in node.get("cpeMatch", []):
                            if m.get("vulnerable", False):
                                result["raw_cpe_matches"].append(m)
                                if m.get("versionEndExcluding") and not result["fixed_version"]:
                                    result["fixed_version"] = m["versionEndExcluding"]
                                if m.get("versionEndIncluding") and not result["vulnerable_range"]:
                                    result["vulnerable_range"] = f"<= {m['versionEndIncluding']}"
                                elif m.get("versionEndExcluding") and not result["vulnerable_range"]:
                                    result["vulnerable_range"] = f"< {m['versionEndExcluding']}"
                                criteria = m.get("criteria", "")
                                parts = criteria.split(":")
                                if len(parts) >= 5:
                                    result["vendor"] = parts[3].capitalize()
                                    result["product"] = parts[4].replace("_", " ").capitalize()
    except Exception as e:
        logger.warning(f"Error querying NIST for CPE version bounds on {cve_id}: {e}")

    return result


def find_github_repo_from_sources(cve_id: str) -> Optional[str]:
    """Inspects cve_sources for any GitHub repository reference (e.g. 'docker/sbx-releases')."""
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT url FROM cve_sources WHERE cve_id = ? AND url LIKE '%github.com/%'", (cve_id,))
    rows = cursor.fetchall()
    conn.close()

    for r in rows:
        url = r["url"]
        match = re.search(r"github\.com/([^/]+/[^/]+)", url, re.IGNORECASE)
        if match:
            repo = match.group(1).rstrip('.git')
            # Ignore exploit payload repos that are not the actual product
            if not any(ign in repo.lower() for ign in ["rapid7/metasploit", "projectdiscovery/nuclei", "trickest/cve"]):
                return repo
    return None


def fetch_github_vulnerable_releases(repo_slug: str, fixed_version: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Queries GitHub API and repository tags to locate releases and archive download links
    that fall within the vulnerable version window (i.e. preceding the fixed version).
    """
    results = []
    fixed_tuple = parse_version_tuple(fixed_version) if fixed_version else None

    # 1. Check GitHub Releases
    api_url = f"https://api.github.com/repos/{repo_slug}/releases?per_page=100"
    releases_data = []
    try:
        res = requests.get(api_url, headers=GITHUB_HEADERS, timeout=8)
        if res.status_code == 200:
            releases_data = res.json()
    except Exception:
        pass

    # 2. Check GitHub Tags if releases are sparse
    tags_data = []
    tags_url = f"https://api.github.com/repos/{repo_slug}/tags?per_page=100"
    try:
        t_res = requests.get(tags_url, headers=GITHUB_HEADERS, timeout=8)
        if t_res.status_code == 200:
            tags_data = t_res.json()
    except Exception:
        pass

    all_tag_names = []
    for r in releases_data:
        t = r.get("tag_name")
        if t and t not in all_tag_names:
            all_tag_names.append(t)
    for t in tags_data:
        t_name = t.get("name")
        if t_name and t_name not in all_tag_names:
            all_tag_names.append(t_name)

    if not all_tag_names:
        return results

    # Separate candidates that are < fixed_version (or all if fixed_version unknown)
    candidates = []
    for t_name in all_tag_names:
        t_tuple = parse_version_tuple(t_name)
        if fixed_tuple:
            if t_tuple < fixed_tuple:
                candidates.append((t_name, t_tuple))
        else:
            candidates.append((t_name, t_tuple))

    if not candidates:
        return results

    # Sort descending
    candidates.sort(key=lambda x: x[1], reverse=True)

    # Pick top stable releases first, then top pre-release candidates
    stable_picks = [c for c in candidates if c[1][3] == 1][:2]
    pre_picks = [c for c in candidates if c[1][3] == 0][:2]
    selected_tags = []
    for p in stable_picks + pre_picks:
        if p[0] not in selected_tags:
            selected_tags.append(p[0])

    for t_name in selected_tags[:4]:
        rel_url = f"https://github.com/{repo_slug}/releases/tag/{t_name}"
        zip_url = f"https://github.com/{repo_slug}/archive/refs/tags/{t_name}.zip"
        tar_url = f"https://github.com/{repo_slug}/archive/refs/tags/{t_name}.tar.gz"
        archive_mirror = query_wayback_machine_snapshot(rel_url)

        results.append({
            "version": t_name,
            "type": "github_release",
            "url": rel_url,
            "direct_download_zip": zip_url,
            "direct_download_tar": tar_url,
            "archive_mirror_url": archive_mirror,
            "source": f"GitHub Repository ({repo_slug})",
            "clone_command": f"git clone --branch {t_name} --depth 1 https://github.com/{repo_slug}.git",
            "is_direct_download": True
        })

    return results


def find_vulnerable_versions(cve_id: str) -> Dict[str, Any]:
    """
    Main entry point: Analyzes a CVE to identify affected software versions and construct
    actionable download links, historical archive snapshots, and lab reproduction recipes.
    """
    cve_id = cve_id.strip().upper()
    conn = db_manager.get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT affected_vendor, affected_product FROM cve_main WHERE cve_id = ?", (cve_id,))
    main_row = cursor.fetchone()

    vendor = main_row["affected_vendor"] if main_row and main_row["affected_vendor"] else "Unknown"
    product = main_row["affected_product"] if main_row and main_row["affected_product"] else "Unknown"

    # Step 1: Query NIST NVD for explicit CPE version boundaries
    cpe_info = extract_cpe_version_bounds(cve_id)
    if vendor == "Unknown" and cpe_info["vendor"] != "Unknown":
        vendor = cpe_info["vendor"]
    if product == "Unknown" and cpe_info["product"] != "Unknown":
        product = cpe_info["product"]

    fixed_version = cpe_info["fixed_version"]
    vulnerable_range = cpe_info["vulnerable_range"]

    # If fixed_version not found in NIST configs, inspect existing cve_sources for release tags
    if not fixed_version:
        cursor.execute("SELECT url FROM cve_sources WHERE cve_id = ? AND (url LIKE '%/releases/tag/%' OR exploit_status = 'vuln_version')", (cve_id,))
        for r in cursor.fetchall():
            m = re.search(r"/releases/tag/v?([0-9]+\.[0-9]+(\.[0-9]+)?)", r["url"], re.IGNORECASE)
            if m:
                fixed_version = m.group(1)
                if not vulnerable_range:
                    vulnerable_range = f"< {m.group(0).split('/')[-1]}"
                break

    vulnerable_links = []

    # Step 2: GitHub Repository Release / Tag Discovery
    repo_slug = find_github_repo_from_sources(cve_id)
    if repo_slug:
        gh_releases = fetch_github_vulnerable_releases(repo_slug, fixed_version=fixed_version)
        vulnerable_links.extend(gh_releases)

    # Step 3: Package Registries & Container Images
    prod_clean = product.lower().replace(" ", "-")
    archive_catalog = load_archive_catalog()

    # Check for container / Docker ecosystem
    if "docker" in vendor.lower() or "docker" in product.lower() or "container" in product.lower():
        tag_str = vulnerable_links[0]["version"] if vulnerable_links else "vulnerable-tag"
        vulnerable_links.append({
            "version": f"{product} (Container)",
            "type": "container_image",
            "url": f"https://hub.docker.com/search?q={urllib.parse.quote(product)}&type=image",
            "archive_mirror_url": None,
            "source": "Docker Hub Registry",
            "clone_command": f"docker pull {vendor.lower()}/{prod_clean}:{tag_str}",
            "is_direct_download": False
        })

    # Step 4: WayBack Machine & Legacy Archives for Software
    generic_archive_url = query_wayback_machine_snapshot(f"http://www.oldversion.com/search?q={urllib.parse.quote(product)}")
    archive_mirrors = [
        {
            "name": "Wayback Machine Historical Mirror",
            "url": generic_archive_url,
            "notes": "Historical archive of previous product installers and distribution mirrors"
        },
        {
            "name": "SourceForge Software Archives",
            "url": f"https://sourceforge.net/directory/?q={urllib.parse.quote(product)}",
            "notes": "Open-source package archive"
        }
    ]

    # Step 5: Save newly discovered vulnerable version links into cve_sources
    for link in vulnerable_links:
        target_url = link.get("url") or link.get("direct_download_zip")
        if target_url:
            cursor.execute('''
                INSERT INTO cve_sources (cve_id, source_name, url, is_poc_link, details, exploit_status)
                SELECT ?, 'Vulnerable Version Download', ?, 0, ?, 'vuln_version'
                WHERE NOT EXISTS (
                    SELECT 1 FROM cve_sources WHERE cve_id = ? AND url = ?
                )
            ''', (
                cve_id, target_url,
                f"Downloadable vulnerable artifact for validation: {link.get('version')} ({link.get('source')})",
                cve_id, target_url
            ))

    conn.commit()
    conn.close()

    return {
        "cve_id": cve_id,
        "vendor": vendor,
        "product": product,
        "vulnerable_range": vulnerable_range or "Check vendor bulletin",
        "fixed_version": fixed_version or "See advisory",
        "vulnerable_links": vulnerable_links,
        "archive_sources": archive_mirrors,
        "total_links_found": len(vulnerable_links)
    }
