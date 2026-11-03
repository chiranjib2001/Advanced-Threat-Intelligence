// ==============================================================================
// Author: Created with love by Chiranjib and Team
// Description: Frontend Logic & SPA Controller for ATI V2 Command Center
// ==============================================================================

const state = {
    currentView: 'dashboard',
    cves: {
        page: 1,
        limit: 15,
        total: 0,
        search: '',
        severity: 'all',
        sortBy: 'cvss_v3_score',
        sortOrder: 'desc',
        hasPoc: false,
        isCisa: false,
        isIot: false,
        isOsint: false,
        isAnalyzed: false,
        hasIocs: false,
        keyword: ''
    },
    scan: {
        selectedPreset: 'single',
        eventSource: null
    },
    enrich: {
        isRunning: false
    },
    assets: {
        items: []
    }
};

// ==============================================================================
// INITIALIZATION
// ==============================================================================
document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    setupLiveClock();
    setupEventListeners();
    setupSSEStream();
    setupEnrichMonitor();

    // Initial Route
    const hash = window.location.hash.replace('#', '') || 'dashboard';
    navigateTo(hash);
});

// ==============================================================================
// NAVIGATION ROUTING
// ==============================================================================
function setupNavigation() {
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.replace('#', '') || 'dashboard';
        navigateTo(hash);
    });

    document.querySelectorAll('.sidebar-nav .nav-item').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const view = link.getAttribute('data-view');
            window.location.hash = view;
        });
    });
}

function navigateTo(viewName) {
    state.currentView = viewName;

    // Update Nav links
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(link => {
        link.classList.toggle('active', link.getAttribute('data-view') === viewName);
    });

    // Update Views
    document.querySelectorAll('.app-view').forEach(view => {
        view.classList.remove('active');
    });

    const targetView = document.getElementById(`view-${viewName}`);
    if (targetView) {
        targetView.classList.add('active');
    }

    // Update Header Breadcrumb
    const titles = {
        dashboard: 'Executive Threat Hunter Dashboard',
        cves: 'Vulnerability Intelligence Explorer',
        scans: 'Threat Hunt Launcher & Live Execution Terminal',
        osint: 'In-The-Wild Social OSINT Radar',
        'iot-ot': 'Critical Infrastructure & IoT / OT Watch',
        reports: 'Intelligence Reports & Codebase Dossier',
        assets: 'Internal Owned Assets Inventory & Threat Correlation Target',
        system: 'System Gateway & Multi-Provider AI Health'
    };
    const titleEl = document.getElementById('current-view-title');
    if (titleEl) titleEl.textContent = titles[viewName] || 'ATI V2 Threat Hunter Command';

    // Trigger View-Specific Data Loaders
    if (viewName === 'dashboard') loadDashboardData();
    else if (viewName === 'cves') loadCves();
    else if (viewName === 'osint') loadOsintData();
    else if (viewName === 'iot-ot') loadIotData();
    else if (viewName === 'reports') loadReportsView();
    else if (viewName === 'assets') loadAssetsView();
    else if (viewName === 'system') loadSystemInfo();
}

function setupLiveClock() {
    const clockEl = document.getElementById('live-clock');
    const updateClock = () => {
        const now = new Date();
        const options = {
            timeZone: 'Asia/Kolkata',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        };
        const istTime = new Intl.DateTimeFormat('en-IN', options).format(now);
        if (clockEl) {
            clockEl.textContent = `${istTime} IST`;
        }
    };
    updateClock();
    setInterval(updateClock, 1000);
}

// ==============================================================================
// 1. DASHBOARD VIEW CONTROLLER
// ==============================================================================
async function loadDashboardData() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();

        // Safe KPI Update
        const setTxt = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = (val !== undefined && val !== null) ? val : 0;
        };

        setTxt('kpi-total', stats.total_cves);
        setTxt('kpi-critical', stats.critical_count);
        setTxt('kpi-pocs', stats.public_poc_count);
        setTxt('kpi-analyzed', stats.analyzed_count);

        // Render Top Priority Threats
        renderTopThreats(stats.top_threats || []);

        // Render Severity Breakdown Bars
        renderSeverityBars(stats);

        // Render Keyword Cloud
        renderKeywordCloud(stats.keyword_distribution || {});

    } catch (err) {
        console.error('Failed loading dashboard stats:', err);
        const threatsBody = document.getElementById('dashboard-threats-body');
        if (threatsBody) {
            threatsBody.innerHTML = `<tr><td colspan="6" class="text-center text-crimson">Failed loading intelligence: ${escapeHtml(err.message)}</td></tr>`;
        }
    }
}

function renderTopThreats(threats) {
    const tbody = document.getElementById('dashboard-threats-body');
    if (!tbody) return;

    if (!threats || threats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No high priority threats found in local database.</td></tr>';
        return;
    }

    tbody.innerHTML = threats.map(t => {
        const epssPct = (t.epss_score !== null && t.epss_score !== undefined) ? (Number(t.epss_score) * 100).toFixed(1) + '%' : 'NA';
        const vendorProd = [t.affected_vendor, t.affected_product].filter(x => x && x !== 'Unknown' && x !== 'None').join(' / ') || 'General / Unknown';
        
        let pocBadge = '<span class="badge badge-low">No Public PoC</span>';
        if (t.has_public_poc) {
            pocBadge = '<span class="badge badge-crimson">🔥 Weaponized</span>';
        } else if (t.has_nuclei) {
            pocBadge = '<span class="badge badge-purple">⚡ Nuclei</span>';
        } else if (t.has_metasploit) {
            pocBadge = '<span class="badge badge-amber">🛡️ MSF</span>';
        }

        const aiSummary = t.recommended_action || t.ai_summary || 'Analysis pending...';

        return `
            <tr>
                <td>
                    <strong class="cve-id-link" style="cursor:pointer; color:var(--accent-cyan);" onclick="openCveModal('${escapeJs(t.cve_id)}')">${escapeHtml(t.cve_id)}</strong>
                </td>
                <td>
                    <span class="badge ${getSeverityBadgeClass(t.severity)}">${escapeHtml(t.severity || 'Unknown')} (${t.cvss_v3_score || 'N/A'})</span>
                </td>
                <td>
                    <span class="epss-pill" style="font-family:var(--font-mono); font-weight:600; color:var(--accent-cyan);">${epssPct}</span>
                </td>
                <td style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(vendorProd)}">
                    ${escapeHtml(vendorProd)}
                </td>
                <td>
                    ${pocBadge}
                </td>
                <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(aiSummary)}">
                    ${escapeHtml(aiSummary)}
                </td>
            </tr>
        `;
    }).join('');
}

function renderSeverityBars(stats) {
    const container = document.getElementById('severity-bars-container');
    if (!container) return;

    const total = (stats.critical_count || 0) + (stats.high_count || 0) + (stats.medium_count || 0) + (stats.low_count || 0) || 1;
    
    const items = [
        { label: 'Critical (CVSS 9.0 - 10.0)', count: stats.critical_count || 0, color: 'critical' },
        { label: 'High (CVSS 7.0 - 8.9)', count: stats.high_count || 0, color: 'high' },
        { label: 'Medium (CVSS 4.0 - 6.9)', count: stats.medium_count || 0, color: 'medium' },
        { label: 'Low (CVSS 0.1 - 3.9)', count: stats.low_count || 0, color: 'low' }
    ];

    container.innerHTML = items.map(item => {
        const pct = Math.round((item.count / total) * 100);
        return `
            <div class="severity-bar-item">
                <div class="severity-bar-header">
                    <span>${item.label}</span>
                    <span class="text-muted">${item.count} (${pct}%)</span>
                </div>
                <div class="severity-bar-track">
                    <div class="severity-bar-fill ${item.color}" style="width: ${pct}%;"></div>
                </div>
            </div>
        `;
    }).join('');
}

function renderKeywordCloud(keywords) {
    const container = document.getElementById('keyword-cloud-container');
    if (!container) return;

    const entries = Object.entries(keywords || {});
    if (entries.length === 0) {
        container.innerHTML = '<span class="text-muted" style="font-size:12px;">No attack vector keywords extracted yet.</span>';
        return;
    }

    container.innerHTML = entries.map(([kw, count]) => `
        <span class="keyword-tag" onclick="filterByKeyword('${escapeJs(kw)}')">
            ${escapeHtml(kw)} <strong style="color:var(--accent-cyan);">(${count})</strong>
        </span>
    `).join('');
}

function filterByKeyword(keyword) {
    state.cves.keyword = keyword;
    window.location.hash = 'cves';
    showToast(`Filtering CVEs by keyword: ${keyword}`);
}

// ==============================================================================
// 2. CVE EXPLORER VIEW CONTROLLER
// ==============================================================================
async function loadCves() {
    const tableBody = document.getElementById('cve-table-body');
    tableBody.innerHTML = '<tr><td colspan="7" class="text-center">Loading intelligence records...</td></tr>';

    const params = new URLSearchParams({
        page: state.cves.page,
        limit: state.cves.limit,
        sort_by: state.cves.sortBy,
        sort_order: state.cves.sortOrder
    });

    if (state.cves.search) params.append('search', state.cves.search);
    if (state.cves.severity && state.cves.severity !== 'all') params.append('severity', state.cves.severity);
    if (state.cves.hasPoc) params.append('has_public_poc', 'true');
    if (state.cves.isCisa) params.append('is_cisa_kev', 'true');
    if (state.cves.isIot) params.append('is_iot_ot', 'true');
    if (state.cves.isOsint) params.append('is_osint', 'true');
    if (state.cves.isAnalyzed) params.append('is_analyzed', 'true');
    if (state.cves.hasIocs) params.append('has_iocs', 'true');
    if (state.cves.keyword) params.append('keyword', state.cves.keyword);

    try {
        const res = await fetch(`/api/cves?${params.toString()}`);
        const data = await res.json();

        state.cves.total = data.total;
        renderCveTable(data.items);
        updatePagination(data);
    } catch (err) {
        tableBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">Error loading CVEs: ${err}</td></tr>`;
    }
}

function renderCveTable(items) {
    const tableBody = document.getElementById('cve-table-body');
    if (!items || items.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="7" class="text-center">No CVEs match the selected filter criteria.</td></tr>';
        return;
    }

    tableBody.innerHTML = items.map(item => {
        const hasEpss = (item.epss_score !== null && item.epss_score !== undefined);
        const epssPercent = hasEpss ? Math.round(Number(item.epss_score) * 100) : 0;
        const epssLabel = hasEpss ? `${(Number(item.epss_score) * 100).toFixed(1)}%` : 'NA';
        return `
            <tr>
                <td>
                    <strong style="color:var(--accent-cyan); font-family:var(--font-mono); cursor:pointer;" onclick="openCveModal('${item.cve_id}')">
                        ${item.cve_id}
                    </strong>
                </td>
                <td>
                    <span class="badge ${getSeverityBadgeClass(item.severity)}">${item.severity || 'Unknown'}</span>
                    <span style="font-family:var(--font-mono); font-size:11px; margin-left:4px;">${item.cvss_v3_score || '0.0'}</span>
                </td>
                <td>
                    <div class="epss-bar-container">
                        <div class="epss-bar">
                            <div class="epss-fill" style="width:${Math.min(epssPercent, 100)}%;"></div>
                        </div>
                        <span style="font-size:11px; font-family:var(--font-mono);">${epssLabel}</span>
                    </div>
                </td>
                <td>
                    <div><strong>${escapeHtml(item.affected_vendor || 'Unknown')}</strong></div>
                    <div style="font-size:11px; color:var(--text-muted);">${escapeHtml(item.affected_product || 'Unknown')}</div>
                </td>
                <td>
                    <div style="display:flex; gap:4px; flex-wrap:wrap;">
                        ${item.is_cisa_kev ? `<span class="badge badge-crimson" title="Active In-The-Wild Exploitation cataloged by CISA${item.cisa_date_added ? ' (' + item.cisa_date_added + ')' : ''}">🚨 CISA KEV${item.cisa_date_added ? ' (' + formatExploitDate(item.cisa_date_added) + ')' : ''}</span>` : ''}
                        ${item.has_nuclei ? '<span class="badge badge-cyan">Nuclei</span>' : ''}
                        ${item.has_metasploit ? '<span class="badge badge-purple">MSF</span>' : ''}
                        ${item.has_public_poc && !item.has_nuclei && !item.has_metasploit ? '<span class="badge badge-high">PoC</span>' : ''}
                        ${item.ioc_count ? `<span class="badge badge-amber" title="${item.ioc_count} Threat IoCs verified">🧬 ${item.ioc_count} IoCs</span>` : ''}
                        ${!item.is_cisa_kev && !item.has_public_poc && !item.ioc_count ? '<span style="color:var(--text-dim); font-size:11px;">None</span>' : ''}
                    </div>
                </td>
                <td>
                    ${item.is_analyzed 
                        ? '<span class="badge badge-emerald">✓ Analyzed</span>' 
                        : '<span style="color:var(--text-dim); font-size:11px;">Pending</span>'}
                </td>
                <td>
                    <div style="display:flex; gap:6px;">
                        <button class="btn btn-xs btn-outline" onclick="openCveModal('${item.cve_id}')">Inspect</button>
                        ${!item.is_analyzed ? `<button class="btn btn-xs btn-primary" onclick="triggerAnalyze('${item.cve_id}')">AI Analyze</button>` : ''}
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

function updatePagination(data) {
    const infoEl = document.getElementById('pagination-info');
    const pageEl = document.getElementById('current-page-num');
    const prevBtn = document.getElementById('btn-prev-page');
    const nextBtn = document.getElementById('btn-next-page');

    const start = (data.page - 1) * data.limit + 1;
    const end = Math.min(data.page * data.limit, data.total);
    infoEl.textContent = `Showing ${data.total > 0 ? start : 0}-${end} of ${data.total} CVEs`;
    pageEl.textContent = `${data.page} / ${data.total_pages || 1}`;

    prevBtn.disabled = data.page <= 1;
    nextBtn.disabled = data.page >= data.total_pages;
}

// ==============================================================================
// 3. CVE DEEP-DIVE & POC LAB MODAL
// ==============================================================================
function closeCveModal() {
    const modal = document.getElementById('cve-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.style.display = 'none';
    }
}
window.closeCveModal = closeCveModal;

// ==============================================================================
// 3b. CISA DATABASE ENRICHMENT MODAL
// ==============================================================================
function openCisaEnrichModal() {
    const modal = document.getElementById('cisa-enrich-modal');
    if (modal) {
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
        updateCisaModalUI();
    }
}
window.openCisaEnrichModal = openCisaEnrichModal;

function closeCisaEnrichModal() {
    const modal = document.getElementById('cisa-enrich-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.style.display = 'none';
    }
}
window.closeCisaEnrichModal = closeCisaEnrichModal;

function updateCisaModalUI() {
    const selected = document.querySelector('input[name="cisa_severity_scope"]:checked')?.value || 'medium_plus';
    const labelMed = document.getElementById('label-scope-medium');
    const labelAll = document.getElementById('label-scope-all');
    if (labelMed && labelAll) {
        if (selected === 'medium_plus') {
            labelMed.style.borderColor = 'var(--accent-cyan)';
            labelMed.style.background = 'rgba(6, 182, 212, 0.08)';
            labelAll.style.borderColor = 'var(--border-color)';
            labelAll.style.background = 'var(--bg-surface)';
        } else {
            labelAll.style.borderColor = 'var(--accent-cyan)';
            labelAll.style.background = 'rgba(6, 182, 212, 0.08)';
            labelMed.style.borderColor = 'var(--border-color)';
            labelMed.style.background = 'var(--bg-surface)';
        }
    }
}
window.updateCisaModalUI = updateCisaModalUI;

async function startCisaEnrichment() {
    const severityScope = document.querySelector('input[name="cisa_severity_scope"]:checked')?.value || 'medium_plus';
    const timeScope = document.getElementById('cisa-enrich-timeframe')?.value || 'this_month';
    const btn = document.getElementById('btn-start-cisa-enrich');

    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Initiating...';
    }

    try {
        const res = await fetch('/api/cisa/enrich', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ severity_scope: severityScope, time_scope: timeScope })
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || 'Failed to start enrichment');
        }

        closeCisaEnrichModal();
        showToast('⚡ CISA Technical Enrichment started! Streaming live logs...');
        navigateTo('scans');
        window.location.hash = 'scans';

    } catch (err) {
        showToast(`Enrichment failed: ${err.message}`, 'crimson');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = '⚡ Start Technical Enrichment';
        }
    }
}
window.startCisaEnrichment = startCisaEnrichment;

function copyModalCveId(btn) {
    const titleEl = document.getElementById('modal-cve-id');
    if (titleEl && titleEl.textContent && titleEl.textContent !== 'CVE-XXXX-YYYY') {
        const cve = titleEl.textContent.trim();
        copyToClipboard(cve);
        if (btn) {
            const orig = btn.innerHTML;
            btn.innerHTML = '✓ Copied';
            btn.style.borderColor = 'var(--accent-emerald)';
            btn.style.color = 'var(--accent-emerald)';
            setTimeout(() => {
                btn.innerHTML = orig;
                btn.style.borderColor = '';
                btn.style.color = '';
            }, 2000);
        }
    }
}
window.copyModalCveId = copyModalCveId;

function copyPocCodeFromModal(btn) {
    const codeEl = document.getElementById('modal-poc-code');
    if (!codeEl) {
        showToast('No PoC code available to copy', 'crimson');
        return;
    }
    const text = codeEl.innerText || codeEl.textContent || '';
    if (!text.trim()) {
        showToast('PoC code is empty', 'crimson');
        return;
    }
    copyToClipboard(text);
    if (btn) {
        const orig = btn.innerHTML;
        btn.classList.add('copied');
        btn.innerHTML = '✓ Copied!';
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.innerHTML = orig;
        }, 2000);
    }
}
window.copyPocCodeFromModal = copyPocCodeFromModal;

function copyDirectValue(btn) {
    if (!btn) return;
    const val = btn.getAttribute('data-value');
    if (val) {
        copyToClipboard(val);
        const orig = btn.innerHTML;
        btn.innerHTML = '✓';
        btn.style.borderColor = 'var(--accent-emerald)';
        btn.style.color = 'var(--accent-emerald)';
        setTimeout(() => {
            btn.innerHTML = orig;
            btn.style.borderColor = '';
            btn.style.color = '';
        }, 1500);
    }
}
window.copyDirectValue = copyDirectValue;

function triggerAnalyzeFromModal() {
    const titleEl = document.getElementById('modal-cve-id');
    if (titleEl && titleEl.textContent && titleEl.textContent !== 'CVE-XXXX-YYYY') {
        triggerAnalyze(titleEl.textContent.trim());
    }
}
window.triggerAnalyzeFromModal = triggerAnalyzeFromModal;

function extractVulnVersionDataFromCurrent(data) {
    if (!data) return null;
    const sources = data.sources || [];
    const vulnSources = sources.filter(s => (s.exploit_status || '').toLowerCase() === 'vuln_version');
    const allCandidateSources = vulnSources.length > 0 ? vulnSources : sources.filter(s => (s.url || '').includes('/releases/tag/'));
    
    if (allCandidateSources.length === 0) return null;

    let fixedVersion = 'See advisory';
    let vulnRange = 'Prior to fixed release';
    
    const recAction = (data.analysis && data.analysis.recommended_action) ? data.analysis.recommended_action : '';
    const summary = (data.analysis && data.analysis.ai_summary) ? data.analysis.ai_summary : '';
    const fullText = `${data.affected_product || ''} ${summary} ${recAction}`;
    
    const mFix = fullText.match(/(?:version\s+|to\s+version\s+|fix(?:ed)?\s+in\s+)(?:v)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i) ||
                 fullText.match(/([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s+or\s+later/i);
    if (mFix) {
        fixedVersion = mFix[1];
        vulnRange = `< v${mFix[1]}`;
    }

    const vulnerableLinks = [];
    const seenVersions = new Set();

    for (const s of allCandidateSources) {
        const url = s.url || '';
        const mGh = url.match(/github\.com\/([^\/]+)\/([^\/]+)\/releases\/tag\/(v?[0-9a-zA-Z\.\-_]+)/i);
        if (mGh) {
            const owner = mGh[1];
            const repo = mGh[2];
            const tag = mGh[3];
            const cleanTag = tag.replace(/^v/, '');
            
            // Exclude fixed tag itself from vulnerable downloads list
            const isFixedTag = (cleanTag === fixedVersion || tag === `v${fixedVersion}`);
            if (isFixedTag) {
                continue;
            }
            if (seenVersions.has(tag)) continue;
            seenVersions.add(tag);

            vulnerableLinks.push({
                version: tag,
                source: `GitHub Repository (${owner}/${repo})`,
                url: url,
                direct_download_zip: `https://github.com/${owner}/${repo}/archive/refs/tags/${tag}.zip`,
                archive_mirror_url: `https://web.archive.org/web/*/${url}`,
                clone_command: `git clone --branch ${tag} --depth 1 https://github.com/${owner}/${repo}.git`
            });
        } else if (url.includes('hub.docker.com')) {
            const vName = `${data.affected_product || 'Container'} (Container)`;
            if (!seenVersions.has(vName)) {
                seenVersions.add(vName);
                vulnerableLinks.push({
                    version: vName,
                    source: 'Docker Hub Registry',
                    url: url,
                    clone_command: `docker pull ${(data.affected_vendor || 'docker').toLowerCase()}/${(data.affected_product || 'app').toLowerCase().replace(/[^a-z0-9]+/g, '-')}:vulnerable`
                });
            }
        }
    }

    // If only fixed tags were present, list them as reference releases
    if (vulnerableLinks.length === 0 && allCandidateSources.length > 0) {
        for (const s of allCandidateSources) {
            const url = s.url || '';
            const mGh = url.match(/github\.com\/([^\/]+)\/([^\/]+)\/releases\/tag\/(v?[0-9a-zA-Z\.\-_]+)/i);
            if (mGh) {
                const tag = mGh[3];
                vulnerableLinks.push({
                    version: `${tag} (Reference Release)`,
                    source: `GitHub Repository (${mGh[1]}/${mGh[2]})`,
                    url: url,
                    direct_download_zip: `https://github.com/${mGh[1]}/${mGh[2]}/archive/refs/tags/${tag}.zip`,
                    archive_mirror_url: `https://web.archive.org/web/*/${url}`,
                    clone_command: `git clone --branch ${tag} --depth 1 https://github.com/${mGh[1]}/${mGh[2]}.git`
                });
            }
        }
    }

    return {
        cve_id: data.cve_id,
        vendor: data.affected_vendor || 'Unknown',
        product: data.affected_product || 'Unknown',
        fixed_version: fixedVersion,
        vulnerable_range: vulnRange,
        vulnerable_links: vulnerableLinks,
        archive_sources: [
            {
                name: "Wayback Machine Historical Mirror",
                url: `https://web.archive.org/web/*/http://www.oldversion.com/search?q=${encodeURIComponent(data.affected_product || '')}`
            },
            {
                name: "SourceForge Software Archives",
                url: `https://sourceforge.net/directory/?q=${encodeURIComponent(data.affected_product || '')}`
            }
        ]
    };
}
window.extractVulnVersionDataFromCurrent = extractVulnVersionDataFromCurrent;

async function findVulnVersionFromModal() {
    const titleEl = document.getElementById('modal-cve-id');
    const btn = document.getElementById('modal-find-vuln-btn');
    if (!titleEl || !titleEl.textContent || titleEl.textContent === 'CVE-XXXX-YYYY') return;

    const cveId = titleEl.textContent.trim();
    const origHtml = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '⏳ Searching...';
    }

    try {
        const existingPanel = document.getElementById('modal-vuln-version-panel');
        if (existingPanel) {
            existingPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        showToast(`Locating vulnerable versions & archives for ${cveId}...`);

        let freshData = null;
        try {
            const res = await fetch(`/api/cves/${encodeURIComponent(cveId)}/vuln-version`, { method: 'POST' });
            if (res.ok) {
                freshData = await res.json();
            }
        } catch (fetchErr) {
            // Handled via local fallback below
        }

        if (freshData && freshData.vulnerable_links && freshData.vulnerable_links.length > 0) {
            renderVulnVersionSection(freshData);
            const panel = document.getElementById('modal-vuln-version-panel');
            if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            showToast(`Discovered ${freshData.vulnerable_links.length} vulnerable release/reproduction source(s)!`, 'emerald');
        } else {
            // Graceful fallback to currently loaded sources in the modal
            const localData = extractVulnVersionDataFromCurrent(window._currentCveData);
            if (localData && localData.vulnerable_links && localData.vulnerable_links.length > 0) {
                renderVulnVersionSection(localData);
                const panel = document.getElementById('modal-vuln-version-panel');
                if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                showToast(`Loaded ${localData.vulnerable_links.length} vulnerable version source(s) from technical references!`, 'emerald');
            } else {
                showToast(`No vulnerable version artifacts found. Restart server (python main.py --gui) to query upstream APIs.`, 'amber');
            }
        }
    } catch (err) {
        const localData = extractVulnVersionDataFromCurrent(window._currentCveData);
        if (localData && localData.vulnerable_links && localData.vulnerable_links.length > 0) {
            renderVulnVersionSection(localData);
            const panel = document.getElementById('modal-vuln-version-panel');
            if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            showToast(`Loaded ${localData.vulnerable_links.length} vulnerable version source(s) from references!`, 'emerald');
        } else {
            showToast(`Vulnerable version discovery pending server restart.`, 'amber');
        }
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = origHtml;
        }
    }
}
window.findVulnVersionFromModal = findVulnVersionFromModal;

function renderVulnVersionSection(data) {
    const bodyEl = document.getElementById('modal-content-body');
    if (!bodyEl) return;

    const existing = document.getElementById('modal-vuln-version-panel');
    if (existing) existing.remove();

    const links = data.vulnerable_links || [];
    const archives = data.archive_sources || [];

    const sectionHtml = `
        <div id="modal-vuln-version-panel" class="cve-box" style="border:1px solid rgba(245,158,11,0.4); background:rgba(245,158,11,0.04); margin-bottom:16px; animation:fadeIn 0.3s ease;">
            <div class="cve-box-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(245,158,11,0.2); padding-bottom:8px;">
                <div class="cve-box-title" style="color:var(--accent-amber); display:flex; align-items:center; gap:8px;">
                    <span>📦 Vulnerable Version & Lab Reproduction Setup</span>
                    <span class="badge badge-amber" style="font-size:10px;">Lab Validation</span>
                </div>
                <div style="font-size:11px; color:var(--text-dim);">
                    Fixed in: <strong style="color:var(--accent-emerald);">${escapeHtml(data.fixed_version || 'Unknown')}</strong>
                </div>
            </div>
            <div style="padding:10px 4px 4px 4px;">
                <div style="display:flex; gap:10px; margin-bottom:12px; flex-wrap:wrap; font-size:12px;">
                    <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.06); padding:4px 10px; border-radius:6px;">
                        <span style="color:var(--text-dim);">Vulnerable Window:</span> <strong style="color:var(--accent-amber);">${escapeHtml(data.vulnerable_range || 'N/A')}</strong>
                    </div>
                    <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.06); padding:4px 10px; border-radius:6px;">
                        <span style="color:var(--text-dim);">Software:</span> <strong style="color:var(--text-main);">${escapeHtml(data.vendor)} ${escapeHtml(data.product)}</strong>
                    </div>
                </div>

                ${links.length > 0 ? `
                    <div style="font-size:11px; font-weight:600; color:var(--text-secondary); margin-bottom:6px;">Available Vulnerable Builds & Sources:</div>
                    <div style="display:flex; flex-direction:column; gap:8px;">
                        ${links.map(l => `
                            <div style="background:rgba(0,0,0,0.25); border:1px solid rgba(255,255,255,0.05); padding:8px 10px; border-radius:6px; display:flex; flex-direction:column; gap:6px;">
                                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;">
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <span class="badge badge-amber" style="font-size:10px; font-weight:bold;">${escapeHtml(l.version)}</span>
                                        <span style="color:var(--text-dim); font-size:11px;">${escapeHtml(l.source || '')}</span>
                                    </div>
                                    <div style="display:flex; gap:6px; align-items:center;">
                                        ${l.url ? `<a href="${escapeHtml(l.url)}" target="_blank" class="btn btn-xs btn-outline" style="text-decoration:none; font-size:10.5px;">🌐 Release Link</a>` : ''}
                                        ${l.direct_download_zip ? `<a href="${escapeHtml(l.direct_download_zip)}" target="_blank" class="btn btn-xs btn-primary" style="text-decoration:none; font-size:10.5px; background:var(--accent-amber); border-color:var(--accent-amber); color:#000;">⬇️ ZIP</a>` : ''}
                                        ${l.archive_mirror_url ? `<a href="${escapeHtml(l.archive_mirror_url)}" target="_blank" class="btn btn-xs btn-outline" style="text-decoration:none; font-size:10.5px; border-color:var(--accent-cyan); color:var(--accent-cyan);" title="Internet Archive Snapshot">🏛️ Wayback</a>` : ''}
                                    </div>
                                </div>
                                ${l.clone_command ? `
                                    <div style="display:flex; align-items:center; justify-content:space-between; background:rgba(0,0,0,0.4); padding:4px 8px; border-radius:4px; font-family:monospace; font-size:10.5px; color:var(--accent-cyan); overflow:hidden;">
                                        <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(l.clone_command)}</span>
                                        <button class="btn btn-xs" onclick="navigator.clipboard.writeText('${escapeHtml(l.clone_command)}'); showToast('Command copied to clipboard!', 'emerald');" style="padding:1px 6px; font-size:9.5px; margin-left:8px; flex-shrink:0;">📋</button>
                                    </div>
                                ` : ''}
                            </div>
                        `).join('')}
                    </div>
                ` : `
                    <div style="font-size:11.5px; color:var(--text-dim); padding:8px;">No direct repository releases were mapped. Check the historical archives below.</div>
                `}

                ${archives.length > 0 ? `
                    <div style="margin-top:10px; padding-top:8px; border-top:1px solid rgba(255,255,255,0.05); display:flex; gap:12px; font-size:11px; flex-wrap:wrap;">
                        <span style="color:var(--text-dim);">Historical Repositories:</span>
                        ${archives.map(a => `<a href="${escapeHtml(a.url)}" target="_blank" style="color:var(--accent-cyan); text-decoration:none;">🏛️ ${escapeHtml(a.name)} ↗</a>`).join('')}
                    </div>
                ` : ''}
            </div>
        </div>
    `;

    bodyEl.insertAdjacentHTML('afterbegin', sectionHtml);
}
window.renderVulnVersionSection = renderVulnVersionSection;

async function openCveModal(cveId) {
    const modal = document.getElementById('cve-modal');
    const titleEl = document.getElementById('modal-cve-id');
    const badgesEl = document.getElementById('modal-badges-container');
    const bodyEl = document.getElementById('modal-content-body');
    const exportCsvBtn = document.getElementById('modal-export-csv');
    const exportStixBtn = document.getElementById('modal-export-stix');

    modal.classList.remove('hidden');
    modal.style.display = 'flex';
    titleEl.textContent = cveId;
    badgesEl.innerHTML = '';
    bodyEl.innerHTML = '<div class="loading-spinner">Loading comprehensive intelligence dossier...</div>';

    if (exportCsvBtn) exportCsvBtn.href = `/api/iocs/export?format=csv&cve_id=${encodeURIComponent(cveId)}`;
    if (exportStixBtn) exportStixBtn.href = `/api/iocs/export?format=stix&cve_id=${encodeURIComponent(cveId)}`;

    try {
        const res = await fetch(`/api/cves/${encodeURIComponent(cveId)}`);
        if (!res.ok) throw new Error('CVE not found in database.');
        const data = await res.json();

        // Modal Badges (Top Header)
        const modalEpss = (data.epss_score !== null && data.epss_score !== undefined) 
            ? `${(Number(data.epss_score) * 100).toFixed(1)}%` 
            : 'N/A';
        const epssPercentile = (data.epss_score !== null && data.epss_score !== undefined)
            ? (Number(data.epss_score) >= 0.5 ? '🔥 High Risk' : (Number(data.epss_score) >= 0.1 ? '⚡ Moderate' : 'Normal'))
            : '';

        badgesEl.innerHTML = `
            <span class="badge ${getSeverityBadgeClass(data.severity)}">${data.severity || 'Unknown'} (CVSS ${data.cvss_v3_score || 'N/A'})</span>
            <span class="badge badge-cyan" title="FIRST.org Exploit Prediction Probability">EPSS: ${modalEpss} ${epssPercentile ? `(${epssPercentile})` : ''}</span>
            ${data.cwe ? `<span class="badge badge-low" style="font-family:var(--font-mono);">${escapeHtml(data.cwe)}</span>` : ''}
            ${data.is_cisa_kev ? '<span class="badge badge-crimson" style="animation:pulse 2s infinite;">🚨 CISA KEV</span>' : ''}
            ${data.has_public_poc ? '<span class="badge badge-purple">🔥 Weaponized PoC</span>' : ''}
            ${data.ransomware_campaign ? `<span class="badge badge-crimson">☣️ ${escapeHtml(data.ransomware_campaign)}</span>` : ''}
            ${data.is_iot_ot ? '<span class="badge badge-purple">🏭 IoT / OT</span>' : ''}
        `;

        const analysis = data.analysis;
        const pocCode = (analysis && analysis.poc_recreation_steps && analysis.poc_recreation_steps !== 'None') 
            ? analysis.poc_recreation_steps 
            : '';

        const iocs = data.iocs || [];
        const sources = data.sources || [];
        const pubDate = data.published_date ? data.published_date.slice(0, 10) : 'N/A';
        const modDate = data.updated_date ? data.updated_date.slice(0, 10) : 'N/A';

        // 2-Column Responsive Widescreen Grid
        bodyEl.innerHTML = `
            <div class="cve-dossier-grid">
                <!-- LEFT PANEL: Strategic Intel, CISA Mandate, AI Summary & Action -->
                <div class="cve-panel-column">
                    
                    <!-- 4-Card Quick Telemetry Grid -->
                    <div class="cve-telemetry-grid">
                        <div class="cve-telemetry-card">
                            <span class="t-label">AFFECTED TARGET</span>
                            <span class="t-val" title="${escapeHtml(data.affected_vendor || 'Unknown')} - ${escapeHtml(data.affected_product || 'Unknown')}">
                                ${escapeHtml(data.affected_vendor || 'Unknown')} / ${escapeHtml(data.affected_product || 'Unknown')}
                            </span>
                            <span class="t-sub">${escapeHtml(data.device_type || 'Software / Appliance')}</span>
                        </div>
                        <div class="cve-telemetry-card">
                            <span class="t-label">CVSS 3.1 VECTOR</span>
                            <span class="t-val" style="color:var(--accent-cyan); font-family:var(--font-mono); font-size:12px;" title="${escapeHtml(data.cvss_vector || 'N/A')}">
                                ${data.cvss_vector ? escapeHtml(data.cvss_vector.replace('CVSS:3.1/', '')) : 'N/A'}
                            </span>
                            <span class="t-sub">CVSS Base: ${data.cvss_v3_score || 'N/A'} (${data.severity || 'Unknown'})</span>
                        </div>
                        <div class="cve-telemetry-card">
                            <span class="t-label">EPSS EXPLOIT PROBABILITY</span>
                            <span class="t-val" style="color:${Number(data.epss_score) >= 0.3 ? 'var(--accent-crimson)' : 'var(--accent-cyan)'};">
                                ${modalEpss}
                            </span>
                            <span class="t-sub">Exploit Discovery: ${data.has_nuclei ? 'Nuclei' : (data.has_metasploit ? 'Metasploit' : (data.has_public_poc ? 'Public PoC' : 'None'))}</span>
                        </div>
                        <div class="cve-telemetry-card">
                            <span class="t-label">INTELLIGENCE TIMELINE</span>
                            <span class="t-val" style="font-size:12.5px;">Published: ${pubDate}</span>
                            <span class="t-sub">Last Modified: ${modDate}</span>
                        </div>
                    </div>

                    <!-- CISA KEV ACTIVE EXPLOITATION ALERT (IF APPLICABLE) -->
                    ${data.is_cisa_kev || data.cisa_due_date ? `
                    <div class="cve-box cve-box-cisa">
                        <div class="cve-box-header">
                            <div class="cve-box-title" style="color:var(--accent-crimson);">
                                🚨 Active In-The-Wild Exploitation (CISA KEV)
                            </div>
                            <div style="display:flex; gap:6px; flex-wrap:wrap;">
                                ${data.cisa_date_added ? `<span class="badge badge-crimson" style="font-size:10px;">Added: ${formatExploitDate(data.cisa_date_added)}</span>` : ''}
                                ${data.cisa_due_date ? `<span class="badge badge-crimson" style="font-size:10px; font-weight:700;">Due: ${escapeHtml(data.cisa_due_date)}</span>` : ''}
                            </div>
                        </div>
                        <p style="font-size:12px; color:var(--text-main); line-height:1.5; margin:4px 0 0 0;">
                            <strong>Mandatory Remediation Directive:</strong> ${escapeHtml(data.cisa_required_action || 'Apply vendor mitigations immediately or disconnect internet exposure.')}
                        </p>
                        ${data.ransomware_campaign ? `
                            <p style="font-size:11.5px; color:#FCA5A5; margin-top:6px;">
                                <strong>Known Threat Groups / Ransomware:</strong> ${escapeHtml(data.ransomware_campaign)}
                            </p>
                        ` : ''}
                    </div>` : ''}

                    <!-- AI EXECUTIVE THREAT SUMMARY -->
                    <div class="cve-box cve-box-ai">
                        <div class="cve-box-header">
                            <div class="cve-box-title" style="color:var(--accent-cyan);">
                                🧠 AI Executive Threat Summary
                            </div>
                            <span class="badge ${analysis && analysis.is_analyzed ? 'badge-emerald' : 'badge-low'}" style="font-size:10px;">
                                ${analysis && analysis.is_analyzed ? 'AI Verified' : 'Awaiting Analysis'}
                            </span>
                        </div>
                        <p style="font-size:13px; line-height:1.65; color:#E2E8F0; margin:4px 0 0 0;">
                            ${analysis && analysis.ai_summary 
                                ? escapeHtml(analysis.ai_summary) 
                                : '<em>Comprehensive AI intelligence pending. Click "Re-Analyze with AI" in the header to trigger multi-provider cascade synthesis.</em>'}
                        </p>
                    </div>

                    <!-- RECOMMENDED REMEDIATION & ACTION REQUIRED -->
                    <div class="cve-box cve-box-action">
                        <div class="cve-box-header">
                            <div class="cve-box-title" style="color:var(--accent-amber);">
                                ✅ Recommended Remediation & Action Required
                            </div>
                        </div>
                        <p style="font-size:12.5px; line-height:1.55; color:var(--text-main); margin:2px 0 0 0;">
                            ${analysis && analysis.recommended_action 
                                ? escapeHtml(analysis.recommended_action) 
                                : 'Review vendor advisory, isolate exposed interfaces, and apply latest security patches immediately.'}
                        </p>
                    </div>

                    <!-- THREAT KEYWORDS & ATT&CK TAGS -->
                    ${analysis && analysis.keywords && analysis.keywords !== 'None' ? `
                    <div class="cve-box" style="padding:10px 14px;">
                        <div class="cve-box-header" style="margin-bottom:6px;">
                            <span style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-dim);">Threat Attributes & Attack Vectors</span>
                        </div>
                        <div style="display:flex; flex-wrap:wrap; gap:6px;">
                            ${analysis.keywords.split(',').map(k => `<span class="badge badge-low" style="font-size:11px;">${escapeHtml(k.trim())}</span>`).join('')}
                        </div>
                    </div>` : ''}

                </div>

                <!-- RIGHT PANEL: Exploit PoC Lab, Verified IoCs, Correlated Sources -->
                <div class="cve-panel-column">
                    
                    <!-- WEAPONIZATION & POC RECREATION LAB -->
                    <div class="cve-box cve-box-poc">
                        <div class="cve-box-header">
                            <div class="cve-box-title" style="color:#A78BFA;">
                                🛠️ Exploit PoC & Weaponization Lab
                            </div>
                            ${pocCode ? `
                                <button type="button" class="btn btn-xs btn-outline btn-copy-poc" onclick="copyPocCodeFromModal(this)" title="Copy Exploit PoC Payload">
                                    📋 Copy Payload
                                </button>
                            ` : ''}
                        </div>
                        ${pocCode ? `
                            <pre class="cve-poc-pre"><code id="modal-poc-code">${escapeHtml(pocCode)}</code></pre>
                        ` : `
                            <div style="padding:16px; background:#050811; border:1px dashed rgba(255,255,255,0.08); border-radius:8px; font-size:12px; color:var(--text-dim); text-align:center;">
                                No direct weaponized proof-of-concept payload cataloged in current exploit feeds.
                            </div>
                        `}
                    </div>

                    <!-- VERIFIED INDICATORS OF COMPROMISE (IOCS) -->
                    <div class="cve-box">
                        <div class="cve-box-header">
                            <div class="cve-box-title" style="color:var(--text-main);">
                                🛡️ Verified Indicators of Compromise (${iocs.length})
                            </div>
                            ${iocs.length > 0 ? `
                                <div style="display:flex; gap:6px;">
                                    <a href="/api/iocs/export?format=csv&cve_id=${encodeURIComponent(data.cve_id)}" target="_blank" class="btn btn-xs btn-outline" style="text-decoration:none; font-size:10px;">CSV</a>
                                    <a href="/api/iocs/export?format=stix&cve_id=${encodeURIComponent(data.cve_id)}" target="_blank" class="btn btn-xs btn-outline" style="text-decoration:none; font-size:10px;">STIX</a>
                                </div>
                            ` : ''}
                        </div>

                        ${iocs.length > 0 ? `
                            <div class="cve-iocs-list">
                                ${iocs.map(ioc => `
                                    <div style="display:flex; justify-content:space-between; align-items:center; padding:7px 10px; border-bottom:1px solid rgba(255,255,255,0.04); font-size:11.5px; gap:8px;">
                                        <div style="display:flex; align-items:center; gap:8px; overflow:hidden;">
                                            <span class="badge ${ioc.ioc_type === 'sha256' ? 'badge-amber' : (ioc.ioc_type === 'ip' ? 'badge-cyan' : 'badge-purple')}" style="font-size:9.5px; text-transform:uppercase; flex-shrink:0;">
                                                ${ioc.ioc_type}
                                            </span>
                                            <code style="font-family:var(--font-mono); color:#38BDF8; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:260px;" title="${escapeHtml(ioc.ioc_value)}">
                                                ${escapeHtml(ioc.ioc_value)}
                                            </code>
                                            <button type="button" class="btn btn-xs btn-outline" style="padding:1px 5px; font-size:10px; flex-shrink:0;" onclick="copyDirectValue(this)" data-value="${escapeHtml(ioc.ioc_value)}">Copy</button>
                                        </div>
                                        <div style="display:flex; align-items:center; gap:6px; flex-shrink:0;">
                                            <span class="badge badge-low" style="font-size:9.5px;">${escapeHtml(ioc.source_feed || 'Feed')}</span>
                                            ${ioc.confidence ? `<span style="font-size:10.5px; color:var(--accent-emerald); font-weight:600;">${ioc.confidence}%</span>` : ''}
                                        </div>
                                    </div>
                                    ${ioc.details ? `<div style="padding:2px 10px 5px 10px; font-size:10.5px; color:var(--text-dim); border-bottom:1px solid rgba(255,255,255,0.03);">${escapeHtml(ioc.details)}</div>` : ''}
                                `).join('')}
                            </div>
                        ` : `
                            <div style="padding:10px 14px; background:rgba(255,255,255,0.02); border:1px dashed rgba(255,255,255,0.08); border-radius:6px; font-size:11.5px; color:var(--text-dim); display:flex; align-items:center; gap:8px;">
                                <span>ℹ️</span> No atomic file hashes, IPs or malicious URLs cataloged in ThreatFox/MalwareBazaar for this CVE.
                            </div>
                        `}
                    </div>

                    <!-- CORRELATED INTELLIGENCE SOURCES -->
                    <div class="cve-box">
                        <div class="cve-box-header">
                            <div class="cve-box-title" style="color:var(--text-main);">
                                🔗 Correlated Technical Proof Sources (${sources.length})
                            </div>
                        </div>
                        ${sources.length > 0 ? `
                            <div class="cve-sources-list">
                                ${sources.map(s => {
                                    const stat = (s.exploit_status || '').toLowerCase();
                                    const isOsint = (s.source_name || '').startsWith('OSINT:');
                                    const isUnverifiedPoc = stat === 'unverified_osint_poc' || (isOsint && s.is_poc_link);
                                    
                                    let badgeHtml = '';
                                    if (stat === 'blog_poc') {
                                        badgeHtml = '<span class="badge badge-purple" style="font-size:9px;" title="Technical Research Writeup with Working PoC">⚡ PoC</span> <span class="badge badge-cyan" style="font-size:9px;">📝 Blog</span>';
                                    } else if (stat === 'vuln_version') {
                                        badgeHtml = '<span class="badge badge-amber" style="font-size:9px;" title="Vulnerable or Fixed Product Version Distribution">📦 Vuln Version</span>';
                                    } else if (stat === 'blog') {
                                        badgeHtml = '<span class="badge badge-cyan" style="font-size:9px;" title="Technical Analysis Blog / Writeup">📝 Blog</span>';
                                    } else if (stat === 'vendor_fix') {
                                        badgeHtml = '<span class="badge badge-low" style="font-size:9px;" title="Official Vendor Security Advisory or Fix">🛡️ Vendor Fix</span>';
                                    } else if (isUnverifiedPoc) {
                                        badgeHtml = '<span class="badge badge-crimson" style="font-size:9px;" title="Unverified Internet PoC / Chatter">⚠️ Unverified PoC</span>';
                                    } else if (s.is_poc_link || stat === 'poc') {
                                        badgeHtml = '<span class="badge badge-purple" style="font-size:9px;">⚡ Verified PoC</span>';
                                    } else if (isOsint) {
                                        badgeHtml = `<span class="badge badge-cyan" style="font-size:9px;">${escapeHtml(s.source_name)}</span>`;
                                    } else {
                                        badgeHtml = `<span class="badge badge-low" style="font-size:9px;">${escapeHtml(s.source_name || 'Link')}</span>`;
                                    }

                                    let typeLabel = 'Advisory';
                                    if (stat === 'vuln_version') {
                                        typeLabel = 'Vuln Version';
                                    } else if (stat === 'blog_poc') {
                                        typeLabel = 'Research PoC';
                                    } else if (stat === 'blog') {
                                        typeLabel = 'Blog Writeup';
                                    } else if (stat === 'vendor_fix') {
                                        typeLabel = 'Vendor Advisory';
                                    } else if (isUnverifiedPoc) {
                                        typeLabel = 'Chatter';
                                    } else if (s.is_poc_link) {
                                        typeLabel = 'PoC Repo';
                                    }

                                    return `
                                        <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 10px; border-bottom:1px solid rgba(255,255,255,0.04); font-size:11.5px; gap:8px;">
                                            <div style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:flex; align-items:center; gap:6px;">
                                                ${badgeHtml}
                                                <a href="${escapeHtml(s.url)}" target="_blank" rel="noopener noreferrer" style="color:var(--accent-cyan); text-decoration:none;" title="${escapeHtml(s.url)}">
                                                    ${escapeHtml(s.url.length > 52 ? s.url.slice(0, 50) + '...' : s.url)}
                                                </a>
                                            </div>
                                            <span style="color:var(--text-dim); font-size:10.5px; flex-shrink:0;">
                                                ${typeLabel}
                                            </span>
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        ` : `
                            <p class="text-muted" style="padding:8px; font-size:11.5px;">No external reference links attached.</p>
                        `}
                    </div>

                </div>
            </div>
        `;

        window._currentCveData = data;
        const autoVulnData = extractVulnVersionDataFromCurrent(data);
        if (autoVulnData && autoVulnData.vulnerable_links && autoVulnData.vulnerable_links.length > 0) {
            renderVulnVersionSection(autoVulnData);
        }

    } catch (err) {
        bodyEl.innerHTML = `<p class="text-crimson">Error loading CVE details: ${err.message}</p>`;
    }
}

async function triggerAnalyze(cveId) {
    try {
        const res = await fetch(`/api/cves/${cveId}/analyze`, { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
            showToast(`Started AI analysis for ${cveId}`);
            navigateTo('scans');
        } else {
            showToast(`Error: ${data.detail}`, 'crimson');
        }
    } catch (err) {
        showToast(`Failed triggering analysis: ${err}`, 'crimson');
    }
}

// ==============================================================================
// 4. SCAN LAUNCHER & SSE STREAM
// ==============================================================================
function setupSSEStream() {
    if (state.scan.eventSource) {
        state.scan.eventSource.close();
    }

    const terminal = document.getElementById('scan-terminal-output');
    state.scan.eventSource = new EventSource('/api/scan/stream');

    state.scan.eventSource.onmessage = (event) => {
        if (!event.data || event.data.trim() === ': ping') return;
        
        const line = document.createElement('div');
        line.className = 'terminal-line';
        
        // Colorize lines based on prefix
        if (event.data.includes('[+]') || event.data.includes('SUCCESS')) {
            line.style.color = 'var(--accent-emerald)';
        } else if (event.data.includes('[-]') || event.data.includes('CRITICAL') || event.data.includes('ERROR')) {
            line.style.color = 'var(--accent-crimson)';
        } else if (event.data.includes('[*]') || event.data.includes('🚀')) {
            line.style.color = 'var(--accent-cyan)';
        } else if (event.data.includes('[?]')) {
            line.style.color = 'var(--accent-amber)';
        }

        line.textContent = event.data;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    };

    state.scan.eventSource.onerror = () => {
        // SSE reconnection handled automatic
    };
}

// ==============================================================================
// 4. SCAN & HUNT CONTROLLER
// ==============================================================================
async function executeScan() {
    if (state.scan.isRunning) {
        showToast('A threat hunt is already running! Please wait for completion.', 'crimson');
        return;
    }

    const preset = state.scan.selectedPreset || 'single';
    const cveInputRow = document.getElementById('row-cve-input');
    const isCveVisible = cveInputRow && !cveInputRow.classList.contains('hidden');
    const targetCve = (preset === 'single' || (preset === 'custom' && isCveVisible)) 
        ? (document.getElementById('scan-cve-id').value.trim() || null) 
        : null;

    const isCountEnabled = !!(document.getElementById('scan-count-enable') && document.getElementById('scan-count-enable').checked);
    const countVal = isCountEnabled ? (parseInt(document.getElementById('scan-count').value, 10) || 10) : null;

    const body = {
        mode: preset,
        cve_id: targetCve,
        exploit_find: document.getElementById('scan-exploit-find').checked,
        start_date: document.getElementById('scan-start-date').value || null,
        end_date: document.getElementById('scan-end-date').value || null,
        limit_enabled: isCountEnabled,
        count: countVal,
        cisa: document.getElementById('scan-cisa').checked,
        all_severity: document.getElementById('scan-all-sev').checked,
        iotot: document.getElementById('scan-iotot') ? document.getElementById('scan-iotot').checked : false,
        active_week_exploits: document.getElementById('scan-active-week') ? document.getElementById('scan-active-week').checked : false,
        in_wild_osint: document.getElementById('scan-in-wild') ? document.getElementById('scan-in-wild').checked : false
    };

    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const data = await res.json();
        if (res.ok) {
            showToast(`🎯 Threat Hunt '${preset.toUpperCase()}' started!`);
        } else {
            showToast(`Hunt initiation failed: ${data.detail}`, 'crimson');
        }
    } catch (err) {
        showToast(`Request failed: ${err}`, 'crimson');
    }
}

async function stopActiveScan() {
    try {
        const res = await fetch('/api/scan/stop', { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
            showToast('⏸️ Scan pausing gracefully... Current item will complete and progress is saved.', 'amber');
        } else {
            showToast(`Failed to pause scan: ${data.detail || 'Unknown error'}`, 'crimson');
        }
    } catch (err) {
        showToast(`Request failed: ${err}`, 'crimson');
    }
}

function runPresetScan(mode) {
    state.scan.selectedPreset = mode;
    navigateTo('scans');
    selectPresetCard(mode);
    executeScan();
}

function selectPresetCard(mode) {
    state.scan.selectedPreset = mode;
    document.querySelectorAll('.preset-card').forEach(card => {
        card.classList.toggle('active', card.getAttribute('data-mode') === mode);
    });

    const rowCve = document.getElementById('row-cve-input');
    const rowDates = document.getElementById('row-dates-input');
    const rowCount = document.getElementById('row-count-input');
    const extraToggles = document.getElementById('extra-custom-toggles');

    if (mode === 'single') {
        rowCve.classList.remove('hidden');
        rowDates.classList.add('hidden');
        rowCount.classList.add('hidden');
        if (extraToggles) extraToggles.classList.add('hidden');
    } else if (mode === 'custom') {
        rowCve.classList.remove('hidden');
        rowDates.classList.remove('hidden');
        rowCount.classList.remove('hidden');
        if (extraToggles) extraToggles.classList.remove('hidden');
    } else if (mode === 'date_audit' || mode === 'iotot') {
        rowCve.classList.add('hidden');
        rowDates.classList.remove('hidden');
        rowCount.classList.remove('hidden');
        if (extraToggles) extraToggles.classList.add('hidden');
    } else {
        rowCve.classList.add('hidden');
        rowDates.classList.add('hidden');
        rowCount.classList.remove('hidden');
        if (extraToggles) extraToggles.classList.add('hidden');
    }

    const countEnable = document.getElementById('scan-count-enable');
    const countWrapper = document.getElementById('count-input-wrapper');
    const countStatus = document.getElementById('count-status-label');
    if (countEnable && countWrapper) {
        countWrapper.style.opacity = countEnable.checked ? '1' : '0.4';
        countWrapper.style.pointerEvents = countEnable.checked ? 'auto' : 'none';
        if (countStatus) {
            countStatus.textContent = countEnable.checked ? 'Limit Active' : 'Default: Process All CVEs';
            countStatus.style.color = countEnable.checked ? 'var(--accent-cyan)' : 'var(--text-muted)';
        }
    }

    updateCustomCliPreview();
}

function updateCustomCliPreview() {
    const preset = state.scan.selectedPreset || 'single';
    let cmd = 'python main.py';

    const cve = (document.getElementById('scan-cve-id')?.value || '').trim();
    const start = document.getElementById('scan-start-date')?.value || '';
    const end = document.getElementById('scan-end-date')?.value || '';
    const isCountEnabled = !!(document.getElementById('scan-count-enable') && document.getElementById('scan-count-enable').checked);
    const countVal = document.getElementById('scan-count')?.value || '';
    const countStr = (isCountEnabled && countVal) ? ` --count ${countVal}` : '';

    const exploitFind = document.getElementById('scan-exploit-find')?.checked ?? true;
    const cisa = document.getElementById('scan-cisa')?.checked ?? false;
    const allSev = document.getElementById('scan-all-sev')?.checked ?? false;
    const iotot = document.getElementById('scan-iotot')?.checked ?? false;
    const activeWeek = document.getElementById('scan-active-week')?.checked ?? false;
    const inWild = document.getElementById('scan-in-wild')?.checked ?? false;

    if (preset === 'single') {
        if (cve) cmd += ` --cve ${cve}`;
        if (exploitFind) cmd += ` --exploit-find`;
    } else if (preset === 'osint') {
        cmd += ` --in-wild-osint`;
        if (countStr) cmd += countStr;
        if (exploitFind) cmd += ` --exploit-find`;
    } else if (preset === 'weekly') {
        cmd += ` --active-week-exploits`;
        if (countStr) cmd += countStr;
        if (allSev) cmd += ` --all-severity`;
    } else if (preset === 'iotot') {
        cmd += ` --iotot --all-severity`;
        if (start) cmd += ` --start ${start}`;
        if (end) cmd += ` --end ${end}`;
        if (countStr) cmd += countStr;
        if (exploitFind) cmd += ` --exploit-find`;
        if (cisa) cmd += ` --cisa`;
    } else if (preset === 'date_audit') {
        if (start) cmd += ` --start ${start}`;
        if (end) cmd += ` --end ${end}`;
        if (countStr) cmd += countStr;
        if (cisa) cmd += ` --cisa`;
        if (exploitFind) cmd += ` --exploit-find`;
        if (allSev) cmd += ` --all-severity`;
    } else if (preset === 'custom') {
        if (cve) cmd += ` --cve ${cve}`;
        if (start && !activeWeek) cmd += ` --start ${start}`;
        if (end && !activeWeek) cmd += ` --end ${end}`;
        if (countStr) cmd += countStr;
        if (cisa) cmd += ` --cisa`;
        if (iotot) cmd += ` --iotot`;
        if (allSev) cmd += ` --all-severity`;
        if (exploitFind) cmd += ` --exploit-find`;
        if (activeWeek) cmd += ` --active-week-exploits`;
        if (inWild) cmd += ` --in-wild-osint`;
    }

    const previewEl = document.getElementById('cli-command-preview');
    if (previewEl) previewEl.textContent = cmd;
}

function copyCliCommand() {
    const previewEl = document.getElementById('cli-command-preview');
    if (previewEl) {
        copyToClipboard(previewEl.textContent);
        showToast('✓ CLI Command copied to clipboard!');
    }
}

// ==============================================================================
// 5. OSINT RADAR CONTROLLER & DATA VISUALIZATION (15-DAY MULTI-STREAM ENGINE)
// ==============================================================================
let osintItemsCache = [];
let osintPieChart = null;
let osintClusterChart = null;
let osintComparativeChart = null;
let currentOsintPlatform = 'all';
let currentOsintCorrelation = 'all';

async function loadOsintData() {
    const container = document.getElementById('osint-cards-container');
    if (container) {
        container.innerHTML = '<div class="loading-spinner">Querying 15-day multi-stream threat telemetry...</div>';
    }

    try {
        const res = await fetch('/api/osint/trending');
        const data = await res.json();

        const items = Array.isArray(data) ? data : (data.items || []);
        osintItemsCache = items;
        let breakdown = data.platform_breakdown || {
            'HackerNews': 0, 'Reddit': 0, 'X (Twitter)': 0,
            'CISA KEV': 0, 'Security Media': 0, 'Dark Web & Underground': 0,
            'Telegram Threat Radar': 0
        };
        let comparative = data.comparative_metrics || {
            cisa_only_count: 0, osint_only_count: 0, correlated_both_count: 0, cisa_vs_osint_series: []
        };
        let clusterPoints = data.cluster_points || [];
        const kpis = data.kpis || {};

        // Self-healing: Populate platforms on each item if missing from legacy response
        items.forEach(item => {
            if (!item.platforms || item.platforms.length === 0) {
                const src = ((item.osint_sources || '') + ' ' + (item.affected_vendor || '')).toLowerCase();
                item.platforms = [];
                if (item.is_cisa_kev || src.includes('cisa')) item.platforms.push('CISA KEV');
                if (src.includes('hackernews') || src.includes('hn')) item.platforms.push('HackerNews');
                if (src.includes('reddit')) item.platforms.push('Reddit');
                if (src.includes('twitter') || src.includes('x')) item.platforms.push('X (Twitter)');
                if (src.includes('media') || src.includes('news')) item.platforms.push('Security Media');
                if (src.includes('dark web') || src.includes('leak')) item.platforms.push('Dark Web & Underground');
                if (src.includes('telegram')) item.platforms.push('Telegram Threat Radar');

                if (item.platforms.length === 0 && Array.isArray(item.sources)) {
                    item.sources.forEach(s => {
                        const sn = (s.source_name || '').toLowerCase();
                        if (sn.includes('cisa') && !item.platforms.includes('CISA KEV')) item.platforms.push('CISA KEV');
                        if (sn.includes('hackernews') && !item.platforms.includes('HackerNews')) item.platforms.push('HackerNews');
                        if (sn.includes('reddit') && !item.platforms.includes('Reddit')) item.platforms.push('Reddit');
                        if ((sn.includes('twitter') || sn.includes('x')) && !item.platforms.includes('X (Twitter)')) item.platforms.push('X (Twitter)');
                        if (sn.includes('media') && !item.platforms.includes('Security Media')) item.platforms.push('Security Media');
                        if ((sn.includes('dark web') || sn.includes('leak')) && !item.platforms.includes('Dark Web & Underground')) item.platforms.push('Dark Web & Underground');
                        if (sn.includes('telegram') && !item.platforms.includes('Telegram Threat Radar')) item.platforms.push('Telegram Threat Radar');
                    });
                }

                if (item.platforms.length === 0) {
                    item.platforms = ['HackerNews'];
                }
            }

            item.in_cisa = item.in_cisa !== undefined ? item.in_cisa : (item.platforms.includes('CISA KEV') ? 1 : 0);
            item.is_correlated = item.is_correlated !== undefined ? item.is_correlated : (item.in_cisa && item.platforms.some(p => p !== 'CISA KEV') ? 1 : 0);
        });

        // Recompute comparative metrics if empty
        if (!comparative.cisa_vs_osint_series || comparative.cisa_vs_osint_series.length === 0) {
            const cisaSet = new Set(items.filter(it => it.in_cisa).map(it => it.cve_id));
            const osintSet = new Set(items.filter(it => (it.platforms || []).some(p => p !== 'CISA KEV')).map(it => it.cve_id));
            const bothSet = new Set([...cisaSet].filter(x => osintSet.has(x)));

            comparative.correlated_both_count = bothSet.size;
            comparative.cisa_only_count = Math.max(0, cisaSet.size - bothSet.size);
            comparative.osint_only_count = Math.max(0, osintSet.size - bothSet.size);

            comparative.cisa_vs_osint_series = items.slice(0, 30).map(it => ({
                cve_id: it.cve_id,
                in_cisa: it.in_cisa,
                osint_mentions: Math.max(1, (it.osint_mention_count || 1) * ((it.platforms || []).filter(p => p !== 'CISA KEV').length || 1)),
                severity: it.severity || 'Medium',
                vendor: it.affected_vendor || 'Unknown',
                is_correlated: it.is_correlated
            }));
        }

        // Recompute cluster points if missing
        if (!clusterPoints || clusterPoints.length === 0) {
            clusterPoints = items.map(d => {
                const cvss = d.cvss_v3_score !== null && d.cvss_v3_score !== undefined ? parseFloat(d.cvss_v3_score) : 7.0;
                const mentions = parseInt(d.osint_mention_count, 10) || 1;
                const epss = parseFloat(d.epss_score) || 0.05;
                return {
                    cve_id: d.cve_id,
                    x: Math.round(cvss * 10) / 10,
                    y: mentions,
                    r: Math.max(8, Math.min(24, Math.round(epss * 35) + 8)),
                    severity: d.severity || 'High',
                    vendor: d.affected_vendor || 'Unknown',
                    epss: Math.round(epss * 10000) / 100,
                    platforms: d.platforms || ['HackerNews'],
                    has_poc: !!(d.has_public_poc || d.has_unverified_poc),
                    in_cisa: d.in_cisa,
                    is_correlated: d.is_correlated
                };
            });
        }

        // Update KPIs
        const elTotal = document.getElementById('osint-kpi-total');
        const elCisa = document.getElementById('osint-kpi-cisa');
        const elCorr = document.getElementById('osint-kpi-correlated');
        const elDark = document.getElementById('osint-kpi-darkweb');

        if (elTotal) elTotal.textContent = kpis.total_threats || items.length;
        if (elCisa) elCisa.textContent = kpis.cisa_count || comparative.cisa_only_count + comparative.correlated_both_count || 0;
        if (elCorr) elCorr.textContent = comparative.correlated_both_count || kpis.correlated_count || 0;
        if (elDark) elDark.textContent = (kpis.darkweb_count || 0) + (kpis.media_count || 0) || items.filter(it => (it.platforms || []).some(p => p.includes('Dark') || p.includes('Media'))).length;

        // Update Comparative Header Badges
        const elBadgeCorr = document.getElementById('badge-corr-both');
        const elBadgeOsint = document.getElementById('badge-osint-only');
        const elBadgeCisa = document.getElementById('badge-cisa-only');

        if (elBadgeCorr) elBadgeCorr.textContent = `🟣 Correlated: ${comparative.correlated_both_count || 0}`;
        if (elBadgeOsint) elBadgeOsint.textContent = `🔵 OSINT Only: ${comparative.osint_only_count || 0}`;
        if (elBadgeCisa) elBadgeCisa.textContent = `🔴 CISA Only: ${comparative.cisa_only_count || 0}`;

        // Update Correlation Filter Badges
        const elCntAll = document.getElementById('filter-cnt-all');
        const elCntCorr = document.getElementById('filter-cnt-corr');
        const elCntEarly = document.getElementById('filter-cnt-early');
        const elCntCisaOnly = document.getElementById('filter-cnt-cisaonly');

        if (elCntAll) elCntAll.textContent = items.length;
        if (elCntCorr) elCntCorr.textContent = comparative.correlated_both_count || 0;
        if (elCntEarly) elCntEarly.textContent = comparative.osint_only_count || 0;
        if (elCntCisaOnly) elCntCisaOnly.textContent = comparative.cisa_only_count || 0;

        // Update Platform Filter Badges
        const setPlatformBadge = (id, count) => {
            const el = document.getElementById(id);
            if (el) el.textContent = count;
        };
        setPlatformBadge('filter-cnt-cisa', items.filter(it => (it.platforms || []).includes('CISA KEV')).length);
        setPlatformBadge('filter-cnt-hn', items.filter(it => (it.platforms || []).includes('HackerNews')).length);
        setPlatformBadge('filter-cnt-reddit', items.filter(it => (it.platforms || []).includes('Reddit')).length);
        setPlatformBadge('filter-cnt-x', items.filter(it => (it.platforms || []).includes('X (Twitter)')).length);
        setPlatformBadge('filter-cnt-media', items.filter(it => (it.platforms || []).includes('Security Media')).length);
        setPlatformBadge('filter-cnt-darkweb', items.filter(it => (it.platforms || []).includes('Dark Web & Underground')).length);
        setPlatformBadge('filter-cnt-telegram', items.filter(it => (it.platforms || []).includes('Telegram Threat Radar')).length);

        // Render Charts
        renderOsintComparativeChart(comparative.cisa_vs_osint_series || []);
        renderOsintPieChart(breakdown);
        renderOsintClusterChart(clusterPoints);

        // Apply filters & render cards
        applyOsintFilters();

    } catch (err) {
        if (container) {
            container.innerHTML = `<p class="text-crimson">Error loading 15-day OSINT data: ${escapeHtml(err.message || err)}</p>`;
        }
    }
}

// ==============================================================================
// 5.1 CISA KEV VS OSINT CHATTER COMPARATIVE BAR CHART
// ==============================================================================
function renderOsintComparativeChart(series) {
    const canvas = document.getElementById('osint-comparative-chart');
    if (!canvas || typeof Chart === 'undefined') return;

    if (osintComparativeChart) {
        osintComparativeChart.destroy();
    }

    const topSeries = (series || []).slice(0, 24);
    const labels = topSeries.map(s => s.cve_id);
    const cisaData = topSeries.map(s => s.in_cisa ? 10 : 0);
    const osintData = topSeries.map(s => s.osint_mentions);

    const ctx = canvas.getContext('2d');
    osintComparativeChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Official CISA KEV Confirmation (Flagged = 10)',
                    data: cisaData,
                    backgroundColor: topSeries.map(s => s.is_correlated ? 'rgba(239, 68, 68, 0.9)' : 'rgba(239, 68, 68, 0.4)'),
                    borderColor: '#ef4444',
                    borderWidth: 1.5,
                    borderRadius: 4
                },
                {
                    label: 'Community / Media / DarkWeb Chatter Velocity',
                    data: osintData,
                    backgroundColor: topSeries.map(s => s.is_correlated ? 'rgba(6, 182, 212, 0.9)' : 'rgba(6, 182, 212, 0.45)'),
                    borderColor: '#06b6d4',
                    borderWidth: 1.5,
                    borderRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8', font: { size: 10 }, maxRotation: 45, minRotation: 45 }
                },
                y: {
                    title: { display: true, text: 'Signal Weight / Mentions', color: '#94a3b8', font: { size: 11 } },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8', stepSize: 2 }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    labels: { color: '#cbd5e1', font: { size: 11 }, boxWidth: 12 }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const raw = context.raw;
                            if (context.datasetIndex === 0) {
                                return raw > 0 ? ' [!] CISA KEV Confirmed Exploited in the Wild' : ' [-] Not on CISA KEV Catalog';
                            }
                            return ` Chatter Velocity: ${raw} social/media/darkweb signals`;
                        }
                    }
                }
            },
            onClick: (e, elements) => {
                if (elements.length > 0) {
                    const idx = elements[0].index;
                    const cveId = labels[idx];
                    if (cveId) openCveModal(cveId);
                }
            }
        }
    });
}

// ==============================================================================
// 5.2 DONUT CHART ACROSS 6 INTELLIGENCE STREAMS
// ==============================================================================
function renderOsintPieChart(breakdown) {
    const canvas = document.getElementById('osint-pie-chart');
    if (!canvas || typeof Chart === 'undefined') return;

    const hn = breakdown['HackerNews'] || 0;
    const reddit = breakdown['Reddit'] || 0;
    const x = breakdown['X (Twitter)'] || 0;
    const cisa = breakdown['CISA KEV'] || 0;
    const media = breakdown['Security Media'] || 0;
    const darkweb = breakdown['Dark Web & Underground'] || 0;
    const telegram = breakdown['Telegram Threat Radar'] || 0;
    const total = hn + reddit + x + cisa + media + darkweb + telegram;

    const badge = document.getElementById('osint-pie-total-badge');
    if (badge) badge.textContent = `${total} Signals`;

    if (osintPieChart) {
        osintPieChart.destroy();
    }

    const ctx = canvas.getContext('2d');
    osintPieChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['CISA KEV', 'HackerNews', 'Reddit Security', 'X (Twitter)', 'Security Media', 'Dark Web & Leaks', 'Telegram Radar'],
            datasets: [{
                data: [cisa, hn, reddit, x, media, darkweb, telegram],
                backgroundColor: [
                    '#ef4444', // Red (CISA)
                    '#f97316', // Orange (HN)
                    '#e11d48', // Crimson (Reddit)
                    '#06b6d4', // Cyan (X)
                    '#10b981', // Emerald (Media)
                    '#a855f7', // Purple (Dark Web)
                    '#0284c7'  // Sky Blue (Telegram)
                ],
                borderColor: '#0f172a',
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '62%',
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const val = context.raw || 0;
                            const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
                            return ` ${context.label}: ${val} signals (${pct}%)`;
                        }
                    }
                }
            }
        }
    });

    const legendEl = document.getElementById('osint-pie-legend');
    if (legendEl) {
        legendEl.innerHTML = `
            <div class="osint-legend-item"><span class="osint-legend-dot" style="background:#ef4444;"></span> CISA KEV (${cisa})</div>
            <div class="osint-legend-item"><span class="osint-legend-dot" style="background:#f97316;"></span> HackerNews (${hn})</div>
            <div class="osint-legend-item"><span class="osint-legend-dot" style="background:#e11d48;"></span> Reddit (${reddit})</div>
            <div class="osint-legend-item"><span class="osint-legend-dot" style="background:#06b6d4;"></span> X / Twitter (${x})</div>
            <div class="osint-legend-item"><span class="osint-legend-dot" style="background:#10b981;"></span> Media (${media})</div>
            <div class="osint-legend-item"><span class="osint-legend-dot" style="background:#a855f7;"></span> Dark Web (${darkweb})</div>
            <div class="osint-legend-item"><span class="osint-legend-dot" style="background:#0284c7;"></span> Telegram (${telegram})</div>
        `;
    }
}

// ==============================================================================
// 5.3 CLUSTER BUBBLE GRAPH (VELOCITY VS CVSS SEVERITY)
// ==============================================================================
function renderOsintClusterChart(points) {
    const canvas = document.getElementById('osint-cluster-chart');
    if (!canvas || typeof Chart === 'undefined') return;

    if (osintClusterChart) {
        osintClusterChart.destroy();
    }

    const severityColors = {
        'Critical': '#ef4444',
        'High': '#f97316',
        'Medium': '#eab308',
        'Low': '#10b981',
        'Unknown': '#06b6d4'
    };

    const datasetData = points.map(pt => ({
        x: pt.x,
        y: pt.y,
        r: pt.r || 8,
        cve_id: pt.cve_id,
        severity: pt.severity,
        vendor: pt.vendor,
        epss: pt.epss,
        has_poc: pt.has_poc,
        in_cisa: pt.in_cisa,
        is_correlated: pt.is_correlated,
        platforms: (pt.platforms || []).join(', ')
    }));

    const ctx = canvas.getContext('2d');
    osintClusterChart = new Chart(ctx, {
        type: 'bubble',
        data: {
            datasets: [{
                label: 'Trending Threats (15 Days)',
                data: datasetData,
                backgroundColor: datasetData.map(d => {
                    if (d.is_correlated) return 'rgba(239, 68, 68, 0.85)';
                    const c = severityColors[d.severity] || '#06b6d4';
                    return c + '99';
                }),
                borderColor: datasetData.map(d => d.is_correlated ? '#fca5a5' : (severityColors[d.severity] || '#06b6d4')),
                borderWidth: datasetData.map(d => d.is_correlated ? 2.5 : 1.5),
                hoverBorderWidth: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    title: { display: true, text: 'CVSS v3 Base Score (0.0 - 10.0)', color: '#94a3b8', font: { size: 11 } },
                    min: 0,
                    max: 10,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    title: { display: true, text: 'Threat Signal Velocity (Mentions)', color: '#94a3b8', font: { size: 11 } },
                    min: 0,
                    suggestedMax: Math.max(5, ...points.map(p => p.y + 2)),
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8', stepSize: 1 }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const raw = context.raw;
                            const cisaStatus = raw.in_cisa ? ' [CISA KEV Confirmed]' : '';
                            const corrStatus = raw.is_correlated ? ' [🔥 High Danger: CISA + OSINT]' : '';
                            return [
                                ` ${raw.cve_id} (${raw.severity})`,
                                ` Mentions: ${raw.y} | CVSS: ${raw.x}${corrStatus}${cisaStatus}`,
                                ` Target: ${raw.vendor}`,
                                ` Streams: ${raw.platforms}`
                            ];
                        }
                    }
                }
            },
            onClick: (e, elements) => {
                if (elements.length > 0) {
                    const idx = elements[0].index;
                    const cveId = datasetData[idx].cve_id;
                    if (cveId) openCveModal(cveId);
                }
            }
        }
    });
}

// ==============================================================================
// 5.4 FILTERING & CARDS RENDERING
// ==============================================================================
function applyOsintFilters() {
    let filtered = osintItemsCache;

    if (currentOsintCorrelation === 'correlated') {
        filtered = filtered.filter(it => it.is_correlated === 1);
    } else if (currentOsintCorrelation === 'osint_only') {
        filtered = filtered.filter(it => !it.in_cisa);
    } else if (currentOsintCorrelation === 'cisa_only') {
        filtered = filtered.filter(it => it.in_cisa && (it.platforms || []).every(p => p === 'CISA KEV'));
    }

    if (currentOsintPlatform !== 'all') {
        filtered = filtered.filter(it => (it.platforms || []).includes(currentOsintPlatform));
    }

    renderOsintCards(filtered);
}

function filterOsintByCorrelation(type) {
    currentOsintCorrelation = type;
    document.querySelectorAll('[data-filter]').forEach(pill => {
        pill.classList.toggle('active', pill.getAttribute('data-filter') === type);
    });
    applyOsintFilters();
}

function filterOsintCards(platform) {
    currentOsintPlatform = platform;
    document.querySelectorAll('[data-platform]').forEach(pill => {
        pill.classList.toggle('active', pill.getAttribute('data-platform') === platform);
    });
    applyOsintFilters();
}

function toggleOsintSources(drawerId, btn) {
    const drawer = document.getElementById(drawerId);
    if (!drawer) return;
    const isOpen = drawer.classList.toggle('open');
    const arrow = btn.querySelector('.arrow');
    if (arrow) arrow.textContent = isOpen ? '▴' : '▾';
}

function renderOsintCards(items) {
    const container = document.getElementById('osint-cards-container');
    if (!container) return;

    if (!items || items.length === 0) {
        container.innerHTML = '<p class="text-muted" style="padding:16px;">No threats match the selected 15-day intelligence filter.</p>';
        return;
    }

    container.innerHTML = items.map(item => {
        const platforms = item.platforms || ['Social Chatter'];
        const platformBadges = platforms.map(p => {
            if (p.includes('CISA')) return '<span class="osint-source-badge badge-cisa">🛡️ CISA KEV</span>';
            if (p.includes('HackerNews')) return '<span class="osint-source-badge badge-hn">🟠 HN</span>';
            if (p.includes('Reddit')) return '<span class="osint-source-badge badge-reddit">🔴 Reddit</span>';
            if (p.includes('X') || p.includes('Twitter')) return '<span class="osint-source-badge badge-x">🔵 𝕏</span>';
            if (p.includes('Media')) return '<span class="osint-source-badge badge-media">📰 Media</span>';
            if (p.includes('Dark') || p.includes('Underground')) return '<span class="osint-source-badge badge-darkweb">🕵️ Dark Web</span>';
            if (p.includes('Telegram')) return '<span class="osint-source-badge badge-telegram">✈️ Telegram</span>';
            return `<span class="osint-source-badge">${escapeHtml(p)}</span>`;
        }).join('');

        const correlatedTag = item.is_correlated
            ? '<span class="correlated-danger-pill" title="Active in CISA KEV AND viral in community OSINT">🔥 CISA + OSINT Confirmed</span>'
            : '';

        const unverifiedPocTag = item.has_unverified_poc 
            ? '<span class="unverified-poc-pill" title="Unverified exploit/PoC chatter detected in public feeds">⚠️ Unverified Internet PoC</span>' 
            : '';

        const sources = item.sources || [];
        const drawerId = `sources-drawer-${escapeHtml(item.cve_id)}`;
        const sourcesToggleHtml = sources.length > 0 ? `
            <div style="margin-top:8px;">
                <button type="button" class="osint-sources-toggle-btn" onclick="toggleOsintSources('${drawerId}', this)">
                    🔗 Proof Sources (${sources.length}) <span class="arrow">▾</span>
                </button>
                <div id="${drawerId}" class="osint-sources-drawer">
                    <table class="osint-sources-table">
                        <thead>
                            <tr>
                                <th>Source</th>
                                <th>Details / Title</th>
                                <th>Link</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${sources.map(s => {
                                const stat = (s.exploit_status || '').toLowerCase();
                                const isPoc = s.is_poc_link || stat === 'poc' || stat === 'blog_poc' || stat === 'unverified_osint_poc';
                                const sName = escapeHtml(s.source_name || 'Source');
                                const sDetails = escapeHtml((s.details || s.source_name || '').slice(0, 65));

                                let badgeClass = 'badge-low';
                                let badgeLabel = sName;
                                if (stat === 'blog_poc') {
                                    badgeClass = 'badge-purple';
                                    badgeLabel = '⚡ PoC + 📝 Blog';
                                } else if (stat === 'vuln_version') {
                                    badgeClass = 'badge-amber';
                                    badgeLabel = '📦 Vuln Version';
                                } else if (stat === 'blog') {
                                    badgeClass = 'badge-cyan';
                                    badgeLabel = '📝 Blog';
                                } else if (stat === 'vendor_fix') {
                                    badgeClass = 'badge-low';
                                    badgeLabel = '🛡️ Advisory';
                                } else if (isPoc) {
                                    badgeClass = 'badge-crimson';
                                    badgeLabel = '⚡ PoC';
                                }

                                return `
                                    <tr>
                                        <td>
                                            <span class="badge ${badgeClass}" style="font-size:9px;">
                                                ${badgeLabel}
                                            </span>
                                        </td>
                                        <td style="color:var(--text-secondary); max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${sDetails}">
                                            ${sDetails}
                                        </td>
                                        <td>
                                            <a href="${escapeHtml(s.url)}" target="_blank" rel="noopener noreferrer" class="osint-source-link">
                                                Open ↗
                                            </a>
                                        </td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        ` : '';

        return `
            <div class="osint-card" style="${item.is_correlated ? 'border-color: rgba(239, 68, 68, 0.4); box-shadow: 0 0 14px rgba(239, 68, 68, 0.15);' : ''}">
                <div class="osint-card-header">
                    <strong style="color:var(--accent-cyan); font-size:14px; cursor:pointer;" onclick="openCveModal('${item.cve_id}')">${item.cve_id}</strong>
                    <span class="mention-count-pill">${item.osint_mention_count || 1} signal(s)</span>
                </div>
                <div class="osint-sources-row">
                    ${platformBadges}
                    ${correlatedTag}
                    ${unverifiedPocTag}
                </div>
                <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">
                    <strong>Target:</strong> ${escapeHtml(item.affected_vendor || 'Unknown')} ${escapeHtml(item.affected_product || '')}
                </div>
                <div style="font-size:12px; color:var(--text-secondary); margin-top:4px; line-height:1.4;">
                    ${item.ai_summary ? escapeHtml(item.ai_summary.slice(0, 140)) + '...' : '<em>Multi-source intelligence aggregated. Open dossier to inspect technical details...</em>'}
                </div>
                ${sourcesToggleHtml}
                <div style="margin-top:auto; padding-top:8px; display:flex; justify-content:space-between; align-items:center; border-top: 1px solid rgba(255,255,255,0.05);">
                    <span class="badge ${getSeverityBadgeClass(item.severity)}">${item.severity || 'Medium'}</span>
                    <button class="btn btn-xs btn-outline" onclick="openCveModal('${item.cve_id}')">Inspect ➔</button>
                </div>
            </div>
        `;
    }).join('');
}

async function loadIotData() {
    const tbody = document.getElementById('iot-table-body');
    tbody.innerHTML = '<tr><td colspan="5" class="text-center">Loading IoT/OT vulnerabilities...</td></tr>';

    try {
        const res = await fetch('/api/cves?is_iot_ot=true&limit=30');
        const data = await res.json();

        if (!data.items || data.items.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No IoT / OT vulnerabilities in local database. Run a hardware sweep scan!</td></tr>';
            return;
        }

        tbody.innerHTML = data.items.map(item => `
            <tr>
                <td><strong style="color:var(--accent-cyan); cursor:pointer;" onclick="openCveModal('${item.cve_id}')">${item.cve_id}</strong></td>
                <td><span class="badge ${getSeverityBadgeClass(item.severity)}">${item.severity || 'Unknown'}</span></td>
                <td><strong>${escapeHtml(item.affected_vendor || 'Unknown')}</strong> - ${escapeHtml(item.affected_product || '')}</td>
                <td style="font-size:12px;">${item.ai_summary ? escapeHtml(item.ai_summary.slice(0, 120)) + '...' : 'Pending analysis'}</td>
                <td><button class="btn btn-xs btn-outline" onclick="openCveModal('${item.cve_id}')">Inspect</button></td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-crimson">Error: ${err}</td></tr>`;
    }
}

// ==============================================================================
// 7. SYSTEM & LOG CONTROLLER
// ==============================================================================
async function loadSystemInfo() {
    const container = document.getElementById('system-info-container');
    container.innerHTML = '<div class="loading-spinner">Querying system metrics...</div>';

    try {
        const res = await fetch('/api/system');
        const sys = await res.json();

        const providers = sys.llm_telemetry || {};
        const providerMeta = {
            groq: { name: 'GroqCloud (LPU Inference)', icon: '⚡', speed: '500+ tok/s' },
            cerebras: { name: 'Cerebras Cloud', icon: '🧠', speed: 'High-speed Wafer' },
            openrouter: { name: 'OpenRouter Free Pool', icon: '🌐', speed: 'Community Pool' },
            gemini: { name: 'Google Gemini Studio', icon: '💎', speed: 'Reasoning Models' },
            mistral: { name: 'Mistral AI (Codestral)', icon: '🌪️', speed: 'Code Analysis' },
            ollama: { name: 'Local Ollama Instance', icon: '🦙', speed: 'Offline Fallback' }
        };

        const providerCardsHtml = Object.entries(providers).map(([key, p]) => {
            const meta = providerMeta[key] || { name: p.name || key, icon: '🤖', speed: 'LLM' };
            const isConfigured = p.configured || p.keys_count > 0;
            const latencyStr = p.avg_latency_sec ? `${p.avg_latency_sec}s avg` : (isConfigured ? 'Ready' : 'Standby');
            const models = p.models || [];

            return `
                <div class="provider-card" style="${isConfigured ? 'border-color: rgba(6, 182, 212, 0.4);' : 'opacity: 0.75;'}">
                    <div class="provider-header">
                        <div class="provider-name">
                            <span>${meta.icon}</span>
                            <span>${meta.name}</span>
                        </div>
                        <span class="badge ${isConfigured ? 'badge-emerald' : 'badge-low'}" style="font-size: 10px;">
                            ${isConfigured ? `✓ ${p.keys_count} Key(s)` : 'Not Configured'}
                        </span>
                    </div>
                    <div class="provider-stats">
                        <span>Speed: <strong>${meta.speed}</strong></span>
                        <span>Latency: <strong style="color:var(--accent-cyan);">${latencyStr}</strong></span>
                        <span>Calls: <strong>${p.success_count || 0} ok / ${p.failures_count || 0} err</strong></span>
                    </div>
                    <div class="provider-models">
                        ${models.slice(0, 4).map(m => `<span class="model-chip">${m.split('/').pop()}</span>`).join('')}
                        ${models.length > 4 ? `<span style="font-size:10px; color:var(--text-dim); padding-top:2px;">+${models.length - 4} more</span>` : ''}
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = `
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:16px;">
                <div class="kpi-card card-cyan">
                    <span class="kpi-label">TOTAL ACTIVE AI KEYS</span>
                    <span class="kpi-value" style="color:var(--accent-cyan);">${sys.total_active_keys || sys.openrouter_keys_count || 0} Key(s)</span>
                    <span class="kpi-sub">Dynamic Cooldown on HTTP 429</span>
                </div>
                <div class="kpi-card card-purple">
                    <span class="kpi-label">PERSISTENT DB STORAGE</span>
                    <span class="kpi-value">${sys.database_size_kb} KB</span>
                    <span class="kpi-sub">${escapeHtml(sys.database_path ? sys.database_path.split(/[\\/]/).pop() : 'cve_database.db')} (WAL Mode)</span>
                </div>
                <div class="kpi-card card-amber">
                    <span class="kpi-label">ORCHESTRATION GATEWAY</span>
                    <span class="kpi-value" style="color:var(--accent-emerald);">Online</span>
                    <span class="kpi-sub">${sys.fallback_models ? sys.fallback_models.length : 0} Models Registered</span>
                </div>
            </div>

            <div style="margin-top:20px;">
                <h4 style="font-size:13px; color:var(--text-main); font-weight:700; margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                    <span>⚡</span> Multi-Provider LLM Inference Cascade & Telemetry
                </h4>
                <div class="provider-grid">
                    ${providerCardsHtml}
                </div>
            </div>
        `;

        loadLog('analyzer');
    } catch (err) {
        container.innerHTML = `<p class="text-crimson">Failed querying system status: ${err}</p>`;
    }
}

async function loadLog(logType) {
    const box = document.getElementById('log-content-box');
    box.textContent = `Fetching ${logType} logs...`;

    document.querySelectorAll('.log-tabs button').forEach(btn => {
        btn.classList.toggle('active', btn.textContent.toLowerCase().includes(logType));
    });

    try {
        const res = await fetch(`/api/logs/${logType}?lines=100`);
        const data = await res.json();
        box.textContent = data.content || 'Log is currently empty.';
        box.scrollTop = box.scrollHeight;
    } catch (err) {
        box.textContent = `Error reading log: ${err}`;
    }
}

// ==============================================================================
// 6. REPORTS & EXPORTS CONTROLLER
// ==============================================================================
async function loadReportsView() {
    try {
        const res = await fetch('/api/reports/stats');
        const data = await res.json();

        const setTxt = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };

        setTxt('rep-kpi-analyzed', `⚡ ${data.total_analyzed || 0} Analyzed`);
        setTxt('rep-kpi-crit', `🔴 ${data.critical_count || 0} Critical`);
        setTxt('rep-kpi-cisa', `🛡️ ${data.cisa_count || 0} CISA KEV`);
        setTxt('rep-kpi-poc', `🔥 ${data.poc_count || 0} PoCs`);
        setTxt('report-sync-status', `System Telemetry Live (${data.total_analyzed || 0} Analyzed CVEs)`);
        setTxt('report-last-sync', `Generated: ${data.last_generated || 'Recent'}`);

        const frame = document.getElementById('html-report-frame');
        if (frame) {
            const scopeSelect = document.getElementById('report-scope-select');
            const scope = scopeSelect ? scopeSelect.value : 'analyzed';
            if (!frame.src || frame.src === 'about:blank' || frame.src.indexOf('&t=') === -1) {
                frame.src = `/api/reports/html?scope=${encodeURIComponent(scope)}&t=${Date.now()}`;
            }
        }
    } catch (e) {
        console.warn('Error loading reports stats:', e);
    }
}

async function refreshHtmlReport() {
    const scopeSelect = document.getElementById('report-scope-select');
    const scope = scopeSelect ? scopeSelect.value : 'analyzed';
    const overlay = document.getElementById('report-loading-overlay');
    const frame = document.getElementById('html-report-frame');
    const btn = document.getElementById('btn-refresh-report');

    if (overlay) overlay.style.display = 'flex';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span>⏳ Regenerating Live Report...</span>';
    }

    try {
        const res = await fetch(`/api/reports/regenerate?scope=${encodeURIComponent(scope)}`, { method: 'POST' });
        const data = await res.json();
        showToast(`✓ Executive report regenerated with ${data.total_analyzed || 'system'} analyzed CVEs!`);
        if (frame) {
            frame.src = `/api/reports/html?scope=${encodeURIComponent(scope)}&t=${Date.now()}`;
        }
        await loadReportsView();
    } catch (err) {
        showToast(`Failed to regenerate report: ${err.message || err}`, 'crimson');
    } finally {
        if (overlay) overlay.style.display = 'none';
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<span>🔄 Regenerate Live Report</span>';
        }
    }
}

function onReportScopeChange() {
    const scopeSelect = document.getElementById('report-scope-select');
    const scope = scopeSelect ? scopeSelect.value : 'analyzed';
    const frame = document.getElementById('html-report-frame');
    const tabBtn = document.getElementById('btn-open-report-tab');
    if (frame) {
        frame.src = `/api/reports/html?scope=${encodeURIComponent(scope)}&refresh=true&t=${Date.now()}`;
    }
    if (tabBtn) {
        tabBtn.href = `/api/reports/html?scope=${encodeURIComponent(scope)}`;
    }
    loadReportsView();
}

function downloadHtmlReport() {
    const scopeSelect = document.getElementById('report-scope-select');
    const scope = scopeSelect ? scopeSelect.value : 'analyzed';
    const dateStr = new Date().toISOString().slice(0, 10);
    const a = document.createElement('a');
    a.href = `/api/reports/html?scope=${encodeURIComponent(scope)}`;
    a.download = `ATI_Executive_Threat_Report_${scope}_${dateStr}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    showToast('✓ Downloading HTML Threat Report...');
}

async function exportPdf() {
    const btn = document.getElementById('btn-export-pdf');
    const typeSelect = document.getElementById('pdf-export-type');
    const exportType = typeSelect ? typeSelect.value : 'full';

    btn.disabled = true;
    btn.innerHTML = '<span>⏳ Compiling Custom PDF Document...</span>';

    try {
        const res = await fetch('/api/export-pdf', { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ export_type: exportType })
        });
        const data = await res.json();

        if (res.ok && data.download_url) {
            showToast(`✓ PDF (${exportType.toUpperCase()}) Generated Successfully!`);
            window.open(data.download_url, '_blank');
        } else {
            showToast(`PDF generation failed: ${data.detail}`, 'crimson');
        }
    } catch (err) {
        showToast(`Request failed: ${err}`, 'crimson');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>📥 Compile & Download PDF</span>';
    }
}

// ==============================================================================
// EVENT LISTENERS & UTILITIES
// ==============================================================================
function setupEventListeners() {
    // Quick search
    const quickSearch = document.getElementById('quick-cve-search');
    if (quickSearch) {
        quickSearch.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const val = quickSearch.value.trim();
                if (val) {
                    state.cves.search = val;
                    window.location.hash = 'cves';
                    loadCves();
                }
            }
        });
    }

    // CVE Filter Inputs
    const cveSearch = document.getElementById('cve-search-input');
    if (cveSearch) {
        let debounceTimeout;
        cveSearch.addEventListener('input', () => {
            clearTimeout(debounceTimeout);
            debounceTimeout = setTimeout(() => {
                state.cves.search = cveSearch.value.trim();
                state.cves.page = 1;
                loadCves();
            }, 300);
        });
    }

    const filterSev = document.getElementById('filter-severity');
    if (filterSev) {
        filterSev.addEventListener('change', () => {
            state.cves.severity = filterSev.value;
            state.cves.page = 1;
            loadCves();
        });
    }

    const filterSort = document.getElementById('filter-sort');
    if (filterSort) {
        filterSort.addEventListener('change', () => {
            state.cves.sortBy = filterSort.value;
            loadCves();
        });
    }

    // Filter checkboxes
    ['chk-poc', 'chk-cisa', 'chk-iot', 'chk-osint', 'chk-analyzed', 'chk-iocs'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('change', () => {
                state.cves.hasPoc = document.getElementById('chk-poc').checked;
                state.cves.isCisa = document.getElementById('chk-cisa').checked;
                state.cves.isIot = document.getElementById('chk-iot').checked;
                state.cves.isOsint = document.getElementById('chk-osint').checked;
                state.cves.isAnalyzed = document.getElementById('chk-analyzed').checked;
                state.cves.hasIocs = document.getElementById('chk-iocs') ? document.getElementById('chk-iocs').checked : false;
                state.cves.page = 1;
                loadCves();
            });
        }
    });

    const btnReset = document.getElementById('btn-reset-filters');
    if (btnReset) {
        btnReset.addEventListener('click', () => {
            state.cves.search = '';
            state.cves.severity = 'all';
            state.cves.hasPoc = false;
            state.cves.isCisa = false;
            state.cves.isIot = false;
            state.cves.isOsint = false;
            state.cves.isAnalyzed = false;
            state.cves.hasIocs = false;
            state.cves.keyword = '';
            state.cves.page = 1;

            if (cveSearch) cveSearch.value = '';
            if (filterSev) filterSev.value = 'all';
            ['chk-poc', 'chk-cisa', 'chk-iot', 'chk-osint', 'chk-analyzed', 'chk-iocs'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.checked = false;
            });
            loadCves();
        });
    }

    // Pagination buttons
    document.getElementById('btn-prev-page').addEventListener('click', () => {
        if (state.cves.page > 1) {
            state.cves.page--;
            loadCves();
        }
    });

    document.getElementById('btn-next-page').addEventListener('click', () => {
        state.cves.page++;
        loadCves();
    });

    // Preset cards selection
    document.querySelectorAll('.preset-card').forEach(card => {
        card.addEventListener('click', () => {
            selectPresetCard(card.getAttribute('data-mode'));
        });
    });

    // Toggle Limit Count input state
    const countEnableEl = document.getElementById('scan-count-enable');
    const countWrapperEl = document.getElementById('count-input-wrapper');
    const countStatusLabel = document.getElementById('count-status-label');

    if (countEnableEl) {
        countEnableEl.addEventListener('change', () => {
            const isChecked = countEnableEl.checked;
            if (countWrapperEl) {
                countWrapperEl.style.opacity = isChecked ? '1' : '0.4';
                countWrapperEl.style.pointerEvents = isChecked ? 'auto' : 'none';
            }
            if (countStatusLabel) {
                countStatusLabel.textContent = isChecked ? 'Limit Active' : 'Default: Process All CVEs';
                countStatusLabel.style.color = isChecked ? 'var(--accent-cyan)' : 'var(--text-muted)';
            }
            updateCustomCliPreview();
        });
    }

    // Dynamic Live CLI Command Preview Updates on any Form Change
    ['scan-cve-id', 'scan-start-date', 'scan-end-date', 'scan-count'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', updateCustomCliPreview);
    });

    ['scan-count-enable', 'scan-exploit-find', 'scan-cisa', 'scan-all-sev', 'scan-iotot', 'scan-active-week', 'scan-in-wild'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('change', updateCustomCliPreview);
    });

    // Initial CLI preview render
    updateCustomCliPreview();

    // Scan Execution
    const btnExecuteScan = document.getElementById('btn-execute-scan');
    if (btnExecuteScan) btnExecuteScan.addEventListener('click', executeScan);

    // Clear Terminal
    const btnClearTerminal = document.getElementById('btn-clear-terminal');
    if (btnClearTerminal) {
        btnClearTerminal.addEventListener('click', () => {
            const term = document.getElementById('scan-terminal-output');
            if (term) term.innerHTML = '';
        });
    }

    // PDF Export
    const btnExportPdf = document.getElementById('btn-export-pdf');
    if (btnExportPdf) btnExportPdf.addEventListener('click', exportPdf);

    // Modal Close
    const btnCloseModal = document.getElementById('btn-close-modal');
    if (btnCloseModal) btnCloseModal.addEventListener('click', closeCveModal);

    const cveModal = document.getElementById('cve-modal');
    if (cveModal) {
        cveModal.addEventListener('click', (e) => {
            if (e.target.id === 'cve-modal') {
                closeCveModal();
            }
        });
    }

    const cisaModal = document.getElementById('cisa-enrich-modal');
    if (cisaModal) {
        cisaModal.addEventListener('click', (e) => {
            if (e.target.id === 'cisa-enrich-modal') {
                closeCisaEnrichModal();
            }
        });
    }

    const assetModal = document.getElementById('add-asset-modal');
    if (assetModal) {
        assetModal.addEventListener('click', (e) => {
            if (e.target.id === 'add-asset-modal') {
                closeAddAssetModal();
            }
        });
    }

    // Escape Key Listener to Close Modals
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' || e.key === 'Esc') {
            closeCveModal();
            closeCisaEnrichModal();
            closeAddAssetModal();
        }
    });
}

// Helpers
function formatExploitDate(dateStr) {
    if (!dateStr) return '';
    try {
        const parts = String(dateStr).split('-');
        if (parts.length >= 2) {
            const year = parts[0];
            const monthIdx = parseInt(parts[1], 10) - 1;
            const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
            if (monthIdx >= 0 && monthIdx < 12) {
                return `${months[monthIdx]} ${year}`;
            }
        }
        return dateStr;
    } catch {
        return dateStr;
    }
}

function getSeverityBadgeClass(sev) {
    if (!sev) return 'badge-low';
    const s = sev.toLowerCase();
    if (s === 'critical') return 'badge-critical';
    if (s === 'high') return 'badge-high';
    if (s === 'medium') return 'badge-medium';
    return 'badge-low';
}

function getSeverityColor(sev) {
    if (!sev) return '#94a3b8';
    const s = sev.toLowerCase();
    if (s === 'critical') return 'var(--accent-crimson)';
    if (s === 'high') return 'var(--accent-amber)';
    if (s === 'medium') return 'var(--accent-blue)';
    return 'var(--text-dim)';
}

function showToast(msg, type = 'cyan') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    if (type === 'crimson') toast.style.borderColor = 'var(--accent-crimson)';
    toast.textContent = msg;
    container.appendChild(toast);
    setTimeout(() => {
        toast.remove();
    }, 4000);
}

function copyToClipboard(text) {
    if (!text && text !== 0) return;
    const str = String(text);
    if (navigator.clipboard && window.isSecureContext && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(str).then(() => {
            showToast('✓ Copied to clipboard!');
        }).catch(() => {
            fallbackCopy(str);
        });
    } else {
        fallbackCopy(str);
    }
}
window.copyToClipboard = copyToClipboard;

function fallbackCopy(text) {
    let textarea = null;
    try {
        textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.left = '-9999px';
        textarea.style.top = '-9999px';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        textarea.setSelectionRange(0, textarea.value.length);
        const successful = document.execCommand('copy');
        if (successful) {
            showToast('✓ Copied to clipboard!');
        } else {
            showToast('Unable to copy', 'crimson');
        }
    } catch (err) {
        showToast('Failed copying to clipboard', 'crimson');
    } finally {
        if (textarea && textarea.parentNode) {
            textarea.parentNode.removeChild(textarea);
        }
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeJs(str) {
    if (!str) return '';
    return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '');
}

// ==============================================================================
// 8. ON-DEMAND DATABASE ENRICHMENT CONTROLLER
// ==============================================================================
let enrichPollInterval = null;

function setupEnrichMonitor() {
    checkEnrichStatus();
    if (!enrichPollInterval) {
        enrichPollInterval = setInterval(checkEnrichStatus, 4000);
    }
}

async function checkEnrichStatus() {
    try {
        const res = await fetch('/api/enrich-db/status');
        if (!res.ok) return;
        const data = await res.json();
        state.enrich.isRunning = !!data.is_running;

        const btn = document.getElementById('btn-enrich-db');
        const icon = document.getElementById('enrich-btn-icon');
        const txt = document.getElementById('enrich-btn-text');

        if (btn && txt) {
            if (data.is_running) {
                btn.className = 'btn btn-warning btn-enrich-active';
                if (icon) icon.textContent = '⏹️';
                txt.textContent = data.current_stage ? `Stop (${data.current_stage.slice(0, 14)}...)` : 'Stop Enriching';
            } else {
                btn.className = 'btn btn-secondary';
                if (icon) icon.textContent = '⚡';
                txt.textContent = 'Enrich DB';
            }
        }
    } catch (e) {
        // silent fail on minor network hiccups
    }
}

async function toggleEnrichDb() {
    const btn = document.getElementById('btn-enrich-db');
    if (state.enrich.isRunning) {
        try {
            if (btn) btn.disabled = true;
            const res = await fetch('/api/enrich-db/stop', { method: 'POST' });
            const data = await res.json();
            showToast(data.message || 'Graceful stop requested.');
        } catch (err) {
            showToast(`Failed stopping enrichment: ${err}`, 'crimson');
        } finally {
            if (btn) btn.disabled = false;
            checkEnrichStatus();
        }
    } else {
        try {
            if (btn) btn.disabled = true;
            const res = await fetch('/api/enrich-db', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    enrich_technical: true,
                    enrich_epss: true,
                    enrich_ai: true,
                    enrich_exploits: false
                })
            });
            const data = await res.json();
            if (res.ok) {
                showToast('⚡ Database & Threat Enrichment started!');
                navigateTo('scans'); // show live terminal stream
            } else {
                showToast(`Could not start: ${data.detail || data.message}`, 'crimson');
            }
        } catch (err) {
            showToast(`Error initiating enrichment: ${err}`, 'crimson');
        } finally {
            if (btn) btn.disabled = false;
            checkEnrichStatus();
        }
    }
}

// ==============================================================================
// 9. OWNED ASSETS INVENTORY CONTROLLER
// ==============================================================================
async function loadAssetsView() {
    const tbody = document.getElementById('assets-table-body');
    if (tbody) tbody.innerHTML = '<tr><td colspan="9" class="text-center">Loading registered assets...</td></tr>';

    try {
        const res = await fetch('/api/assets');
        const data = await res.json();
        state.assets.items = data.assets || [];
        renderAssetsTable(state.assets.items);
    } catch (err) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="9" class="text-center text-crimson">Error loading assets: ${err}</td></tr>`;
    }
}

function renderAssetsTable(items) {
    const tbody = document.getElementById('assets-table-body');
    if (!tbody) return;

    if (!items || items.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center text-muted" style="padding: 28px;">
                    No owned assets registered yet.<br>
                    <button class="btn btn-primary btn-sm" onclick="openAddAssetModal()" style="margin-top: 10px;">
                        ➕ Register Your First Asset
                    </button>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = items.map(a => {
        const critClass = (a.criticality || 'High').toLowerCase();
        let badgeClass = 'badge-medium';
        if (critClass === 'critical') badgeClass = 'badge-crimson';
        else if (critClass === 'high') badgeClass = 'badge-amber';
        else if (critClass === 'low') badgeClass = 'badge-low';

        return `
            <tr>
                <td><strong style="color:var(--accent-cyan);">${escapeHtml(a.asset_name)}</strong></td>
                <td><span class="badge badge-low">${escapeHtml(a.asset_type || 'Server')}</span></td>
                <td><strong>${escapeHtml(a.vendor)}</strong></td>
                <td>${escapeHtml(a.product)}</td>
                <td>
                    <code style="font-family:var(--font-mono); font-size:11px; color:#38BDF8;">${escapeHtml(a.version || a.cpe || 'Any')}</code>
                </td>
                <td><span style="font-family:var(--font-mono); font-size:11px;">${escapeHtml(a.ip_address || a.domain_name || 'Internal')}</span></td>
                <td><span class="badge ${badgeClass}">${escapeHtml(a.criticality || 'High')}</span></td>
                <td>
                    ${a.match_count > 0 
                        ? `<span class="badge badge-crimson" title="${a.high_risk_match_count || 0} Weaponized / KEV matches">🚨 ${a.match_count} Matches</span>`
                        : '<span style="color:var(--text-dim); font-size:11px;">0 Matches</span>'}
                </td>
                <td>
                    <div style="display: flex; gap: 6px;">
                        <button class="btn btn-xs btn-outline" style="color:var(--accent-crimson); border-color:rgba(239,68,68,0.3);" onclick="deleteAsset(${a.asset_id})">🗑️ Delete</button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

function filterAssetsTable() {
    const q = (document.getElementById('asset-search-input')?.value || '').toLowerCase().trim();
    if (!q) {
        renderAssetsTable(state.assets.items);
        return;
    }
    const filtered = (state.assets.items || []).filter(a => 
        (a.asset_name || '').toLowerCase().includes(q) ||
        (a.vendor || '').toLowerCase().includes(q) ||
        (a.product || '').toLowerCase().includes(q) ||
        (a.ip_address || '').toLowerCase().includes(q) ||
        (a.version || '').toLowerCase().includes(q)
    );
    renderAssetsTable(filtered);
}

function openAddAssetModal() {
    const modal = document.getElementById('add-asset-modal');
    if (modal) modal.classList.remove('hidden');
}

function closeAddAssetModal() {
    const modal = document.getElementById('add-asset-modal');
    if (modal) modal.classList.add('hidden');
}

async function submitNewAsset(e) {
    e.preventDefault();
    const body = {
        asset_name: document.getElementById('asset-in-name').value.trim(),
        asset_type: document.getElementById('asset-in-type').value,
        vendor: document.getElementById('asset-in-vendor').value.trim(),
        product: document.getElementById('asset-in-product').value.trim(),
        version: document.getElementById('asset-in-version').value.trim() || null,
        cpe: document.getElementById('asset-in-cpe').value.trim() || null,
        ip_address: document.getElementById('asset-in-ip').value.trim() || null,
        criticality: document.getElementById('asset-in-crit').value,
        notes: document.getElementById('asset-in-notes').value.trim() || null
    };

    try {
        const res = await fetch('/api/assets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`✓ Asset '${body.asset_name}' registered successfully!`);
            closeAddAssetModal();
            document.getElementById('asset-form')?.reset();
            loadAssetsView();
        } else {
            showToast(`Failed registering asset: ${data.detail || data.message}`, 'crimson');
        }
    } catch (err) {
        showToast(`Request error: ${err}`, 'crimson');
    }
}

async function deleteAsset(assetId) {
    if (!confirm('Are you sure you want to remove this asset from inventory?')) return;
    try {
        const res = await fetch(`/api/assets/${assetId}`, { method: 'DELETE' });
        if (res.ok) {
            showToast('✓ Asset removed from inventory.');
            loadAssetsView();
        } else {
            showToast('Failed deleting asset.', 'crimson');
        }
    } catch (err) {
        showToast(`Error: ${err}`, 'crimson');
    }
}
