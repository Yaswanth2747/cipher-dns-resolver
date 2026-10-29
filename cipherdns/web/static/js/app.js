/**
 * cipherDNS Frontend Application Controller
 * Handles WebSockets, live telemetry, status animations, cache table, and Zeek audit.
 */

let ws = null;
let reconnectTimer = null;
let idleResetTimer = null;
let currentCacheEntries = [];
let localTtlInterval = null;
let currentTrafficScope = "clean"; // default: Clean Demo (User Sites)

// DOM Elements
const statusRing = document.getElementById("statusRing");
const ringIcon = document.getElementById("ringIcon");
const statusPrimaryText = document.getElementById("statusPrimaryText");
const statusSecondaryText = document.getElementById("statusSecondaryText");
const activeProviderText = document.getElementById("activeProviderText");
const portBadge = document.getElementById("portBadge");
const wsStatusPill = document.getElementById("wsStatusPill");
const wsStatusText = document.getElementById("wsStatusText");
const scopeFilterSelect = document.getElementById("scopeFilterSelect");

const btnModeDoh = document.getElementById("btnModeDoh");
const btnModePlain = document.getElementById("btnModePlain");
const providerSelect = document.getElementById("providerSelect");

const metricHitRatio = document.getElementById("metricHitRatio");
const metricHitsMisses = document.getElementById("metricHitsMisses");
const metricCachedEntries = document.getElementById("metricCachedEntries");
const metricAvgLatency = document.getElementById("metricAvgLatency");

const cacheTableBody = document.getElementById("cacheTableBody");
const emptyCacheRow = document.getElementById("emptyCacheRow");
const tableCountBadge = document.getElementById("tableCountBadge");
const cacheSearchInput = document.getElementById("cacheSearchInput");
const logStreamContainer = document.getElementById("logStreamContainer");
const logEmptyState = document.getElementById("logEmptyState");

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
    connectWebSocket();
    startLocalTtlCountdown();
    fetchCurrentStatus();
    checkSystemDnsStatus();
    reloadCacheTable();
});

// WebSocket Connection
function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/events`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        wsStatusPill.className = "status-pill connected";
        wsStatusText.textContent = "Live Feed";
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleServerEvent(data);
        } catch (e) {
            console.error("Malformed WebSocket message:", e);
        }
    };

    ws.onclose = () => {
        wsStatusPill.className = "status-pill";
        wsStatusText.textContent = "Reconnecting...";
        reconnectTimer = setTimeout(connectWebSocket, 2000);
    };

    ws.onerror = () => {
        ws.close();
    };
}

// Event Dispatcher
function handleServerEvent(event) {
    switch (event.type) {
        case "init_state":
            applyServerStatus(event.status);
            if (event.cache_entries) {
                renderCacheTable(event.cache_entries);
            }
            if (event.recent_history) {
                event.recent_history.reverse().forEach(appendLogEntry);
            }
            break;

        case "query_start":
            onQueryStart(event);
            appendLogEntry(event);
            break;

        case "query_resolved":
            onQueryResolved(event);
            appendLogEntry(event);
            reloadCacheTable(false);
            break;

        case "mode_change":
            setModeUI(event.cipher_mode);
            break;

        case "provider_change":
            if (providerSelect) {
                providerSelect.value = event.provider;
            }
            if (activeProviderText && event.provider_info) {
                activeProviderText.textContent = event.provider_info.name;
            }
            break;

        case "cache_cleared":
            currentCacheEntries = [];
            renderCacheTable([]);
            if (event.stats) {
                updateStats(event.stats);
            }
            break;

        case "system_dns_change":
            applySystemDnsUI(event.status);
            break;
    }
}

// Traffic Scope Filtering
function matchesTrafficScope(item) {
    if (!item) return false;
    const cat = item.category || "web";
    const app = (item.source_app || "").toLowerCase();
    const domain = (item.domain || "").toLowerCase();

    const isSystemNoise = cat === "system" || 
        domain.includes("ubuntu.com") || 
        domain.includes("canonical.com") || 
        domain.includes("snapcraft.io") || 
        domain.includes(".arpa") || 
        domain.includes("connectivity-check") || 
        domain.includes("detectportal") ||
        domain.includes(".local") ||
        domain.includes(".lan") ||
        domain.includes(".home") ||
        domain.includes("ntp.org") ||
        domain.includes("wsdd");

    if (currentTrafficScope === "all") {
        return true;
    } else if (currentTrafficScope === "clean") {
        return !isSystemNoise;
    } else if (currentTrafficScope === "chrome") {
        return (app.includes("chrome") || app.includes("browser") || (!isSystemNoise && app !== "curl" && app !== "wget"));
    } else if (currentTrafficScope === "cli") {
        return (app.includes("curl") || app.includes("wget") || cat === "cli");
    }
    return true;
}

function changeTrafficScope(scope) {
    currentTrafficScope = scope;
    if (scopeFilterSelect) scopeFilterSelect.value = scope;
    renderCacheTable(currentCacheEntries);
}

// State 1: Query Initiated
function onQueryStart(event) {
    if (!matchesTrafficScope(event)) return; // Ignore noise in status ring
    if (idleResetTimer) clearTimeout(idleResetTimer);

    statusRing.className = "status-ring loading";
    ringIcon.innerHTML = `
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <polyline points="12 6 12 12 16 14"/>
        </svg>
    `;

    statusPrimaryText.textContent = event.message || `Making a DoH request to ${event.provider || 'upstream'}...`;
    statusPrimaryText.style.color = "var(--accent-amber)";
    statusSecondaryText.innerHTML = `Querying record <span class="mono-badge">${event.domain} (${event.qtype || 'A'})</span> from client ${event.client_ip || 'local'}`;
}

// State 2: Query Completed
function onQueryResolved(event) {
    if (matchesTrafficScope(event)) {
        if (idleResetTimer) clearTimeout(idleResetTimer);

        if (event.action === "CACHE_HIT") {
            // Cache Hit
            statusRing.className = "status-ring cache-hit";
            ringIcon.innerHTML = `
                <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="20 6 9 17 4 12"/>
                </svg>
            `;
            statusPrimaryText.textContent = `Successfully delivered the cached entry for ${event.domain}`;
            statusPrimaryText.style.color = "var(--accent-emerald)";
            statusSecondaryText.innerHTML = `Served from local memory • Latency: <span class="mono-badge">${event.latency_ms} ms</span> • Remaining TTL: <span class="mono-badge">${event.remaining_ttl}s</span>`;
        } else {
            // DoH or Plaintext Resolve
            const isDoh = event.action === "DOH_RESOLVE";
            statusRing.className = isDoh ? "status-ring doh-success" : "status-ring idle";
            ringIcon.innerHTML = `
                <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <polyline points="9 12 11 14 15 10"/>
                </svg>
            `;

            if (event.error) {
                statusPrimaryText.textContent = `Resolution Error: ${event.domain}`;
                statusPrimaryText.style.color = "var(--accent-rose)";
                statusSecondaryText.textContent = event.error;
            } else {
                statusPrimaryText.textContent = `Securely retrieved IP for ${event.domain}`;
                statusPrimaryText.style.color = isDoh ? "var(--accent-cyan)" : "var(--accent-amber)";
                statusSecondaryText.innerHTML = `Upstream: <span class="provider-highlight">${event.provider || 'DoH'}</span> • Latency: <span class="mono-badge">${event.latency_ms} ms</span> • Result: ${formatAnswerSummary(event.answers)}`;
            }
        }

        // Schedule return to normal idle state
        idleResetTimer = setTimeout(resetToIdleState, 3500);
    }
}

// State 3: Reset to Normal Idle State
function resetToIdleState() {
    statusRing.className = "status-ring idle";
    ringIcon.innerHTML = `
        <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <polyline points="9 12 11 14 15 10"/>
        </svg>
    `;
    statusPrimaryText.textContent = "cipherDNS running";
    statusPrimaryText.style.color = "var(--text-primary)";

    const port = portBadge.textContent || "53";
    const prov = (providerSelect && providerSelect.options[providerSelect.selectedIndex]) 
        ? providerSelect.options[providerSelect.selectedIndex].text 
        : "Cloudflare";

    statusSecondaryText.innerHTML = `Listening on UDP port <span class="mono-badge">${port}</span> • Encrypted DoH active via <span class="provider-highlight">${prov}</span>`;
}

// Fetch Status & Update Controls
async function fetchCurrentStatus() {
    try {
        const res = await fetch("/api/status");
        if (res.ok) {
            const data = await res.json();
            applyServerStatus(data);
        }
    } catch (e) {
        console.error("Error fetching status:", e);
    }
}

function applyServerStatus(status) {
    if (!status) return;

    if (portBadge && status.port) {
        portBadge.textContent = status.port;
    }
    if (status.provider_info && activeProviderText) {
        activeProviderText.textContent = status.provider_info.name;
    }
    if (providerSelect && status.current_provider) {
        providerSelect.value = status.current_provider;
    }
    setModeUI(status.cipher_mode_enabled !== false);

    if (status.stats) {
        updateStats(status.stats);
    }
}

function setModeUI(isCipherActive) {
    if (isCipherActive) {
        btnModeDoh.className = "mode-btn active";
        btnModePlain.className = "mode-btn";
    } else {
        btnModeDoh.className = "mode-btn";
        btnModePlain.className = "mode-btn active plain-active";
    }
}

async function setResolverMode(enableDoh) {
    try {
        const res = await fetch("/api/mode", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: enableDoh }),
        });
        if (res.ok) {
            setModeUI(enableDoh);
        }
    } catch (e) {
        console.error("Error setting resolver mode:", e);
    }
}

async function changeProvider(providerKey) {
    try {
        const res = await fetch("/api/provider", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ provider: providerKey }),
        });
        if (res.ok) {
            const data = await res.json();
            if (activeProviderText && data.provider_info) {
                activeProviderText.textContent = data.provider_info.name;
            }
        }
    } catch (e) {
        console.error("Error changing provider:", e);
    }
}

// System DNS Capture Controller
let isSystemDnsRouted = false;

async function checkSystemDnsStatus() {
    try {
        const res = await fetch("/api/system-dns");
        if (res.ok) {
            const data = await res.json();
            applySystemDnsUI(data);
        }
    } catch (e) {
        console.error("Error checking system DNS status:", e);
    }
}

function applySystemDnsUI(status) {
    const dot = document.getElementById("systemCaptureDot");
    const text = document.getElementById("systemCaptureText");
    const btn = document.getElementById("btnSystemDnsToggle");
    if (!dot || !text) return;

    isSystemDnsRouted = !!(status && status.is_routed_to_cipherdns);

    if (isSystemDnsRouted) {
        dot.style.background = "var(--accent-emerald)";
        dot.style.boxShadow = "0 0 8px var(--accent-emerald)";
        text.textContent = "Laptop Traffic: Captured";
        text.style.color = "var(--accent-emerald)";
        if (btn) btn.title = "Click to restore default system DNS";
    } else {
        dot.style.background = "var(--accent-amber)";
        dot.style.boxShadow = "none";
        text.textContent = "Route Laptop Traffic";
        text.style.color = "var(--text-secondary)";
        if (btn) btn.title = "Click to route all Chrome, curl, wget traffic through cipherDNS";
    }
}

async function toggleSystemDnsCapture() {
    const nextState = !isSystemDnsRouted;
    const text = document.getElementById("systemCaptureText");
    if (text) text.textContent = "Applying...";

    try {
        const res = await fetch("/api/system-dns", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enable: nextState }),
        });
        if (res.ok) {
            const data = await res.json();
            applySystemDnsUI(data.status);
        }
    } catch (e) {
        alert("Failed to toggle system DNS: " + e.message);
        checkSystemDnsStatus();
    }
}

// Cache Table Operations
async function reloadCacheTable(showReloadAnimation = true) {
    const btnReload = document.getElementById("btnReloadCache");
    if (showReloadAnimation && btnReload) {
        btnReload.style.transform = "rotate(180deg)";
        setTimeout(() => { btnReload.style.transform = ""; }, 300);
    }

    try {
        const res = await fetch("/api/cache");
        if (res.ok) {
            const data = await res.json();
            currentCacheEntries = data.entries || [];
            renderCacheTable(currentCacheEntries);
            if (data.stats) updateStats(data.stats);
        }
    } catch (e) {
        console.error("Error reloading cache:", e);
    }
}

function renderCacheTable(entries) {
    currentCacheEntries = entries;
    const filter = (cacheSearchInput ? cacheSearchInput.value : "").trim().toLowerCase();

    // 1. Filter by active traffic scope
    const scoped = entries.filter(matchesTrafficScope);
    // 2. Filter by search input
    const filtered = filter ? scoped.filter(e => e.domain.includes(filter)) : scoped;

    tableCountBadge.textContent = `${filtered.length} entries (${entries.length} total)`;
    metricCachedEntries.textContent = filtered.length;

    if (filtered.length === 0) {
        cacheTableBody.innerHTML = `
            <tr class="empty-row">
                <td colspan="9">
                    <div class="empty-state">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                        <span>${filter ? "No domains matching '" + filter + "'" : "No cached entries matching scope '" + currentTrafficScope + "'. Make a request or try netflix.com above!"}</span>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    let html = "";
    filtered.forEach(entry => {
        const statusClass = entry.status === "expired" ? "expired" : (entry.status === "expiring" ? "expiring" : "active");
        const ipsHtml = entry.answers && entry.answers.length > 0
            ? entry.answers.map(ans => `<span class="ip-badge">${escapeHtml(ans)}</span>`).join("")
            : `<span class="ip-badge" style="color:var(--text-muted)">NXDOMAIN</span>`;

        // App badge
        let appBadge = '<span class="app-tag tag-web">Web / User</span>';
        const appName = (entry.source_app || '').toLowerCase();
        if (appName.includes('chrome')) {
            appBadge = '<span class="app-tag tag-chrome">Chrome</span>';
        } else if (appName.includes('curl')) {
            appBadge = '<span class="app-tag tag-cli">curl</span>';
        } else if (appName.includes('wget')) {
            appBadge = '<span class="app-tag tag-cli">wget</span>';
        } else if (entry.category === 'system' || entry.domain.includes('ubuntu') || entry.domain.includes('arpa')) {
            appBadge = '<span class="app-tag tag-system">OS Daemon</span>';
        }

        html += `
            <tr data-domain="${escapeHtml(entry.domain)}">
                <td class="domain-cell">
                    <span>${escapeHtml(entry.domain)}</span>
                </td>
                <td>${appBadge}</td>
                <td><span class="record-type-badge">${escapeHtml(entry.type)}</span></td>
                <td><div class="ip-list">${ipsHtml}</div></td>
                <td>
                    <div class="ttl-container">
                        <div class="ttl-text">
                            <span class="ttl-val mono">${entry.remaining_ttl}s</span>
                            <span class="ttl-pct">${entry.ttl_percent}%</span>
                        </div>
                        <div class="ttl-bar-bg">
                            <div class="ttl-bar-fill ${statusClass}" style="width: ${entry.ttl_percent}%"></div>
                        </div>
                    </div>
                </td>
                <td class="mono">${entry.original_ttl}s</td>
                <td class="mono">${entry.hit_count}</td>
                <td class="mono" style="color:var(--text-muted)">${entry.inserted_at_iso}</td>
                <td><span class="status-tag ${statusClass}">${escapeHtml(entry.status)}</span></td>
            </tr>
        `;
    });

    cacheTableBody.innerHTML = html;
}

function filterCacheTable() {
    renderCacheTable(currentCacheEntries);
}

// Local live TTL countdown tick every second
function startLocalTtlCountdown() {
    if (localTtlInterval) clearInterval(localTtlInterval);
    localTtlInterval = setInterval(() => {
        if (!currentCacheEntries || currentCacheEntries.length === 0) return;

        let needsRerender = false;
        currentCacheEntries.forEach(entry => {
            if (entry.remaining_ttl > 0) {
                entry.remaining_ttl = Math.max(0, entry.remaining_ttl - 1);
                entry.ttl_percent = entry.original_ttl > 0 ? Math.floor((entry.remaining_ttl / entry.original_ttl) * 100) : 0;
                if (entry.remaining_ttl === 0) {
                    entry.status = "expired";
                    needsRerender = true;
                } else if (entry.remaining_ttl < 15 && entry.status !== "expiring") {
                    entry.status = "expiring";
                    needsRerender = true;
                }
            }
        });

        // Fast in-place DOM update for countdown numbers
        const rows = cacheTableBody.querySelectorAll("tr[data-domain]");
        rows.forEach(row => {
            const domain = row.getAttribute("data-domain");
            const entry = currentCacheEntries.find(e => e.domain === domain);
            if (entry) {
                const ttlVal = row.querySelector(".ttl-val");
                const ttlPct = row.querySelector(".ttl-pct");
                const ttlFill = row.querySelector(".ttl-bar-fill");
                if (ttlVal) ttlVal.textContent = `${entry.remaining_ttl}s`;
                if (ttlPct) ttlPct.textContent = `${entry.ttl_percent}%`;
                if (ttlFill) {
                    ttlFill.style.width = `${entry.ttl_percent}%`;
                    ttlFill.className = `ttl-bar-fill ${entry.status}`;
                }
            }
        });

        if (needsRerender) {
            renderCacheTable(currentCacheEntries);
        }
    }, 1000);
}

async function clearCache() {
    try {
        const res = await fetch("/api/cache/clear", { method: "POST" });
        if (res.ok) {
            reloadCacheTable(true);
        }
    } catch (e) {
        console.error("Error clearing cache:", e);
    }
}

// Manual Test Query
async function executeManualQuery() {
    const input = document.getElementById("testDomainInput");
    const domain = input ? input.value.trim() : "netflix.com";
    if (!domain) return;

    try {
        const res = await fetch("/api/test-query", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: domain, record_type: "A" }),
        });
        if (res.ok) {
            const data = await res.json();
            if (data.entries) {
                renderCacheTable(data.entries);
            }
            if (data.stats) {
                updateStats(data.stats);
            }
        }
    } catch (e) {
        console.error("Error executing test query:", e);
    }
}

// Live Stream Log Appender
function appendLogEntry(event) {
    if (!matchesTrafficScope(event)) return; // Ignore background noise in live stream

    if (logEmptyState && logEmptyState.style.display !== "none") {
        logEmptyState.style.display = "none";
    }

    const timeStr = event.timestamp 
        ? new Date(event.timestamp * 1000).toLocaleTimeString() 
        : new Date().toLocaleTimeString();

    let entryClass = "log-entry";
    let actionBadge = "";

    if (event.action === "CACHE_HIT") {
        entryClass += " cache-hit";
        actionBadge = `<span class="log-action hit">CACHE HIT</span>`;
    } else if (event.action === "DOH_RESOLVE" || event.action === "DOH_START") {
        entryClass += " doh-resolve";
        actionBadge = `<span class="log-action doh">DoH</span>`;
    } else {
        entryClass += " plaintext";
        actionBadge = `<span class="log-action plain">PLAIN</span>`;
    }

    const entry = document.createElement("div");
    entry.className = entryClass;
    entry.innerHTML = `
        <span class="log-time">${timeStr}</span>
        ${actionBadge}
        <span class="log-msg">${escapeHtml(event.message || event.domain)}</span>
        ${event.latency_ms ? `<span class="log-latency">${event.latency_ms}ms</span>` : ''}
    `;

    logStreamContainer.insertBefore(entry, logStreamContainer.firstChild);

    // Keep max 50 log elements
    while (logStreamContainer.children.length > 50) {
        logStreamContainer.removeChild(logStreamContainer.lastChild);
    }
}

function clearLogFeed() {
    logStreamContainer.innerHTML = `<div class="log-empty" id="logEmptyState">Log feed cleared. Waiting for queries...</div>`;
}

function updateStats(stats) {
    if (metricHitRatio && stats.hit_ratio_pct !== undefined) {
        metricHitRatio.textContent = `${stats.hit_ratio_pct}%`;
    }
    if (metricHitsMisses) {
        metricHitsMisses.textContent = `${stats.total_hits || 0} hits / ${stats.total_misses || 0} misses`;
    }
    if (metricCachedEntries && stats.total_entries !== undefined) {
        metricCachedEntries.textContent = stats.total_entries;
    }
}

// Zeek Modal Controller
function openZeekModal() {
    document.getElementById("zeekModal").style.display = "flex";
}

function closeZeekModal() {
    document.getElementById("zeekModal").style.display = "none";
}

async function runZeekAudit() {
    const domainInput = document.getElementById("zeekDomainInput");
    const domain = domainInput ? domainInput.value.trim() : "netflix.com";

    const loading = document.getElementById("zeekLoading");
    const results = document.getElementById("zeekResultsArea");
    const btn = document.getElementById("btnExecuteZeekAudit");

    loading.style.display = "flex";
    results.style.display = "none";
    btn.disabled = true;

    try {
        const res = await fetch("/api/zeek/audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: domain }),
        });
        const data = await res.json();

        // Render Verdict
        const banner = document.getElementById("zeekVerdictBanner");
        banner.className = "audit-verdict-banner pass";
        banner.innerHTML = `
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
            <span>${escapeHtml(data.verdict)}</span>
        `;

        // Render Traditional Column
        const plainLog = document.getElementById("plainZeekLog");
        const plainNote = document.getElementById("plainRiskNote");
        plainLog.textContent = data.traditional_dns.details && data.traditional_dns.details.length > 0
            ? JSON.stringify(data.traditional_dns.details, null, 2)
            : `query: ${data.traditional_dns.leaked_queries.join(', ')}\n(Port 53 UDP query in plaintext)`;
        plainNote.textContent = data.traditional_dns.risk_assessment;

        // Render cipherDNS DoH Column
        const dohLog = document.getElementById("dohZeekLog");
        const dohNote = document.getElementById("dohSecurityNote");
        dohLog.textContent = data.cipher_dns.leaked_queries.length === 0
            ? `# Zero plain queries detected in Zeek dns.log!\n# Traffic to 1.1.1.1:443 encapsulated in TLS 1.3 Application Data.`
            : JSON.stringify(data.cipher_dns.leaked_queries);
        dohNote.textContent = data.cipher_dns.security_status;

        loading.style.display = "none";
        results.style.display = "block";
    } catch (e) {
        alert("Zeek audit error: " + e.message);
        loading.style.display = "none";
    } finally {
        btn.disabled = false;
    }
}

function openSystemModal() {
    document.getElementById("systemSetupModal").style.display = "flex";
}

function closeSystemModal() {
    document.getElementById("systemSetupModal").style.display = "none";
}

function formatAnswerSummary(answers) {
    if (!answers || answers.length === 0) return "NXDOMAIN";
    return answers.slice(0, 2).join(", ") + (answers.length > 2 ? ` (+${answers.length - 2} more)` : "");
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

