let scanResults = null;
let currentJobId = null;
let pollTimer = null;
let lastLogCount = 0;

const TOP_PORT_PRESETS = {
    top100: "1-100",
    top1000: "1-1000",
    web: "80,443,8080,8443,8000,8888,3000,5000",
    db: "1433,1521,3306,5432,6379,27017,9200,11211",
    remote: "21,22,23,3389,5900,5985,5986"
};

function logToTerminal(msg) {
    const terminal = document.getElementById("scan-log");
    if (!terminal) return;
    terminal.innerText += msg + "\n";
    terminal.scrollTop = terminal.scrollHeight;
}

function formatEta(seconds) {
    if (seconds === null || seconds === undefined) return "--";
    const s = Math.max(0, Math.round(seconds));
    const hh = Math.floor(s / 3600);
    const mm = Math.floor((s % 3600) / 60);
    const ss = s % 60;
    if (hh > 0) return `${hh}h ${mm}m ${ss}s`;
    if (mm > 0) return `${mm}m ${ss}s`;
    return `${ss}s`;
}

function setProgress(percent = 0, completed = 0, total = 0, etaSeconds = null) {
    const progressContainer = document.getElementById("progress-container");
    const progressBar = document.getElementById("progress-bar");
    const progressText = document.getElementById("progress-text");
    const etaText = document.getElementById("eta-text");
    if (!progressContainer || !progressBar) return;
    progressContainer.style.display = "block";
    progressBar.style.animation = "none";
    progressBar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
    if (progressText) {
        if (total > 0) {
            progressText.innerText = `${percent.toFixed(1)}% (${completed}/${total})`;
        } else {
            progressText.innerText = `${percent.toFixed(1)}%`;
        }
    }
    if (etaText) etaText.innerText = formatEta(etaSeconds);
}

function applyTopPreset() {
    const preset = document.getElementById("top_ports_preset")?.value || "";
    const portRangeInput = document.getElementById("port_range");
    if (!portRangeInput) return;
    if (!preset) return;
    const mapped = TOP_PORT_PRESETS[preset];
    if (mapped) portRangeInput.value = mapped;
}

function hideProgress() {
    const progressContainer = document.getElementById("progress-container");
    if (progressContainer) progressContainer.style.display = "none";
}

function showError(err) {
    const outputDiv = document.getElementById("output");
    if (!outputDiv) return;
    const message = err?.message || err?.error?.message || "An error occurred during scan.";
    const hint = err?.hint || err?.error?.hint || "";
    outputDiv.style.display = "block";
    outputDiv.innerHTML = `<p><strong>Error:</strong> ${message}</p>${hint ? `<p><strong>Hint:</strong> ${hint}</p>` : ""}`;
}

function renderRouteTable(targetDiv = "route-table") {
    const routeDiv = document.getElementById(targetDiv);
    if (!routeDiv || !scanResults) return;
    const hops = scanResults.route_table || [];
    if (!Array.isArray(hops) || hops.length === 0) {
        routeDiv.innerHTML = "<p><strong>Route Table:</strong> No hop data available.</p>";
        return;
    }

    let html = `
        <h3>Route Table</h3>
        <table>
            <tr><th>Hop</th><th>IP</th><th>RTT (ms)</th><th>Status</th></tr>
    `;
    hops.forEach((hop) => {
        html += `
            <tr>
                <td>${hop.hop ?? ""}</td>
                <td>${hop.ip ?? ""}</td>
                <td>${hop.rtt_ms ?? ""}</td>
                <td>${hop.status ?? ""}</td>
            </tr>
        `;
    });
    html += "</table>";
    routeDiv.innerHTML = html;
}

function renderCompare() {
    const container = document.getElementById("compare-box");
    if (!container || !scanResults) return;
    const compare = scanResults.compare || { opened: [], closed: [] };
    const opened = compare.opened || [];
    const closed = compare.closed || [];
    container.innerHTML = `
        <h3>Compared To Previous</h3>
        <p><strong>Newly Open:</strong> ${opened.length ? opened.join(", ") : "None"}</p>
        <p><strong>Now Closed:</strong> ${closed.length ? closed.join(", ") : "None"}</p>
    `;
}

function renderPortTable(targetDiv = "scan-table") {
    const outputDiv = document.getElementById(targetDiv);
    if (!outputDiv || !scanResults || !scanResults.results) return;

    const showAll = document.getElementById("show_all").checked;
    const filteredResults = showAll
        ? scanResults.results
        : scanResults.results.filter((p) => p.status.toLowerCase().includes("open"));

    let tableHTML = `
        <table>
            <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Service</th>
                <th>Status</th>
                <th>Version</th>
            </tr>
    `;

    filteredResults.forEach((port) => {
        tableHTML += `
            <tr>
                <td>${port.host || scanResults.ip || ""}</td>
                <td>${port.port ?? ""}</td>
                <td>${port.service ?? ""}</td>
                <td>${port.status ?? ""}</td>
                <td>${port.version || ""}</td>
            </tr>
        `;
    });
    tableHTML += "</table>";

    if (filteredResults.some((p) => p.status.toLowerCase().includes("filtered"))) {
        tableHTML += "<p><strong>Network Filtering Detected:</strong> Some ports are filtered or uncertain.</p>";
    }
    outputDiv.innerHTML = tableHTML;
}

function toggleResults() {
    renderPortTable("scan-table");
    const liveStatus = document.getElementById("live-status");
    if (liveStatus) liveStatus.innerText = document.getElementById("show_all").checked ? "Yes" : "No";
    const toggleStatus = document.getElementById("toggle-status");
    if (toggleStatus) toggleStatus.innerText = document.getElementById("show_all").checked ? "(All ports)" : "(Only open ports)";
}

async function pollScan(jobId) {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
        try {
            const res = await fetch(`/scan/status/${jobId}`);
            const statusData = await res.json();
            if (!res.ok) {
                clearInterval(pollTimer);
                showError(statusData.error || statusData);
                hideProgress();
                return;
            }

            setProgress(
                statusData.percent || 0,
                statusData.completed || 0,
                statusData.total || 0,
                statusData.eta_seconds
            );
            const terminal = document.getElementById("scan-log");
            if (terminal) {
                const logs = statusData.logs || [];
                if (logs.length < lastLogCount) {
                    terminal.innerText = "";
                    lastLogCount = 0;
                }
                for (let i = lastLogCount; i < logs.length; i += 1) {
                    logToTerminal(logs[i]);
                }
                lastLogCount = logs.length;
            }

            if (statusData.status === "completed" || statusData.status === "failed") {
                clearInterval(pollTimer);
                await fetchScanResult(jobId);
            }
        } catch (error) {
            clearInterval(pollTimer);
            showError({ message: "Failed to poll scan status." });
            hideProgress();
        }
    }, 700);
}

async function fetchScanResult(jobId) {
    try {
        const res = await fetch(`/scan/result/${jobId}`);
        const data = await res.json();

        if (!res.ok) {
            showError(data.error || data);
            hideProgress();
            return;
        }
        if (res.status === 202) return;

        scanResults = data;
        const outputDiv = document.getElementById("output");
        const includeRoute = document.getElementById("include_route").checked;

        outputDiv.style.display = "block";
        outputDiv.innerHTML = `
            <p><strong>Target:</strong> ${data.target || ""}</p>
            <p><strong>Mode:</strong> ${data.target_mode || "single"}</p>
            <p><strong>Resolved IP:</strong> ${data.ip || ""} ${data.hostname ? `( ${data.hostname} )` : ""}</p>
            <p><strong>Alive Hosts:</strong> ${(data.alive_hosts || []).join(", ") || "N/A"}</p>
            <p><strong>Scanned Hosts:</strong> ${(data.scanned_hosts || []).join(", ") || "N/A"}</p>
            <p><strong>Location:</strong> ${(data.geolocation?.city || "Unknown")}, ${(data.geolocation?.region || "Unknown")}, ${(data.geolocation?.country || "Unknown")}</p>
            <p><strong>Detected OS:</strong> ${data.os || "Unknown"}</p>
            <p><strong>Firewall/WAF:</strong> ${data.firewall || "Unknown"}</p>
            <p><strong>Scan Type:</strong> ${data.scan_type || ""}</p>
            <p><strong>Port Query:</strong> ${data.port_query || ""}</p>
            <p><strong>Scanned Ports:</strong> ${data.scanned_ports || 0}</p>
            <p><strong>Show All:</strong> <span id="live-status">${document.getElementById("show_all").checked ? "Yes" : "No"}</span></p>
            <p><strong>Route Table:</strong> ${includeRoute ? "Enabled" : "Disabled"}</p>
            <hr/>
            <div id="compare-box"></div>
            <div id="scan-table"></div>
            <div id="route-table"></div>
        `;

        renderCompare();
        renderPortTable("scan-table");
        if (includeRoute) renderRouteTable("route-table");
        await loadHistory();
    } catch (error) {
        showError({ message: "Failed to fetch scan result." });
    } finally {
        hideProgress();
    }
}

async function startScan() {
    const target = document.getElementById("target").value.trim();
    const numPorts = parseInt(document.getElementById("num_ports").value, 10);
    const portRange = document.getElementById("port_range").value.trim();
    const scanType = document.getElementById("scan_type").value;
    const preset = document.getElementById("top_ports_preset")?.value || "";
    const showAll = document.getElementById("show_all").checked;
    const includeRoute = document.getElementById("include_route").checked;
    const scanAllHosts = document.getElementById("scan_all_hosts")?.checked || false;
    const tuning = "T3";

    let effectivePortRange = portRange;
    if (!effectivePortRange && preset && TOP_PORT_PRESETS[preset]) {
        effectivePortRange = TOP_PORT_PRESETS[preset];
    }

    const hasRange = effectivePortRange.length > 0;
    const rangePattern = /^\s*\d+(\s*-\s*\d+)?(\s*,\s*\d+(\s*-\s*\d+)?)*\s*$/;
    const validCount = !Number.isNaN(numPorts) && numPorts >= 1 && numPorts <= 65535;

    if (!target) {
        showError({ message: "No target specified.", hint: "Provide a domain, IP, or CIDR block." });
        return;
    }
    if (!hasRange && !validCount) {
        showError({ message: "Invalid ports value.", hint: "Use Number of Ports or provide Port Range/List." });
        return;
    }
    if (hasRange && !rangePattern.test(effectivePortRange)) {
        showError({ message: "Invalid port range format.", hint: "Example: 1-1024,3306,8080" });
        return;
    }

    const outputDiv = document.getElementById("output");
    const terminal = document.getElementById("scan-log");
    document.getElementById("log-container").style.display = "block";
    outputDiv.style.display = "block";
    outputDiv.innerHTML = `<p>Queued scan for <strong>${target}</strong>...</p>`;
    if (terminal) terminal.innerText = "";
    lastLogCount = 0;
    setProgress(0, 0, 0, null);

    try {
        const response = await fetch("/scan/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                target,
                ports: numPorts,
                port_range: effectivePortRange,
                scan_type: scanType,
                show_all: showAll,
                include_route: includeRoute,
                scan_all_hosts: scanAllHosts,
                tuning,
            }),
        });
        const payload = await response.json();
        if (!response.ok) {
            showError(payload.error || payload);
            hideProgress();
            return;
        }
        currentJobId = payload.job_id;
        logToTerminal(`Job ${currentJobId} started.`);
        await pollScan(currentJobId);
    } catch (error) {
        showError({ message: "Failed to start scan job." });
        hideProgress();
    }
}

function exportToCSV() {
    if (!scanResults || !scanResults.results || scanResults.results.length === 0) {
        alert("No scan results to export.");
        return;
    }

    const showAll = document.getElementById("show_all").checked;
    const filtered = showAll
        ? scanResults.results
        : scanResults.results.filter((p) => p.status.toLowerCase().includes("open"));

    let csvContent = "data:text/csv;charset=utf-8,";
    csvContent += "Target,Host,Port,Service,Status,Version\n";
    filtered.forEach((port) => {
        csvContent += `${scanResults.target || ""},${port.host || ""},${port.port},${port.service},${port.status},${(port.version || "").replaceAll(",", ";")}\n`;
    });

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "port_scan_report.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function exportToJSON() {
    if (!scanResults) {
        alert("No scan results to export.");
        return;
    }
    const blob = new Blob([JSON.stringify(scanResults, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "port_scan_report.json";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function exportToMarkdown() {
    if (!scanResults) {
        alert("No scan results to export.");
        return;
    }
    const lines = [];
    lines.push(`# Port Scan Report`);
    lines.push(`- Target: ${scanResults.target || ""}`);
    lines.push(`- Mode: ${scanResults.target_mode || "single"}`);
    lines.push(`- Scan Type: ${scanResults.scan_type || ""}`);
    lines.push(`- Port Query: ${scanResults.port_query || ""}`);
    lines.push(`- Scanned Ports: ${scanResults.scanned_ports || 0}`);
    lines.push(``);
    lines.push(`## Compare`);
    lines.push(`- Opened: ${(scanResults.compare?.opened || []).join(", ") || "None"}`);
    lines.push(`- Closed: ${(scanResults.compare?.closed || []).join(", ") || "None"}`);
    lines.push(``);
    lines.push(`## Results`);
    lines.push(`| Host | Port | Service | Status | Version |`);
    lines.push(`|---|---:|---|---|---|`);
    (scanResults.results || []).forEach((r) => {
        lines.push(`| ${r.host || ""} | ${r.port || ""} | ${r.service || ""} | ${r.status || ""} | ${(r.version || "").replace(/\|/g, "\\|")} |`);
    });

    const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "port_scan_report.md";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

async function loadHistory() {
    const table = document.getElementById("history-table");
    if (!table) return;
    try {
        const res = await fetch("/history");
        const data = await res.json();
        const history = data.history || [];
        if (!history.length) {
            table.innerHTML = "<p>No scan history yet.</p>";
            return;
        }
        let html = `
            <table>
                <tr>
                    <th>Time</th>
                    <th>Target</th>
                    <th>Mode</th>
                    <th>Hosts</th>
                    <th>Ports</th>
                    <th>Open</th>
                </tr>
        `;
        history.forEach((h) => {
            const dt = new Date((h.timestamp || 0) * 1000).toLocaleString();
            html += `
                <tr>
                    <td>${dt}</td>
                    <td>${h.target_key || ""}</td>
                    <td>${h.target_mode || ""}</td>
                    <td>${(h.scanned_hosts || []).length}</td>
                    <td>${h.scanned_ports || 0}</td>
                    <td>${h.open_ports_count || 0}</td>
                </tr>
            `;
        });
        html += "</table>";
        table.innerHTML = html;
    } catch (error) {
        table.innerHTML = "<p>Failed to load history.</p>";
    }
}

window.addEventListener("DOMContentLoaded", () => {
    loadHistory();
});
