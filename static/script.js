"use strict";

// All server data is rendered through the DOM text APIs or the escape helper
// below, never via innerHTML string interpolation, so a hostile banner/title
// (e.g. one containing <script>) can never inject into this page.

let currentJobId = null;
let eventSource = null;
let lastResult = null;

const PRESETS = {
  top20: "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443",
  web: "80,443,8080,8443,8000,8888,3000,5000",
  db: "1433,1521,3306,5432,6379,27017,9200,11211",
  remote: "21,22,23,3389,5900,5985,5986",
  all: "-",
};

function $(id) { return document.getElementById(id); }

function esc(value) {
  const s = value === null || value === undefined ? "" : String(value);
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}

function logLine(msg) {
  const term = $("scan-log");
  if (!term) return;
  term.appendChild(document.createTextNode(msg + "\n"));
  term.scrollTop = term.scrollHeight;
}

function formatEta(seconds) {
  if (seconds === null || seconds === undefined) return "--";
  const s = Math.max(0, Math.round(seconds));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (h) return `${h}h ${m}m ${sec}s`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}

function setProgress(p) {
  $("progress-container").style.display = "block";
  const pct = Math.max(0, Math.min(100, p.percent || 0));
  $("progress-bar").style.width = pct + "%";
  $("progress-text").textContent =
    (p.total ? `${pct.toFixed(1)}% (${p.completed}/${p.total})` : `${pct.toFixed(1)}%`);
  $("eta-text").textContent = formatEta(p.eta_seconds);
}

async function loadCapability() {
  try {
    const res = await fetch("/capability");
    const cap = await res.json();
    const b = $("auth-banner");
    b.textContent = `Engine: ${cap.os} — ${cap.note}`;
    b.classList.toggle("ok", !!cap.raw_tcp);
    b.classList.toggle("warn", !cap.raw_tcp);
  } catch (_) { /* leave default text */ }
}

$("preset").addEventListener("change", () => {
  const v = $("preset").value;
  if (v && PRESETS[v]) $("ports").value = PRESETS[v];
});

$("show_all").addEventListener("change", renderResults);

function collectConfig() {
  const allow = $("allow").value.trim();
  return {
    target: $("target").value.trim(),
    ports: $("ports").value.trim() || "1-1000",
    scan_type: $("scan_type").value,
    timing: parseInt($("timing").value, 10),
    service_detection: $("service_detection").checked,
    os_detection: $("os_detection").checked,
    vuln_check: $("vuln_check").checked,
    skip_discovery: $("skip_discovery").checked,
    scan_all_hosts: $("scan_all_hosts").checked,
    frag_mtu: parseInt($("frag_mtu").value, 10) || 0,
    decoys: $("decoys").value.trim(),
    source_port: $("source_port").value.trim(),
    ttl: $("ttl").value.trim(),
    authorized: $("authorized").checked,
    allow: allow ? [allow] : [],
  };
}

async function startScan() {
  const cfg = collectConfig();
  if (!cfg.target) { alert("Enter a target."); return; }

  $("summary").style.display = "none";
  $("results").style.display = "none";
  $("log-container").style.display = "block";
  $("scan-log").textContent = "";
  lastResult = null;
  toggleExports(false);

  let payload;
  try {
    const res = await fetch("/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cfg),
    });
    payload = await res.json();
    if (!res.ok) { logLine("ERROR: " + (payload.error?.message || "start failed")); return; }
  } catch (e) { logLine("ERROR: could not reach server"); return; }

  currentJobId = payload.job_id;
  $("btn-scan").disabled = true;
  $("btn-cancel").disabled = false;
  logLine(`Job ${currentJobId} started.`);
  openStream(currentJobId);
}

function openStream(jobId) {
  if (eventSource) eventSource.close();
  eventSource = new EventSource(`/scan/stream/${jobId}`);

  eventSource.onmessage = (ev) => {
    let e;
    try { e = JSON.parse(ev.data); } catch (_) { return; }

    if (e.type === "progress") { setProgress(e.data || {}); return; }
    if (e.type === "hello") return;

    if (e.message && e.type !== "done") logLine(`[${e.type}] ${e.message}`);

    if (e.type === "done" && e.data && e.data.final) {
      eventSource.close();
      eventSource = null;
      $("btn-scan").disabled = false;
      $("btn-cancel").disabled = true;
      $("progress-container").style.display = "none";
      if (e.result) { lastResult = e.result; renderSummary(); renderResults(); toggleExports(true); }
      loadHistory();
    }
  };

  eventSource.onerror = () => {
    logLine("[stream] connection closed.");
    if (eventSource) { eventSource.close(); eventSource = null; }
    $("btn-scan").disabled = false;
    $("btn-cancel").disabled = true;
    // Fall back to a one-shot result fetch in case the stream dropped early.
    if (currentJobId && !lastResult) fetchResultFallback(currentJobId);
  };
}

async function fetchResultFallback(jobId) {
  try {
    const res = await fetch(`/scan/result/${jobId}`);
    if (res.status === 202) return;
    const data = await res.json();
    if (data.result) { lastResult = data.result; renderSummary(); renderResults(); toggleExports(true); loadHistory(); }
  } catch (_) {}
}

async function cancelScan() {
  if (!currentJobId) return;
  try { await fetch(`/scan/cancel/${currentJobId}`, { method: "POST" }); logLine("Cancellation requested."); }
  catch (_) {}
}

function renderSummary() {
  const d = lastResult;
  const box = $("summary");
  box.textContent = "";
  box.style.display = "block";

  const rows = [
    ["Target", d.target],
    ["Scan type", d.scan_type],
    ["Ports", d.port_query],
    ["Duration", `${(d.duration || 0).toFixed(1)}s`],
    ["Capability", d.capability?.note || ""],
  ];
  if (d.evasion && d.evasion.length) rows.push(["Evasion", d.evasion.join(", ")]);

  rows.forEach(([k, v]) => {
    const p = el("p");
    p.appendChild(el("strong", k + ": "));
    p.appendChild(document.createTextNode(v || ""));
    box.appendChild(p);
  });

  (d.warnings || []).forEach((w) => box.appendChild(el("p", "⚠ " + w, "warn-text")));

  // Scan diff vs previous run.
  const cmp = d.compare || { opened: [], closed: [] };
  const diff = el("p");
  diff.appendChild(el("strong", "Since last scan — "));
  diff.appendChild(document.createTextNode(
    `newly open: ${cmp.opened?.length ? cmp.opened.join(", ") : "none"}; ` +
    `now closed: ${cmp.closed?.length ? cmp.closed.join(", ") : "none"}`));
  box.appendChild(diff);
}

function renderResults() {
  if (!lastResult) return;
  const showAll = $("show_all").checked;
  const box = $("results");
  box.textContent = "";
  box.style.display = "block";

  (lastResult.hosts || []).forEach((host) => {
    const h = el("h3", host.host + (host.hostname ? ` (${host.hostname})` : ""));
    box.appendChild(h);

    if (host.os) {
      const label = host.os.name && host.os.name !== "Unknown"
        ? `OS: ${host.os.name} (${Math.round((host.os.confidence || 0) * 100)}%) — ${host.os.details || ""}`
        : `OS: Unknown — ${host.os.details || "no signal"}`;
      box.appendChild(el("p", label, "os-line"));
    }

    const ports = (host.ports || []).filter((p) => showAll || String(p.state).startsWith("open"));
    if (!ports.length) { box.appendChild(el("p", "No matching ports.")); return; }

    const table = el("table");
    const head = el("tr");
    ["Port", "Proto", "State", "Service", "Product/Version", "CVEs", "RTT"].forEach((t) => head.appendChild(el("th", t)));
    table.appendChild(head);

    ports.forEach((p) => {
      const tr = el("tr");
      if (String(p.state).startsWith("open")) tr.className = "row-open";
      const svc = p.service || {};
      const cves = (svc.vulns || []).map((v) => v.cve).join(", ");
      tr.appendChild(el("td", p.port));
      tr.appendChild(el("td", p.protocol));
      tr.appendChild(el("td", p.state));
      tr.appendChild(el("td", svc.name || ""));
      const pv = `${svc.product || ""} ${svc.version || ""}`.trim();
      tr.appendChild(el("td", pv));
      const cveCell = el("td", cves);
      if (cves) cveCell.className = "cve-cell";
      tr.appendChild(cveCell);
      tr.appendChild(el("td", p.rtt_ms != null ? p.rtt_ms + "ms" : ""));
      table.appendChild(tr);

      // Detail row: banner + vuln summaries (escaped).
      if (svc.banner || (svc.vulns && svc.vulns.length) || svc.extra) {
        const dtr = el("tr", null, "detail-row");
        const td = el("td");
        td.colSpan = 7;
        if (svc.extra) td.appendChild(el("div", svc.extra, "svc-extra"));
        if (svc.banner) td.appendChild(el("pre", svc.banner, "svc-banner"));
        (svc.vulns || []).forEach((v) => {
          td.appendChild(el("div", `${v.cve} [${v.severity}${v.cvss ? " " + v.cvss : ""}] — ${v.summary}`, "vuln-line"));
        });
        dtr.appendChild(td);
        table.appendChild(dtr);
      }
    });
    box.appendChild(table);
  });
}

function toggleExports(on) {
  ["btn-csv", "btn-json", "btn-xml", "btn-md", "btn-html"].forEach((id) => { $(id).disabled = !on; });
}

function downloadReport(fmt) {
  if (!currentJobId) return;
  window.location.href = `/scan/report/${currentJobId}.${fmt}`;
}

async function loadHistory() {
  const table = $("history-table");
  try {
    const res = await fetch("/history");
    const data = await res.json();
    const hist = data.history || [];
    table.textContent = "";
    if (!hist.length) { table.appendChild(el("p", "No scan history yet.")); return; }

    const t = el("table");
    const head = el("tr");
    ["Time", "Target", "Type", "Hosts", "Open"].forEach((x) => head.appendChild(el("th", x)));
    t.appendChild(head);
    hist.forEach((h) => {
      const tr = el("tr");
      tr.appendChild(el("td", new Date((h.timestamp || 0) * 1000).toLocaleString()));
      tr.appendChild(el("td", h.target));
      tr.appendChild(el("td", h.scan_type));
      tr.appendChild(el("td", h.hosts));
      tr.appendChild(el("td", h.open_count));
      t.appendChild(tr);
    });
    table.appendChild(t);
  } catch (_) { table.textContent = "Failed to load history."; }
}

$("btn-scan").addEventListener("click", startScan);
$("btn-cancel").addEventListener("click", cancelScan);
$("btn-csv").addEventListener("click", () => downloadReport("csv"));
$("btn-json").addEventListener("click", () => downloadReport("json"));
$("btn-xml").addEventListener("click", () => downloadReport("xml"));
$("btn-md").addEventListener("click", () => downloadReport("markdown"));
$("btn-html").addEventListener("click", () => downloadReport("html"));

window.addEventListener("DOMContentLoaded", () => { loadCapability(); loadHistory(); });
