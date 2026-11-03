/* SOC Agent Monitor — vanilla JS, no external scripts (air-gapped requirement).
   Data sources: /api/* (soc_ui.py). All remote/host-derived strings are
   inserted with textContent only. */
(() => {
"use strict";

// ---------------------------------------------------------------- state ---
const S = {
  state: null,          // runner snapshot
  defaults: null,       // /api/config-defaults payload
  status: null,         // /api/status payload
  externalBoot: null,   // [{pid}] when a checkstat.py ran before boot
  console: { entries: [], next: 0, follow: true },
  traffic: { rows: [], newestTs: 0, boundary: null, expanded: new Set() },
  findings: {
    records: [], nextSeq: 0, filter: "ALL", loaded: false,
    expanded: new Set(),   // finding keys whose triage panel is open
    nodes: new Map(),      // finding key -> card node, for keyed reconciliation
    chat: null,            // null | { seq, timestamp, key, messages, ... }
    context: null,         // null | { key, record, previousFocus }
    allowlist: {
      entries: [], activeIds: new Set(), loaded: false, error: "",
      serverTime: "", invalidEntries: 0, status: "missing",
    },
    allowlistDialog: null,
    allowlistManager: null,
    allowlistConfirm: null,
  },
  range: 900,
  expandedChart: null,  // id of the chart card currently in focus mode
  theme: localStorage.getItem("soc_ui.theme") || "auto",
};

const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";

function svgEl(tag, attrs) {
  const el = document.createElementNS(SVGNS, tag);
  for (const k in attrs) el.setAttribute(k, attrs[k]);
  return el;
}

// Gauge vs counter rule (README): gauges are used as-is and never diffed;
// counters get rates = delta/dt between consecutive samples.
const COUNTER_FIELDS = new Set([
  "bytes_recv", "bytes_sent", "packets_recv", "packets_sent",
  "discards_recv", "discards_sent", "errors_recv", "errors_sent",
  "retransmits", "failed_connects", "active_opens", "passive_opens",
  "udp_received", "udp_no_ports", "udp_errors", "icmp_messages",
  "ip_received", "ip_discarded",
]);

const CHARTS = [
  { id: "connections", title: "Connections", series: [
    { label: "Established", key: "established", counter: false, slot: 1 },
    { label: "Time wait", key: "time_wait", counter: false, slot: 2 }] },
  { id: "syn", title: "SYN activity", series: [
    { label: "SYN received", key: "syn_received", counter: false, slot: 1 },
    { label: "SYN sent", key: "syn_sent", counter: false, slot: 2 }] },
  { id: "throughput", title: "Throughput", unit: "bytes", series: [
    { label: "Rx/s", key: "bytes_recv", counter: true, slot: 3 },
    { label: "Tx/s", key: "bytes_sent", counter: true, slot: 4 }] },
  { id: "retrans", title: "Retransmits & failures", series: [
    { label: "Retransmits/s", key: "retransmits", counter: true, slot: 1 },
    { label: "Failed connects/s", key: "failed_connects", counter: true, slot: 2 }] },
  // Open rates capture SYN-flood churn between the 3 s gauge samples the
  // SYN activity card can miss (gauges are instantaneous snapshots).
  { id: "openrate", title: "Connection open rates", series: [
    { label: "Active opens/s", key: "active_opens", counter: true, slot: 1 },
    { label: "Passive opens/s", key: "passive_opens", counter: true, slot: 2 }] },
  // UDP/ICMP floods produce no TCP table rows at all; only the counters see them.
  { id: "udp", title: "UDP & ICMP", series: [
    { label: "UDP datagrams/s", key: "udp_received", counter: true, slot: 1 },
    { label: "ICMP messages/s", key: "icmp_messages", counter: true, slot: 2 }] },
];

// ------------------------------------------------------------------ auth ---
// soc_ui.py prints (and auto-opens) a URL whose #token=... fragment carries
// the /api/* auth token. Fragments are never sent to the server; keep the
// token in this tab's sessionStorage and strip it from the visible URL.
const AUTH_TOKEN_KEY = "soc_ui.auth_token";

function readHashToken() {
  if (!location.hash) return null;
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  return token ? token.trim() : null;
}

function loadAuthToken() {
  const fromHash = readHashToken();
  let token = fromHash;
  try {
    if (fromHash) sessionStorage.setItem(AUTH_TOKEN_KEY, fromHash);
    else token = sessionStorage.getItem(AUTH_TOKEN_KEY);
  } catch { /* storage disabled: fall back to the hash value */ }
  if (fromHash) {
    try {
      history.replaceState(null, "", location.pathname + location.search);
    } catch { /* ignore */ }
  }
  return token;
}

const AUTH_TOKEN = loadAuthToken();
let authNoticeShown = false;

function authError(message) {
  if (!authNoticeShown) {
    authNoticeShown = true;
    console.error(`[auth] ${message}`);
    if ($("banner")) banner(message);
  }
  const err = new Error(message);
  err.status = 401;
  err.auth = true;
  return err;
}

function authHeaders(extra) {
  const headers = new Headers(extra || undefined);
  headers.set("X-Auth-Token", AUTH_TOKEN);
  return headers;
}

// ---------------------------------------------------------------- helpers ---
async function api(path, opts) {
  if (!AUTH_TOKEN) {
    throw authError("Dashboard auth token missing. Open the URL printed by "
      + "soc_ui.py (it carries a #token=... fragment).");
  }
  const options = { cache: "no-store", ...opts };
  options.headers = authHeaders(options.headers);
  const r = await fetch(path, options);
  if (r.status === 401) {
    throw authError("Dashboard rejected the auth token (401). Restart "
      + "soc_ui.py and open the newly printed URL.");
  }
  if (!r.ok) {
    const err = new Error(r.statusText);
    err.status = r.status;
    try { err.body = await r.json(); } catch { /* no body */ }
    throw err;
  }
  return r.json();
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function sampleInterval() {
  const v = S.status && S.status.sample_interval;
  return (typeof v === "number" && v > 0) ? v : 3;
}

function fmtNum(v) {
  if (v == null) return "–";
  if (v >= 100) return Math.round(v).toLocaleString();
  if (v >= 10) return Math.round(v).toLocaleString();
  return v.toFixed(1);
}

function fmtByteRate(v) {
  if (v == null) return "–";
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function fmtTime(ts, seconds = true) {
  const d = new Date(ts * 1000);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return seconds ? `${hh}:${mm}:${ss}` : `${hh}:${mm}`;
}

function fmtUptime(sec) {
  if (sec == null) return "";
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60),
        s = sec % 60;
  return h ? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`
           : `${m}:${String(s).padStart(2, "0")}`;
}

function fmtRate(rows, i, field, boundary) {
  // rate for COUNTER_FIELDS; gauge value passed through untouched
  const cur = rows[i];
  if (!COUNTER_FIELDS.has(field)) {
    return cur[field] == null ? null : cur[field];
  }
  const prev = i > 0 ? rows[i - 1] : boundary;
  if (!prev) return null;
  const dt = cur.timestamp - prev.timestamp;
  if (!(dt > 0)) return null;
  // the agent's sampler thread and scan-loop capture can emit paired rows
  // ~0.3 s apart; a delta over that near-zero dt is not a rate but a spike
  if (dt < 0.5 * sampleInterval()) return null;
  const a = prev[field], b = cur[field];
  if (a == null || b == null) return null;
  if (b < a) return null;  // counter reset / rotation boundary -> gap
  return (b - a) / dt;
}

function rateFmt(rows, i, field, boundary, unit) {
  const v = fmtRate(rows, i, field, boundary);
  return unit === "bytes" ? fmtByteRate(v) : fmtNum(v);
}

function banner(text, actions) {
  const el = $("banner");
  el.textContent = "";
  el.classList.toggle("hidden", !text);
  if (!text) return;
  el.append(Object.assign(document.createElement("span"),
    { textContent: text }));
  (actions || []).forEach((a) => {
    const b = document.createElement("button");
    b.className = "btn btn-ghost";
    b.type = "button";
    b.textContent = a.label;
    b.addEventListener("click", () => a.onClick());
    el.append(b);
  });
}

// ------------------------------------------------------------- top bar ---
function renderState() {
  const st = S.state;
  if (!st) return;
  const pill = $("state-pill");
  const stateNames = { RUNNING: "RUNNING", STARTING: "STARTING",
                       STOPPING: "STOPPING", STOPPED: "STOPPED" };
  pill.textContent = stateNames[st.state] || st.state;
  pill.className = "pill " + (st.state === "RUNNING" ? "pill-running"
    : st.state === "STOPPED" ? "pill-stopped" : "pill-busy");
  if (st.state === "STOPPED" && st.exit_kind === "crashed") {
    pill.textContent = "CRASHED";
    pill.className = "pill pill-crashed";
  }
  const bits = [];
  if (st.state === "RUNNING" || st.state === "STOPPING") {
    if (st.uptime_seconds != null) bits.push(`up ${fmtUptime(st.uptime_seconds)}`);
    if (st.pid != null) bits.push(`pid ${st.pid}`);
    if (st.attached === false) bits.push("adopted · no output");
    if (st.mode === "replay") bits.push("replay");
  } else if (st.exit_code != null) {
    bits.push(`exit ${st.exit_code} · ${st.exit_kind}`);
  } else if (st.exit_kind === "stopped_by_ui") {
    bits.push("stopped");
  }
  $("state-detail").textContent = bits.join(" · ");
  $("btn-start").disabled = st.state !== "STOPPED";
  $("btn-start-form").disabled = st.state !== "STOPPED";
  $("btn-stop").disabled = st.state === "STOPPED";

  const cb = $("console-banner");
  cb.classList.toggle("hidden", !(st.state === "STOPPED" && st.exit_kind));
  cb.classList.toggle("info", st.exit_kind !== "crashed" && st.exit_kind != null);
  cb.textContent = st.state === "STOPPED" && st.exit_kind === "crashed"
    ? `Agent exited unexpectedly (code ${st.exit_code}). Console output below.`
    : (st.state === "STOPPED" && st.exit_kind === "console_event"
        ? "Agent exited on stop event (console break, not the graceful path)." : "");
}

async function startAgent(force = false) {
  const payload = collectForm();
  if (!payload.ok) return;
  const body = payload.data;
  if (force) body.force = true;
  try {
    const r = await api("/api/start",
      { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body) });
    $("controls-details").open = false;
    $("form-error").textContent = "";
    localStorage.setItem("soc_ui.form", JSON.stringify(payload.data));
    S.state = await api("/api/state");
    renderState();
    await Promise.all([fetchConsole(), fetchTraffic(true), fetchFindings()]);
    void r;
  } catch (e) {
    if (e.status === 412 && e.body && e.body.external) {
      const pids = e.body.external.map((p) => p.pid).join(", ");
      banner(`Another checkstat.py process appears to be running (pid ${pids}). ` +
              "Two agents writing the same files can corrupt them. Start anyway?",
        [{ label: "Start anyway", onClick: () => { banner(null); startAgent(true); } },
         { label: "Cancel", onClick: () => banner(null) }]);
    } else if (e.status === 400 && e.body && e.body.fields) {
      markFieldErrors(e.body.fields);
      $("form-error").textContent = e.body.error;
    } else if (e.status === 409) {
      banner(e.body && e.body.error || "Agent is already running.");
    } else {
      banner(`Start failed: ${e.message}`);
    }
  }
}

async function stopAgent() {
  try { await api("/api/stop", { method: "POST" }); } catch { /* noop */ }
  try {
    S.state = await api("/api/state");
    renderState();
  } catch (e) {
    banner(`Could not refresh state: ${e.message}`);
  }
}

// ---------------------------------------------------------------- form ---
const FORM_FIELDS = [
  { key: "interval", el: "f-interval", type: "int", def: "scan_interval_seconds" },
  { key: "rules_path", el: "f-rules-path", type: "str", def: null },
  { key: "replay_path", el: "f-replay-path", type: "str", def: null },
  { key: "model", el: "f-model", type: "str", def: "model" },
  { key: "escalation_model", el: "f-escalation-model", type: "str",
    def: "escalation_model" },
  { key: "ollama_url", el: "f-ollama-url", type: "str", def: "ollama_url" },
  { key: "no_escalation", el: "f-no-escalation", type: "bool" },
  { key: "max_ai_checks", el: "f-max-ai-checks", type: "int",
    def: "max_ai_checks_per_run" },
  { key: "max_escalations", el: "f-max-escalations", type: "int",
    def: "max_escalations_per_run" },
  { key: "ai_timeout", el: "f-ai-timeout", type: "float",
    def: "ai_timeout_seconds" },
  { key: "escalation_timeout", el: "f-escalation-timeout", type: "float",
    def: "escalation_timeout_seconds" },
  { key: "num_ctx", el: "f-num-ctx", type: "int", def: "num_ctx" },
  { key: "keep_alive", el: "f-keep-alive", type: "str", def: "keep_alive" },
  { key: "cache_hours", el: "f-cache-hours", type: "float", def: "cache_hours" },
  { key: "think", el: "f-think", type: "select-on", def: "think" },
  { key: "no_cache", el: "f-no-cache", type: "bool" },
  { key: "no_ai", el: "f-no-ai", type: "bool" },
  { key: "no_traffic", el: "f-no-traffic", type: "bool" },
  { key: "no_whois", el: "f-no-whois", type: "bool" },
  { key: "no_rdns", el: "f-no-rdns", type: "bool" },
  { key: "no_process_details", el: "f-no-process-details", type: "bool" },
  { key: "no_toast", el: "f-no-toast", type: "bool" },
  { key: "include_private_remotes", el: "f-include-private-remotes", type: "bool" },
  { key: "verbose", el: "f-verbose", type: "bool" },
];

function fillForm() {
  const saved = (() => {
    try { return JSON.parse(localStorage.getItem("soc_ui.form") || "null"); }
    catch { return null; }
  })();
  const d = S.defaults && S.defaults.agent || {};
  for (const f of FORM_FIELDS) {
    const el = $(f.el);
    let value = saved && Object.prototype.hasOwnProperty.call(saved, f.key)
      ? saved[f.key] : (f.def ? d[f.def] : undefined);
    if (saved && f.def && !Object.prototype.hasOwnProperty.call(saved, f.key)) {
      value = d[f.def];  // saved payload omits untouched defaults
    }
    if (f.type === "bool") { el.checked = Boolean(value); continue; }
    if (f.type === "select-on") {
      el.value = value === true ? "on" : "";
      continue;
    }
    el.value = value == null ? "" : value;
  }
  // replay path set -> cadence disabled
  syncReplayMode();
  const chips = $("yaml-chips");
  chips.textContent = "";
  Object.entries(S.defaults.yaml_only || {}).forEach(([k, v]) => {
    const chip = document.createElement("span");
    chip.className = "mini-chip readonly";
    chip.textContent = `${k} = ${Array.isArray(v) ? v.join("/") : v}`;
    chips.append(chip);
  });
  const summaryNote = $("controls-summary-note");
  summaryNote.textContent = saved ? "pre-filled with last-used options" : "";
}

function syncReplayMode() {
  const replay = $("f-replay-path").value.trim() !== "";
  $("f-interval").disabled = replay;
  $("f-interval").parentElement.querySelector("span").textContent =
    replay ? "Scan interval (s) — ignored in replay" : "Scan interval (s)";
}

function collectForm() {
  const data = {};
  for (const f of FORM_FIELDS) {
    const el = $(f.el);
    el.parentElement.classList.remove("invalid");
    if (f.type === "bool") { data[f.key] = el.checked; continue; }
    if (f.type === "select-on") {
      if (el.value === "on") data[f.key] = true;
      continue;
    }
    const text = el.value.trim();
    if (text === "" || el.disabled) continue;
    if (f.type === "int") data[f.key] = Number.parseInt(text, 10);
    else if (f.type === "float") data[f.key] = Number(text);
    else data[f.key] = text;
  }
  return { ok: true, data };
}

function markFieldErrors(fields) {
  fields.forEach((fe) => {
    if (!fe.key) return;
    const spec = FORM_FIELDS.find((f) => f.key === fe.key);
    if (spec) $(spec.el).parentElement.classList.add("invalid");
  });
}

// ------------------------------------------------------------- console ---
async function fetchConsole() {
  const data = await api(`/api/console?since=${S.console.next}`);
  if (data.gap) {
    S.console.entries = data.lines.slice();
  } else {
    S.console.entries.push(...data.lines);
    if (S.console.entries.length > 3000) {
      S.console.entries.splice(0, S.console.entries.length - 3000);
    }
  }
  S.console.next = data.next;
  if (data.state) { S.state = data.state; renderState(); }
  renderConsole();
}

function renderConsole() {
  const wrap = $("console-lines");
  wrap.textContent = "";
  for (const e of S.console.entries) {
    const div = document.createElement("div");
    let cls = e.s;
    if (e.line.startsWith("[warn]")) cls = "warn";
    else if (e.line.startsWith("[debug]")) cls = "debug";
    else if (e.s === "err") cls = "err";
    div.className = `console-line ${cls}`;
    div.textContent = e.line;
    wrap.append(div);
  }
  if (S.console.follow) wrap.scrollTop = wrap.scrollHeight;
  while (wrap.childElementCount > 3000) wrap.firstElementChild.remove();
}

// ------------------------------------------------------------- traffic ---
async function fetchTraffic(first = false) {
  const since = first ? "" : `&since=${S.traffic.newestTs}`;
  const data = await api(`/api/traffic${since ? "?" + since.slice(1) : ""}`);
  let incoming = data.rows.slice().reverse();  // payload is newest-first
  if (data.reset || first) {
    S.traffic.rows = incoming;
    S.traffic.boundary = data.prev || null;
  } else {
    for (const row of incoming) {
      if (row.timestamp > S.traffic.newestTs) S.traffic.rows.push(row);
    }
    S.traffic.rows.splice(0, Math.max(0, S.traffic.rows.length - 740));
    if (data.prev) S.traffic.boundary = data.prev;
  }
  S.traffic.newestTs = S.traffic.rows.length
    ? S.traffic.rows[S.traffic.rows.length - 1].timestamp : 0;
  renderTraffic();
  renderCharts();
}

function renderTraffic() {
  const rows = S.traffic.rows;
  const body = $("traffic-body");
  body.textContent = "";
  $("traffic-empty").classList.toggle("hidden", rows.length > 0);
  const show = Math.min(60, rows.length);
  for (let i = rows.length - 1; i >= rows.length - show; i -= 1) {
    const row = rows[i];
    const tr = document.createElement("tr");
    tr.className = "row-main";
    const cells = [fmtTime(row.timestamp),
      row.established ?? "–", row.syn_received ?? "–", row.syn_sent ?? "–",
      row.time_wait ?? "–", row.unique_remotes ?? "–",
      row.top_remote ? `${row.top_remote} ·×${row.top_remote_count ?? 0}` : "–",
      rateFmt(rows, i, "bytes_recv", S.traffic.boundary, "bytes"),
      rateFmt(rows, i, "bytes_sent", S.traffic.boundary, "bytes"),
      rateFmt(rows, i, "retransmits", S.traffic.boundary),
      topProcess(row)];
    cells.forEach((text, idx) => {
      const td = document.createElement("td");
      td.textContent = text;
      if (idx === 6) td.className = "cell-remote";
      if (idx === 10) td.className = "cell-proc";
      tr.append(td);
    });
    tr.addEventListener("click", () => {
      const key = row.timestamp;
      if (S.traffic.expanded.has(key)) S.traffic.expanded.delete(key);
      else S.traffic.expanded.add(key);
      renderTraffic();
    });
    body.append(tr);
    if (S.traffic.expanded.has(row.timestamp)) {
      const det = document.createElement("tr");
      det.className = "row-detail";
      const td = document.createElement("td");
      td.colSpan = 11;
      td.textContent = JSON.stringify(row, (k, v) => v, 2);
      det.append(td);
      body.append(det);
    }
  }
}

function topProcess(row) {
  const names = row.per_process_names || {};
  let best = null;
  for (const [name, count] of Object.entries(names)) {
    if (!best || count > best[1]) best = [name, count];
  }
  if (best) return `${best[0]} ·×${best[1]}`;
  const pids = row.per_process || {};
  let bestPid = null;
  for (const [pid, count] of Object.entries(pids)) {
    if (!bestPid || count > bestPid[1]) bestPid = [pid, count];
  }
  return bestPid ? `pid ${bestPid[0]} ·×${bestPid[1]}` : "–";
}

// ------------------------------------------------------------ findings ---
const SEVERITY_CLASS = {
  CRITICAL: "badge-critical", HIGH: "badge-high",
  MEDIUM: "badge-medium", LOW: "badge-low", INFO: "badge-info",
};
const FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "MUTED"];
const MUTABLE_RULES = new Set([
  "NET-T10", "NET-001", "NET-002", "NET-007", "NET-009",
]);

function renderFindingChips() {
  const wrap = $("finding-filter");
  wrap.textContent = "";
  FILTERS.forEach((name) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip" + (S.findings.filter === name ? " active" : "");
    chip.textContent = name;
    chip.addEventListener("click", () => {
      S.findings.filter = name;
      renderFindingChips();
      renderFindings(true);  // filter changes are user-initiated: full rebuild
    });
    wrap.append(chip);
  });
}

function severityOf(r) {
  if (r.informational) return "INFO";
  const sev = r.rule && r.rule.severity;
  return sev ? sev.toUpperCase() : "INFO";
}

function findingKey(r) {
  if (Number.isInteger(r._seq)) return `s:${r._seq}`;
  const fallback = (r.verdict && r.verdict.verdict_id) || r.timestamp || "unknown";
  return `v:${fallback}`;
}

function ruleIdsOf(r) {
  const rule = r && r.rule ? r.rule : {};
  const ids = Array.isArray(rule.rule_ids) ? rule.rule_ids : [];
  if (ids.length) return ids;
  return rule.rule_id ? [rule.rule_id] : [];
}

function isRecordMuted(r) {
  const disposition = r && r.disposition;
  if (
    disposition
    && disposition.muted === true
    && typeof disposition.allowlist_id === "string"
    && S.findings.allowlist.activeIds.has(disposition.allowlist_id)
  ) {
    return true;
  }
  // Historical records predate the allow-list entry, so the server annotates
  // them for display when their scope still matches an active entry.
  return Boolean(
    r
    && r.display_muted === true
    && typeof r.display_allowlist_id === "string"
    && S.findings.allowlist.activeIds.has(r.display_allowlist_id),
  );
}

function canMarkFalsePositive(r) {
  if (!Number.isInteger(r._seq)) return false;
  const sev = severityOf(r);
  if (sev === "INFO" || sev === "CRITICAL") return false;
  return ruleIdsOf(r).some((id) => MUTABLE_RULES.has(id));
}

function renderFindings(forceRebuild) {
  const list = $("findings-list");
  const filter = S.findings.filter;
  const records = S.findings.records.filter((r) => {
    const muted = isRecordMuted(r);
    if (filter === "MUTED") return muted;
    if (muted) return false;
    const sev = severityOf(r);
    if (filter === "ALL") return true;
    if (filter === "INFO") return sev === "INFO";
    return sev === filter;
  }).slice(0, 200);

  if (forceRebuild) {
    list.textContent = "";
    S.findings.nodes.clear();
  }

  if (!records.length) {
    list.textContent = "";
    S.findings.nodes.clear();
    const p = document.createElement("p");
    p.className = "empty-note";
    if (filter === "MUTED") {
      p.textContent = "No muted findings. Open a finding and choose "
        + "Mark false positive to add one.";
    } else {
      p.textContent = S.findings.records.length
        ? "No findings match this filter." : "No findings yet.";
    }
    list.append(p);
    return;
  }
  const note = list.querySelector(".empty-note");
  if (note) note.remove();

  // Keyed reconciliation: JSONL records never change once written, so an
  // existing card only needs to move, never to be rebuilt. Reusing nodes keeps
  // scroll position, focus, text selection and expanded panels intact across
  // the 2 s poll.
  const map = S.findings.nodes;
  const desired = new Set();
  let cursor = list.firstChild;
  for (const r of records) {
    const key = findingKey(r);
    desired.add(key);
    let node = map.get(key);
    if (!node) {
      node = findingCard(r);
      map.set(key, node);
    }
    if (node === cursor) cursor = cursor.nextSibling;
    else list.insertBefore(node, cursor);
    updateFindingCardDisposition(node, r);
  }
  while (cursor) {
    const next = cursor.nextSibling;
    cursor.remove();
    cursor = next;
  }
  for (const [key, node] of map) {
    if (!desired.has(key)) {
      node.remove();
      map.delete(key);
    }
  }
}

function findingCard(r) {
  const key = findingKey(r);
  const expanded = S.findings.expanded.has(key);
  const card = document.createElement("div");
  card.className = expanded ? "finding is-expanded" : "finding";
  card._record = r;  // records are immutable; used to lazily build the panel
  const top = document.createElement("div");
  top.className = "finding-top";
  const time = document.createElement("span");
  time.className = "finding-time";
  time.textContent = (r.timestamp || "").replace("T", " ").slice(0, 19);
  const sev = document.createElement("span");
  sev.className = `badge ${SEVERITY_CLASS[severityOf(r)] || "badge-info"}`;
  sev.textContent = severityOf(r);
  top.append(time, sev);
  if (r.rule) {
    const rid = document.createElement("span");
    rid.className = "rule-id";
    rid.textContent = r.rule.rule_id || "";
    top.append(rid);
  }
  if (r.snapshot) {
    const snap = document.createElement("span");
    snap.className = "mini-chip";
    snap.textContent = r.snapshot.startsWith("live-") ? "live"
      : r.snapshot.startsWith("deferred-") ? "deferred"
      : r.snapshot;
    top.append(snap);
  }
  const hasVerdict = Boolean(r.verdict) && typeof r.verdict === "object"
    && !Array.isArray(r.verdict);
  if (hasVerdict) top.append(findingToggleButton(key, expanded));
  const detail = document.createElement("div");
  detail.className = "finding-detail";
  detail.textContent = (r.rule && r.rule.rule_name) ||
    r.detail || r.rule && r.rule.description || "";
  const meta = document.createElement("div");
  meta.className = "finding-meta";
  const isFastLane = (r.snapshot || "").startsWith("fast-");
  const trafficChips = () => {
    const chip = document.createElement("span");
    chip.className = "mini-chip";
    chip.textContent = "deterministic · no LLM";
    meta.append(chip);
    if (typeof r.occurrences === "number") {
      const occ = document.createElement("span");
      occ.className = "mini-chip";
      occ.textContent = `seen ×${r.occurrences}`;
      meta.append(occ);
    }
  };
  // Compact cache-verdict id for tracing which triage minted a reused
  // verdict; full GUID on hover, click to copy.
  const verdictIdChip = (id) => {
    if (!id) return;
    const short = `id: ${String(id).slice(0, 8)}`;
    const chip = document.createElement("span");
    chip.className = "mini-chip verdict-id";
    chip.textContent = short;
    chip.title = `${id}\ncached verdict id — click to copy`;
    chip.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(String(id));
        chip.textContent = "id: copied";
        setTimeout(() => { chip.textContent = short; }, 1200);
      } catch { /* clipboard unavailable */ }
    });
    meta.append(chip);
  };
  if (r.verdict && isFastLane) {
    // The fast lane never runs the model: show the reused verdict as a plain
    // label next to the deterministic provenance chips. The tier/source/class
    // chips belong to the scan run that minted the verdict, not this sighting.
    const vp = document.createElement("span");
    vp.className = `verdict-pill v-${r.verdict.verdict}`;
    const conf = typeof r.verdict.confidence === "number"
      ? ` ${r.verdict.confidence}%` : "";
    vp.textContent = `${r.verdict.verdict}${conf}`;
    meta.append(vp);
    trafficChips();
    verdictIdChip(r.verdict.verdict_id);
  } else if (r.verdict) {
    const vp = document.createElement("span");
    vp.className = `verdict-pill v-${r.verdict.verdict}`;
    const conf = typeof r.verdict.confidence === "number"
      ? ` ${r.verdict.confidence}%` : "";
    // Cached verdicts describe the moment they were computed, not this
    // sighting — show when the verdict was minted (vetted_at) when known.
    const vettedAt = r.verdict.vetted_at ? ` ${r.verdict.vetted_at.slice(11, 16)}` : "";
    const cachedTag = r.cache_hit ? ` (cached${vettedAt})` : "";
    vp.textContent = `${r.verdict.verdict}${conf}${cachedTag}`;
    meta.append(vp);
    [["tier", r.verdict.tier], ["guardrail", r.verdict.guardrail],
     ["class", r.verdict.classification], ["source", r.verdict.source]]
     .forEach(([label, value]) => {
      if (!value) return;
      const chip = document.createElement("span");
      chip.className = "mini-chip";
      chip.textContent = `${label}: ${value}`;
      meta.append(chip);
    });
    verdictIdChip(r.verdict.verdict_id);
  } else if (r.source === "traffic") {
    trafficChips();
  }
  const dispositionChips = document.createElement("span");
  dispositionChips.className = "disposition-chips";
  meta.append(dispositionChips);
  if (canMarkFalsePositive(r)) {
    const mark = document.createElement("button");
    mark.type = "button";
    mark.className = "chip finding-allowlist-open";
    mark.dataset.focusKey = `allowlist:${key}`;
    mark.setAttribute("aria-haspopup", "dialog");
    mark.textContent = "Mark false positive";
    mark.addEventListener("click", (ev) => {
      ev.stopPropagation();
      openAllowlistDialog(r);
    });
    meta.append(mark);
  }
  const hostBits = [];
  const g = r.group || {};
  if (g.remote_ip) hostBits.push(`remote ${g.remote_ip}:${g.foreign_port ?? ""}`);
  if (g.process_name) hostBits.push(`process ${g.process_name}`);
  if (g.pid) hostBits.push(`pid ${g.pid}`);
  const host = document.createElement("div");
  host.className = "finding-host";
  const extra = r.traffic && r.traffic.process_name
    ? `owner ${r.traffic.process_name}` : "";
  host.textContent = [hostBits.join(" · "), extra].filter(Boolean).join(" · ");
  // The container always exists so aria-controls always resolves; contents
  // are built only for the open cards.
  const panel = document.createElement("div");
  panel.className = "finding-triage";
  panel.id = `triage-${key}`;
  panel.setAttribute("role", "region");
  panel.setAttribute("aria-label", "AI triage");
  if (expanded) panel.append(...buildTriagePanel(r));
  else panel.hidden = true;
  card.append(top, detail, meta, host, panel);
  updateFindingCardDisposition(card, r);
  return card;
}

function findingToggleButton(key, expanded) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "chip finding-expand";
  btn.dataset.focusKey = `toggle:${key}`;
  btn.setAttribute("aria-expanded", expanded ? "true" : "false");
  btn.setAttribute("aria-controls", `triage-${key}`);
  btn.title = expanded ? "Hide the AI triage analysis"
    : "Show the AI triage analysis";
  const label = document.createElement("span");
  label.textContent = "AI triage";
  const chevron = document.createElement("span");
  chevron.className = "chevron";
  chevron.setAttribute("aria-hidden", "true");
  chevron.textContent = "▸";
  btn.append(label, chevron);
  btn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    toggleFindingTriage(key);
  });
  return btn;
}

function toggleFindingTriage(key) {
  const expanded = !S.findings.expanded.has(key);
  if (expanded) S.findings.expanded.add(key);
  else S.findings.expanded.delete(key);
  const card = S.findings.nodes.get(key);
  if (!card) {
    renderFindings();
    return;
  }
  applyFindingExpansion(card, key, expanded);
  const btn = card.querySelector(`[data-focus-key="toggle:${key}"]`);
  if (btn) btn.focus({ preventScroll: true });
}

function applyFindingExpansion(card, key, expanded) {
  card.classList.toggle("is-expanded", expanded);
  const btn = card.querySelector(`[data-focus-key="toggle:${key}"]`);
  if (btn) {
    btn.setAttribute("aria-expanded", expanded ? "true" : "false");
    btn.title = expanded ? "Hide the AI triage analysis"
      : "Show the AI triage analysis";
  }
  const panel = document.getElementById(`triage-${key}`);
  if (!panel) return;
  if (expanded && !panel.childElementCount && card._record) {
    panel.append(...buildTriagePanel(card._record));
  }
  panel.hidden = !expanded;
}

function triageSection(titleText) {
  const section = document.createElement("div");
  section.className = "triage-section";
  if (titleText) {
    const heading = document.createElement("div");
    heading.className = "triage-heading";
    heading.textContent = titleText;
    section.append(heading);
  }
  return section;
}

function triageParagraph(value, className) {
  const text = typeof value === "string" ? value.trim() : "";
  if (!text) return null;
  const p = document.createElement("p");
  p.className = className || "triage-text";
  p.textContent = text.slice(0, 4000);
  return p;
}

function triageFactorList(title, values) {
  let items = [];
  if (Array.isArray(values)) items = values;
  else if (typeof values === "string") items = [values];
  items = items.map((v) => String(v).trim()).filter(Boolean).slice(0, 10);
  if (!items.length) return null;
  const section = triageSection(title);
  const ul = document.createElement("ul");
  ul.className = "triage-list";
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item.slice(0, 1000);
    ul.append(li);
  }
  section.append(ul);
  return section;
}

function triageVerdictPill(verdict) {
  const name = typeof verdict.verdict === "string" ? verdict.verdict : "UNVERIFIED";
  const pill = document.createElement("span");
  pill.className = `verdict-pill v-${name}`;
  const conf = typeof verdict.confidence === "number"
    && Number.isFinite(verdict.confidence)
    ? ` ${Math.max(0, Math.min(100, Math.round(verdict.confidence)))}%` : "";
  pill.textContent = `${name}${conf}`;
  return pill;
}

function triageChipRow(verdict) {
  const row = document.createElement("div");
  row.className = "finding-meta";
  row.append(triageVerdictPill(verdict));
  [["classification", verdict.classification], ["tier", verdict.tier],
   ["guardrail", verdict.guardrail], ["effective", verdict.effective_verdict],
   ["source", verdict.source]].forEach(([label, value]) => {
    if (!value) return;
    const chip = document.createElement("span");
    chip.className = "mini-chip";
    chip.textContent = `${label}: ${value}`;
    row.append(chip);
  });
  return row;
}

function buildTriagePanel(r) {
  const key = findingKey(r);
  const verdict = r.verdict || {};
  const routine = verdict.routine_opinion
    && typeof verdict.routine_opinion === "object"
    && !Array.isArray(verdict.routine_opinion) ? verdict.routine_opinion : null;
  const nodes = [];

  const provenance = triageSection("Provenance");
  const bits = [];
  if (verdict.tier) bits.push(`tier: ${verdict.tier}`);
  if (verdict.source) bits.push(`source: ${verdict.source}`);
  const model = r.models && (r.models.escalation || r.models.routine);
  if (model) bits.push(`model: ${model}`);
  if (verdict.vetted_at) bits.push(`vetted: ${verdict.vetted_at}`);
  if (bits.length) {
    const p = document.createElement("p");
    p.className = "triage-provenance";
    p.textContent = bits.join(" · ");
    provenance.append(p);
  }
  if (r.cache_hit || (r.snapshot || "").startsWith("fast-")) {
    const p = document.createElement("p");
    p.className = "triage-provenance";
    p.textContent = verdict.vetted_at
      ? `Reused cached verdict minted ${verdict.vetted_at}; this sighting made no model call.`
      : "Reused cached verdict; this sighting made no model call.";
    provenance.append(p);
  }
  if (bits.length || provenance.children.length) nodes.push(provenance);

  if (routine) {
    const tier1 = triageSection("Tier 1 — routine analyst's prior opinion");
    tier1.append(triageChipRow(routine));
    for (const node of [
      triageParagraph(routine.reasoning),
      triageFactorList("Risk factors", routine.risk_factors),
      triageFactorList("Benign / false-positive factors",
        routine.false_positive_factors),
      triageParagraph(routine.recommended_action),
    ]) if (node) tier1.append(node);
    nodes.push(tier1);
  } else if (verdict.tier === "escalated") {
    const note = triageSection("");
    const p = document.createElement("p");
    p.className = "triage-provenance";
    p.textContent = "Tier-1 opinion was not recorded for this verdict.";
    note.append(p);
    nodes.push(note);
  }

  const twoTier = Boolean(routine) || verdict.tier === "escalated";
  const finalSection = triageSection(
    twoTier ? "Final verdict (Tier 2)" : "Final verdict");
  finalSection.append(triageChipRow(verdict));
  if (verdict.escalation_note) {
    const note = document.createElement("p");
    note.className = /fail/i.test(String(verdict.escalation_note))
      ? "triage-note-warn" : "triage-provenance";
    note.textContent = String(verdict.escalation_note).slice(0, 2000);
    finalSection.append(note);
  }
  for (const node of [
    triageParagraph(verdict.reasoning),
    triageFactorList("Risk factors", verdict.risk_factors),
    triageFactorList("Benign / false-positive factors",
      verdict.false_positive_factors),
    triageParagraph(verdict.recommended_action),
  ]) if (node) finalSection.append(node);
  nodes.push(finalSection);

  const actions = triageSection("");
  actions.classList.add("triage-actions");
  const contextBtn = document.createElement("button");
  contextBtn.type = "button";
  contextBtn.className = "chip finding-context-open";
  contextBtn.dataset.focusKey = `context:${key}`;
  contextBtn.setAttribute("aria-haspopup", "dialog");
  contextBtn.textContent = "View AI context";
  contextBtn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    openFindingContext(r);
  });
  actions.append(contextBtn);

  const chatBtn = document.createElement("button");
  chatBtn.type = "button";
  chatBtn.className = "chip finding-chat-open";
  chatBtn.dataset.focusKey = `chat:${key}`;
  chatBtn.setAttribute("aria-haspopup", "dialog");
  chatBtn.textContent = "Chat about this finding";
  if (Number.isInteger(r._seq)) {
    chatBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      openFindingChat(r);
    });
  } else {
    chatBtn.disabled = true;
    chatBtn.title = "Reload the dashboard to chat about this finding";
  }
  actions.append(chatBtn);
  nodes.push(actions);

  return nodes;
}

let findingsInFlight = false;
async function fetchFindings() {
  // Overlapping fetches (2 s poll + refocus refresh) can both carry the same
  // new record; the busy guard and the _seq dedupe keep it from being
  // unshifted onto the list twice.
  if (findingsInFlight) return;
  findingsInFlight = true;
  try {
    const after = S.findings.nextSeq
      ? `?after=${S.findings.nextSeq}` : "?limit=1000";
    const data = await api(`/api/findings${after}`);
    let changed = false;
    if (data.reset) {
      S.findings.records = data.records.slice();
      // _seq values are only meaningful for one server process; a reset means
      // the old expansion keys no longer identify anything.
      S.findings.expanded.clear();
      changed = true;
    } else {
      // Records arrive newest-first (same as the initial load), so new
      // findings must go at the front — pushing them would bury them at the
      // bottom and, past the 200-card render slice, hide them entirely.
      const have = new Set(S.findings.records.map((r) => r._seq));
      const fresh = data.records.filter((r) => !have.has(r._seq));
      S.findings.records.unshift(...fresh);
      if (S.findings.records.length > 1000) {
        S.findings.records.splice(1000);
        const live = new Set(S.findings.records.map(findingKey));
        for (const key of S.findings.expanded) {
          if (!live.has(key)) S.findings.expanded.delete(key);
        }
      }
      changed = fresh.length > 0;
    }
    S.findings.nextSeq = data.next_seq || S.findings.nextSeq;
    const first = !S.findings.loaded;
    S.findings.loaded = true;
    // Reconcile only when something changed. A reset replaces node identity
    // wholesale, so force a rebuild in that case.
    if (first || changed) renderFindings(first || data.reset);
  } finally {
    findingsInFlight = false;
  }
}

// ---------------------------------------------------------------- chat ---
const CHAT_MAX_MESSAGES = 8;
const CHAT_MAX_MESSAGE_CHARS = 2000;
const CHAT_MAX_HISTORY_CHARS = 4000;

function ensureChatModal() {
  let dialog = $("finding-chat-dialog");
  if (dialog) return dialog;

  const backdrop = document.createElement("div");
  backdrop.id = "finding-chat-backdrop";
  backdrop.className = "modal-backdrop hidden";
  backdrop.addEventListener("click", () => closeFindingChat());

  dialog = document.createElement("section");
  dialog.id = "finding-chat-dialog";
  dialog.className = "finding-chat hidden";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "finding-chat-title");
  dialog.tabIndex = -1;

  const head = document.createElement("div");
  head.className = "finding-chat-head";
  const headMain = document.createElement("div");
  const title = document.createElement("h3");
  title.id = "finding-chat-title";
  title.textContent = "Ask about this finding";
  const subtitle = document.createElement("p");
  subtitle.id = "finding-chat-subtitle";
  subtitle.className = "finding-chat-subtitle";
  headMain.append(title, subtitle);
  const close = document.createElement("button");
  close.type = "button";
  close.className = "btn btn-ghost";
  close.textContent = "Close";
  close.addEventListener("click", () => closeFindingChat());
  head.append(headMain, close);

  const messages = document.createElement("div");
  messages.id = "finding-chat-messages";
  messages.className = "finding-chat-messages";
  messages.setAttribute("role", "log");
  messages.setAttribute("aria-live", "polite");
  messages.setAttribute("aria-relevant", "additions text");
  const note = document.createElement("p");
  note.className = "chat-note";
  note.textContent = "This finding's evidence and AI triage are loaded as "
    + "context. The assistant is read-only and cannot change anything.";
  messages.append(note);

  const form = document.createElement("form");
  form.id = "finding-chat-form";
  form.className = "finding-chat-form";
  const label = document.createElement("label");
  label.className = "hidden";
  label.htmlFor = "finding-chat-input";
  label.textContent = "Question";
  const input = document.createElement("textarea");
  input.id = "finding-chat-input";
  input.rows = 2;
  input.maxLength = 1500;
  input.placeholder = "Ask a question about this finding…";
  const send = document.createElement("button");
  send.type = "submit";
  send.id = "finding-chat-send";
  send.className = "btn btn-primary";
  send.textContent = "Send";
  form.append(label, input, send);

  const modelRow = document.createElement("div");
  modelRow.className = "finding-chat-model-row";
  const modelLabel = document.createElement("label");
  modelLabel.htmlFor = "finding-chat-model";
  modelLabel.textContent = "Model";
  const modelSelect = document.createElement("select");
  modelSelect.id = "finding-chat-model";
  modelSelect.addEventListener("change", () => {
    if (S.findings.chat) S.findings.chat.model = modelSelect.value;
  });
  modelRow.append(modelLabel, modelSelect);

  const status = document.createElement("p");
  status.id = "finding-chat-status";
  status.className = "finding-chat-status";
  status.setAttribute("role", "status");

  dialog.append(head, messages, modelRow, form, status);
  document.body.append(backdrop, dialog);

  form.addEventListener("submit", sendFindingChat);
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey) {
      ev.preventDefault();
      void sendFindingChat(ev);
    }
  });
  input.addEventListener("input", updateChatControls);
  dialog.addEventListener("keydown", (ev) => trapFocusIn(dialog, ev));
  return dialog;
}

function trapFocusIn(dialog, ev) {
  if (ev.key !== "Tab") return;
  const focusable = Array.from(dialog.querySelectorAll(
    'button, textarea, input, [href], [tabindex]:not([tabindex="-1"])'))
    .filter((el) => !el.disabled);
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (ev.shiftKey && document.activeElement === first) {
    ev.preventDefault();
    last.focus();
  } else if (!ev.shiftKey && document.activeElement === last) {
    ev.preventDefault();
    first.focus();
  }
}

function openFindingChat(record) {
  closeFindingChat({ restoreFocus: false });
  closeFindingContext({ restoreFocus: false });
  closeAllowlistDialog({ restoreFocus: false });
  closeAllowlistManager({ restoreFocus: false });
  closeAllowlistConfirm({ restoreFocus: false });
  if (S.expandedChart) {
    S.expandedChart = null;
    renderCharts();
  }
  const dialog = ensureChatModal();
  const verdict = record.verdict || {};
  const ruleId = record.rule && record.rule.rule_id
    ? record.rule.rule_id : "Finding";
  const verdictLabel = typeof verdict.verdict === "string" ? verdict.verdict : "";
  const conf = typeof verdict.confidence === "number"
    ? ` ${Math.round(verdict.confidence)}%` : "";
  $("finding-chat-subtitle").textContent = [
    ruleId, severityOf(record), `${verdictLabel}${conf}`.trim(),
  ].filter(Boolean).join(" · ");
  S.findings.chat = {
    seq: Number.isInteger(record._seq) ? record._seq : null,
    timestamp: record.timestamp || "",
    key: findingKey(record),
    messages: [],
    model: "",
    pending: false,
    error: "",
    controller: null,
    previousFocus: document.activeElement,
  };
  $("finding-chat-input").value = "";
  const modelSelect = $("finding-chat-model");
  modelSelect.textContent = "";
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Default model";
  modelSelect.append(placeholder);
  modelSelect.value = "";
  void loadChatConfig(S.findings.chat);
  renderChatMessages();
  $("finding-chat-backdrop").classList.remove("hidden");
  dialog.classList.remove("hidden");
  document.body.classList.add("chat-open");
  $("finding-chat-input").focus();
}

async function loadChatConfig(chat) {
  try {
    const config = await api("/api/findings/chat/config");
    if (S.findings.chat !== chat) return;
    const select = $("finding-chat-model");
    if (!select) return;
    select.textContent = "";
    const models = Array.isArray(config.models) ? config.models : [];
    for (const name of models) {
      const option = document.createElement("option");
      option.value = name;
      const tags = [];
      if (name === config.default_model) tags.push("default");
      if (name === config.routine_model && name !== config.default_model) {
        tags.push("faster");
      }
      option.textContent = tags.length
        ? `${name} (${tags.join(", ")})` : name;
      select.append(option);
    }
    if (!models.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = config.default_model || "Default model";
      select.append(option);
    }
    const preferred = config.default_model || models[0] || "";
    select.value = preferred;
    chat.model = preferred;
    updateChatControls();
  } catch {
    if (S.findings.chat !== chat) return;
    const select = $("finding-chat-model");
    if (select && !select.options.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "Default model";
      select.append(option);
    }
  }
}

function closeFindingChat(opts) {
  const chat = S.findings.chat;
  if (!chat) return;
  if (chat.controller) chat.controller.abort();
  S.findings.chat = null;
  const dialog = $("finding-chat-dialog");
  const backdrop = $("finding-chat-backdrop");
  if (dialog) dialog.classList.add("hidden");
  if (backdrop) backdrop.classList.add("hidden");
  document.body.classList.remove("chat-open");
  if (opts && opts.restoreFocus === false) return;
  const target = chat.previousFocus;
  if (target && target.isConnected) {
    target.focus({ preventScroll: true });
    return;
  }
  const fallback = document.querySelector(
    `[data-focus-key="chat:${chat.key}"]`);
  if (fallback) fallback.focus({ preventScroll: true });
  else $("findings-list").focus({ preventScroll: true });
}

function renderChatMessages() {
  const chat = S.findings.chat;
  const log = $("finding-chat-messages");
  if (!chat || !log) return;
  Array.from(log.querySelectorAll(".chat-msg")).forEach((node) => node.remove());
  for (const msg of chat.messages) {
    const wrap = document.createElement("div");
    wrap.className = `chat-msg chat-msg-${msg.role}`;
    const label = document.createElement("div");
    label.className = "chat-msg-label";
    label.textContent = msg.role === "user" ? "You" : "AI triage assistant";
    const body = document.createElement("div");
    body.className = "chat-msg-body";
    body.textContent = msg.content;
    wrap.append(label, body);
    log.append(wrap);
  }
  if (chat.pending) {
    const pending = document.createElement("div");
    pending.className = "chat-msg chat-msg-assistant chat-pending";
    const label = document.createElement("div");
    label.className = "chat-msg-label";
    label.textContent = "AI triage assistant";
    const body = document.createElement("div");
    body.className = "chat-msg-body";
    body.textContent = "Thinking…";
    pending.append(label, body);
    log.append(pending);
  }
  log.setAttribute("aria-busy", chat.pending ? "true" : "false");
  const status = $("finding-chat-status");
  if (status) {
    status.textContent = chat.error
      || (chat.pending ? "Waiting for the local model…" : "");
    status.classList.toggle("error", Boolean(chat.error));
    status.setAttribute("role", chat.error ? "alert" : "status");
  }
  log.scrollTop = log.scrollHeight;
  updateChatControls();
}

function updateChatControls() {
  const chat = S.findings.chat;
  const send = $("finding-chat-send");
  const input = $("finding-chat-input");
  if (!send || !input) return;
  send.disabled = !chat || chat.pending || !input.value.trim();
  const model = $("finding-chat-model");
  if (model) model.disabled = !chat || chat.pending;
}

function chatHistory(chat) {
  // The current question was just pushed, so drop it before sending history.
  const prior = chat.messages.slice(0, -1);
  const picked = [];
  let total = 0;
  for (let i = prior.length - 1; i >= 0 && picked.length < CHAT_MAX_MESSAGES;
       i -= 1) {
    const content = String(prior[i].content || "").slice(0, CHAT_MAX_MESSAGE_CHARS);
    if (!content) continue;
    if (total + content.length > CHAT_MAX_HISTORY_CHARS) break;
    total += content.length;
    picked.push({ role: prior[i].role, content });
  }
  return picked.reverse();
}

async function sendFindingChat(ev) {
  if (ev && ev.preventDefault) ev.preventDefault();
  const chat = S.findings.chat;
  if (!chat || chat.pending) return;
  const input = $("finding-chat-input");
  const question = input.value.trim();
  if (!question) return;
  if (!Number.isInteger(chat.seq)) {
    chat.error = "This finding is no longer available; reload the dashboard.";
    renderChatMessages();
    return;
  }
  chat.error = "";
  chat.messages.push({ role: "user", content: question });
  input.value = "";
  chat.pending = true;
  chat.controller = new AbortController();
  renderChatMessages();
  try {
    const data = await api("/api/findings/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        seq: chat.seq,
        timestamp: chat.timestamp,
        question,
        model: chat.model || undefined,
        history: chatHistory(chat),
      }),
      signal: chat.controller.signal,
    });
    const answer = typeof data.answer === "string" ? data.answer : "";
    chat.messages.push({
      role: "assistant",
      content: answer.slice(0, 4000) || "(no answer returned)",
    });
  } catch (err) {
    if (!(err && err.name === "AbortError")) {
      chat.error = (err && err.body && err.body.error)
        || (err && err.message) || "The chat request failed.";
    }
  } finally {
    chat.pending = false;
    chat.controller = null;
    if (S.findings.chat === chat) {
      renderChatMessages();
      $("finding-chat-input").focus();
    }
  }
}

// ---------------------------------------------------- finding context ---
const CONTEXT_MAX_DEPTH = 6;
const CONTEXT_MAX_ITEMS = 50;
const CONTEXT_MAX_STRING = 4000;
const CONTEXT_RAW_MAX = 200000;
const CONTEXT_KEYS_SHOWN = new Set([
  "timestamp", "snapshot", "source", "detail", "recommended_action",
  "informational", "occurrences", "cache_hit", "deferred_from", "alerted",
  "schema_version", "host", "rule", "process", "traffic", "group", "intel",
  "related_activity", "structured_remediation", "models", "verdict",
]);

function ensureContextModal() {
  let dialog = $("finding-context-dialog");
  if (dialog) return dialog;

  const backdrop = document.createElement("div");
  backdrop.id = "finding-context-backdrop";
  backdrop.className = "modal-backdrop hidden";
  backdrop.addEventListener("click", () => closeFindingContext());

  dialog = document.createElement("section");
  dialog.id = "finding-context-dialog";
  dialog.className = "finding-context hidden";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "finding-context-title");
  dialog.tabIndex = -1;

  const head = document.createElement("div");
  head.className = "finding-chat-head";
  const headMain = document.createElement("div");
  const title = document.createElement("h3");
  title.id = "finding-context-title";
  title.textContent = "Finding evidence & AI context";
  const subtitle = document.createElement("p");
  subtitle.id = "finding-context-subtitle";
  subtitle.className = "finding-chat-subtitle";
  headMain.append(title, subtitle);
  const close = document.createElement("button");
  close.type = "button";
  close.className = "btn btn-ghost";
  close.textContent = "Close";
  close.addEventListener("click", () => closeFindingContext());
  head.append(headMain, close);

  const body = document.createElement("div");
  body.id = "finding-context-body";
  body.className = "finding-context-body";

  dialog.append(head, body);
  document.body.append(backdrop, dialog);
  dialog.addEventListener("keydown", (ev) => trapFocusIn(dialog, ev));
  return dialog;
}

function openFindingContext(record) {
  closeFindingChat({ restoreFocus: false });
  closeFindingContext({ restoreFocus: false });
  closeAllowlistDialog({ restoreFocus: false });
  closeAllowlistManager({ restoreFocus: false });
  closeAllowlistConfirm({ restoreFocus: false });
  const dialog = ensureContextModal();
  const verdict = record.verdict || {};
  const ruleId = record.rule && record.rule.rule_id
    ? record.rule.rule_id : "Finding";
  const verdictLabel = typeof verdict.verdict === "string" ? verdict.verdict : "";
  const conf = typeof verdict.confidence === "number"
    ? ` ${Math.round(verdict.confidence)}%` : "";
  $("finding-context-subtitle").textContent = [
    ruleId, severityOf(record), `${verdictLabel}${conf}`.trim(),
  ].filter(Boolean).join(" · ");
  S.findings.context = {
    key: findingKey(record),
    record,
    previousFocus: document.activeElement,
  };
  renderFindingContext(record);
  $("finding-context-backdrop").classList.remove("hidden");
  dialog.classList.remove("hidden");
  document.body.classList.add("context-open");
  dialog.focus();
}

function closeFindingContext(opts) {
  const ctx = S.findings.context;
  if (!ctx) return;
  S.findings.context = null;
  const dialog = $("finding-context-dialog");
  const backdrop = $("finding-context-backdrop");
  if (dialog) dialog.classList.add("hidden");
  if (backdrop) backdrop.classList.add("hidden");
  document.body.classList.remove("context-open");
  if (opts && opts.restoreFocus === false) return;
  const target = ctx.previousFocus;
  if (target && target.isConnected) {
    target.focus({ preventScroll: true });
    return;
  }
  const fallback = document.querySelector(
    `[data-focus-key="context:${ctx.key}"]`);
  if (fallback) fallback.focus({ preventScroll: true });
}

function renderFindingContext(record) {
  const body = $("finding-context-body");
  if (!body) return;
  body.textContent = "";

  const notice = document.createElement("p");
  notice.className = "context-notice";
  notice.textContent = "This is the evidence persisted with the finding. "
    + "The exact prompt used for the original AI triage is not stored, and "
    + "the model also received baseline and deterministic-signal summaries "
    + "that are not persisted. The chat assistant receives a trimmed version "
    + "of this record.";
  body.append(notice);

  const sections = [
    ["Finding", contextPick(record, [
      "timestamp", "snapshot", "source", "detail", "recommended_action",
      "informational", "occurrences", "cache_hit", "deferred_from", "alerted",
      "schema_version",
    ])],
    ["Host", record.host],
    ["Rule", record.rule],
    ["Process", record.process],
    ["Measured values", record.traffic],
    ["Connections", record.group],
    ["Remote intelligence (WHOIS / reverse DNS)", record.intel],
    ["Related activity", record.related_activity],
    ["Structured remediation", record.structured_remediation],
    ["Models used", record.models],
    ["AI triage", record.verdict],
  ];
  for (const [title, value] of sections) {
    if (!hasContextValue(value)) continue;
    body.append(contextSection(title, value, 0));
  }

  const others = {};
  for (const [key, value] of Object.entries(record)) {
    if (CONTEXT_KEYS_SHOWN.has(key) || key === "_seq") continue;
    if (hasContextValue(value)) others[key] = value;
  }
  if (Object.keys(others).length) {
    body.append(contextSection("Other fields", others, 0));
  }

  const details = document.createElement("details");
  details.className = "context-raw";
  const summary = document.createElement("summary");
  summary.textContent = "Raw finding record (JSON)";
  const pre = document.createElement("pre");
  pre.className = "context-raw-json";
  pre.textContent = JSON.stringify(record, null, 2).slice(0, CONTEXT_RAW_MAX);
  details.append(summary, pre);
  body.append(details);
}

function contextPick(obj, keys) {
  const out = {};
  for (const key of keys) {
    if (obj[key] !== undefined) out[key] = obj[key];
  }
  return out;
}

function hasContextValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

function contextSection(title, value, depth) {
  const section = document.createElement("section");
  section.className = "context-section";
  const heading = document.createElement("div");
  heading.className = "triage-heading";
  heading.textContent = title;
  section.append(heading, contextValue(value, depth));
  return section;
}

function contextValue(value, depth) {
  if (depth > CONTEXT_MAX_DEPTH) return contextPre(value);
  if (Array.isArray(value)) {
    if (!value.length) return contextText("—");
    if (value.every((item) => item === null || typeof item !== "object")) {
      const ul = document.createElement("ul");
      ul.className = "context-list";
      for (const item of value.slice(0, CONTEXT_MAX_ITEMS)) {
        const li = document.createElement("li");
        li.textContent = contextTextOf(item);
        ul.append(li);
      }
      if (value.length > CONTEXT_MAX_ITEMS) {
        const li = document.createElement("li");
        li.textContent = `… ${value.length - CONTEXT_MAX_ITEMS} more`;
        ul.append(li);
      }
      return ul;
    }
    const wrap = document.createElement("div");
    wrap.className = "context-nested";
    for (const item of value.slice(0, CONTEXT_MAX_ITEMS)) {
      const block = document.createElement("div");
      block.className = "context-object";
      block.append(contextValue(item, depth + 1));
      wrap.append(block);
    }
    if (value.length > CONTEXT_MAX_ITEMS) {
      const more = document.createElement("div");
      more.className = "context-val";
      more.textContent = `… ${value.length - CONTEXT_MAX_ITEMS} more`;
      wrap.append(more);
    }
    return wrap;
  }
  if (value && typeof value === "object") {
    const wrap = document.createElement("div");
    wrap.className = "context-nested";
    const entries = Object.entries(value);
    for (const [key, item] of entries.slice(0, CONTEXT_MAX_ITEMS)) {
      if (item === undefined) continue;
      wrap.append(contextRow(key, item, depth + 1));
    }
    if (entries.length > CONTEXT_MAX_ITEMS) {
      const more = document.createElement("div");
      more.className = "context-val";
      more.textContent = `… ${entries.length - CONTEXT_MAX_ITEMS} more fields`;
      wrap.append(more);
    }
    return wrap;
  }
  return contextText(contextTextOf(value));
}

function contextRow(key, value, depth) {
  const row = document.createElement("div");
  row.className = "context-row";
  const label = document.createElement("span");
  label.className = "context-key";
  label.textContent = key;
  const val = document.createElement("div");
  val.className = "context-val";
  if (value === null || typeof value !== "object") {
    val.textContent = contextTextOf(value);
  } else {
    row.classList.add("context-row-stacked");
    val.append(contextValue(value, depth));
  }
  row.append(label, val);
  return row;
}

function contextText(text) {
  const node = document.createElement("div");
  node.className = "context-val";
  node.textContent = text;
  return node;
}

function contextTextOf(value) {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value).slice(0, CONTEXT_MAX_STRING);
    } catch {
      return String(value).slice(0, CONTEXT_MAX_STRING);
    }
  }
  return String(value).slice(0, CONTEXT_MAX_STRING);
}

function contextPre(value) {
  const pre = document.createElement("pre");
  pre.className = "context-raw-json";
  try {
    pre.textContent = JSON.stringify(value, null, 2).slice(0, CONTEXT_MAX_STRING);
  } catch {
    pre.textContent = String(value).slice(0, CONTEXT_MAX_STRING);
  }
  return pre;
}

// ----------------------------------------------------------- allow-list ---
const ALLOWLIST_TTL_OPTIONS = [7, 30, 90];
const GUARD_LABELS = {
  severity_increase: "severity increased",
  rate_above_band: "rate above mute band",
  rate_unavailable: "rate unavailable",
  udp_errors: "UDP receive errors",
  udp_errors_unavailable: "UDP error counter unavailable",
  process_share_below_min: "different process now dominates",
  share_unavailable: "owner share unavailable",
  identity_unverified: "process identity could not be verified",
  rule_set_changed: "additional rule fired",
  baseline_drift: "baseline shifted",
  severity_unknown: "severity unknown",
};

function humanizeGuard(reason) {
  if (reason.startsWith("cofire:")) return `co-firing ${reason.slice(7)}`;
  return GUARD_LABELS[reason] || String(reason).replaceAll("_", " ");
}

function updateFindingCardDisposition(card, r) {
  const chips = card.querySelector(".disposition-chips");
  if (!chips) return;
  chips.textContent = "";
  const disposition = r && r.disposition;
  if (disposition && disposition.muted === true) {
    const muted = isRecordMuted(r);
    const chip = document.createElement("span");
    chip.className = "mini-chip muted-chip";
    if (muted) {
      chip.textContent = "muted";
      chip.title = `Muted as a false positive until `
        + `${disposition.expires_at || "expiry"}`
        + (disposition.reason ? ` — ${disposition.reason}` : "");
    } else {
      chip.textContent = "mute ended";
      chip.title = "The allow-list entry is disabled or expired.";
    }
    chips.append(chip);
  } else if (disposition && disposition.muted === false
             && disposition.guard_blocked) {
    const chip = document.createElement("span");
    chip.className = "mini-chip reopened-chip";
    chip.textContent = `reopened: ${humanizeGuard(disposition.guard_blocked)}`;
    chip.title = "The allow-list entry matched, but a safety guard "
      + "reopened this finding.";
    chips.append(chip);
  } else if (r && r.display_muted === true && isRecordMuted(r)) {
    const chip = document.createElement("span");
    chip.className = "mini-chip muted-chip";
    chip.textContent = "muted";
    chip.title = "Matched the active allow-list entry; this record was "
      + "written before the mute and is hidden for display only.";
    chips.append(chip);
  }
  const mark = card.querySelector(".finding-allowlist-open");
  if (mark) mark.hidden = isRecordMuted(r);
}

async function reloadFindings() {
  // A new mute makes the server annotate older records for display, so pull
  // the full page again instead of waiting for the incremental cursor.
  try {
    const data = await api("/api/findings?limit=1000");
    S.findings.records = data.records.slice();
    S.findings.nextSeq = data.next_seq || 0;
    S.findings.loaded = true;
    S.findings.expanded.clear();
    S.findings.nodes.clear();
    renderFindings(true);
  } catch {
    /* keep the current list on failure */
  }
}

async function fetchAllowlist() {
  try {
    const data = await api("/api/allowlist");
    const entries = Array.isArray(data.entries) ? data.entries : [];
    S.findings.allowlist = {
      entries,
      activeIds: new Set(entries.filter((entry) => entry.active)
        .map((entry) => entry.id)),
      loaded: true,
      error: "",
      serverTime: data.server_time || "",
      invalidEntries: Number(data.invalid_entries || 0),
      status: data.status || "ok",
    };
  } catch (e) {
    // Fail safe: with no known active ids, nothing is hidden from the list.
    S.findings.allowlist = {
      entries: [],
      activeIds: new Set(),
      loaded: false,
      error: (e && e.message) || "allow-list unavailable",
      serverTime: "",
      invalidEntries: 0,
      status: "unavailable",
    };
  }
  if (S.findings.loaded) renderFindings();
  if (S.findings.allowlistManager) renderAllowlistManager();
}

function allowlistSection(titleText) {
  const section = document.createElement("section");
  section.className = "allowlist-section";
  const heading = document.createElement("div");
  heading.className = "triage-heading";
  heading.textContent = titleText;
  section.append(heading);
  return section;
}

function ensureAllowlistDialog() {
  let dialog = $("allowlist-dialog");
  if (dialog) return dialog;

  const backdrop = document.createElement("div");
  backdrop.id = "allowlist-backdrop";
  backdrop.className = "modal-backdrop hidden";
  backdrop.addEventListener("click", () => closeAllowlistDialog());

  dialog = document.createElement("section");
  dialog.id = "allowlist-dialog";
  dialog.className = "finding-chat allowlist-dialog hidden";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "allowlist-title");
  dialog.tabIndex = -1;

  const head = document.createElement("div");
  head.className = "finding-chat-head";
  const headMain = document.createElement("div");
  const title = document.createElement("h3");
  title.id = "allowlist-title";
  title.textContent = "Mark false positive";
  const subtitle = document.createElement("p");
  subtitle.id = "allowlist-subtitle";
  subtitle.className = "finding-chat-subtitle";
  headMain.append(title, subtitle);
  const close = document.createElement("button");
  close.type = "button";
  close.className = "btn btn-ghost";
  close.textContent = "Close";
  close.addEventListener("click", () => closeAllowlistDialog());
  head.append(headMain, close);

  const body = document.createElement("div");
  body.id = "allowlist-body";
  body.className = "allowlist-body";

  const form = document.createElement("form");
  form.id = "allowlist-form";
  form.className = "allowlist-form";
  const ttlLabel = document.createElement("label");
  ttlLabel.htmlFor = "allowlist-ttl";
  ttlLabel.textContent = "Mute for";
  const ttl = document.createElement("select");
  ttl.id = "allowlist-ttl";
  for (const days of ALLOWLIST_TTL_OPTIONS) {
    const option = document.createElement("option");
    option.value = String(days);
    option.textContent = `${days} days`;
    ttl.append(option);
  }
  ttl.value = "30";
  ttl.addEventListener("change", () => {
    if (S.findings.allowlistDialog) {
      S.findings.allowlistDialog.ttlDays = Number(ttl.value) || 30;
    }
  });
  const reasonLabel = document.createElement("label");
  reasonLabel.htmlFor = "allowlist-reason";
  reasonLabel.textContent = "Reason (optional)";
  const reason = document.createElement("input");
  reason.id = "allowlist-reason";
  reason.type = "text";
  reason.maxLength = 200;
  reason.placeholder = "e.g. YouTube/Twitch streaming";
  reason.addEventListener("input", () => {
    if (S.findings.allowlistDialog) {
      S.findings.allowlistDialog.reason = reason.value;
    }
  });
  const actions = document.createElement("div");
  actions.className = "allowlist-actions";
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "btn btn-ghost";
  cancel.textContent = "Cancel";
  cancel.addEventListener("click", () => closeAllowlistDialog());
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.id = "allowlist-submit";
  submit.className = "btn btn-primary";
  submit.textContent = "Add to allow-list";
  actions.append(cancel, submit);
  form.append(ttlLabel, ttl, reasonLabel, reason, actions);

  const status = document.createElement("p");
  status.id = "allowlist-status";
  status.className = "finding-chat-status";
  status.setAttribute("role", "status");

  dialog.append(head, body, form, status);
  document.body.append(backdrop, dialog);
  form.addEventListener("submit", submitAllowlistEntry);
  dialog.addEventListener("keydown", (ev) => trapFocusIn(dialog, ev));
  return dialog;
}

async function openAllowlistDialog(record) {
  closeFindingChat({ restoreFocus: false });
  closeFindingContext({ restoreFocus: false });
  closeAllowlistManager({ restoreFocus: false });
  closeAllowlistConfirm({ restoreFocus: false });
  if (S.expandedChart) {
    S.expandedChart = null;
    renderCharts();
  }
  const dialog = ensureAllowlistDialog();
  const verdict = record.verdict || {};
  const verdictLabel = typeof verdict.verdict === "string" ? verdict.verdict : "";
  const conf = typeof verdict.confidence === "number"
    ? ` ${Math.round(verdict.confidence)}%` : "";
  $("allowlist-subtitle").textContent = [
    ruleIdsOf(record).join(", ") || "Finding",
    severityOf(record),
    `${verdictLabel}${conf}`.trim(),
  ].filter(Boolean).join(" · ");
  S.findings.allowlistDialog = {
    record,
    seq: record._seq,
    timestamp: record.timestamp || "",
    key: findingKey(record),
    preview: null,
    ttlDays: 30,
    reason: "",
    saving: false,
    error: "",
    previousFocus: document.activeElement,
  };
  $("allowlist-ttl").value = "30";
  $("allowlist-reason").value = "";
  renderAllowlistDialog();
  $("allowlist-backdrop").classList.remove("hidden");
  dialog.classList.remove("hidden");
  syncAllowlistBodyLock();
  dialog.focus();
  try {
    const seq = encodeURIComponent(record._seq);
    const timestamp = encodeURIComponent(record.timestamp || "");
    const data = await api(
      `/api/allowlist/preview?seq=${seq}&timestamp=${timestamp}`);
    const current = S.findings.allowlistDialog;
    if (!current) return;
    current.preview = data;
    current.ttlDays = data.default_ttl_days || 30;
    $("allowlist-ttl").value = String(current.ttlDays);
    renderAllowlistDialog();
  } catch (e) {
    const current = S.findings.allowlistDialog;
    if (!current) return;
    current.error = (e && e.body && e.body.error) || (e && e.message)
      || "Could not load the mute preview.";
    renderAllowlistDialog();
  }
}

function renderAllowlistDialog() {
  const dlg = S.findings.allowlistDialog;
  const body = $("allowlist-body");
  const submit = $("allowlist-submit");
  const status = $("allowlist-status");
  if (!dlg || !body || !submit) return;
  body.textContent = "";
  submit.disabled = true;
  const preview = dlg.preview;
  if (!preview) {
    const p = document.createElement("p");
    p.className = dlg.error ? "allowlist-warning" : "empty-note";
    p.textContent = dlg.error || "Checking the mute scope…";
    body.append(p);
  } else if (!preview.eligible) {
    body.append(allowlistEvidenceSection(preview));
    const why = allowlistSection("Why this finding is not eligible");
    const p = document.createElement("p");
    p.className = "allowlist-warning";
    p.textContent = preview.reason || "This finding cannot be muted.";
    why.append(p);
    if (preview.code) {
      const code = document.createElement("p");
      code.className = "allowlist-note";
      code.textContent = `code: ${preview.code}`;
      why.append(code);
    }
    const proceed = document.createElement("p");
    proceed.className = "allowlist-note";
    proceed.textContent = allowlistProceedNote(preview.code);
    why.append(proceed);
    body.append(why);
  } else {
    body.append(allowlistEvidenceSection(preview));
    body.append(allowlistScopeSection(preview));
    if (Array.isArray(preview.warnings) && preview.warnings.length) {
      const warn = allowlistSection("Warnings");
      warn.append(allowlistList(preview.warnings));
      body.append(warn);
    }
    if (Array.isArray(preview.guards) && preview.guards.length) {
      const guards = allowlistSection("What will still alert");
      guards.append(allowlistList(preview.guards));
      body.append(guards);
    }
    const note = document.createElement("p");
    note.className = "allowlist-note";
    note.textContent = "Muted findings stay in soc_findings.jsonl. This "
      + "applies to future sightings; past records are not deleted.";
    body.append(note);
    if (preview.existing_entry_id) {
      const existing = document.createElement("p");
      existing.className = "allowlist-warning";
      existing.textContent = "An active allow-list entry already covers "
        + "this finding.";
      body.append(existing);
    }
  }
  submit.disabled = !preview || !preview.eligible
    || Boolean(preview.existing_entry_id) || dlg.saving;
  submit.textContent = dlg.saving ? "Adding…" : "Add to allow-list";
  status.textContent = dlg.error || "";
  status.classList.toggle("error", Boolean(dlg.error));
}

function allowlistList(items) {
  const ul = document.createElement("ul");
  ul.className = "allowlist-guard-list";
  for (const text of items) {
    const li = document.createElement("li");
    li.textContent = String(text);
    ul.append(li);
  }
  return ul;
}

function allowlistRow(label, value) {
  if (value === "" || value === null || value === undefined) return null;
  const row = document.createElement("div");
  row.className = "allowlist-row";
  const key = document.createElement("span");
  key.className = "allowlist-key";
  key.textContent = label;
  const val = document.createElement("span");
  val.className = "allowlist-val";
  val.textContent = String(value);
  row.append(key, val);
  return row;
}

function allowlistAppendRows(section, rows) {
  for (const [label, value] of rows) {
    const row = allowlistRow(label, value);
    if (row) section.append(row);
  }
}

function allowlistRate(value) {
  return typeof value === "number" && Number.isFinite(value)
    ? `${Math.round(value * 10) / 10}/s` : "unavailable";
}

function allowlistEvidenceSection(preview) {
  const diagnostics = preview.diagnostics || {};
  const section = allowlistSection("Observed evidence");
  const rows = [
    ["Rule", (diagnostics.rule_ids || preview.rule_ids || []).join(", ")
      || preview.rule_id || ""],
    ["Severity", diagnostics.severity || preview.severity || ""],
  ];
  if (diagnostics.kind === "traffic_udp") {
    const pids = Array.isArray(diagnostics.pids)
      && diagnostics.pids.length
      ? ` (pids ${diagnostics.pids.join(", ")})` : "";
    rows.push(["Process",
      `${(diagnostics.process_names || []).join(", ")}${pids}`]);
    rows.push(["Observed UDP rate", allowlistRate(diagnostics.udp_rate)]);
    rows.push(["Baseline", allowlistRate(diagnostics.baseline_rate)]);
    rows.push(["UDP errors",
      allowlistRate(diagnostics.udp_errors_per_second)]);
    rows.push(["UDP socket count",
      diagnostics.udp_socket_count == null
        ? "not recorded" : diagnostics.udp_socket_count]);
    if (typeof diagnostics.owner_share === "number") {
      const counts = diagnostics.numerator != null
        && diagnostics.denominator != null
        ? ` (${diagnostics.numerator}/${diagnostics.denominator})` : "";
      rows.push(["Owner share",
        `${Math.round(diagnostics.owner_share * 100)}%${counts}`
        + (diagnostics.approximate ? " · approximate" : "")]);
    }
    const owners = Array.isArray(diagnostics.top_owners)
      ? diagnostics.top_owners.map((owner) => {
        const ownerPids = Array.isArray(owner.pids) && owner.pids.length
          ? ` pids ${owner.pids.join(", ")}` : "";
        return `${owner.process_name} ×${owner.count}${ownerPids}`;
      }) : [];
    if (owners.length) rows.push(["Top owners", owners.join(" · ")]);
    if (diagnostics.ambiguity_candidate) {
      rows.push(["Ambiguity",
        `${diagnostics.ambiguity_candidate.process_name} ×`
        + `${diagnostics.ambiguity_candidate.count}`]);
    }
  } else if (diagnostics.kind === "row_endpoint") {
    rows.push(["Process",
      `${diagnostics.process_name || "unknown"}`
      + (diagnostics.pid ? ` (pid ${diagnostics.pid})` : "")]);
    rows.push(["Remote IP", diagnostics.remote_ip]);
    rows.push(["Remote port", diagnostics.foreign_port]);
    rows.push(["Protocols", (diagnostics.protocols || []).join(", ")]);
    rows.push(["Local ports", (diagnostics.local_ports || []).join(", ")]);
  }
  allowlistAppendRows(section, rows);
  return section;
}

function allowlistProceedNote(code) {
  switch (code) {
    case "owner_share_below_min":
    case "ambiguous_udp_owner":
      return "Wait for a sample where one process owns at least 50% of the "
        + "UDP sockets, or add a rule exception in the baseline YAML.";
    case "absolute_flood_floor":
      return "Rates at or above the absolute flood ceiling are never muted; "
        + "investigate the event or tune the UDP threshold.";
    case "critical_not_mutable":
      return "CRITICAL findings can never be muted.";
    case "rate_unavailable":
    case "no_process_attribution":
    case "no_protocol_evidence":
    case "no_endpoint":
      return "The record lacks the evidence needed to build a safe scope. "
        + "Wait for a richer sample or add a rule exception.";
    default:
      return "This finding cannot be muted. Review the reason above.";
  }
}

function allowlistScopeSection(preview) {
  const section = allowlistSection("Scope of this mute");
  const scope = preview.scope || {};
  const rows = [
    ["Rule", (preview.rule_ids || []).join(", ") || preview.rule_id || ""],
    ["Severity", preview.severity || ""],
    ["Process", (scope.process_names || []).join(", ")],
  ];
  if (scope.kind === "traffic_udp") {
    if (Array.isArray(scope.pids_at_mute) && scope.pids_at_mute.length) {
      rows.push(["PIDs", scope.pids_at_mute.join(", ")]);
    }
    rows.push(["Rate band", `below ${scope.rate_max}/s`]);
    rows.push(["Owner share",
      `at least ${Math.round((scope.min_share || 0.5) * 100)}%`]);
  } else if (scope.kind === "row_endpoint") {
    if (scope.remote_ip) rows.push(["Remote IP", scope.remote_ip]);
    if (scope.foreign_port) rows.push(["Remote port", scope.foreign_port]);
    rows.push(["Protocols", (scope.protocols || []).join(", ")]);
  }
  allowlistAppendRows(section, rows);
  return section;
}

function closeAllowlistDialog(opts) {
  const dlg = S.findings.allowlistDialog;
  if (!dlg) return;
  S.findings.allowlistDialog = null;
  const dialog = $("allowlist-dialog");
  const backdrop = $("allowlist-backdrop");
  if (dialog) dialog.classList.add("hidden");
  if (backdrop) backdrop.classList.add("hidden");
  syncAllowlistBodyLock();
  if (opts && opts.restoreFocus === false) return;
  const target = dlg.previousFocus;
  if (target && target.isConnected) {
    target.focus({ preventScroll: true });
    return;
  }
  const fallback = document.querySelector(
    `[data-focus-key="allowlist:${dlg.key}"]`);
  if (fallback) fallback.focus({ preventScroll: true });
}

async function submitAllowlistEntry(ev) {
  if (ev && ev.preventDefault) ev.preventDefault();
  const dlg = S.findings.allowlistDialog;
  if (!dlg || dlg.saving || !dlg.preview || !dlg.preview.eligible) return;
  if (dlg.preview.existing_entry_id) return;
  dlg.saving = true;
  dlg.error = "";
  const reason = $("allowlist-reason").value.trim();
  const ttlDays = Number($("allowlist-ttl").value) || dlg.ttlDays;
  renderAllowlistDialog();
  try {
    const data = await api("/api/allowlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        seq: dlg.seq,
        timestamp: dlg.timestamp,
        ttl_days: ttlDays,
        reason,
      }),
    });
    const entry = data.entry || {};
    dlg.record.disposition = {
      muted: true,
      allowlist_id: entry.id,
      reason: entry.reason || reason,
      expires_at: entry.expires_at,
      matched_scope: entry.scope || {},
      guard_blocked: null,
    };
    S.findings.allowlist.activeIds.add(entry.id);
    S.findings.allowlist.entries.push(entry);
    if (S.findings.allowlistDialog === dlg) {
      closeAllowlistDialog({ restoreFocus: false });
    }
    renderFindings();
    void reloadFindings();
    void fetchAllowlist();
  } catch (e) {
    dlg.saving = false;
    dlg.error = (e && e.body && e.body.error) || (e && e.message)
      || "Could not create the allow-list entry.";
    renderAllowlistDialog();
  }
}

function ensureAllowlistManager() {
  let dialog = $("allowlist-manager-dialog");
  if (dialog) return dialog;
  const backdrop = document.createElement("div");
  backdrop.id = "allowlist-manager-backdrop";
  backdrop.className = "modal-backdrop hidden";
  backdrop.addEventListener("click", () => closeAllowlistManager());

  dialog = document.createElement("section");
  dialog.id = "allowlist-manager-dialog";
  dialog.className = "finding-chat allowlist-dialog hidden";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "allowlist-manager-title");
  dialog.tabIndex = -1;

  const head = document.createElement("div");
  head.className = "finding-chat-head";
  const headMain = document.createElement("div");
  const title = document.createElement("h3");
  title.id = "allowlist-manager-title";
  title.textContent = "Allow-list";
  const subtitle = document.createElement("p");
  subtitle.id = "allowlist-manager-subtitle";
  subtitle.className = "finding-chat-subtitle";
  subtitle.textContent = "Confirmed false positives for this host.";
  headMain.append(title, subtitle);
  const actions = document.createElement("div");
  actions.className = "allowlist-manager-actions";
  const clear = document.createElement("button");
  clear.type = "button";
  clear.id = "allowlist-clear-all";
  clear.className = "btn btn-danger";
  clear.textContent = "Clear all";
  clear.addEventListener("click", requestClearAll);
  const close = document.createElement("button");
  close.type = "button";
  close.className = "btn btn-ghost";
  close.textContent = "Close";
  close.addEventListener("click", () => closeAllowlistManager());
  actions.append(clear, close);
  head.append(headMain, actions);

  const body = document.createElement("div");
  body.id = "allowlist-manager-body";
  body.className = "allowlist-body";

  dialog.append(head, body);
  document.body.append(backdrop, dialog);
  dialog.addEventListener("keydown", (ev) => trapFocusIn(dialog, ev));
  return dialog;
}

async function openAllowlistManager() {
  closeAllowlistDialog({ restoreFocus: false });
  closeAllowlistConfirm({ restoreFocus: false });
  closeFindingChat({ restoreFocus: false });
  closeFindingContext({ restoreFocus: false });
  if (S.expandedChart) {
    S.expandedChart = null;
    renderCharts();
  }
  const dialog = ensureAllowlistManager();
  S.findings.allowlistManager = { previousFocus: document.activeElement };
  const body = $("allowlist-manager-body");
  body.textContent = "";
  const loading = document.createElement("p");
  loading.className = "empty-note";
  loading.textContent = "Loading…";
  body.append(loading);
  $("allowlist-manager-backdrop").classList.remove("hidden");
  dialog.classList.remove("hidden");
  syncAllowlistBodyLock();
  dialog.focus();
  await fetchAllowlist();
  renderAllowlistManager();
}

function renderAllowlistManager() {
  const body = $("allowlist-manager-body");
  if (!body || !S.findings.allowlistManager) return;
  const state = S.findings.allowlist;
  body.textContent = "";
  const unreadable = ["unreadable", "oversized", "unsupported_version"]
    .includes(state.status);
  const subtitle = $("allowlist-manager-subtitle");
  if (subtitle) {
    const active = state.entries.filter((entry) => entry.active).length;
    subtitle.textContent = state.entries.length
      ? `${state.entries.length} entries · ${active} active`
      : "No entries";
  }
  const clear = $("allowlist-clear-all");
  if (clear) {
    clear.disabled = !state.loaded
      || !(state.entries.length > 0 || state.invalidEntries > 0 || unreadable);
  }
  if (state.error) {
    const p = document.createElement("p");
    p.className = "allowlist-warning";
    p.textContent = state.error;
    body.append(p);
  }
  if (!state.entries.length) {
    const p = document.createElement("p");
    p.className = unreadable ? "allowlist-warning" : "empty-note";
    p.textContent = unreadable
      ? "The allow-list file is unreadable. Use Clear all to replace it "
        + "with an empty allow-list."
      : "No allow-list entries yet. Open a finding and choose "
        + "Mark false positive.";
    body.append(p);
  } else {
    for (const entry of state.entries) {
      body.append(allowlistManagerEntry(entry));
    }
  }
  if (state.invalidEntries > 0 || state.status === "unreadable"
      || state.status === "unsupported_version") {
    const p = document.createElement("p");
    p.className = "allowlist-warning";
    p.textContent = `${state.invalidEntries} malformed or unreadable `
      + "allow-list entr(ies) were ignored. Fix or remove "
      + "soc_user_allowlist.json.";
    body.append(p);
  }
  const note = document.createElement("p");
  note.className = "allowlist-note";
  note.textContent = "Allow-list changes apply without restarting the agent. "
    + "YAML rule changes still require a restart.";
  body.append(note);
}

function allowlistManagerEntry(entry) {
  const scope = entry.scope || {};
  const card = document.createElement("div");
  card.className = "allowlist-entry";
  const head = document.createElement("div");
  head.className = "allowlist-entry-head";
  const title = document.createElement("strong");
  title.textContent = (scope.rule_ids || []).join(", ") || "Allow-list entry";
  const state = document.createElement("span");
  state.className = `mini-chip ${entry.active ? "muted-chip" : "reopened-chip"}`;
  state.textContent = entry.active ? "active" : "disabled/expired";
  head.append(title, state);

  const details = document.createElement("p");
  details.className = "allowlist-note";
  details.textContent = [
    (scope.process_names || []).join(", "),
    scope.kind === "traffic_udp"
      ? `rate < ${Math.round(Number(scope.rate_max) || 0)}/s` : null,
    scope.remote_ip ? `remote ${scope.remote_ip}` : null,
    scope.foreign_port ? `port ${scope.foreign_port}` : null,
    entry.expires_at ? `expires ${entry.expires_at}` : null,
    entry.disabled_at ? `disabled ${entry.disabled_at}` : null,
    entry.reason || null,
  ].filter(Boolean).join(" · ");

  const actions = document.createElement("div");
  actions.className = "allowlist-entry-actions";
  if (entry.active) {
    const deactivate = document.createElement("button");
    deactivate.type = "button";
    deactivate.className = "btn btn-ghost";
    deactivate.textContent = "Deactivate";
    deactivate.addEventListener("click", () => deactivateAllowlistEntry(entry.id));
    actions.append(deactivate);
  }
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn btn-danger";
  remove.textContent = "Delete permanently";
  remove.addEventListener("click", () => requestHardDelete(entry));
  actions.append(remove);
  card.append(head, details, actions);
  return card;
}

function optimisticallyUnmute(ids) {
  for (const id of ids) S.findings.allowlist.activeIds.delete(id);
  renderFindings();
}

async function refreshAfterAllowlistChange() {
  await fetchAllowlist();
  await reloadFindings();
  renderAllowlistManager();
}

async function deactivateAllowlistEntry(id) {
  S.findings.allowlist.error = "";
  try {
    await api(`/api/allowlist/${encodeURIComponent(id)}`, { method: "DELETE" });
  } catch (e) {
    S.findings.allowlist.error = (e && e.body && e.body.error)
      || (e && e.message) || "Could not deactivate the entry.";
    renderAllowlistManager();
    return;
  }
  optimisticallyUnmute([id]);
  await refreshAfterAllowlistChange();
}

function requestHardDelete(entry) {
  openAllowlistConfirm({
    kind: "delete",
    entryId: entry.id,
    title: "Delete allow-list entry permanently?",
    message: "This removes the entry from soc_user_allowlist.json and "
      + "un-mutes matching findings (they reappear under ALL). This cannot "
      + "be undone. Use Deactivate instead to keep the entry for reference.",
    confirmLabel: "Delete permanently",
  });
}

function requestClearAll() {
  const state = S.findings.allowlist;
  const unreadable = ["unreadable", "oversized", "unsupported_version"]
    .includes(state.status);
  openAllowlistConfirm({
    kind: "clear",
    title: "Clear the entire allow-list?",
    message: unreadable
      ? "The allow-list file is unreadable. Clearing replaces it with an "
        + "empty allow-list and un-mutes every finding. This cannot be undone."
      : `This permanently deletes all ${state.entries.length} entries and `
        + "un-mutes every finding (they reappear under ALL). This cannot be "
        + "undone.",
    confirmLabel: "Clear all",
  });
}

function closeAllowlistManager(opts) {
  const mgr = S.findings.allowlistManager;
  if (!mgr) return;
  closeAllowlistConfirm({ restoreFocus: false });
  S.findings.allowlistManager = null;
  const dialog = $("allowlist-manager-dialog");
  const backdrop = $("allowlist-manager-backdrop");
  if (dialog) dialog.classList.add("hidden");
  if (backdrop) backdrop.classList.add("hidden");
  syncAllowlistBodyLock();
  if (opts && opts.restoreFocus === false) return;
  if (mgr.previousFocus && mgr.previousFocus.isConnected) {
    mgr.previousFocus.focus({ preventScroll: true });
  } else if ($("btn-allowlist-manage")) {
    $("btn-allowlist-manage").focus({ preventScroll: true });
  }
}

function syncAllowlistBodyLock() {
  document.body.classList.toggle(
    "allowlist-open",
    Boolean(
      S.findings.allowlistDialog
      || S.findings.allowlistManager
      || S.findings.allowlistConfirm,
    ),
  );
}

function ensureAllowlistConfirm() {
  let dialog = $("allowlist-confirm-dialog");
  if (dialog) return dialog;
  const backdrop = document.createElement("div");
  backdrop.id = "allowlist-confirm-backdrop";
  backdrop.className = "modal-backdrop hidden";
  backdrop.addEventListener("click", () => closeAllowlistConfirm());

  dialog = document.createElement("section");
  dialog.id = "allowlist-confirm-dialog";
  dialog.className =
    "finding-chat allowlist-dialog allowlist-confirm-dialog hidden";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-labelledby", "allowlist-confirm-title");
  dialog.tabIndex = -1;

  const head = document.createElement("div");
  head.className = "finding-chat-head";
  const headMain = document.createElement("div");
  const title = document.createElement("h3");
  title.id = "allowlist-confirm-title";
  headMain.append(title);
  const close = document.createElement("button");
  close.type = "button";
  close.className = "btn btn-ghost";
  close.textContent = "Close";
  close.addEventListener("click", () => closeAllowlistConfirm());
  head.append(headMain, close);

  const message = document.createElement("p");
  message.id = "allowlist-confirm-message";
  message.className = "allowlist-confirm-message";

  const actions = document.createElement("div");
  actions.className = "allowlist-confirm-actions";
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "btn btn-ghost";
  cancel.textContent = "Cancel";
  cancel.addEventListener("click", () => closeAllowlistConfirm());
  const confirm = document.createElement("button");
  confirm.type = "button";
  confirm.id = "allowlist-confirm-action";
  confirm.className = "btn btn-danger";
  confirm.addEventListener("click", () => {
    void confirmAllowlistAction();
  });
  actions.append(cancel, confirm);

  const status = document.createElement("p");
  status.id = "allowlist-confirm-status";
  status.className = "finding-chat-status";
  status.setAttribute("role", "status");

  dialog.append(head, message, actions, status);
  document.body.append(backdrop, dialog);
  dialog.addEventListener("keydown", (ev) => trapFocusIn(dialog, ev));
  return dialog;
}

function openAllowlistConfirm(config) {
  const dialog = ensureAllowlistConfirm();
  S.findings.allowlistConfirm = {
    ...config,
    busy: false,
    error: "",
    previousFocus: document.activeElement,
  };
  $("allowlist-confirm-title").textContent = config.title;
  $("allowlist-confirm-message").textContent = config.message;
  $("allowlist-confirm-action").textContent = config.confirmLabel;
  $("allowlist-confirm-action").disabled = false;
  $("allowlist-confirm-status").textContent = "";
  $("allowlist-confirm-status").classList.remove("error");
  $("allowlist-confirm-backdrop").classList.remove("hidden");
  dialog.classList.remove("hidden");
  syncAllowlistBodyLock();
  dialog.focus();
  const cancel = dialog.querySelector(".allowlist-confirm-actions .btn-ghost");
  if (cancel) cancel.focus();
}

function renderAllowlistConfirm() {
  const confirm = S.findings.allowlistConfirm;
  if (!confirm) return;
  const action = $("allowlist-confirm-action");
  const status = $("allowlist-confirm-status");
  if (action) {
    action.disabled = confirm.busy;
    action.textContent = confirm.busy ? "Working…" : confirm.confirmLabel;
  }
  if (status) {
    status.textContent = confirm.error || "";
    status.classList.toggle("error", Boolean(confirm.error));
  }
}

function closeAllowlistConfirm(opts) {
  const confirm = S.findings.allowlistConfirm;
  if (!confirm) return;
  S.findings.allowlistConfirm = null;
  const dialog = $("allowlist-confirm-dialog");
  const backdrop = $("allowlist-confirm-backdrop");
  if (dialog) dialog.classList.add("hidden");
  if (backdrop) backdrop.classList.add("hidden");
  syncAllowlistBodyLock();
  if (opts && opts.restoreFocus === false) return;
  if (confirm.previousFocus && confirm.previousFocus.isConnected) {
    confirm.previousFocus.focus({ preventScroll: true });
  }
}

async function confirmAllowlistAction() {
  const confirm = S.findings.allowlistConfirm;
  if (!confirm || confirm.busy) return;
  confirm.busy = true;
  confirm.error = "";
  renderAllowlistConfirm();
  try {
    if (confirm.kind === "delete") {
      await api(
        `/api/allowlist/${encodeURIComponent(confirm.entryId)}?hard=1`,
        { method: "DELETE" },
      );
      optimisticallyUnmute([confirm.entryId]);
    } else {
      await api("/api/allowlist", { method: "DELETE" });
      S.findings.allowlist.activeIds.clear();
      renderFindings();
    }
    closeAllowlistConfirm({ restoreFocus: false });
    await refreshAfterAllowlistChange();
    if ($("allowlist-manager-dialog")) $("allowlist-manager-dialog").focus();
  } catch (e) {
    confirm.busy = false;
    confirm.error = (e && e.body && e.body.error) || (e && e.message)
      || "The allow-list change failed.";
    S.findings.allowlist.error = confirm.error;
    renderAllowlistConfirm();
    renderAllowlistManager();
  }
}

// --------------------------------------------------------------- charts ---
function niceTicks(maxVal) {
  if (!(maxVal > 0)) return { top: 1, ticks: [0, 1] };
  const raw = maxVal / 3;
  const pow = Math.pow(10, Math.floor(Math.log10(raw)));
  let step = pow;
  for (const m of [1, 2, 5, 10]) {
    if (m * pow >= raw) { step = m * pow; break; }
  }
  let top = Math.ceil(maxVal / step) * step;
  let ticks = [];
  for (let v = 0; v <= top + step / 2; v += step) ticks.push(v);
  while (ticks.length > 5) {
    step *= 2;
    top = Math.ceil(maxVal / step) * step;
    ticks = [];
    for (let v = 0; v <= top + step / 2; v += step) ticks.push(v);
  }
  return { top, ticks };
}

function toggleChart(id) {
  S.expandedChart = S.expandedChart === id ? null : id;
  renderCharts();
}

function renderCharts() {
  const grid = $("charts-grid");
  const rows = S.traffic.rows;
  const now = S.traffic.newestTs || 0;
  const t0 = now - S.range;
  let backdrop = $("chart-backdrop");
  if (!backdrop) {
    backdrop = document.createElement("div");
    backdrop.id = "chart-backdrop";
    backdrop.className = "chart-backdrop hidden";
    backdrop.addEventListener("click",
      () => { if (S.expandedChart) toggleChart(S.expandedChart); });
    document.body.append(backdrop);
  }
  backdrop.classList.toggle("hidden", !S.expandedChart);
  document.body.classList.toggle("chart-open", Boolean(S.expandedChart));
  for (const cfg of CHARTS) {
    let card = $(`chart-${cfg.id}`);
    const expanded = S.expandedChart === cfg.id;
    if (!card) {
      card = document.createElement("div");
      card.className = "chart-card";
      card.id = `chart-${cfg.id}`;
      const head = document.createElement("div");
      head.className = "section-head";
      const headMain = document.createElement("div");
      headMain.className = "chart-head-main";
      const h3 = document.createElement("h3");
      h3.textContent = cfg.title;
      headMain.append(h3);
      const legend = document.createElement("div");
      legend.className = "chart-legend";
      headMain.append(legend);
      const expandBtn = document.createElement("button");
      expandBtn.type = "button";
      expandBtn.className = "chip chart-expand";
      expandBtn.addEventListener("click", () => toggleChart(cfg.id));
      head.append(headMain, expandBtn);
      const bodyWrap = document.createElement("div");
      bodyWrap.className = "chart-body";
      bodyWrap.tabIndex = 0;
      bodyWrap.setAttribute("role", "img");
      bodyWrap.setAttribute("aria-label", cfg.title);
      card.append(head, bodyWrap);
      grid.append(card);
      bindChartEvents(cfg, bodyWrap);
    }
    card.classList.toggle("expanded", expanded);
    const expandBtn = card.querySelector(".chart-expand");
    expandBtn.textContent = expanded ? "Minimize" : "Expand";
    expandBtn.title = expanded ? "Return to grid" : "Focus mode (Esc closes)";
    const legend = card.querySelector(".chart-legend");
    legend.textContent = "";
    if (cfg.series.length > 1) {  // single series needs no legend box
      for (const s of cfg.series) {
        const item = document.createElement("span");
        item.className = "legend-item";
        const key = document.createElement("span");
        key.className = "legend-key";
        key.style.background = cssVar(`--series-${s.slot}`);
        item.append(key, document.createTextNode(s.label));
        legend.append(item);
      }
    }
    const bodyWrap = card.querySelector(".chart-body");
    const height = expanded ? Math.max(360, bodyWrap.clientHeight || 420) : 190;
    drawChart(cfg, bodyWrap, $("tooltip"), rows, now, t0, height);
    if (expanded) bodyWrap.focus({ preventScroll: true });
  }
}

function drawChart(cfg, bodyWrap, tip, rows, now, t0, height) {
  bodyWrap.textContent = "";
  const W = Math.max(260, bodyWrap.clientWidth || 320);
  const H = height || 190;
  const padL = 44, padR = 12, padT = 10, padB = 24;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H,
    "aria-hidden": "true" });
  bodyWrap.append(svg);

  // series values over the window; rates use the full array for boundaries
  const points = [];
  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];
    if (row.timestamp < t0) continue;
    const rec = { ts: row.timestamp, iso: row.iso, idx: i, vals: [] };
    for (const s of cfg.series) {
      rec.vals.push(fmtRate(rows, i, s.key, S.traffic.boundary));
    }
    points.push(rec);
  }
  let maxVal = 0;
  for (const p of points) {
    for (const v of p.vals) { if (v != null && v > maxVal) maxVal = v; }
  }
  const { top, ticks } = niceTicks(maxVal);
  const y = (v) => padT + plotH - (plotH * (v / (top || 1)));
  const t1 = Math.max(now, points.length ? points[points.length - 1].ts : now);
  // x grows with time: oldest at padL, newest at the right edge
  const xAt = (ts) => padL + ((ts - t0) / (t1 - t0 || 1)) * plotW;

  // grid (hairline, solid, recessive) + y tick labels
  for (const v of ticks) {
    svg.append(svgEl("line", { x1: padL, x2: padL + plotW, y1: y(v), y2: y(v),
      stroke: v === 0 ? cssVar("--baseline") : cssVar("--grid"), "stroke-width": 1 }));
    const label = svgEl("text", { x: padL - 6, y: y(v) + 3,
      "text-anchor": "end", "font-size": 10, fill: cssVar("--muted") });
    label.textContent = cfg.unit === "bytes" ? fmtByteRate(v).replace("B/s", "") :
      (v >= 10000 ? `${Math.round(v / 1000)}K` : `${Math.round(v * 10) / 10}`);
    svg.append(label);
  }
  // x labels: sparse HH:MM
  const xLabels = [];
  if (points.length > 1) {
    const picks = [0, Math.floor((points.length - 1) / 2), points.length - 1];
    for (const idx of picks) {
      const lbl = fmtTime(points[idx].ts, false);
      if (xLabels.length && xLabels[xLabels.length - 1].lbl === lbl) continue;
      xLabels.push({ lbl, x: xAt(points[idx].ts) });
    }
  } else if (points.length === 1) {
    xLabels.push({ lbl: fmtTime(points[0].ts, false), x: padL });
  }
  for (const { lbl, x: lx } of xLabels) {
    const t = svgEl("text", { x: lx, y: H - 8, "text-anchor": "middle",
      "font-size": 10, fill: cssVar("--muted") });
    t.textContent = lbl;
    svg.append(t);
  }

  // series paths: 2px, round join/cap; nulls and sampling gaps break the line
  const gapThresh = Math.max(15, 5 * sampleInterval());
  for (let si = 0; si < cfg.series.length; si += 1) {
    const s = cfg.series[si];
    let d = "";
    let started = false;
    let lastPlotted = null;
    for (const p of points) {
      const v = p.vals[si];
      if (v == null) { started = false; continue; }
      if (lastPlotted != null && p.ts - lastPlotted > gapThresh) {
        started = false;  // never draw a fake ramp across an idle gap
      }
      const px = xAt(p.ts), py = y(Math.min(v, top));
      d += `${started ? "L" : "M"}${px.toFixed(1)} ${py.toFixed(1)}`;
      started = true;
      lastPlotted = p.ts;
    }
    if (d) {
      svg.append(svgEl("path", { d, fill: "none",
        stroke: cssVar(`--series-${s.slot}`), "stroke-width": 2,
        "stroke-linejoin": "round", "stroke-linecap": "round" }));
    }
  }

  // crosshair + end dot for the newest value of the first series
  const hairline = svgEl("line", { y1: padT, y2: padT + plotH,
    stroke: cssVar("--baseline"), "stroke-width": 1, opacity: 0 });
  svg.append(hairline);
  bodyWrap._chart = { points, xAt, y, cfg, hairline, svg, tip, top, t0, t1,
    padT, padL, plotH };
}

function fmtPointValue(cfg, si, v) {
  return cfg.unit === "bytes" ? fmtByteRate(v) : fmtNum(v);
}

function showChartTip(ch, point, clientXY) {
  ch.tip.textContent = "";
  const timeDiv = document.createElement("div");
  timeDiv.className = "tooltip-time";
  const iso = point.iso || new Date(point.ts * 1000).toISOString();
  timeDiv.textContent = iso.slice(11, 19);
  ch.tip.append(timeDiv);
  ch.cfg.series.forEach((s, si) => {
    const row = document.createElement("div");
    row.className = "tooltip-row";
    const key = document.createElement("span");
    key.className = "tooltip-key";
    key.style.background = cssVar(`--series-${s.slot}`);
    const val = document.createElement("span");
    val.className = "tooltip-val";
    val.textContent = fmtPointValue(ch.cfg, si, point.vals[si]);
    const name = document.createElement("span");
    name.className = "tooltip-ser";
    name.textContent = s.label;
    row.append(key, val, name);
    ch.tip.append(row);
  });
  ch.tip.classList.remove("hidden");
  ch.hairline.setAttribute("x1", ch.xAt(point.ts));
  ch.hairline.setAttribute("x2", ch.xAt(point.ts));
  ch.hairline.setAttribute("opacity", 1);
  if (clientXY) {
    positionTip(ch.tip, clientXY.x, clientXY.y);
  }
}

function positionTip(tip, x, y) {
  const box = tip.getBoundingClientRect();
  const px = Math.min(x + 14, window.innerWidth - box.width - 8);
  const py = Math.max(8, Math.min(y - box.height - 14, window.innerHeight - box.height - 8));
  tip.style.left = `${px}px`;
  tip.style.top = `${py}px`;
}

function nearestPoint(ch, clientX) {
  const box = ch.svg.getBoundingClientRect();
  const scaleX = box.width / parseFloat(ch.svg.getAttribute("width"));
  const cx = (clientX - box.left) / (scaleX || 1);
  let best = null, bestDist = Infinity;
  for (const p of ch.points) {
    const dx = Math.abs(ch.xAt(p.ts) - cx);
    if (dx < bestDist) { bestDist = dx; best = p; }
  }
  return best;
}

function bindChartEvents(cfg, bodyWrap, tip) {
  let focusIdx = -1;
  const chart = () => bodyWrap._chart;
  bodyWrap.addEventListener("pointermove", (ev) => {
    const ch = chart();
    if (!ch || !ch.points.length) return;
    const p = nearestPoint(ch, ev.clientX);
    if (p) showChartTip(ch, p, { x: ev.clientX, y: ev.clientY });
  });
  bodyWrap.addEventListener("pointerleave", () => {
    const ch = chart();
    if (ch) { ch.tip.classList.add("hidden"); ch.hairline.setAttribute("opacity", 0); }
    focusIdx = -1;
  });
  bodyWrap.addEventListener("keydown", (ev) => {
    const ch = chart();
    if (!ch || !ch.points.length) return;
    if (ev.key === "Escape") {
      ch.tip.classList.add("hidden");
      ch.hairline.setAttribute("opacity", 0);
      focusIdx = -1;
      return;
    }
    if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
    ev.preventDefault();
    if (focusIdx < 0) focusIdx = ch.points.length - 1;
    else focusIdx = ev.key === "ArrowLeft"
      ? Math.max(0, focusIdx - 1) : Math.min(ch.points.length - 1, focusIdx + 1);
    const rect = ch.svg.getBoundingClientRect();
    const scaleX = rect.width / parseFloat(ch.svg.getAttribute("width"));
    showChartTip(ch, ch.points[focusIdx], {
      x: rect.left + ch.xAt(ch.points[focusIdx].ts) * (scaleX || 1),
      y: rect.top + 40 });
  });
}

// ---------------------------------------------------------------- status ---
async function fetchStatus() {
  const data = await api("/api/status");
  S.status = data;
  S.externalBoot = data.external_boot || null;
  renderStatus();
}

function chipEl(cls, text, title) {
  const span = document.createElement("span");
  span.className = `stat-chip ${cls || ""}`;
  if (title) span.title = title;
  const dot = document.createElement("span");
  dot.className = "dot";
  span.append(dot, Object.assign(document.createElement("span"),
    { textContent: text }));
  return span;
}

function renderStatus() {
  const st = S.status;
  if (!st) return;
  const strip = $("status-strip");
  strip.textContent = "";
  const ollama = st.ollama || {};
  const models = Array.isArray(ollama.models) ? ollama.models : [];
  const loading = ollama.error === "status loading";
  strip.append(chipEl(loading ? "" : (ollama.reachable ? "good" : "bad"),
    `Ollama ${loading ? "checking" : (ollama.reachable ? "reachable" : "unreachable")} · ${models.length} model${models.length === 1 ? "" : "s"}`,
    ollama.reachable ? models.map((m) => m.name).join("\n")
      : (ollama.error || "")));
  const net = st.network || {};
  const netCaveat = net.caveat || "";
  const netTitle = () => {
    const parts = [];
    const describe = (p, prefix) => {
      if (!p) return;
      if (p.reachable) {
        parts.push(`${prefix}${p.label || p.host}: ${p.rtt_ms_avg != null ? Math.round(p.rtt_ms_avg) : "?"}ms / ${p.loss_pct != null ? Math.round(p.loss_pct) : "?"}% loss`);
      } else {
        parts.push(`${prefix}${p.label || p.host}: ${p.error || "unreachable"}`);
      }
    };
    describe(net.gateway, "gateway ");
    (net.targets || []).forEach((p) => describe(p, ""));
    if (net.summary) parts.push(net.summary);
    if (net.age_seconds != null) parts.push(`sample age ${Math.round(net.age_seconds)}s`);
    if (netCaveat) parts.push(netCaveat);
    if (net.error) parts.push(net.error);
    return parts.join("\n");
  };
  if (net.enabled === false) {
    strip.append(chipEl("", "network probes off", netCaveat));
  } else if (!net.available) {
    strip.append(chipEl("warn", "network unknown", netTitle()));
  } else {
    const up = net.targets_up ?? 0;
    const total = net.targets_total ?? 0;
    const labels = {
      RESPONSIVE: ["good", `network normal · ${up}/${total}`],
      LOCAL_LINK: ["bad", "network local link"],
      UPSTREAM_ISP: ["bad", `network upstream/ISP or pre-NIC · ${up}/${total}`],
      DESTINATION_PATH: ["warn", `network destination path · ${up}/${total}`],
      UNKNOWN: ["warn", "network unknown"],
    };
    const [cls, text] = labels[net.verdict] || labels.UNKNOWN;
    strip.append(chipEl(net.stale && cls === "good" ? "warn" : cls,
      net.stale ? `${text} (stale)` : text, netTitle()));
  }
  const interval = st.sample_interval || 10;
  const staleAfter = Math.max(30, interval * 4);
  if (st.sample_age != null) {
    strip.append(chipEl(st.sample_age > staleAfter ? "warn" : "",
      `last sample ${st.sample_age.toFixed(0)}s ago`));
  } else {
    strip.append(chipEl("", "no traffic samples yet"));
  }
  strip.append(chipEl("", `sample cadence ${interval}s`));
  const traffic = st.traffic || {};
  strip.append(chipEl("", `traffic samples ${traffic.rows ?? 0}`));
  const verdictCache = st.verdict_cache || {};
  if (verdictCache.entries != null) {
    strip.append(chipEl("", `verdict cache ${verdictCache.entries}`));
  }
  const files = Object.fromEntries((st.files || []).map((f) => [f.name, f]));
  const findingsFile = files["soc_findings.jsonl"];
  const snapshotFile = files["netstat_snapshot.log"];
  if (findingsFile) strip.append(chipEl("", `findings ${findingsFile.size_human}`));
  if (snapshotFile) strip.append(chipEl("", `snapshot log ${snapshotFile.size_human}`));
  const runner = st.runner || {};
  if (runner.attached === false) {
    strip.append(chipEl("warn", "adopted agent from previous dashboard"));
  }
  if (S.externalBoot && S.externalBoot.length) {
    strip.append(chipEl("bad",
      `other checkstat.py at boot: pid ${S.externalBoot.map((p) => p.pid).join(", ")}`));
  }
}

// ------------------------------------------------------------ polling ---
function pollLoop(name, period, fn) {
  async function tick() {
    let delay = period;
    if (document.hidden) delay = 15000;
    try { await fn(); } catch { /* transient fetch errors ignored */ }
    setTimeout(tick, delay);
  }
  setTimeout(tick, name === "status" ? 1000 : 0);
}

// ---------------------------------------------------------------- theme ---
function applyTheme() {
  if (S.theme === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.dataset.theme = S.theme;
  localStorage.setItem("soc_ui.theme", S.theme);
  renderCharts();          // chart strokes/labels re-read the CSS variables
  renderTraffic();
}

function cycleTheme() {
  S.theme = S.theme === "auto" ? "dark" : S.theme === "dark" ? "light" : "auto";
  applyTheme();
}

// ------------------------------------------------------------------ init ---
async function init() {
  $("btn-theme").addEventListener("click", cycleTheme);
  $("btn-allowlist-manage").addEventListener("click", () => {
    void openAllowlistManager();
  });
  $("btn-start").addEventListener("click", () => startAgent(false));
  $("btn-start-form").addEventListener("click", (e) => {
    e.preventDefault();
    startAgent(false);
  });
  $("options-form").addEventListener("submit", (e) => {
    e.preventDefault();
    startAgent(false);
  });
  $("btn-stop").addEventListener("click", stopAgent);
  $("btn-follow").addEventListener("click", () => {
    S.console.follow = true;
    $("console-lines").scrollTop = $("console-lines").scrollHeight;
    $("btn-follow").classList.add("hidden");
  });
  $("console-lines").addEventListener("scroll", () => {
    const el = $("console-lines");
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    S.console.follow = nearBottom;
    $("btn-follow").classList.toggle("hidden", nearBottom);
  });
  $("f-replay-path").addEventListener("input", syncReplayMode);

  const ranges = [["5m", 300], ["15m", 900], ["60m", 3600]];
  const chipWrap = $("range-chips");
  ranges.forEach(([label, sec]) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip" + (S.range === sec ? " active" : "");
    chip.textContent = label;
    chip.addEventListener("click", () => {
      S.range = sec;
      [...chipWrap.children].forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      renderCharts();
    });
    chipWrap.append(chip);
  });
  renderFindingChips();

  applyTheme();
  try {
    const [defaults, state] = await Promise.all(
      [api("/api/config-defaults"), api("/api/state")]);
    S.defaults = defaults;
    S.state = state;
    fillForm();
    renderState();
    await Promise.all([fetchConsole(), fetchTraffic(true),
      fetchFindings(), fetchStatus(), fetchAllowlist()]);
  } catch (e) {
    if (e && e.auth) banner(e.message);
    else banner(`Dashboard failed to initialize: ${e.message}`);
  }
  pollLoop("console", 1000, fetchConsole);
  pollLoop("traffic", 2000, () => fetchTraffic(false));
  pollLoop("findings", 2000, fetchFindings);
  pollLoop("status", 15000, fetchStatus);
  pollLoop("allowlist", 15000, fetchAllowlist);
}

// When the tab has been hidden (polls throttle to 15 s), refocusing refreshes
// everything immediately instead of waiting for the next throttled tick.
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && document.readyState === "complete") {
    void fetchConsole();
    void fetchTraffic(false);
    void fetchFindings();
    void fetchStatus();
  }
});

document.addEventListener("keydown", (ev) => {
  if (ev.key !== "Escape") return;
  if (S.findings.allowlistConfirm) {
    closeAllowlistConfirm();
    return;
  }
  if (S.findings.allowlistDialog) {
    closeAllowlistDialog();
    return;
  }
  if (S.findings.allowlistManager) {
    closeAllowlistManager();
    return;
  }
  if (S.findings.context) {
    closeFindingContext();
    return;
  }
  if (S.findings.chat) {
    closeFindingChat();
    return;
  }
  if (S.expandedChart) toggleChart(S.expandedChart);
});

let resizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(renderCharts, 200);
});

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  void init();
}
})();