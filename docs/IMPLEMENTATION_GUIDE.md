# SOCA — Implementation Guide

Developer and architecture reference for SOCA (Security Operations Center
Agent), alpha version. User-facing behavior is documented in `README.md`;
security findings and remediation priorities are in `docs/internal/CODE_REVIEW.md`.

*Last verified against the post-P3b source hashes recorded in `docs/internal/CODE_REVIEW.md`
on 2026-11-01.*

---

## Overview

`checkstat.py` is a stateful local agent with two evaluation lanes and a shared
result pipeline:

```text
scan lane (every scan_interval_seconds, default 300 s)
  netstat -ano text
    -> parse TCP/UDP rows
    -> row rules (NET-001, NET-002, NET-007, NET-009 enabled)
    -> group hits by endpoint + process
    -> enrich (RDAP/WHOIS, reverse DNS, process path/signature)
    -> tier 1 routine model -> tier 2 escalation model
    -> guardrails -> verdict cache -> report + JSONL + toast

traffic sampler (gauge 1 s, persist 3 s)
  iphlpapi direct capture (netstat fallback)
    -> traffic metrics + rolling history
    -> evaluate_traffic() every gauge tick
    -> fast lane emits new findings (deterministic, no model wait)
    -> findings with no cached verdict are queued for scan-lane triage
    -> scan lane drains the deferred queue through the same two-tier path
```

The LLM only sees candidate anomalies and their evidence, never the full
netstat dump. The model is advisory: it produces a verdict and reasoning, but it
cannot change rule severity, run commands, or write files.

---

## Files

| Path | Purpose |
| --- | --- |
| `checkstat.py`, `soc_ui.py` | Thin root launchers (kept for WMI detection and process adoption) |
| `soca/paths.py` | Single source of filesystem paths (`PROJECT_ROOT`, `CONFIG_DIR`, `DATA_DIR`, `STATIC_DIR`, defaults) |
| `soca/agent/checkstat.py` | Unified agent: parser, rule engine, enrichment, LLM triage, traffic detector, reporting, CLI |
| `soca/agent/netapi.py` | Direct unelevated iphlpapi capture for the traffic sampler |
| `soca/ui/soc_ui.py` | Localhost dashboard and process runner (spawns the root `checkstat.py`, reads `data/`) |
| `soca/ui/finding_chat.py` | Read-only per-finding chat with bounded evidence context |
| `soca/ui/static/` | Dashboard assets (`index.html`, `app.css`, `app.js`) |
| `soca/core/install_security.py` | Install-ACL/elevation warnings and process-principal probes |
| `soca/core/network_health.py` | Active gateway/external probes, verdict matrix, shared result file |
| `soca/core/user_allowlist.py` | Scoped user allow-list schema, matching, and persistence |
| `config/netstat_baseline_rules.yaml` | Live baseline, row rules, traffic thresholds, agent/enrichment config (ignored) |
| `config/netstat_baseline_rules.example.yaml` | Sanitized example baseline (tracked) |
| `tests/` | Offline parser, netapi, dashboard, network-health, allow-list, and chat tests |
| `README.md` | User documentation |
| `docs/internal/CODE_REVIEW.md` | Formal code review/security assessment (local-only, ignored) |
| `.gitignore` | Excludes the venv, live config, runtime data, and internal notes |
| `pyproject.toml`, `uv.lock` | Dependencies and pinned lockfile |

Runtime files (generated, ignored): everything under `data/` —
`local_soc_agent.log`, `netstat_snapshot.log`, `soc_findings.jsonl`,
`soc_traffic_history.jsonl`, `soc_verdict_cache.json`, `soc_intel_cache.json`,
`soc_ui_agent_state.json`, `soc_network_health.json`, and
`soc_user_allowlist.json`.

---

## Quick start

```powershell
# Create/refresh the environment from the lockfile
uv sync --frozen

# One scan and exit
.venv\Scripts\python.exe checkstat.py --once

# Continuous monitoring
.venv\Scripts\python.exe checkstat.py

# Replay saved snapshots
.venv\Scripts\python.exe checkstat.py --file data\netstat_snapshot.log

# Rules + enrichment only
.venv\Scripts\python.exe checkstat.py --once --no-ai --no-toast

# Dashboard
.venv\Scripts\python.exe soc_ui.py

# Tests (offline suite; test_netapi includes live checks and may be flaky)
uv run python -m unittest discover -s tests -t . -v
uv run python -m unittest tests.test_netapi -v
```

`--once` waits for two traffic samples; with the 1 s gauge this is about a
second or two, not the old 10 s estimate.

---

## How an anomaly is vetted

1. **Rule match.** For example, NET-002 fires on an established connection to
   an external port above 1024 that is not a standard web port, not a documented
   benign client port, outside the trusted CDN ranges, and not owned by a known
   client process.
2. **Grouping.** Rows and rule hits for the same remote IP, port, PID, and
   process become one group, so the model is asked once per endpoint.
3. **Enrichment.** RDAP/WHOIS, reverse DNS, process name/path/signature, trusted
   network, known-risk port, related connections, and snapshot context.
4. **Tier 1 (routine model).** Ollama returns strict JSON:
   `FALSE_POSITIVE`, `SUSPICIOUS`, or `CRITICAL`, with confidence, reasoning,
   factors, and a recommended action.
5. **Tier 2 (escalation model).** If the guarded routine verdict is
   `SUSPICIOUS`/`CRITICAL`, or the rule severity is in `escalation_severities`
   (default HIGH/CRITICAL), the larger model gets the evidence plus the routine
   opinion. It can confirm or override. Escalations are capped per run
   (`max_escalations_per_run`, default 2). If the budget is exhausted or the
   model is unavailable, the routine verdict is kept and the report states why.
6. **Guardrail.** A `FALSE_POSITIVE` is downgraded to `SUSPICIOUS` when the
   endpoint is public, outside the trusted baseline, and either the process
   signature is not valid or the port is on the known-risk list. Guardrails run
   before escalation and again on the escalated verdict.
7. **Cache.** Verdicts are reused for `verdict_cache_hours` (default 24).
   Failed, deferred, heuristic, or escalation-skipped verdicts are retried after
   30 minutes. The cache key includes the routine/escalation model names and the
   escalation severity list, but not thresholds or prompt version. Delete
   `data/soc_verdict_cache.json` after editing detection rules.

**Traffic findings** use the same two-tier path on the **scan lane**, with
`traffic_ai_max_checks` as an independent budget. The **fast gauge lane** is
deterministic: it never calls the model, but it may read a verdict the scan
already cached for the signature. Findings with no cached verdict are queued
for the next scan's triage (bounded queue) and logged with a
`deferred-<timestamp>` snapshot label. Deferred triage never toasts on its own.

---

## Traffic / attack-signature layer

The per-row rules cannot see a flood, so a separate sampler evaluates aggregate
signals.

- **Capture.** Live mode defaults to `netapi.py` (direct unelevated iphlpapi:
  `GetExtendedTcpTable`, `GetExtendedUdpTable`, `GetTcpStatisticsEx`,
  `GetUdpStatisticsEx`, `GetIpStatisticsEx`, `GetIcmpStatistics`/
  `GetIcmpStatisticsEx`, `GetIfTable2`). If an API call fails, the sampler logs
  one warning and uses `netstat` parsing, then retries the API after
  `api_retry_seconds` (default 60). Interface bytes come from the 64-bit v2
  driver counters aggregated over hardware interfaces only.
- **Cadence.** The gauge lane captures and evaluates every
  `gauge_interval_seconds` (1 s). History persistence uses
  `sample_interval_seconds` (3 s). Relative baselines use
  `baseline_window_seconds` (900 s), exclude the newest
  `baseline_guard_seconds` (60 s), and take a low `baseline_percentile` (p25);
  `min_baseline_samples` is 6. Samples that produced a real finding are marked
  `triggered` and excluded from later baselines. `window_seconds` remains as a
  legacy fallback for hand-built options and is no longer the live evaluation
  window.
- **Rate series.** `_rate_series` pairs each endpoint with the closest earlier
  sample at least `min_rate_seconds` (5 s) apart, so the 1 s gauge produces
  non-overlapping 5 s intervals. A counter reset, wrap, or source switch ends
  the walk instead of producing a rate across it.
- **Metrics.** Instantaneous gauges: `syn_received`, `syn_sent`, `established`,
  `time_wait`. Cumulative counters: `bytes_*`, `active_opens`, `passive_opens`,
  `udp_*`, `icmp_messages`, `ip_*`. Do not sum the gauges across history rows.
- **Rules.** `evaluate_traffic()` emits NET-T01..NET-T14: inbound SYN flood,
  outbound connection burst, single-remote connection flood, distributed flood
  on one local port, connection-count spike, TIME_WAIT pressure, bandwidth
  spike, discards, retransmits, UDP flood, ICMP flood, UDP no-ports scan, IP
  packet-rate spike, and per-process connection growth.
- **Fast lane.** New findings surface every gauge tick. Per finding key, a
  condition that reappears after `fast_finding_quiet_seconds` (120 s) counts as
  new; a shape change re-emits at most once per `fast_finding_min_emit_seconds`
  (60 s). First sightings are never throttled.
- **Bulk-transfer allowlist.** Process-scoped, never IP-scoped. It can downgrade
  only `bulk_transfer_exempt_rules` (NET-T02/T05/T06/T07/T14) to LOW/
  informational, only when SYN/passive-open/discard signals are quiet, and only
  when the allowlisted processes own at least `bulk_transfer_min_share` of
  active external connections. NET-T07 additionally requires inbound-dominated
  traffic. Nothing is deleted; replay disables the exemption.
- **NET-T14.** Per-process baseline keyed by image name, not PID. The typical
  level is a low percentile over all samples (idle counted as zero), falling
  back to the smallest observed active level when the process is idle most of
  the time; a sparse process therefore keeps its normal floor during a
  sustained attack. The verdict signature includes a coarse `scale-density`
  bucket (small/medium/large; fan-out vs dense); the alert signature is the
  coarser rule + process name so a growing burst counts as one repeat event.
- **Replay.** `--file` feeds snapshots through the evaluator with counters set
  to `None`; only netstat-derived signals are available. Replay disables the
  verdict cache, uses a non-persisting intel provider, ignores the live process
  table, and never toasts.

### Network-health layer (H8)

A daemon thread (`network_health.NetworkHealthMonitor`) probes the default
gateway and 1–8 configured external IP anchors every `interval_seconds`
(default 60). IPv4 uses `IcmpSendEcho`; blocked-ICMP and IPv6 paths use a TCP
connect fallback. Gateway discovery uses the IPv4 forward table
(`gateway: auto`) or a configured IPv4 literal. Results are written atomically
to `data/soc_network_health.json` and cached in memory for the scan report.

The verdict is a symptom classification: `RESPONSIVE`, `LOCAL_LINK`,
`UPSTREAM_ISP`, `DESTINATION_PATH`, or `UNKNOWN`. Per target it records RTT
min/avg/max, jitter, loss, probe method, and error. The report adds a
`Network health:` line, a hedged correlation line when traffic findings are
active, and an explicit caveat: probes cannot prove an upstream DDoS or see
pre-NIC/ISP drops. The dashboard status strip reads the shared file; it does
not run its own probe, and marks the result stale after
`max(file_max_age_seconds, 2*interval+15)`.

Configuration is the top-level `network_health` block. Targets must be IP
literals; thresholds are type/range-checked at startup and the worst-case
probe budget must fit inside the interval. `--no-network-probes` disables the
monitor and writes no new result.

### P0/P1/P2/P3 review fixes and remaining defects

The P0–P3 review items were fixed in these post-review passes:

- **E1 fixed:** `_Tcp6Row` uses the documented address-first
  `MIB_TCP6ROW_OWNER_PID` layout; tests pin every field offset and cross-check
  live IPv6 rows against `netstat -ano`.
- **E2 fixed:** `_rate_series` builds non-overlapping intervals at the live
  cadence, so the relative thresholds for NET-T01/T04/T07/T10/T13 participate.
- **E4 fixed:** baselines use a 900 s window, 60 s guard, and p25; triggered
  samples are excluded; NET-T14 keeps a sparse-process normal floor.
- **E3 fixed:** occurrence/cooldown state is separate from verdict entries, so
  `note_finding_seen` no longer refreshes a verdict's TTL. Traffic verdicts use
  `agent.traffic_verdict_cache_hours`; a routine-model FP cannot silence a
  HIGH/CRITICAL traffic finding.
- **E5 mitigated/fixed:** both prompts fence evidence in
  `<untrusted_evidence>`; `apply_traffic_guardrails` downgrades a routine FP on
  a HIGH/CRITICAL finding and preserves the routine opinion.
- **H1/M13 fixed:** traffic options carry `trusted_networks`; a trusted NET-T02
  is informational and never recommends blocking. Findings carry structured
  remediation (`block_remote`, `close_port`, `inspect_process`, `contact_isp`,
  `investigate`) with safety notes. Cached row intel recomputes trust from the
  current rules, and v4-mapped IPv6 peers match IPv4 CIDRs.
- **H5 fixed:** every report prints a Coverage line and a Scope line; CLEAR
  means no configured detector fired.
- **U1/U2/U4/U5 fixed:** the dashboard requires a per-launch `X-Auth-Token` on
  every `/api/*` request with loopback Host and same-origin checks; adopted PIDs
  are verified by creation time, absolute command line, interpreter image,
  owner SID, and session, watched, and re-checked before `taskkill`; the
  `SOC_UI_CHILD_COMMAND` override is gone; rules/replay paths, interval bounds,
  and strict booleans are validated.
- **U3 fixed (code + startup warning):** `soc_ui.py` and `checkstat.py` use
  absolute PowerShell/taskkill/netstat/tasklist paths. Both entry points call
  `install_security.install_warnings()`, which reports an install directory
  writable by `Authenticated Users`/`Everyone`/`Users`/`Guests` and warns when
  the process is elevated. Resetting the ACL remains an operator step.
- **E6/E7/E8/E9 fixed:** `VerdictCache` is lock-protected; the traffic AI has a
  per-scan circuit breaker; corrupt verdict/intel cache entries are dropped and
  the JSON writer tolerates non-serializable fields; `history_file` is confined
  to the project; enrichment has per-scan count/time budgets, and the intel
  cache is pruned and capped. Budget-skipped groups are reported with minimal
  intel and are not cached, so a later scan can backfill.
- **U6–U12 fixed (dashboard):** Ollama URLs are loopback-only by default
  (`--allow-remote-ollama` opt-in, redirects refused, response capped); request
  and console/tailer responses are bounded; path inputs resolve symlinks and
  junctions before containment; the state temp file is unique; security headers
  are set; API errors are generic; and start/stop cannot leave a stuck state.
- **E10–E14, L7 fixed (engine correctness; E14a documented):** replay is isolated from the live cache, intel store, process
  table, and toasts; name-based rule exceptions and bulk exemptions fail closed
  without path/signature evidence (`process_identity_mode: verify`); included
  private remotes are no longer
  auto-`FALSE_POSITIVE`; fallback counters honor the source switch and cache on
  the sample cadence with `api_retry_seconds`; the ICMP parser handles both
  `MIB_ICMP` and `MIB_ICMP_EX` and Windows' two-column text rows; exception keys
  are ANDed; console output is decoded with the OEM code page; report text is
  stripped of ANSI/C0/C1; UNC paths skip signature checks; the deferred queue
  keeps the newest items; and findings carry `schema_version`.

Remaining:

- **E14 residuals:** connected-UDP remotes are still unavailable in direct
  `iphlpapi` mode (Windows exposes only wildcard UDP rows there), so the traffic
  layer's remote-count metrics omit them; row rules (including NET-009) use the
  scan-lane text and are unaffected. Localized TCP state
  labels are canonicalized through iphlpapi in live mode, mapped by built-in
  aliases or `state_aliases` for text, and counted in `Coverage:` when
  unrecognized. The `netstat -e`/`-s` counter labels remain English-only in
  pure text capture mode when API counters are unavailable.
- **Dashboard residual:** the install-directory ACL is still inherited from
  `C:\` on a default install (the startup warning is advisory), and a same-user
  process that reproduces the exact command line can still spoof adoption. The
  U6–U12 code paths and the image/owner/session checks are fixed.
- **Residual baseline limit:** a flood that begins before the agent has a clean
  pre-event history, or one that never triggers a detector, cannot be separated
  from the host's established state. Absolute floors remain the last defense.
- **Prompt-injection residual:** fencing and the traffic guardrail reduce model
  influence but do not eliminate it; findings remain advisory.
- **Lint:** `uv run ruff check .` passes with zero findings under the pinned
  rule selection. The follow-up pass (89 findings: 37 safe autofixes, 23
  reviewed unsafe fixes, 29 manual) is recorded in docs/internal/CODE_REVIEW.md Appendix D
  (§11). Keep the explicit `select` list in `pyproject.toml` in sync with any
  future `noqa` use; an inert directive is itself a `RUF100` finding.

---

## Configuration setup

The live `config/netstat_baseline_rules.yaml` is host-specific and gitignored.
A clean clone must copy the example to that name and tune it before running:

```powershell
Copy-Item config\netstat_baseline_rules.example.yaml config\netstat_baseline_rules.yaml
```

The example intentionally ships with no observed PIDs, no host application
ports, and an empty `trusted_remote_networks` list. Add those values for your
environment; do not commit the live file. The example is validated by
`tests/test_baseline_example.py`.

## Rule engine behavior notes

- The row engine evaluates one rule against one row. It does not implement
  `count`, `count_per_pid`, `not_in_history`, `same_as_previous`, or
  `changes_rapidly`, so NET-005/006/008/010/011/012/014 cannot match. They are
  disabled design notes. Enabled rules: NET-001, NET-002, NET-007, NET-009.
- `alert_thresholds` and `maintenance.auto_learn` are not read; every enabled
  rule hit is immediate. Time windows exist only in the traffic layer.
- Exception dictionaries are ANDed across keys. An exception with both `pid`
  and `remote_ip_range` must match both. An empty exception dict matches
  everything and is rejected.
- Process-name exceptions and the bulk allowlist require executable
  path/signature evidence (`process_identity_mode: verify`); inconclusive
  evidence denies the exemption. `name` restores the legacy spoofable behavior
  for compatibility only. `--no-process-details` and
  `bulk_transfer_verify_identity: false` also deny exemptions.

### User allow-list (dashboard "Mark false positive")

- The dashboard owns `data/soc_user_allowlist.json`; the agent only reads it, so new
  mutes apply without an agent restart. YAML edits still require one.
- Entries are compound scopes, never rule-wide: a rule id plus an
  identity-verified process name and a rate band (NET-T10) or endpoint
  (NET-001/002/007/009; NET-002/NET-009 pin the remote IP). TTL is 7/30/90 days
  (default 30). CRITICAL findings can never be muted.
- NET-T10 owner attribution aggregates every sampled PID by process name. The
  50% share and the ambiguity check use the aggregate; `pids_at_mute` stores all
  PIDs of the winning process. `describe_record()` returns the observed
  evidence (numerator, denominator, owner share, top owners, PIDs) even when a
  finding is ineligible, and the preview always includes it.
  `describe_scope()` produces the `scope_summary` that states the complete
  match scope, and muted cards show the covering entry's scope, reason, and
  expiry.
- `DELETE /api/allowlist/<id>` soft-disables (Deactivate). Add `?hard=1` to
  remove the entry permanently. `DELETE /api/allowlist` clears all entries,
  writes a valid empty document, and is the repair path for a corrupt,
  oversized, missing, or unsupported file.
- `GET /api/findings` passes the configured
  `udp_datagrams_absolute_floor` to the display matcher, so display matching
  and the preview use the same rate ceiling.
- Matching annotates the finding with a `disposition` object; the record is
  always logged with its deterministic severity unchanged. The dashboard hides
  it from ALL/severity views and shows it under MUTED.
- Enforcement fails closed: severity increase, rate above the mute band or the
  absolute flood floor, UDP receive errors or an unavailable counter, another
  process owning the sockets, unverified/inconclusive identity, a co-firing
  NET-T01/T02/T03/T04/T08/T09/T11/T12/T13/T14, or baseline drift reopens the
  finding with `disposition.guard_blocked`.
- An unreadable, corrupt, oversized, or unsupported-version file disables all
  mutes; malformed entries are ignored individually. The file's `guards` field
  is audit data and is never trusted. The dashboard preview is derived
  server-side from the selected finding; the browser never supplies a scope.
- `GET /api/findings` annotates records that predate a mute with a display-only
  `display_muted`/`display_allowlist_id`. It applies scope, severity, rate,
  error, share and baseline guards, but not live identity or co-fire context
  (unavailable for history). Records with an agent `disposition` are never
  overridden, so a reopened finding stays visible.
- The static baseline remains hand-maintained; there is no UI baseline
  generator. The learned traffic baseline is still computed from history.
- The parser decodes tool output with the OEM code page. TCP state labels are
  canonicalized from iphlpapi in live mode and from built-in/configurable
  aliases in text mode; unrecognized labels are reported. `tasklist` CSV
  name/PID columns are position-based, so headers do not matter.
- IPv6 scope IDs such as `fe80::1%17` are normalized in the **text** parser.
  The API traffic path now decodes IPv6 correctly (E1 fixed); v4-mapped peers
  also match IPv4 trusted-network CIDRs.

### Dead or inert configuration

- The unread `metadata`, `baseline.local_ips`, `alert_thresholds`, and
  `maintenance` blocks were removed from the shipped YAML. Unknown threshold
  keys are rejected at startup; other configuration values are type-checked
  and range-clamped.
- `baseline.expected_listening_ports` and `traffic_detection.ignore_local_ports`
  are separate, duplicated lists; keep them in sync if you edit them.
- `history_file` must resolve inside the data directory (`data/`, or
  `SOCA_DATA_DIR`); an absolute or `..` path outside it is rejected at startup.

---

## Configuration

The YAML is the source of truth. The full schema is in
`config/netstat_baseline_rules.yaml`; the keys that are actually read are summarized
here.

| Key | Read by | Notes |
| --- | --- | --- |
| `agent.model`, `escalation_model` | LLM triage | Cache key includes both |
| `agent.ollama_url` | LLM triage, dashboard status | http/https, no userinfo/query/fragment; loopback-only unless `--allow-remote-ollama` |
| `agent.ai_enabled` | Scan lane | Master AI switch |
| `agent.ai_timeout_seconds`, `escalation_timeout_seconds` | LLM triage | Per-call timeouts |
| `agent.max_ai_checks_per_run`, `max_escalations_per_run` | Scan lane | Per-scan budgets |
| `agent.keep_alive`, `escalation_keep_alive` | Ollama requests | Model residency |
| `agent.num_ctx`, `escalation_num_ctx`, `*_think` | LLM triage | Context/reasoning |
| `agent.scan_interval_seconds` | Scan loop | Clamped to >= 15 |
| `agent.verdict_cache_hours` | Verdict cache | Row TTL; traffic TTL is separate |
| `agent.traffic_verdict_cache_hours` | Verdict cache | Shorter traffic TTL (1 h default), clamped to the row TTL |
| `agent.max_enrichment_checks_per_run`, `enrichment_budget_seconds` | Enrichment | Per-scan count/time caps (20 / 20 s); skipped groups are not cached |
| `agent.alert_cooldown_minutes` | Toast gates | Per-signature cooldown; state survives verdict expiry |
| `agent.traffic_alert_min_occurrences`, `traffic_alert_window_minutes` | Traffic toasts | Occurrence gate |
| `agent.traffic_ai_max_checks` | Traffic triage | Per-scan traffic-model call budget |
| `agent.traffic_ai_enabled` | Traffic triage | Master switch for traffic-layer AI; `false` leaves traffic findings deterministic |
| `agent.ignore_private_remote_ips` | Row layer | CLI `--include-private-remotes` overrides |
| `agent.process_identity_mode` | Rule exceptions, bulk exemptions | `verify` default; `name` is legacy; `strict` = fail closed |
| `traffic_detection.enabled`, `capture_mode` | Sampler | `api` default, `netstat` fallback |
| `traffic_detection.api_retry_seconds` | Sampler | Retry direct API after fallback (default 60, min 10) |
| `traffic_detection.gauge_interval_seconds`, `sample_interval_seconds` | Sampler | 1 s / 3 s shipped |
| `traffic_detection.baseline_window_seconds`, `baseline_guard_seconds`, `baseline_percentile` | Evaluator | 900 / 60 / 25; triggered samples excluded |
| `traffic_detection.min_baseline_samples`, `min_rate_seconds` | Evaluator | 6 / 5 |
| `traffic_detection.window_seconds` | Legacy | Fallback for hand-built options; not the live baseline window |
| `traffic_detection.history_file`, `max_history_samples` | Persistence | Must resolve inside the project; 1,800 default; auto-raised for the window; capped at 20,000 |
| `traffic_detection.include_private_remotes` | Traffic layer | Independent YAML switch; `--include-private-remotes` (and the dashboard checkbox) overrides both layers to included |
| `traffic_detection.bulk_transfer_processes`, `bulk_transfer_exempt_rules`, `bulk_transfer_min_share`, `bulk_transfer_min_rx_tx_ratio` | Traffic exemption | Allowlist entries are matched by name but require identity evidence |
| `traffic_detection.bulk_transfer_verify_identity` | Traffic exemption | Must stay true for exemptions to apply; false denies |
| `traffic_detection.thresholds.*` | Evaluator | Type-checked and range-validated at startup; unknown keys are rejected |
| `network_health.enabled`, `interval_seconds`, `timeout_ms`, `probes_per_target` | Probe monitor | Default on; 60 s, 1000 ms, 4 attempts; budget must fit the interval |
| `network_health.degraded_loss_pct`, `degraded_jitter_ms`, `degraded_rtt_ms` | Verdict | 20%, 80 ms, 500 ms; tune for satellite/mobile links |
| `network_health.gateway`, `gateway_tcp_port`, `targets`, `file_max_age_seconds` | Probe monitor | Gateway auto/IPv4; targets are IP literals; 1–8 targets; stale threshold |
| `state_aliases` (top level) | Text parser | `localized label: CANONICAL_STATE`; used for replay and `capture_mode: netstat`; invalid values fail at startup |
| `trusted_remote_networks` | Row and traffic layers | A trusted NET-T02 is informational and never block-recommended; v4-mapped IPv6 peers match IPv4 CIDRs |
| `baseline.*`, rule exceptions | Row engine | See the rule-engine notes |

CLI flags override the corresponding `agent` values. Changing model names or the
escalation severity list changes the cache namespace; changing thresholds does
not, so delete the verdict cache after threshold edits.

---

## Model sizing

Measured on the target machine with this agent's prompt shape (about 2k tokens
in, 300 tokens out). Treat these as machine-specific.

| Model | Quant | Loaded size | Placement | Generation | One verdict |
| --- | --- | --- | --- | --- | --- |
| `qwen3.8:27b` | Q4_K_M | ~18 GB | ~60% CPU / 40% GPU | ~6.4 tok/s | ~55 s |
| `llama3.1:8b` | Q4_K_M | ~5 GB | 100% GPU | ~110 tok/s | ~10 s |
| 12B class | Q4_K_M | ~7.5 GB | 100% GPU expected | ~45-60 tok/s | ~8-12 s |
| 14B class | Q4_K_M | ~9 GB | mostly/full GPU at 4k context | ~30-45 tok/s | ~10-15 s |

- **Default:** two-tier (`llama3.1:8b` routine, `qwen3.8:27b` escalation), 300 s
  interval, 8 routine / 2 escalation checks.
- **Single-model quality:** 27B with `--no-escalation`, 600-900 s interval, 2-4
  routine checks.
- **Single-model balance:** 12B-14B Q4_K_M.
- **Avoid:** 30B+ dense models on a 10 GB GPU; they spill to CPU.
- **Model swapping:** the 8B and 27B do not both fit in 10 GB VRAM; escalation
  can evict the routine model and add reload time. `keep_alive` reduces but does
  not eliminate this.

`keep_alive` controls residency. `--keep-alive` affects the routine model only;
the escalation model uses `agent.escalation_keep_alive` from the YAML (no CLI
flag). Ctrl+C reaches the graceful unload (`keep_alive: 0` for both models); a
hard kill or an aborted dashboard Stop may skip it.

---

## Output and alerting

Every run writes a report to `data/local_soc_agent.log` and prints it. Example shape:

```text
[1/2] [HIGH] NET-001/NET-002 Connection to Suspicious Port (x1)
  Endpoint : <remote>:<port> | scope=global | trusted=False
  Process  : PID <pid> <name> | signature=Valid | path=<path>
  WHOIS    : <registrant> | <range> | <country> | abuse: <contact>
  rDNS     : <name>
  Rule     : NET-001: all conditions matched; NET-002: all conditions matched
  Verdict  : SUSPICIOUS (90% via ai-escalated)
  Routine : FALSE_POSITIVE (80% via ai-routine) | guardrail -> SUSPICIOUS
  Reasoning: ...
  Action   : Review the process and its configuration.
```

- `data/soc_findings.jsonl` contains the same information plus structured evidence.
- **Traffic findings** print severity, rule, detail, `Recommended`, and a
  `Remediation:` line when a structured action is available. The console report
  does **not** print the traffic verdict/confidence/classification or the
  escalation-skip reason; those are in the JSONL record and dashboard (M6).
- **CLEAR** (`Result: CLEAR - no configured detector fired in this run`) always
  follows with a `Coverage:` line (row rules, traffic layer and baseline, AI,
  private-remotes modes) and a `Scope:` line (host-side only; no upstream/
  volumetric flood or ISP visibility). It is not proof the host is clean.
- **Remediation** is structured: `block_remote`, `close_port`,
  `inspect_process`, `contact_isp`, or `investigate`, with a safety note. Treat
  it as a candidate action and apply the README safety checks (CDN/trusted,
  NAT/CGNAT, IPv6, PID reuse, name spoofing). Cached row intel recomputes trust
  from the current rules before it can recommend a block.
- **Traffic verdicts** use `traffic_verdict_cache_hours` (default 1 h); a
  routine-model FP cannot silence a HIGH/CRITICAL finding.

**Toasts:** row findings notify for `SUSPICIOUS`, `CRITICAL`, and `UNVERIFIED`
HIGH/CRITICAL with a 60-minute cooldown. Traffic findings require
`traffic_alert_min_occurrences` repeats within `traffic_alert_window_minutes`.
A cached or fresh `FALSE_POSITIVE >= 80` silences the toast, not the record; for
HIGH/CRITICAL traffic findings only an escalated verdict may silence it.
Deferred triage never toasts.

---

## State and concurrency

- **Verdict cache.** `VerdictCache.entries` holds per-signature verdicts and
  intel with a TTL; `VerdictCache.alert_state` holds `seen_at` and
  `last_alerted` separately. `get()` enforces the verdict TTL; a verdict may
  expire while the alert state, and therefore the cooldown, survives. Row
  verdicts use `verdict_cache_hours`; traffic verdicts use
  `traffic_verdict_cache_hours`. `note_finding_seen()` updates only the alert
  state; `should_notify()`/`mark_alerted()` implement the cooldown. All public
  cache methods take an `RLock`, so the sampler and scan threads cannot race a
  save or lose a sighting (E6).
- **Migration.** Older cache files that stored `seen_at`/`last_alerted` inside a
  verdict entry are migrated into `alert_state` on load.
- **Enrichment budget.** The scan enforces `max_enrichment_checks_per_run` and
  `enrichment_budget_seconds` on time spent inside `provider.enrich()` only; a
  slow AI call does not consume the lookup budget. Groups over budget are
  reported with minimal deterministic intel and are not cached, so a later scan
  can backfill the lookup. `IntelProvider.save()` prunes expired entries and
  caps the cache at `MAX_INTEL_CACHE_ENTRIES` (2,000).
- **Intel cache.** `data/soc_intel_cache.json` stores RDAP/WHOIS/rDNS results with
  per-entry TTLs. Expired entries are pruned on save, and the cache is capped
  at 2,000 entries.
- **Deferred queue.** `DeferredTrafficQueue` is bounded at `MAX_PENDING` (20)
  and restores unprocessed items after a budget/model outage. `restore()` keeps
  the newest items when the queue overflows.
- **Traffic baseline.** `TrafficMetrics.triggered` marks samples that produced
  a non-informational finding; `_baseline_history` excludes them. The flag is
  persisted in the history file so a restart does not re-admit event samples.
  `max_history_samples` is auto-raised to fit the baseline window and capped at
  `MAX_HISTORY_SAMPLES` (20,000).
- **History.** `data/soc_traffic_history.jsonl` is appended on the sample cadence and
  trimmed at startup to `max_history_samples` (default 1,800) only when it
  exceeds twice that many lines; it is capped/rotated at 64 MB.
- **Logs.** `append_text()` rotates at 10 MB and deletes the existing `.1`
  backup, so only the current file and one previous generation survive.
- **Replay** uses a disabled verdict cache, a non-persisting intel provider, no
  live process identity, and no toasts. Only netstat-derived signals are
  evaluated.

---

## Web dashboard implementation

`soca/ui/soc_ui.py` (launched through the root `soc_ui.py` shim) is a Flask app
that spawns `checkstat.py`, streams its stdout/stderr, tails
`data/soc_findings.jsonl` and `data/soc_traffic_history.jsonl`, and renders the
status strip. It writes `data/soc_ui_agent_state.json` for PID adoption. It binds
`127.0.0.1` only and runs the Werkzeug development server with `debug=False`,
`use_reloader=False`.

Developer/security notes:

- Every `/api/*` route requires `X-Auth-Token` (per-launch, delivered via a
  `#token=...` fragment) plus a loopback Host and, when present, a same-origin
  Origin. `/` and `/static/*` remain unauthenticated.
- `validate_payload()` restricts `rules_path` to YAML files with an
  `anomaly_rules` mapping containing at least one enabled rule, restricts
  `replay_path` to `.log`/`.txt`, caps `interval` at 86400, requires strict
  JSON booleans for `force`, and validates `ollama_url` (loopback-only unless
  `--allow-remote-ollama`).
- `build_argv(flags, mode, child_command=None)` has no environment override;
  `child_command` is an explicit test/embedding hook and production passes None.
- Adoption rejects invalid PIDs, missing creation times, creation mismatches,
  and command lines that lack the absolute `CHECKSTAT_PATH`; adopted PIDs are
  watched, and Stop re-verifies identity before `taskkill`.
- Both `soc_ui.py` and `checkstat.py` use absolute System32 paths for
  PowerShell, taskkill, netstat, and tasklist.
- `resolve_agent_path()` uses `Path.resolve(strict=True)` plus containment, so
  `..` and symlink/junction escapes are rejected (U8).
- `ollama_url` is loopback-only unless `--allow-remote-ollama`; the status
  probe refuses redirects and caps the `/api/tags` response.
- `MAX_CONTENT_LENGTH` (64 KiB), console/tailer byte budgets, and a serialized
  start probe bound resource use (U7).
- Responses set CSP, `X-Frame-Options`, `X-Content-Type-Options`, and
  `Referrer-Policy` (U10); API failures are generic (U11); start/stop cannot
  leave a stuck state (U12).
- `app.js` renders untrusted strings with `textContent`; there is no XSS.

See `docs/internal/CODE_REVIEW.md` §4.2 for the full list and fixes.

---

## Limitations and notes

- **Upstream blindness.** Host-side counters cannot see packets dropped before
  the NIC, upstream volumetric floods, or ISP congestion. The DDoS-vs-ISP
  question is not solved by this tool; router/ISP telemetry or active path
  probes are required. A CLEAR result is not evidence of no attack.
- **Compromise scope.** SOCA sees connection metadata, process identity, and
  aggregate counters. It does not inspect files, memory, payloads, DNS
  contents, persistence, or logs. "Suspicious connection" is not "confirmed
  compromise."
- **Baseline needs clean pre-event history.** A flood that begins before the
  agent has observed normal traffic, or one that never triggers a detector,
  cannot be separated from the host's established state. Absolute floors remain
  the last defense.
- **Prompt injection is mitigated, not eliminated.** Both prompts fence
  evidence as `<untrusted_evidence>` and the traffic guardrail prevents a
  routine FP from silencing a HIGH/CRITICAL finding, but the local model remains
  advisory and can still be influenced.
- **Coverage is reported, not a guarantee.** CLEAR now includes `Coverage:` and
  `Scope:` lines, but `--no-traffic`, AI off, a learning baseline, disabled
  rules, skipped private remotes, or an upstream flood still limit what it sees.
- **Private remotes.** `ignore_private_remote_ips: true` and
  `traffic_detection.include_private_remotes: false` reduce noise but hide LAN
  lateral movement. The CLI flag and the YAML key are separate. When private
  remotes are included, HIGH/CRITICAL private findings are `SUSPICIOUS` and can
  alert; the old heuristic FP 80 path no longer applies (E12 fixed).
- **Name-based trust.** Process-name exceptions and the bulk allowlist now
  require path/signature evidence, but the evidence itself is not
  cryptographically trusted; a decoy binary with a valid signature, or one
  placed in a protected install path, can still qualify. Require path/signature
  before uninstalling anything.
- **Replay.** `--file` no longer uses the live cache, intel store, process
  table, or toasts, but it evaluates only netstat-derived signals and process
  identity is historical.
- **Localization.** Live TCP states are language-independent through
  iphlpapi; text capture uses built-in aliases plus `state_aliases` and reports
  unknown labels. `netstat -e`/`-s` counter labels remain English-only in pure
  text capture mode.
- **Connected UDP (traffic metrics only).** Direct API capture cannot see
  connected UDP peers, so the traffic layer's remote-count metrics and history
  omit them. Row rules, including NET-009, always evaluate the scan-lane
  `netstat -ano` text and are unaffected (E14a).
- **Upstream visibility (H8).** Active probes classify local-link vs upstream/ISP
  vs destination-path symptoms, but cannot prove an upstream DDoS or see
  pre-NIC/ISP drops; router/ISP telemetry remains out of scope. The dashboard
  shows a stale/no-sample state when the agent is stopped.
- **Dashboard security.** Loopback-only but unauthenticated; any local user can
  read telemetry and start/stop the agent. The install directory is writable by
  `Authenticated Users` (inherited from `C:\`) and the UI executes files from it.
  Do not run elevated; see the README hardening steps.
- **No per-process bandwidth.** It requires elevation and was deliberately
  declined. Bandwidth is host-wide (`NET-T07`); NET-T14 measures connection count
  and remote spread only.

---

## Testing

```powershell
# Offline suite
uv run python -m unittest discover -s tests -t . -v

# Live netapi checks; may be flaky
uv run python -m unittest tests.test_netapi -v

# Static analysis (ruff is a pinned dev dependency; config in pyproject.toml)
uv run ruff check .
uv run ruff check . --statistics
```

`uv run ruff check .` currently passes with zero findings. If the selection
changes, fix safe findings with `--fix` and review any unsafe fix individually;
see docs/internal/CODE_REVIEW.md Appendix D (§11) for the resolved baseline.

Coverage and gaps:

- `tests/test_parser.py`: parsing (TCP/UDP/IPv6), rule matching, private/trusted
  exclusions, grouping, guardrails, two-tier escalation with fake analysts,
  1 s-cadence rate series, sustained-attack and sparse-process baselines,
  triggered-sample exclusion, counter-reset handling, history cap, traffic
  verdict/toast gates, prompt fencing, trusted-remote remediation, structured
  remediation for host-wide rules, cached-intel trust recomputation,
  v4-mapped IPv6 matching, coverage/replay reporting, `VerdictCache` locking
  and concurrency, the traffic-AI circuit breaker, corrupt-cache validation,
  enrichment budgets, intel-cache pruning, absolute system-tool paths,
  fail-closed process identity, full per-process maps beyond the top 15,
  included-private guardrails, two-column ICMP text rows, control-character
  stripping, ANDed exception keys, deferred-queue newest retention, and
  `schema_version`.
- `tests/test_ui_runner.py`: argv round-trip, validation, path containment, tailer
  edge cases, console cursors, Flask test-client auth/Host/Origin checks,
  adoption verification/watcher/refusal, install-ACL/elevation warnings,
  process-principal binding, input hardening, status defaults, and `/api/*`
  start/stop lifecycle/concurrency (one spawned child per race, state
  cleanup, clean/crashed exits, adopted-process stop). The replay test creates
  its own placeholder file, so the suite is hermetic on a clean tree.
- `tests/test_network_health.py`: offline with mocked ICMP/TCP/gateway discovery;
  verdict matrix, aggregation, deadline, atomic result file, and monitor
  lifecycle.
- `tests/test_netapi.py`: helper tests plus live `iphlpapi`/`netstat` checks, the
  deterministic 56-byte IPv6 layout test, a live `netstat` IPv6 cross-check, and
  fast-lane guardrail/toast tests. It is live and can be flaky.
- `VerdictCache` now has direct tests for verdict TTL, traffic TTL, alert-state
  survival across put/expiry, persistence, and migration.
- The E1 layout test now fails deterministically under the old state-first
  struct, so the decoder regression cannot recur silently.

Post-follow-up baseline (before the package-layout refactor):
`tests/test_parser.py` 227 tests, `tests/test_netapi.py` 41 tests, and
`tests/test_ui_runner.py` 137 tests with 1 skipped (file symlinks unavailable
without developer mode), plus 35 offline `tests/test_network_health.py` tests.
A live scan with `--once --no-ai --no-toast` returned CLEAR with exit 0, and
the live ICMP parser matched `netapi`.

Run the suites with `uv run python -m unittest discover -s tests -t . -v`.

---

## Related documents

- `README.md` — user-facing usage, remediation safety, privacy/retention.
- `docs/internal/CODE_REVIEW.md` — severity-ranked findings (E/U/H/M/L), verified non-findings,
  remediation roadmap, and reproduction commands.
