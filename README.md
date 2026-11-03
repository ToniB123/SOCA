# SOCA — Security Operations Center Agent (Alpha)

**SOCA** is a local, unelevated security-operations agent for Windows. It watches
network connections, applies deterministic baseline rules, samples host-wide
traffic counters, and optionally asks a local Ollama model to triage candidate
anomalies. It runs entirely on one workstation and has no cloud dependency.

> **Alpha status.** This is a personal, single-user alpha. Flags, file formats,
> thresholds, and detection behavior may change. It is not an EDR/AV replacement,
> does not inspect files, memory, or packet payloads, and is not safe to expose
> beyond a single-user machine. Read the known limitations below and
> `CODE_REVIEW.md` before relying on it.

---

## What SOCA answers — and does not

| Question | What SOCA can say | What it cannot say |
|---|---|---|
| Is this connection compromised? | Flags unusual remotes, ports, process behavior, and attack shapes; shows the evidence it used | Cannot prove or disprove compromise; it does not see files, memory, payloads, persistence, or logs |
| Am I under a DoS/DDoS attack? | Detects host-visible flood shapes: SYN bursts, connection floods, UDP/ICMP floods, packet-rate spikes, bandwidth/discard/retransmit spikes, per-process fan-out; adds active gateway/external probes that classify local-link vs upstream/ISP vs destination symptoms | Cannot see an upstream or volumetric flood that is dropped before the NIC, or prove that a DDoS (rather than ISP congestion) is the cause |
| Is my internet just slow? | Shows host-side congestion signals (bytes/s, discards, retransmits) and actively measures gateway/external RTT, jitter, and loss, classifying local link vs upstream/ISP vs a destination path | Cannot prove the cause, see pre-NIC/ISP drops, or measure router/ISP-side telemetry |
| What should I do? | Recommends candidate actions: investigate a PID, block a remote, close a port, uninstall an app, contact the ISP | Does not auto-apply any action, and its advice needs the safety checks in "Remediation safety" |

**A clean run means "no configured detector fired in this run," not "the host
is clean."** See "Reading the results."

---

## Threat model and scope

**Designed for:** a single-user Windows workstation, run unelevated, with a local
Ollama instance. The intended adversary is unsophisticated to moderate: a
suspicious outbound connection, a malware beacon, a port scan, a connection
flood, or a UDP/ICMP flood that reaches the host.

**In scope**

- Host-visible connection metadata, process identity/path/signature, aggregate
  interface and protocol counters, per-process connection counts, and active
  gateway/external RTT/loss/jitter probes.
- Deterministic rule hits and traffic-shape findings, with advisory AI triage.
- Actionable but human-confirmed remediation suggestions.

**Out of scope / blind spots**

- Traffic dropped before the NIC, proof of an upstream DDoS, and router/ISP
  telemetry. Active probes classify symptoms; they cannot close these gaps.
- Packet payloads, DNS contents, file/memory/registry inspection, persistence.
- Per-process byte counters (they require elevation; the project deliberately
  stays unelevated).
- Confirmed compromise attribution. SOCA reports suspicious connections; it does
  not prove a host is compromised.
- Non-English Windows: live TCP states are canonicalized through iphlpapi and
  text labels use built-in/configurable aliases, but `netstat -e`/`-s` counter
  labels remain English-only in pure text capture mode.

**Trust boundary.** The dashboard is a local control channel. It binds to
`127.0.0.1` only and requires a per-launch token on every `/api/*` call, with
loopback Host and same-origin checks. Loopback is still machine-wide, and the
install directory ACL is part of the trust boundary. See "Web dashboard →
Security posture and hardening."

---

## Alpha status and known limitations

This build includes the P0–P3 review fixes from `CODE_REVIEW.md`:

- **IPv6 decoder (E1) fixed.** `_Tcp6Row` now uses the documented address-first
  `MIB_TCP6ROW_OWNER_PID` layout. Tests pin every field offset and cross-check
  live IPv6 rows against `netstat -ano`.
- **Live rate baselines (E2) fixed.** `_rate_series` now builds non-overlapping
  intervals at the 1 s gauge cadence, so the relative thresholds for
  NET-T01/T04/T07/T10/T13 participate in live detection instead of silently
  relying on absolute floors.
- **Baseline contamination (E4) fixed.** Baselines use a 900 s window, a 60 s
  guard, and a low (p25) percentile. Samples that produced a real finding are
  excluded, so a sustained event cannot become the normal it is measured
  against. NET-T14 also keeps a normal floor for intermittently active
  processes.
- **Sticky cached verdicts (E3) fixed.** Occurrence and cooldown state is now
  separate from verdict entries, so a recurring finding keeps its counter and
  cooldown even when the verdict TTL expires or a new verdict replaces it.
  Traffic verdicts use a shorter `traffic_verdict_cache_hours` TTL (default 1 h),
  and a routine-model `FALSE_POSITIVE` can no longer silence a HIGH/CRITICAL
  traffic finding; only an escalated verdict can.
- **Prompt injection and traffic guardrails (E5) fixed/mitigated.** Enrichment
  is fenced as `<untrusted_evidence>` in both prompts, and a deterministic
  traffic guardrail downgrades routine-model false positives on HIGH/CRITICAL
  findings.
- **Trusted-network and remediation safety (H1/M13) fixed.** The traffic layer
  now consults `trusted_remote_networks` and never recommends blocking a trusted
  address. Findings carry a structured remediation (`block_remote`,
  `close_port`, `inspect_process`, `contact_isp`, `investigate`) with a safety
  note.
- **Coverage-aware results (H5) fixed.** Every report now prints a `Coverage:`
  line (row rules, traffic layer and baseline, AI, private-remotes modes) and a
  `Scope:` line; `CLEAR` says no configured detector fired, not that the host is
  clean.
- **Dashboard hardening (U1/U2/U4/U5) fixed.** The dashboard requires a
  per-launch `X-Auth-Token` on every `/api/*` call, validates loopback Host and
  same-origin requests, verifies adopted PIDs by creation time and absolute
  agent path and watches them, removes the `SOC_UI_CHILD_COMMAND` environment
  override, and restricts rules/replay paths, interval bounds, and strict
  booleans. The UI uses absolute PowerShell/taskkill paths.
- **Engine reliability (E6/E7/E8/E9) fixed.** `VerdictCache` is lock-protected;
  the traffic AI has a per-scan circuit breaker; corrupt verdict/intel cache
  entries are dropped instead of aborting scans; `history_file` is confined to
  the project; enrichment has per-scan count/time budgets and the intel cache is
  pruned and capped.
- **Absolute system binaries (U3) fixed.** `checkstat.py` and `soc_ui.py` invoke
  `netstat.exe`, `tasklist.exe`, `powershell.exe`, and `taskkill.exe` by
  absolute System32 paths.
- **Dashboard hardening (U6–U12) fixed.** Ollama URLs are loopback-only by
  default (explicit `--allow-remote-ollama` opt-in, redirects refused, response
  capped), requests/console/tailer responses are bounded, paths resolve
  symlinks/junctions before containment, security headers (CSP/frame/nosniff/
  referrer) are set, API errors are generic, and start/stop races no longer
  leave a stuck state.
- **Engine correctness (E10–E14) fixed, except the documented Windows UDP
  capture limitation.** Live TCP states are canonicalized through the
  Windows API, and localized text labels are mapped or reported. Replay uses a disabled verdict cache
  and a non-persisting intel provider, ignores live process identity, and never
  toasts; name-based exceptions and bulk exemptions fail closed without
  path/signature evidence; included private remotes are no longer
  auto-`FALSE_POSITIVE`; fallback counters honor the source switch and cache on
  the sample cadence; the ICMP parser handles Windows' two-column tables;
  exception keys are ANDed; report text is stripped of ANSI/C0/C1; deferred
  restore keeps the newest items.
- **Findings schema (L7) fixed.** Every `soc_findings.jsonl` record carries
  `schema_version`; one-generation log rotation is documented.
- **Configuration and reporting follow-up (M11/M12/H2/M6) fixed.** Thresholds
  and agent settings are type-checked and range-clamped at startup, dead YAML
  blocks were removed, `traffic_ai_enabled` now gates traffic triage, and the
  console report prints the traffic verdict, confidence, classification,
  guardrail, and escalation notes.
- **Lifecycle/concurrency coverage (H9) added.** `/api/start` and `/api/stop`
  races, restart, state-file cleanup, clean/crashed exits, and adopted-process
  stop are tested through the Flask client; a concurrent start that loses the
  runner lock now returns `409`, not a start failure.
- **Install/adoption hardening (U2/U3) added.** Both entry points warn when
  the install directory is writable by broad principals or when running
  elevated. Adoption and Stop now require the recorded PID to be the same
  interpreter image, user SID, and session (in addition to creation time and
  the absolute agent command line).
- **Network-health probes (H8) added.** A background monitor probes the
  default gateway and two external anchors every 60 s and classifies local-link
  vs upstream/ISP vs destination-path symptoms in the report and dashboard.
  It cannot prove an upstream DDoS or see pre-NIC drops; the caveat is printed
  and documented. Disable with `--no-network-probes` or `enabled: false`.
- **Private-remotes flag (H3) fixed.** `--include-private-remotes` (and the
  dashboard checkbox) now enables private remotes in both the row and traffic
  layers. The two YAML switches remain independently tunable when the flag is
  absent.

Remaining known issues (details and evidence in `CODE_REVIEW.md`):

- **Dashboard residual (U2/U3, High).** The install directory still inherits
  `Authenticated Users: Modify` from `C:\` on a default install, and the UI
  executes files from it. SOCA now warns on startup and binds adoption to the
  interpreter image, owner SID, and session, but a same-user process that
  reproduces the exact command line and creation time can still spoof the
  probe. Do not run the dashboard elevated or on a shared machine; install
  outside `C:\` and restrict the ACL. See the hardening steps below.
- **Prompt-injection residual risk (E5, mitigated).** Prompt fencing and the
  traffic guardrail reduce the risk, but a local model can still be influenced;
  findings remain advisory.
- **`CLEAR` is still not proof of cleanliness.** The report now states coverage,
  but a clean run with `--no-traffic`, AI off, a learning baseline, disabled
  rules, skipped private remotes, or an invisible upstream flood is still
  limited.
- **Localized labels.** Tool output is decoded with the OEM code page. Live
  TCP states are canonicalized through iphlpapi, so they are
  language-independent. The text parser maps common localized state labels
  and accepts a top-level `state_aliases` map for other languages; labels it
  still does not recognize are counted in the report's `Coverage:` line and
  logged once instead of degrading silently. The `netstat -e`/`-s` counter
  labels remain English-only when the agent is forced onto the pure text
  capture mode (`capture_mode: netstat`) and the direct API counters are
  unavailable.
- **Network-health limits.** Active probes classify local-link/upstream/destination
  symptoms, but cannot prove an upstream DDoS or see pre-NIC/ISP drops. The
  dashboard reads the agent's shared sample; when the agent is stopped, the
  network chip becomes stale or unavailable.
- **Connected UDP peers (traffic metrics only).** Direct API capture exposes
  only wildcard UDP rows, so the traffic layer's `unique_remotes` /
  `external_remotes` counts and dashboard history omit connected UDP peers.
  Row rules, including NET-009, evaluate the scan-lane `netstat -ano` text and
  are unaffected by `capture_mode`.
- **Baseline needs a clean pre-event history.** A flood that begins before the
  agent has observed normal traffic, or one that never triggers a detector,
  cannot be separated from the host's established state. Absolute floors remain
  the last line of defense.
- **Remaining residual P3.** The install-directory ACL reset is an operator
  step; active probes partially mitigate upstream blindness but cannot prove
  an upstream DDoS or see pre-NIC drops. Both are tracked in `CODE_REVIEW.md`.

---

## Requirements and installation

- Windows 10/11. The parser targets Windows `netstat -ano` / iphlpapi.
- Python 3.14 with the project virtual environment.
- `PyYAML` and `Flask` (declared in `pyproject.toml`, pinned by `uv.lock`).
- [Ollama](https://ollama.com/) on `http://localhost:11434` for AI triage.
- Local models. The defaults expect:

```powershell
ollama pull llama3.1:8b
ollama pull qwen3.8:27b
```

Create the environment from the lockfile (recommended):

```powershell
uv sync --frozen
```

Or, if `uv` is not available:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
```

If your model tags differ, update `agent.model` / `agent.escalation_model` in
`netstat_baseline_rules.yaml` or pass `--model` / `--escalation-model`.

---

## Quick start

**Before first run:** the live, host-tuned baseline is intentionally gitignored.
Copy the sanitized example and tune it for your host:

```powershell
Copy-Item netstat_baseline_rules.example.yaml netstat_baseline_rules.yaml
```

The example contains generic Windows defaults. Add your own application ports,
service PIDs, and trusted ranges before starting the agent. Keep the live
`netstat_baseline_rules.yaml` local (do not commit it). See
`docs/PUBLIC_LAUNCH.md` for the data-sanitization checklist.

From `C:\SOCAgent`:

```powershell
# One scan and exit
.venv\Scripts\python.exe checkstat.py --once

# Continuous monitoring (300 s scan interval)
.venv\Scripts\python.exe checkstat.py

# Rules and enrichment only, no model
.venv\Scripts\python.exe checkstat.py --once --no-ai --no-toast

# Replay saved RAW NETSTAT SNAPSHOT blocks
.venv\Scripts\python.exe checkstat.py --file netstat_snapshot.log

# Dashboard
.venv\Scripts\python.exe soc_ui.py
```

`--once` waits for two traffic samples, which takes about a second or two with
the 1 s gauge, then exits. The first AI run may take longer while Ollama loads
the model.

**Scheduled runs:** use `--once --no-toast`, start in `C:\SOCAgent`, and run
unelevated. Toasts are unavailable to non-interactive tasks; use the report,
`soc_findings.jsonl`, and the dashboard instead. Do not add "run with highest
privileges"; SOCA is designed to run unelevated.

---

## CLI reference

| Flag | What it changes |
|---|---|
| `--file PATH` | Replay `RAW NETSTAT SNAPSHOT` blocks from a saved log. |
| `--once` | Run one live scan and exit. Returns 0 even when findings exist. |
| `--interval SECONDS` | Live scan cadence. Default from YAML (300). Values below 15 are clamped to 15. |
| `--rules PATH` | Use a different baseline YAML. |
| `--model NAME` | Routine/default model. |
| `--escalation-model NAME` | Second-opinion model. |
| `--no-escalation` | Disable two-tier triage; use only `--model`. |
| `--max-escalations N` | Maximum escalation calls per scan. |
| `--escalation-timeout SECONDS` | Timeout per escalation call. |
| `--ollama-url URL` | Ollama generate endpoint. Default `http://localhost:11434/api/generate`. |
| `--ai-timeout SECONDS` | Timeout per routine call. |
| `--max-ai-checks N` | Maximum routine-model calls per scan. |
| `--num-ctx N` | Routine model context window. |
| `--keep-alive DURATION` | How long Ollama keeps the routine model loaded (e.g. `30m`, `0`). |
| `--think` | Enable hidden reasoning for the routine model (default off). |
| `--cache-hours H` | Verdict-cache TTL in hours (default 24). |
| `--no-cache` | Do not reuse or persist verdicts. |
| `--no-ai` | Disable the local LLM. |
| `--no-traffic` | Disable the traffic/attack-signature layer. |
| `--no-network-probes` | Disable active gateway/external network-health probes. |
| `--no-whois` | Disable RDAP/WHOIS lookups. |
| `--no-rdns` | Disable reverse DNS lookups. |
| `--no-process-details` | Skip executable path and signature enrichment. |
| `--no-toast` | Disable Windows notifications. |
| `--include-private-remotes` | Evaluate private/LAN remotes in **both** the row and traffic rules. Without this flag, `agent.ignore_private_remote_ips` and `traffic_detection.include_private_remotes` remain independent. |
| `--verbose` | Print debug diagnostics. |
| `--list-rules` | Print enabled row rules and exit. |

**Exit codes:** `0` normal completion (including findings and CLEAR), `1`
configuration/file errors, `2` command-line usage errors.

The enabled row rules are `NET-001`, `NET-002`, `NET-007`, and `NET-009`. The
other `NET-*` entries in the YAML are disabled design notes or require
operators the engine does not implement; see `IMPLEMENTATION_GUIDE.md`.

---

## Reading the results

| Verdict | Meaning |
|---|---|
| `FALSE_POSITIVE` | Concrete benign evidence explains the process and destination. No notification. |
| `SUSPICIOUS` | Plausible threat, unusual port/process relationship, or insufficient context. Human review. |
| `CRITICAL` | Strong evidence of malicious or unauthorized activity. |
| `UNVERIFIED` | Model unavailable, budget exhausted, or evidence insufficient. Review-worthy for HIGH/CRITICAL rules. |

Traffic findings (`NET-T01`..`NET-T14`) carry a deterministic rule severity.
On the scan lane they also receive an advisory AI verdict (and escalation for
HIGH/CRITICAL); the console report prints that verdict with its confidence,
classification, guardrail, and escalation notes. The fast gauge lane is
deterministic and reuses a cached verdict if one exists. The model never
changes the rule severity.

**`CLEAR` means:** no configured detector fired in this run. The report now
prints a `Coverage:` line with the enabled row rules, traffic layer status and
baseline state, AI/escalation status, and the row/traffic private-remotes modes,
plus a `Scope:` line. Read those before treating CLEAR as a clean bill of
health: a clean run with `--no-traffic`, AI off, a learning baseline, disabled
rules, skipped private remotes, or an invisible upstream flood is still limited.

**Notifications:** row findings notify for `SUSPICIOUS`, `CRITICAL`, and
`UNVERIFIED` HIGH/CRITICAL, with a 60-minute cooldown per signature. Traffic
findings notify only after the same signature recurs
`traffic_alert_min_occurrences` times (default 2) inside
`traffic_alert_window_minutes` (default 30), subject to the same cooldown. A
cached or fresh `FALSE_POSITIVE >= 80` silences the toast but not the record;
for HIGH/CRITICAL traffic findings, only an escalated verdict may silence it.
Deferred triage of a fast-lane finding never toasts on its own.

**Cache:** row verdicts are reused for `verdict_cache_hours` (default 24);
traffic verdicts use `traffic_verdict_cache_hours` (default 1, clamped to the
row TTL). Failed, deferred, heuristic, or escalation-skipped verdicts are
retried after 30 minutes. Occurrence counts and cooldowns live in a separate
alert-state section of `soc_verdict_cache.json`, so they survive verdict expiry
and replacement. Changing the model names or escalation severity list changes
the cache key; changing rule thresholds does not, so delete
`soc_verdict_cache.json` after editing detection rules.

---

## Network health / attack vs ISP

Host counters cannot see packets dropped before the NIC. To improve the
attack-vs-ISP answer, SOCA runs a low-rate active probe in the background
(every 60 s by default) and reports the **symptom**, never a proven cause:

- The default gateway is probed to establish whether the local link is healthy.
- Two external anchors (`1.1.1.1`, `8.8.8.8` by default) are probed to see
  whether the path beyond the gateway is degraded.
- The report and the dashboard status strip show RTT, loss, and a verdict:
  `EXTERNAL PATH RESPONSIVE`, `LOCAL LINK`, `UPSTREAM/ISP OR PRE-NIC`,
  `DESTINATION/PEERING`, or `UNKNOWN`.
- If host-traffic findings are active, the report adds a hedged correlation
  line (for example, "upstream path degraded while host-visible attack signals
  were active").

**What it can say:** whether the gateway, the external path, or only one
destination anchor is degraded, and whether that changed while host-visible
attack signals were present.

**What it cannot say:** it cannot prove an upstream DDoS, cannot separate ISP
congestion from an attack dropped upstream, and cannot see traffic that never
reaches the host's NIC. Probe filtering can also mimic path failure; the report
states this. Router/ISP telemetry and packet capture remain out of scope.

Targets must be IP literals (IPv4 uses ICMP; IPv6 and blocked-ICMP paths use
TCP). Disable the feature with `--no-network-probes` or
`network_health.enabled: false`. See `IMPLEMENTATION_GUIDE.md` for thresholds
and failure handling.

---

## Remediation safety

SOCA can surface a candidate action, but you should validate it before acting.
No action is applied automatically. Findings carry a structured remediation
(`block_remote`, `close_port`, `inspect_process`, `contact_isp`,
`investigate`) with a safety note; the report and JSONL show it.

**Blocking a remote IP**

- Confirm the remote is public and is the actual peer you intend to block. Do
  not block a CDN, shared hosting, cloud, or trusted-network address; it can
  break unrelated services. The traffic layer now consults
  `trusted_remote_networks` and will not recommend blocking a trusted address;
  a trusted NET-T02 is reported as informational. Still validate the remaining
  CDN/NAT/CGNAT/IPv6 caveats.
- Behind NAT/CGNAT, blocking a remote can be ineffective or can affect other
  hosts sharing the public address. An upstream volumetric flood may be dropped
  before the host, so a host-side block does nothing.
- For IPv6, a distributed flood uses many source addresses; blocking one address
  is rarely sufficient. Prefer upstream/firewall rate limits.
- A block is a mitigation, not a cleanup. If the connection came from a local
  process, investigate or uninstall that process as well.

**Closing a port**

- Identify the listening process first (`netstat -ano`, the report's PID, or the
  dashboard findings). Do not close Windows RPC/SMB/listener ports blindly.
- Closing a local port does not stop an inbound flood to a closed port; it only
  removes the service exposure. Correlate with SYN/UDP findings before changing
  firewall rules.

**Uninstalling an application**

- Require the executable path and signature status, not just a process name.
  Name-based exceptions and the bulk allowlist now require identity evidence,
  but a decoy binary with a valid signature or a protected install path can
  still qualify.
- PIDs can be reused between the capture and a later lookup. Confirm the path
  and signature before uninstalling anything.

**Never** let a toast or a model recommendation drive an irreversible action
without checking the report evidence and, where possible, a second source
(router/firewall logs).

---

## How detection works (summary)

```text
scan lane (every 300 s)                     fast lane (every 1 s)
  netstat text -> row rules                  netstat/iphlpapi gauntlet
  traffic metrics -> traffic rules           new traffic findings
  enrichment (RDAP/rDNS/process)             (deterministic, no LLM wait)
  two-tier AI triage                         deferred queue for scan-lane triage
  verdict cache, report, JSONL, toast

network-health lane (every 60 s)
  gateway + external IP probes -> RTT/loss/jitter
  symptom verdict -> report line + dashboard chip + shared JSON
```

- **Row rules** evaluate one connection row at a time: suspicious ports,
  non-standard high ports, legacy cleartext services, and UDP remote rules.
  Enabled: NET-001, NET-002, NET-007, NET-009.
- **Traffic rules** evaluate aggregate host signals: SYN/passive-open bursts,
  single-remote and distributed connection floods, connection-count growth,
  TIME_WAIT pressure, bandwidth spikes, discards, retransmits, UDP/ICMP floods,
  UDP no-ports scans, IP packet-rate spikes, and per-process connection growth
  (NET-T14). Thresholds live under `traffic_detection.thresholds`.
- **Network-health probes** run in a separate 60 s thread: gateway and external
  IP anchors, ICMP with TCP fallback. The report and dashboard classify the
  path symptom (responsive/local link/upstream-ISP/destination) and carry the
  explicit non-proof caveat.
- **Bulk-transfer allowlist:** a process-scoped exemption (never an IP
  allowlist) for game launchers, backup/sync, and streaming clients. It can
  downgrade only NET-T02/T05/T06/T07/T14 to LOW/informational, only when the
  inbound flood signals are quiet. It never deletes a finding.
- **NET-T14** compares each process with its own recent norm, keyed by image
  name (not PID), and distinguishes a dense download-like burst from a fan-out
  scan/C2 shape.
- **Two-tier triage:** a routine model vets candidates; a larger model reviews
  HIGH/CRITICAL and suspicious findings. The model is advisory; deterministic
  guardrails can downgrade a `FALSE_POSITIVE`.
- **Replay** (`--file`) evaluates netstat-derived signals only; counters are
  unavailable. It uses a disabled verdict cache and a non-persisting intel
  provider, ignores the live process table, and never toasts.

See `IMPLEMENTATION_GUIDE.md` for the data flow, cache keys, and algorithm
details.

---

## Web dashboard

`soc_ui.py` is an optional localhost dashboard that runs `checkstat.py` for you
and reads its files.

```powershell
.venv\Scripts\python.exe soc_ui.py
.venv\Scripts\python.exe soc_ui.py --port 8765 --no-browser
```

The console prints and auto-opens `http://127.0.0.1:8765/#token=...`; open that
tokenized URL (a bare URL cannot authenticate a fresh tab). Panels: live
console, traffic history, findings feed, rolling charts, and a status strip
(Ollama reachability, network-health verdict, sample age, file sizes, cache
size). Form values default from the YAML and persist in browser `localStorage`.

Behaviour notes:

- Closing the dashboard stops a running agent. If the dashboard was killed while
  the agent ran, the next launch can adopt the orphan; output streaming is not
  available for an adopted process, and Stop terminates it.
- **Stop may skip the graceful model unload.** Ctrl+C reaches the agent's
  `finally` block, which asks Ollama to unload both models. Dashboard Stop sends
  a console break and, if the agent does not exit within 5 s, force-kills the
  process tree; a hard kill skips the unload. The model then expires after
  `keep_alive`. Check with `ollama ps`.
- Replay (`--file`) is one-shot and does not write traffic history.

### Security posture and hardening

- The dashboard binds `127.0.0.1` only. Every `/api/*` call requires a
  per-launch `X-Auth-Token`; the Host header must be loopback and, when an
  Origin is present, it must be same-origin. `/` and `/static/*` are
  unauthenticated but carry no telemetry. The token is delivered in a
  `#token=...` URL fragment, stored in `sessionStorage`, and stripped from the
  address bar; it is regenerated each launch and not written to disk.
- Adoption verifies the PID's creation time, requires the absolute
  `checkstat.py` path in its command line, and binds the decision to the same
  interpreter image, user SID, and session as the dashboard. Adopted PIDs are
  watched and Stop re-verifies identity before `taskkill`. A same-user process
  that reproduces the exact command line could still spoof the probe; the
  install directory ACL is part of the trust boundary.
- `ollama_url` is loopback-only by default; non-loopback hosts require the
  explicit `--allow-remote-ollama` flag. The status probe refuses redirects and
  caps the response at 512 KiB.
- Requests are capped at 64 KiB; console, traffic, and findings responses are
  byte-bounded; path inputs are resolved with symlinks/junctions and must stay
  inside the project; API failures return generic messages (details stay in the
  console).
- Responses set CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options:
  nosniff`, and `Referrer-Policy: no-referrer`.
- `soc_ui.py` and `checkstat.py` check the install directory at startup and
  print a `SECURITY` warning when it grants write access to `Authenticated
  Users`, `Everyone`, `Users`, or `Guests`, or when the process is elevated.
  For a hardened install: put the project under `%LOCALAPPDATA%` or `Program
  Files`, restrict the ACL to your account, and never run the dashboard or
  agent elevated. Example (adjust the path/account):

  ```powershell
  icacls C:\SOCAgent /inheritance:r /grant:r "$env:USERNAME:(OI)(CI)F"
  ```
- The UI is a single-user tool. Do not expose the port, port-forward it, or run
  it on a shared machine.

---

## Configuration

All settings live in `netstat_baseline_rules.yaml`. CLI flags override the
`agent` values. The YAML is the source of truth for thresholds; the block below
is a summary, not a second copy of the file.

```yaml
agent:
  model: "llama3.1:8b"
  ollama_url: "http://localhost:11434/api/generate"
  ai_enabled: true
  ai_timeout_seconds: 120
  max_ai_checks_per_run: 8
  keep_alive: "30m"
  num_ctx: 4096
  think: false

  escalation_enabled: true
  escalation_model: "qwen3.8:27b"
  escalation_severities: ["HIGH", "CRITICAL"]
  escalation_timeout_seconds: 180
  max_escalations_per_run: 2
  escalation_num_ctx: 4096
  escalation_think: false
  escalation_keep_alive: "30m"

  scan_interval_seconds: 300
  max_enrichment_checks_per_run: 20
  enrichment_budget_seconds: 20
  verdict_cache_hours: 24
  traffic_verdict_cache_hours: 1
  alert_cooldown_minutes: 60
  traffic_alert_min_occurrences: 2
  traffic_alert_window_minutes: 30
  traffic_ai_max_checks: 2
  traffic_ai_enabled: true
  ignore_private_remote_ips: true
  process_identity_mode: "verify"

network_health:
  enabled: true
  interval_seconds: 60
  timeout_ms: 1000
  probes_per_target: 4
  degraded_loss_pct: 20
  degraded_jitter_ms: 80
  degraded_rtt_ms: 500
  gateway: auto
  gateway_tcp_port: null
  targets:
    - host: "1.1.1.1"
      port: 443
      label: "Cloudflare"
    - host: "8.8.8.8"
      port: 443
      label: "Google"
  file_max_age_seconds: 180

traffic_detection:
  enabled: true
  sample_interval_seconds: 3
  gauge_interval_seconds: 1
  min_rate_seconds: 5
  api_retry_seconds: 60
  baseline_window_seconds: 900
  baseline_guard_seconds: 60
  baseline_percentile: 25
  max_history_samples: 1800
  include_private_remotes: false
  bulk_transfer_verify_identity: true
```

**Important configuration notes**

- `network_health` controls the active probes. They are on by default and send
  a few ICMP packets (TCP fallback) per minute to the configured IP anchors.
  Disable with `--no-network-probes` or `enabled: false`. Targets must be IP
  literals; `gateway: auto` discovers the IPv4 default route. Thresholds are
  tunable for satellite/mobile links; loss and jitter are primary.
- `agent.traffic_ai_enabled` gates the traffic-layer model triage. Set it to
  `false` (or `traffic_ai_max_checks: 0`) to keep row AI while leaving traffic
  findings deterministic.
- `agent.traffic_verdict_cache_hours` (default 1) shortens traffic verdict
  reuse and is clamped to `verdict_cache_hours`; row verdicts keep the normal
  TTL. Occurrence and cooldown state is stored separately and survives both a
  verdict replacement and its expiry.
- `agent.ignore_private_remote_ips` and
  `traffic_detection.include_private_remotes` are independent YAML controls.
  The `--include-private-remotes` CLI flag overrides both to include private
  remotes (the dashboard checkbox maps to the same flag); without the flag the
  YAML values apply. When private remotes are included, HIGH/CRITICAL private
  findings are `SUSPICIOUS` and can alert; they are no longer heuristic
  `FALSE_POSITIVE 80%`. The report's `Coverage:` line prints both modes
  separately.
- `agent.process_identity_mode` (default `verify`) requires path/signature
  evidence before a name-based rule exception or bulk-transfer exemption can
  hide a finding. `name` is legacy and unsafe; `verify` and `strict` both deny
  when evidence is unavailable. `traffic_detection.bulk_transfer_verify_identity`
  must stay true for allowlist exemptions to apply; `--no-process-details` also
  prevents them.
- `traffic_detection.api_retry_seconds` (default 60) controls how often the
  direct iphlpapi capture is retried after a fallback to `netstat`.
- The traffic baseline uses `baseline_window_seconds` with the newest
  `baseline_guard_seconds` excluded, and takes `baseline_percentile` (a low
  percentile by design). Samples that produced a finding are excluded from
  future baselines. Raising the percentile makes the baseline less sensitive to
  normal variation but more vulnerable to attack contamination.
- `max_history_samples` is automatically raised to fit the baseline window at
  the current gauge cadence and is capped at 20,000 samples. A pathological
  baseline window is clamped to what the history can hold.
- Thresholds and agent settings are type-checked and range-limited at startup.
  A non-numeric threshold, unknown threshold key, or quoted boolean such as
  `ai_enabled: "false"` exits with a precise `Invalid configuration ...`
  message instead of failing inside every scan. Out-of-range numbers are
  clamped (for example, `scan_interval_seconds` below 15 becomes 15).
- `history_file` must resolve inside the project directory; an absolute or
  `..` path outside it is rejected at startup.
- `max_enrichment_checks_per_run` and `enrichment_budget_seconds` cap serial
  RDAP/WHOIS/rDNS lookups per scan. Groups over budget are reported with a
  minimal deterministic intel record, and their verdict is not cached, so a
  later scan can backfill the lookup.
- `state_aliases` is an optional top-level `localized label: CANONICAL_STATE`
  map for replay logs and `capture_mode: netstat`. Values must be canonical
  TCP states; unknown values fail at startup. Live capture does not need it
  when iphlpapi is available.
- `trusted_remote_networks` now applies to the traffic layer as well as the row
  rules. A trusted NET-T02 is informational, never recommends blocking, and
  v4-mapped IPv6 peers match the equivalent IPv4 CIDR.
- The YAML also contains `baseline.expected_listening_ports`,
  `baseline.application_ports`, rule exceptions, and the bulk-transfer allowlist.
  Tune those to your environment.

---

## Files, privacy, and retention

| File | Contents | Retention |
|---|---|---|
| `local_soc_agent.log` | Human-readable reports, hostname/local IP, findings | Appended; rotated at 10 MB, one previous generation |
| `netstat_snapshot.log` | Raw `netstat` output including local/remote IPs and PIDs | Rotated at 10 MB, one previous generation |
| `soc_findings.jsonl` | One JSON record per anomaly group or traffic finding: host, IPs, process paths, WHOIS, model reasoning | Rotated at 10 MB, one previous generation |
| `soc_verdict_cache.json` | Verdicts, occurrence/cooldown alert state, cached intel | TTL-based (row 24 h; traffic 1 h default) |
| `soc_intel_cache.json` | WHOIS/RDAP and reverse-DNS cache, including abuse contacts | TTL-based; pruned on save and capped at 2,000 entries |
| `soc_traffic_history.jsonl` | Rolling traffic samples, including per-process names and connection counts | Trimmed at startup to `max_history_samples` (default 1,800) after exceeding twice that; capped/rotated at 64 MB |
| `soc_ui_agent_state.json` | Dashboard PID bookkeeping (ephemeral) | Removed on clean stop |
| `soc_network_health.json` | Latest gateway/external probe result (RTT, loss, verdict) | Overwritten every probe interval; read by the dashboard; 64 KiB cap |
| `soc_user_allowlist.json` | User-confirmed false positives (compound scope, expiry, guards) created from the dashboard | Active until removed/expired; disabled entries pruned after 90 days |

These files are **plaintext** and contain network inventory and process data.
They are excluded by `.gitignore`; do not commit or share the directory without
reviewing them. The agent sends public remote IPs to RDAP/WHOIS services and
reverse DNS to your resolver; it does not query reputation or blocklist
services. Disable with `--no-whois` / `--no-rdns`. Network-health probes send
ICMP echo (or a TCP handshake fallback) to the configured gateway/anchors;
disable with `--no-network-probes` or `network_health.enabled: false`.

**Complete reset** (destructive; this deletes evidence):

```powershell
Remove-Item soc_verdict_cache.json, soc_intel_cache.json, soc_findings.jsonl, `
            soc_traffic_history.jsonl, local_soc_agent.log, `
            netstat_snapshot.log, soc_ui_agent_state.json, `
            soc_network_health.json `
            -ErrorAction SilentlyContinue
```

---

## Troubleshooting

**Ollama connection errors.** Start Ollama (`ollama serve`) and confirm
`curl http://localhost:11434/api/tags`. The AI is optional; `--no-ai` keeps the
deterministic detector running.

**Model not found.** Run `ollama list`; pull the model or update
`agent.model` / `agent.escalation_model`.

**First scan is slow.** Ollama is loading the model. Later scans reuse it for
`keep_alive` (30 minutes by default). If model RAM matters, set
`escalation_keep_alive` to a smaller value or `0` in the YAML; the CLI
`--keep-alive` controls the routine model only.

**High CPU or RAM.** The 27B escalation model is large. Lower
`max_escalations_per_run`, use a smaller escalation model, or run
`--no-escalation` with a mid-size model.

**The report says CLEAR, but I expected an alert.** CLEAR means no configured
detector fired. Check whether `--no-traffic` or `--no-ai` is set, whether the
traffic baseline has enough samples, whether the remote is private (skipped by
default), and whether the event is upstream/volumetric (invisible to the host).
Read the report's `Coverage:` and `Scope:` lines.

**Network health says UPSTREAM/ISP.** The gateway answered but the external
anchors are degraded. That is a symptom, not proof: it can be ISP congestion, a
peering problem, or a flood dropped before this host's NIC. Check the router/ISP
traffic graphs and the host traffic findings; the report intentionally does not
claim a cause. If the verdict is `LOCAL LINK`, check Wi-Fi/router connectivity
first. If it says probes are blocked, the network may filter ICMP and TCP to the
configured anchors; adjust targets or thresholds in `network_health`.

**Too many false positives.** Add trusted ranges to
`trusted_remote_networks`, legitimate ports to `baseline.application_ports`, or
rule exceptions. Prefer narrow image names over wildcards; name-based
exceptions require executable identity evidence by default. Delete
`soc_verdict_cache.json` after rule changes.

For a single noisy finding (for example NET-T10 while streaming video), use
**Mark false positive** on the finding card instead. The dashboard creates a
scoped exception in `soc_user_allowlist.json`: the rule, the identity-verified
owning process, and a rate band (or endpoint for row rules). It expires after
7/30/90 days (default 30) and CRITICAL findings cannot be muted. The finding is
still written to `soc_findings.jsonl`; the dashboard hides it from the normal
views and keeps it under the **MUTED** filter. Safety guards reopen it
automatically on a severity increase, a rate above the mute band, UDP errors, a
different process owning the traffic, an unverifiable process identity, a
co-firing flood/scan rule, or baseline drift. Allow-list changes apply without
restarting the agent; edits to `netstat_baseline_rules.yaml` still require a
restart. Remove entries from the **Allow-list** button next to the findings
filter. Records written before the mute are matched for display against the
active scope, so they stay under **MUTED** after a refresh. This display match
cannot replay live identity/co-fire guards (a historical record has no live
process evidence); the agent remains authoritative for new sightings, and a
record it explicitly reopened is never re-hidden. The static baseline remains
hand-maintained — there is no UI baseline generator.

**Finding chat times out.** The finding chat defaults to
`agent.escalation_model` (the larger 27B model). Use the **Model** selector in
the chat window to switch to a smaller installed model (for example the routine
`llama3.1:8b`) for faster answers. The selector lists the configured default,
the routine model, and the models Ollama reports; an explicit choice is checked
against the installed set. The error message also suggests trying a smaller
model. If the agent is triaging at the same time, Ollama may be busy — retry
after the scan completes.

**Notifications do not appear.** Focus Assist or notification settings may
suppress them. Toasts are unavailable to non-interactive scheduled tasks.
Traffic findings require `traffic_alert_min_occurrences` repeats within the
window.

**The dashboard is unreachable.** Confirm it is running and bound to
`127.0.0.1:8765` (`netstat -ano | findstr :8765`). Check the console for a port
conflict.

---

## Testing

Run from `C:\SOCAgent` with the project venv:

```powershell
.venv\Scripts\python.exe -B test_parser.py          # offline: parser, rules, guardrails, triage
.venv\Scripts\python.exe -B test_ui_runner.py       # offline: runner, validation, paths, tailers
.venv\Scripts\python.exe -B test_network_health.py  # offline: probes, verdicts, monitor (mocked)
.venv\Scripts\python.exe -B test_netapi.py          # live: iphlpapi/netstat; may be flaky
```

`test_netapi.py` includes live tests and can fail on table churn; a failure is
not automatically a regression. The traffic suite includes 1 s-cadence,
sustained-attack, sparse-process, counter-reset, history-cap, trusted-remote,
remediation, guardrail, and coverage regressions; the netapi suite pins the IPv6
layout and cross-checks live IPv6 rows; `VerdictCache` now has direct TTL,
alert-state, and persistence tests. The UI suite includes Flask test-client
tests for token/Host/Origin auth, adoption (including image/owner/session
binding), install-ACL/elevation warnings, input validation, and `/api/*`
start/stop lifecycle and concurrency. `test_network_health.py` is offline and
mocks ICMP/TCP/gateway discovery; it covers the verdict matrix, aggregation,
monitor lifecycle, and result-file bounds.

---

## Project layout and release status

```text
checkstat.py                  Unified agent (CLI, parser, rules, traffic, triage)
netapi.py                     Direct unelevated iphlpapi capture for the sampler
soc_ui.py                     Localhost dashboard and process runner
install_security.py          Install-ACL/elevation warnings and process-principal probes
network_health.py            Active gateway/external probes and symptom classification
static/                       Dashboard assets (index.html, app.css, app.js)
netstat_baseline_rules.yaml   Baseline, rules, traffic thresholds, agent config
test_parser.py                Offline parser/rule/triage tests
test_netapi.py                Live and helper tests for netapi / fast lane
test_ui_runner.py             Offline dashboard runner/validation tests
test_network_health.py        Offline network-health probe/verdict/monitor tests
README.md                     This file
IMPLEMENTATION_GUIDE.md       Developer/architecture reference
CODE_REVIEW.md                Formal code review and security assessment
.gitignore                    Excludes runtime artifacts and the venv
.venv/                        Local virtual environment (ignored, not shipped)
```

Generated at runtime and ignored: `local_soc_agent.log`,
`netstat_snapshot.log`, `soc_findings.jsonl`, `soc_traffic_history.jsonl`,
`soc_verdict_cache.json`, `soc_intel_cache.json`, `soc_ui_agent_state.json`,
`soc_network_health.json`, `soc_user_allowlist.json`.

**Release status:** personal alpha. No LICENSE, CI, or SECURITY policy is
included in this pass. The project is not currently a git repository; the
`.gitignore` is provided for when it becomes one.

*Last verified against the follow-up-pass source hashes in `CODE_REVIEW.md`
Appendix D on 2026-11-01.*
