# Sieve Security — System Architecture

**Platform Version:** 3.1.0-alpha  
**Thesis:** *Fewer findings, each true, each with a fix.*

---

## 1. System Overview & Core Philosophy

Sieve Security is an enterprise-grade vulnerability management platform engineered around a single operating premise: **Security teams spend their time fixing verified risk rather than triaging false-positive noise.**

Unlike legacy vulnerability scanners that prioritize raw check volume (often resulting in thousands of unverified CVE alerts for unreferenced libraries), Sieve couples network discovery with **Two-Tier Reachability Analysis**, **Authoritative Distro Backport Awareness**, and **Remediation Action Grouping**.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  CLIENTS   Web UI (Zen Triage) · CLI · REST/WebSocket APIs                │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────────┐
│  CONTROL PLANE & API GATEWAY                                             │
│  - Multi-tenant Authorization & Scope Guard (Compiled Trie Backstop)     │
│  - Asset Inventory & Multi-Signal Identity Resolution Engine             │
│  - Declarative Plugin VM & Evaluation Engine                             │
│  - Two-Tier Reachability Evaluator (Socket/Process Binding)             │
│  - Remediation Action Grouping & Verification Engine                     │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────────┐
│  SCANNER & WORKER SUBSYSTEM                                              │
│  - Rate-limited Port Scanner (Token Bucket, Congestion Backoff)          │
│  - Service & Protocol Fingerprinter (TLS, HTTP, SSH, FTP, MySQL)         │
│  - Authenticated Host Collector (SSH / Local Fact Extraction)            │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────────┐
│  PERSISTENCE & REPORTING                                                 │
│  - PostgreSQL Operational Store with Row-Level Security (RLS)            │
│  - Four-Column Defensible Scan Diff (New, Fixed, Reopened, Vanished)     │
│  - Isolated Render Sandbox (Networkless Container for HTML/PDF reports)   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 Scope & Double Authorization Enforcement (§4.1)
Authorization is a first-class security boundary. The system enforces destination authorization at two separate checkpoints:
1. **Scan Inception & Job Dispatch:** Targets are validated against active tenant scopes and explicit exclusions. External IP addresses require verified ownership proofs.
2. **Pre-Flight Socket Write Backstop:** Inside worker processes, immediately before any TCP connection or packet emission, destination addresses are checked against a compiled in-memory IP/CIDR trie.
3. **DNS Rebinding Defense:** Any target hostname that resolves to an IP address outside authorized boundaries is immediately dropped and flagged as a security event.

### 2.2 Scan Engine & Rate Control (§12, §13)
- **Token-Bucket Rate Limiter:** Enforces strict Packets-Per-Second (PPS) ceilings to prevent network saturation.
- **Adaptive Congestion Backoff:** Automatically scales probe concurrency upon detecting packet loss or latency spikes.
- **Fragile Device Avoidance:** Identifies and isolates sensitive network elements (such as printers and industrial controllers) to passive or low-impact probing profiles.

### 2.3 Two-Tier Reachability Engine (§1.2, §38.4)
The reachability engine acts as the primary filter for actionable risk:
- **Tier 1 (Network & Socket Binding) [P2]:** Correlates open network listeners (`0.0.0.0:*` vs `127.0.0.1:*`) with local host process sockets (`ss`/`netstat` + `/proc/<pid>/exe`). It proves whether an active process is bound to an exposed port before raising an alert.
- **Tier 2 (Runtime Code & Symbol Execution) [P3]:** Uses eBPF memory tracing to verify whether vulnerable shared libraries or functions are actually executed by the process.

### 2.4 Remediation Orchestration Engine (§50)
Rather than producing a disconnected list of hundreds of CVEs, Sieve clusters related findings into **Remediation Items**:
- Groups findings by target fix (e.g. package upgrade, configuration change, or certificate renewal).
- Synthesizes multi-modal deployment artifacts: Copy-pasteable CLI commands, Ansible playbook tasks, and Dockerfile directives.
- Implements **Sub-60s Verification Rescans**: Re-probes only the specific host and port to immediately verify whether a fix successfully landed.

### 2.5 Defensible 4-Column Scan Diff (§68.4)
To eliminate "false victories," Sieve tracks finding state across successive scans using four explicit categories:
1. **NEW:** Vulnerabilities first observed in the current scan.
2. **CONFIRMED FIXED:** Vulnerabilities previously seen where the service was successfully re-probed and verified patched.
3. **REOPENED:** Vulnerabilities previously resolved that regressed due to rollback or configuration drift.
4. **UNVERIFIED / VANISHED:** Vulnerabilities that disappeared because the target host timed out or credentials failed. Sieve marks these as `unverified_absent` rather than claiming a fix.
