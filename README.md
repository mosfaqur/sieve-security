# Sieve Security

> **"Fewer findings, each true, each with a fix."**

**Sieve Security** is a next-generation vulnerability management platform built to replace noisy, legacy vulnerability scanners. Rather than inundating security operations with thousands of unverified CVE alerts, Sieve tells teams which ~40 things to fix this week, provides the exact verified evidence behind each finding, and confirms the fix landed with sub-60-second verification rescans.

Based on the **Version 3.1 Consolidated Engineering Plan** ([vulnerability-platform-plan-v3.md](file:///root/agy-vul/vulnerability-platform-plan-v3.md)).

---

## Key Differentiators & The Thesis

1. **Accuracy You Can Interrogate (§1.2):**  
   Every finding carries its detection method (`active_probe`, `version_inference`, `credentialed`), confidence tier (`confirmed`, `probable`, `potential`), and redacted raw evidence. Full distro backport awareness prevents false positives on patched Linux packages.
2. **Two-Tier Reachability Engine (§1.2, §38.4):**  
   - **Tier 1 (Network & Socket Binding):** Correlates open network listeners with local host process sockets (`ss` / `netstat` + `/proc/<pid>/exe`). Proves whether a listening port connects to the vulnerable component before any agent is deployed.
   - **Tier 2 (Runtime Code & Symbol Execution):** Traces whether vulnerable shared libraries or static symbols are actively mapped into process memory.
3. **Remediation-Centric Output (§50):**  
   Instead of a list of raw CVEs, Sieve outputs prioritized **Remediation Items** with copy-pasteable CLI commands, Ansible playbook tasks, Dockerfile snippets, and **sub-60-second targeted verification rescans**.
4. **Four-Column Defensible Scan Diff (§68.4):**  
   Categorizes findings into `NEW`, `CONFIRMED FIXED`, `REOPENED`, and `UNVERIFIED / VANISHED` (surfacing credential failures and host timeouts so teams never claim false victories).
5. **Zen Triage Mode (`Shift+Z`) (§68.11):**  
   A full-screen, keyboard-first triage surface allowing security engineers to process backlogs in minutes using single-key dispositions (`[T]` Ticket, `[A]` Accept Risk, `[F]` False Positive, `[V]` Verify Rescan, `[N]` Next).

---

## Architecture Overview

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

## Detailed Documentation

Comprehensive architectural and engineering specifications are located in [`docs/`](file:///root/agy-vul/docs/):
- **[docs/architecture.md](file:///root/agy-vul/docs/architecture.md):** Full system architecture, control plane, workers, and blast radius safety classes.
- **[docs/data-model.md](file:///root/agy-vul/docs/data-model.md):** Data models, Network Zones (`network_zone_id`), multi-signal asset identity resolution algorithm, and finding lifecycle.
- **[docs/scan-and-reachability.md](file:///root/agy-vul/docs/scan-and-reachability.md):** Host discovery, TCP connect/SYN scanning, token-bucket rate limiting, and Tier 1 / Tier 2 reachability analysis.
- **[docs/remediation-orchestration.md](file:///root/agy-vul/docs/remediation-orchestration.md):** Remediation action grouping, risk reduction quantification, and sub-60s verification rescans.
- **[docs/plugin-guide.md](file:///root/agy-vul/docs/plugin-guide.md):** Declarative YAML Plugin DSL specification (Appendix A), ecosystem version matchers, and mandatory true-negative CI gates.
- **[docs/deployment-and-testvm.md](file:///root/agy-vul/docs/deployment-and-testvm.md):** Production deployment runbook, systemd units, and live test lab report for `192.168.1.30`.

---

## Quickstart

### 1. Build the Binary
```bash
go build -o sieve ./cmd/sieve
```

### 2. Run a Standalone CLI Scan
Assess a target with real-time port discovery, service fingerprinting, and reachability:
```bash
./sieve scan 192.168.1.30
```

With authenticated SSH assessment:
```bash
./sieve scan 192.168.1.30 --ssh-user root
```

Output formatted as structured JSON:
```bash
./sieve scan 192.168.1.30 --json
```

### 3. Launch the Control Plane & High-Density Web UI
```bash
./sieve server --addr 0.0.0.0:8080
```
Open **`http://localhost:8080`** in your browser to access:
- **Work Queue & Prioritized Weekly Actions**
- **Remediation Queue with Copy-Paste Commands**
- **Findings with Reachability Proof Stack**
- **Four-Column Defensible Scan Diff**
- **Zen Triage Mode (`Shift+Z`)**

---

## Remote Test VM Deployment (`192.168.1.30`)

A deployment pipeline script is included to automatically compile, package, and deploy Sieve Security to a remote server with systemd daemon management:

```bash
./deploy/deploy_vm.sh 192.168.1.30 root
```

This installs the service to `/opt/sieve/`, configures UFW firewall access for port 8080, and registers `sieve.service` under systemd.

---

## REST API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/health` | `GET` | Health check, plugin count, and system status |
| `/api/v1/scans` | `GET` | List all historical scan executions |
| `/api/v1/scans` | `POST` | Launch a new scan against a target |
| `/api/v1/assets` | `GET` | Retrieve asset inventory and identity signals |
| `/api/v1/findings` | `GET` | Query findings (filterable by `severity` and `state`) |
| `/api/v1/findings/state` | `POST` | Update finding lifecycle state (accept risk, mark false positive) |
| `/api/v1/remediations` | `GET` | Retrieve synthesized remediation action items |
| `/api/v1/verify` | `POST` | Trigger sub-60-second targeted verification rescan |
| `/api/v1/diff` | `GET` | Retrieve four-column defensible scan diff metrics |

---

## Declarative Plugin DSL Example

All vulnerability content is written in declarative YAML under [`content/plugins/`](file:///root/agy-vul/content/plugins/):

```yaml
id: openssh-regresshion-cve-2024-6387
schema_version: 2

info:
  name: OpenSSH RegreSSHion Remote Code Execution Vulnerability
  family: ssh
  severity: critical
  cve:
    - CVE-2024-6387
  description: A signal handler race condition vulnerability in sshd allows RCE.
  remediation: Upgrade openssh-server to version 9.8p1 or newer.
  safety: active-safe
  method: version_inference
  confidence: probable

requires:
  service:
    - ssh
    - openssh
  ports:
    - 22

matchers_condition: and
matchers:
  - type: banner
    pattern: "(?i)OpenSSH"
  - type: version
    fixed_in: "9.8"
    ecosystem: generic

emit:
  title: OpenSSH Server Remote Code Execution (regreSSHion - CVE-2024-6387)
  evidence:
    include:
      - banner
    max_bytes: 1024
  evidence_signature:
    - openssh
    - version
```

---

## License & Roadmap
- **Roadmap:** See [vulnerability-platform-plan-v3.md §98](file:///root/agy-vul/vulnerability-platform-plan-v3.md#L5284) for Phase 1–5 milestones.
- **License:** Commercial Enterprise / Open-Core Architecture.
