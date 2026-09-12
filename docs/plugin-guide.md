# Sieve Security — Plugin Authoring & Detection-as-Code Guide

**Platform Version:** 3.1.0-alpha  
**Document Reference:** Plan Sections 18–22, 91, and Appendix A

---

## 1. Declarative YAML Plugin Specification

All vulnerability checks in Sieve are authored in a declarative YAML DSL. No obscure scripting languages (like NASL) are required.

```yaml
id: openssh-regresshion-cve-2024-6387    # Globally unique kebab-case ID
schema_version: 2

info:
  name: OpenSSH RegreSSHion Remote Code Execution Vulnerability
  family: ssh                            # Category
  severity: critical                     # critical | high | medium | low | info
  cve:
    - CVE-2024-6387
  cwe:
    - CWE-362
  references:
    - https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt
  description: A signal handler race condition vulnerability in sshd allows RCE.
  remediation: Upgrade openssh-server to version 9.8p1 or newer.
  safety: active-safe                    # passive | active-safe | active-noisy | intrusive | destructive
  method: version_inference              # version_inference | active_probe | credentialed
  confidence: probable                   # confirmed | probable | potential
  timeout_seconds: 5

requires:                                # Gating conditions
  service:
    - ssh
    - openssh
  ports:
    - 22
  credentials: false                     # Set true if authenticated assessment required

matchers_condition: and                  # and | or
matchers:
  - type: banner
    pattern: "(?i)OpenSSH"
  - type: version
    fixed_in: "9.8"
    ecosystem: generic                   # semver | dpkg | rpm | apk | generic

emit:
  title: OpenSSH Server Remote Code Execution (regreSSHion - CVE-2024-6387)
  evidence:
    include:
      - banner
    max_bytes: 1024                      # Strict evidence size bounding
  evidence_signature:                    # Key used for deterministic deduplication
    - openssh
    - version
```

---

## 2. Matcher Types & Ecosystem Version Comparison

Sieve supports multiple matcher primitives:
1. **`banner`**: Regex or substring evaluation against raw protocol banners.
2. **`version`**: Semantic version comparison respecting ecosystem conventions:
   - `semver`: Standard semantic versioning (`major.minor.patch`).
   - `dpkg`: Debian/Ubuntu package epochs and release revisions.
   - `rpm`: Red Hat Epoch-Version-Release (EVR) syntax.
   - `generic`: Numeric segment parsing.
3. **`tls`**: Cryptographic checks (`weak_ciphers`, `expired`, `self_signed`).
4. **`package`**: Evaluates installed packages from authenticated assessment.
5. **`http-status` / `http-header`**: Evaluates response status codes and headers.

---

## 3. Blast Radius Safety Classes (§4.2)

Every plugin must declare its safety class:
- **`passive`**: Observes only (e.g. DNS or passive banner reading).
- **`active-safe`**: Sends standard network traffic; mathematically incapable of altering state or crashing healthy software.
- **`active-noisy`**: Generates high log volume or automated test alerts.
- **`intrusive`**: Probing that could trigger service resets, lockouts, or high CPU. Gated behind explicit opt-in.
- **`destructive`**: Active exploitation or brute-force tests. Disabled by default.

---

## 4. Quality Gates & True-Negative CI Validation (§91)

To prevent false-positive regressions, every check must pass two automated test gates before deployment:
1. **True-Positive Fixture:** Proves the check triggers when run against a known-vulnerable environment.
2. **True-Negative Fixture:** Mandatory test proving the check produces **zero findings** when run against the patched/fixed reference version. Checks without true-negative tests fail CI builds.
