# Sieve Security — Remediation Orchestration & Verification

**Platform Version:** 3.1.0-alpha  
**Document Reference:** Plan Section 50

---

## 1. Remediation-Centric Philosophy

In traditional vulnerability management, an assessment produces a dump of hundreds or thousands of disassociated CVE items. Security teams then spend weeks triaging and sorting tickets before operations teams can begin patching.

**Sieve flips this paradigm:**
The primary output of the platform is an ordered queue of **Actionable Remediation Items**, each grouping related CVEs into a single practical fix.

```
Individual CVE Findings                     Grouped Remediation Item
────────────────────────                    ────────────────────────
CVE-2024-6387 (OpenSSH RCE)        ──┐
CVE-2023-38408 (PKCS#11 Provider)  ──┼───>  Action #1: Upgrade OpenSSH Server
CVE-2023-48795 (Terrapin Attack)   ──┘      - Single apt command
                                            - Resolves 3 CVEs across 5 hosts
                                            - 24% Total Risk Reduction
```

---

## 2. Action Grouping & Risk Reduction (§50.1)

### 2.1 Heuristic Grouping
Findings are synthesized based on shared remediation vectors:
1. **Package Upgrades:** Multiple CVEs affecting the same package (e.g. `openssh-server`, `nginx`, `mysql-server`, `openssl`) are consolidated into one package upgrade action.
2. **Configuration Changes:** TLS protocol deprecation, weak cipher hardening, or server header concealment are clustered into config-patching actions.
3. **Certificate Operations:** Expired or soon-to-expire certificates are grouped into rotation requests.

### 2.2 Quantified Risk Reduction
Each remediation item calculates its total risk contribution:
$$\text{RiskRemoved} = \sum \text{RiskScore}(\text{Finding}_i)$$

The dashboard aggregates this to show that resolving the top 4 remediation actions eliminates the majority of current environmental risk.

---

## 3. Multi-Modal Script Synthesis

For every remediation action, Sieve generates copy-pasteable snippets across three operational modalities:

1. **CLI Shell Command:**
   ```bash
   sudo apt-get update && sudo apt-get install -y --only-upgrade openssh-server && sudo systemctl restart openssh-server
   ```
2. **Ansible Playbook Task:**
   ```yaml
   - name: Upgrade openssh-server to latest security release
     ansible.builtin.apt:
       name: openssh-server
       state: latest
       update_cache: yes
     notify: Restart sshd
   ```
3. **Dockerfile Directive:**
   ```dockerfile
   RUN apt-get update && apt-get install -y --only-upgrade openssh-server && rm -rf /var/lib/apt/lists/*
   ```

---

## 4. Sub-60-Second Targeted Verification Rescans (§50.2)

A core failure of incumbent scanners is the inability to quickly confirm that a patch landed. Running a full network scan to check one patch takes hours.

Sieve implements **Sub-60-Second Verification Rescans**:
- Targets **only** the specific asset, port, and check plugin associated with the remediation item.
- Executes targeted protocol probes or credentialed package queries without re-scanning the entire subnet.
- Immediately updates the finding state to `FIXED` and records `fixed_at` timestamps in the audit trail.
- If the verification probe discovers the issue still present, the user receives actionable feedback immediately.
