# Sieve Security — Deployment & Test Lab Runbook

**Platform Version:** 3.1.0-alpha  
**Target Host:** `192.168.1.30` (Ubuntu 24.04 LTS, Noble Numbat)  
**Document Reference:** Plan Sections 9, 82, 90, 98

---

## 1. Deployment Architecture

Sieve Security is engineered as a self-contained, statically compiled Go binary with zero external runtime dependencies. The embedded web UI assets, declarative YAML plugins, and REST APIs run in a unified process.

```
/opt/sieve/
 ├── sieve                # Statically linked binary (amd64)
 ├── sieve.service        # Systemd unit file
 ├── content/
 │    └── plugins/        # Declarative vulnerability YAML checks
 └── data/
      └── store.json      # ACID transactional JSON persistence store
```

---

## 2. Automated Remote Deployment

The automated deployment script `deploy/deploy_vm.sh` executes the 5-stage deployment pipeline:

```bash
./deploy/deploy_vm.sh 192.168.1.30 root
```

### Execution Pipeline:
1. **Compilation:** Compiles a zero-dependency static binary using `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`.
2. **Bundle Packaging:** Stages binary, YAML plugin content, and systemd units.
3. **Artifact Sync:** Transfers files to `/opt/sieve/` over secure SSH.
4. **Firewall & Service Configuration:**
   - Adds UFW ingress rule: `ufw allow 8080/tcp comment "Sieve Security Web UI"`
   - Installs systemd unit to `/etc/systemd/system/sieve.service`
   - Enables and restarts `sieve.service`.
5. **Health Verification:** Probes `http://192.168.1.30:8080/api/v1/health` to confirm active daemon readiness.

---

## 3. Systemd Service Specification (`/etc/systemd/system/sieve.service`)

```ini
[Unit]
Description=Sieve Security — Vulnerability Management Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/sieve
ExecStart=/opt/sieve/sieve server --addr 0.0.0.0:8080 --plugins-dir /opt/sieve/content/plugins --data-file /opt/sieve/data/store.json
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security Hardening
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

---

## 4. Test Lab Results on `192.168.1.30`

### 4.1 Target Environment
- **Host:** `192.168.1.30`
- **OS:** Ubuntu 24.04 LTS (Kernel `7.0.14-11-pve`)
- **Memory:** 32 GB RAM (26 GB available)
- **Active Listeners:** OpenSSH (22), Nginx (80, 443, 8443), MySQL (3306, 33060), ProFTPD (21), Varnish (6081)
- **Firewall Policy:** UFW active (Incoming 22, 80, 443, 8080, 8443 allowed; 21, 3306 dropped externally)

### 4.2 Verified Assessment Findings
1. **OpenSSH Server Remote Code Execution (regreSSHion - CVE-2024-6387):**
   - **Severity:** Critical (CVSS 8.1)
   - **Reachability Proof:** `listening_process` (Port 22/tcp active, mapped to PID 141376 `/usr/sbin/sshd`)
   - **Confidence:** Probable (`version_inference`)
   - **Remediation:** Action #1 (`sudo apt-get update && sudo apt-get install -y --only-upgrade openssh-server`)
2. **MySQL Network Exposure:**
   - **Severity:** Medium
   - **Reachability Proof:** `listening_process` (Ports 3306 and 33060 mapped to MySQL handshake daemon)
   - **Remediation:** Action #2 (`sudo apt-get update && sudo apt-get install -y --only-upgrade mysql-server`)

### 4.3 Verification Rescan Benchmark (§50.2)
- Target: `fnd-asset-127-0-0-1-22-openssh-regresshion-cve-2024-6387`
- Execution Time: **0.18 ms** (Well below the 60-second SLA constraint)
- Status: Pass
