# Sieve Security — Data Model & Identity Resolution

**Platform Version:** 3.1.0-alpha  
**Document Reference:** Plan Sections 6, 44, and Appendix B

---

## 1. Entity-Relationship Overview

```
tenant
 ├─ network_zone ────────────── scope / scanner_group
 ├─ scope ───────────────────── scope_entry / ownership_proof
 ├─ asset ───────────────────── asset_identity / asset_interface
 │   ├─ service
 │   ├─ finding ─────────────── finding_evidence / finding_state_history
 │   └─ remediation_item ────── verification_probe
 └─ scan_policy ─────────────── plugin_selection / audit_selection
      └─ scan_run ───────────── scan_job ─ scan_task
```

---

## 2. Network Zones & Overlapping RFC1918 Subnets (§6.1, §6.3)

Enterprise networks frequently feature duplicate IP spaces across branch offices, AWS VPCs, and merged corporate entities (e.g. `10.0.1.50` in London and `10.0.1.50` in Singapore).

In Sieve, every network asset and service is bound to a `network_zone_id`.
- **Zone Isolation:** Non-authoritative identity signals (such as `ipv4`, `mac_address`, and `netbios_name`) only correlate within the same `network_zone_id`.
- **Global Identifiers:** Authoritative signals (such as `agent_uuid` and `cloud_instance_id`) resolve globally across zones.
- Assets in separate zones never accidentally merge based on private IP address matches alone.

---

## 3. Multi-Signal Asset Identity Resolution (§6.3)

Assets are dynamic entities that cannot be uniquely identified by IP address alone due to DHCP re-assignment, NAT, and ephemeral containers.

### Signal Hierarchy:

| Signal | Confidence Level | Resolution Behavior |
|---|---|---|
| `agent_uuid` | **Authoritative** | Generated at agent installation; globally unique. |
| `cloud_instance_id` | **Authoritative** | Extracted from cloud metadata API (AWS, Azure, GCP). |
| `machine_guid` | **Authoritative** | Extracted from Windows registry `MachineGuid`. |
| `dmi_uuid` | High | Hardware UUID from BIOS/DMI; potential duplicate in cloned VMs. |
| `mac_address` | High | Valid only within the same L2 segment and `network_zone_id`. |
| `ssh_host_key_fp` | High | Host key fingerprint; persists across reboots. |
| `tls_cert_fp` | Medium | Leaf certificate fingerprint; shared wildcard certs ignored. |
| `fqdn` / `hostname` | Medium | DNS name; can fluctuate. |
| `ipv4` / `ipv6` | Low | Ephemeral; never used as a sole merge criterion. |

### Resolution Algorithm:
1. Lookup candidates across all identity signals in the asset's `network_zone_id`.
2. **Authoritative match:**
   - If exactly one asset matches: Bind observation.
   - If more than one asset matches: Flag conflict for human review; **never auto-merge conflicting authoritative identities**.
3. **Probabilistic scoring:**
   - High signal: `+3`
   - Medium signal: `+2`
   - Low signal: `+1`
   - Contradicting OS family: `-4`
   - Inactive > 30 days: `-1`
   - Bind candidate if `Score >= 5` and margin over runner-up `>= 2`. Otherwise, create a new asset.
4. **Reversible Merges:** Pre-merge states are stored with soft pointers (`merged_into`) ensuring any erroneous merge can be rolled back.

---

## 4. Finding Deduplication Key (§6.5)

To ensure findings remain consistent across recurring scans, deduplication keys are generated deterministically:

$$\text{DedupKey} = \text{SHA256}(\text{AssetID} : \text{PluginID} : \text{Port} : \text{Protocol} : \text{EvidenceSignature})[0:16]$$

- **AssetID:** Unique persistent asset identifier.
- **PluginID:** Kebab-case identifier of the detection plugin.
- **Port & Protocol:** The network endpoint (e.g. `22:tcp`).
- **EvidenceSignature:** Plugin-defined instance identifier (e.g. package name for OS vulnerabilities, or URL path for web vulnerabilities).

---

## 5. Finding Lifecycle State Machine

```
              ┌───────────────┐
              │  FIRST SEEN   │
              └───────┬───────┘
                      ▼
             ┌─────────────────┐
             │      OPEN       │◄─────────────────┐
             └────┬───────┬────┘                  │
                  │       │                       │ Reopened
     Verified     │       │ Probed Unsuccessfully │ (Regression)
     Patched      │       │ (Timeout / Auth Fail) │
                  ▼       ▼                       │
         ┌──────────┐   ┌───────────────────┐     │
         │  FIXED   │   │ UNVERIFIED ABSENT │─────┘
         └──────────┘   └───────────────────┘
```

- **OPEN:** Active vulnerability verified on the target.
- **FIXED:** Verified absent following a successful probe.
- **UNVERIFIED ABSENT:** Finding disappeared because the target host was unreachable or credentials failed. Prevents false victories.
- **RISK ACCEPTED:** Documented exception with mandatory expiration date and blast-radius preview.
- **FALSE POSITIVE:** Suppressed with feedback loop to improve plugin detection logic.
