-- Sieve Security Core Schema (Appendix B & Section 6)
-- Enforces Row-Level Security (RLS) across all tenant-partitioned entities.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenancy & Network Zones (§6.1, §6.3)
CREATE TABLE IF NOT EXISTS tenant (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS network_zone (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Authorization Scope & Exclusions (§4.1)
CREATE TABLE IF NOT EXISTS scope (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    attestation_expires TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS scope_entry (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scope_id UUID NOT NULL REFERENCES scope(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, -- cidr, ip, hostname, domain
    value TEXT NOT NULL,
    is_exclusion BOOLEAN NOT NULL DEFAULT FALSE
);

-- Assets & Multi-Signal Identity (§6.2, §6.3)
CREATE TABLE IF NOT EXISTS asset (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    network_zone_id UUID NOT NULL REFERENCES network_zone(id) ON DELETE CASCADE,
    display_name TEXT,
    ipv4 INET,
    ipv6 INET,
    mac_address MACADDR,
    hostname TEXT,
    fqdn TEXT,
    os_family TEXT,
    os_vendor TEXT,
    os_product TEXT,
    os_version TEXT,
    os_confidence SMALLINT,
    asset_class TEXT,
    criticality SMALLINT DEFAULT 5,
    exposure TEXT DEFAULT 'internal',
    environment TEXT DEFAULT 'prod',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scanned TIMESTAMPTZ,
    last_credentialed TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    attributes JSONB
);

CREATE TABLE IF NOT EXISTS asset_identity (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    network_zone_id UUID NOT NULL REFERENCES network_zone(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, network_zone_id, kind, value)
);

-- Network Services & Listeners (§6.4)
CREATE TABLE IF NOT EXISTS service (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    network_zone_id UUID NOT NULL REFERENCES network_zone(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    service_name TEXT NOT NULL,
    product TEXT,
    version TEXT,
    cpe TEXT[],
    tunnel TEXT DEFAULT 'none',
    tls_info JSONB,
    banner TEXT,
    banner_hash TEXT,
    process_pid INTEGER,
    process_binary TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Findings with Authoritative Dedup Key and Reachability (§6.5)
CREATE TABLE IF NOT EXISTS finding (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    network_zone_id UUID NOT NULL REFERENCES network_zone(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    service_id UUID REFERENCES service(id) ON DELETE SET NULL,
    plugin_id TEXT NOT NULL,
    plugin_version TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_v3_score NUMERIC(3,1),
    epss_score NUMERIC(5,4),
    in_kev BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score NUMERIC(5,2) NOT NULL,
    confidence TEXT NOT NULL,
    method TEXT NOT NULL,
    reachability TEXT NOT NULL DEFAULT 'unknown',
    cve_ids TEXT[],
    cwe_ids TEXT[],
    state TEXT NOT NULL DEFAULT 'open',
    evidence TEXT,
    evidence_signature TEXT,
    dedup_key TEXT NOT NULL,
    remediation_id UUID,
    first_detected TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_detected TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fixed_at TIMESTAMPTZ,
    reopened_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, dedup_key)
);

-- Remediation Items & Action Grouping (§50.1)
CREATE TABLE IF NOT EXISTS remediation_item (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    action_type TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    max_severity TEXT NOT NULL,
    total_risk_removed NUMERIC(6,2) NOT NULL,
    estimated_effort TEXT,
    cli_script TEXT,
    ansible_snippet TEXT,
    dockerfile_snippet TEXT,
    verification_cmd TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Row-Level Security Policies
ALTER TABLE asset ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE service ENABLE ROW LEVEL SECURITY;
ALTER TABLE scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_item ENABLE ROW LEVEL SECURITY;
