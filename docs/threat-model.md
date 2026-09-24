# Qredin Threat Model

## Scope

This document models threats to Qredin in a production deployment spanning Kubernetes, VM/bare-metal, and cloud database deployments.

## Trust Boundaries

1. **Workload ↔ Agent**: Trusted within a node but isolated by namespace/container.
2. **Agent ↔ Server**: Untrusted network; secured via mTLS with node-attested identities.
3. **Server ↔ Database**: Secured via TLS and database credentials.
4. **Server ↔ KMS (AWS KMS)**: Uses IAM roles; key material never leaves KMS.
5. **Operator ↔ Admin API**: Requires SSO/OIDC, MFA, and RBAC.

## Assets

- CA private keys
- Workload SVIDs (short-lived X.509 certificates)
- Registration entries and policies
- Audit events (tamper-evident log)
- Database records

## Threat Actors

| Actor | Trust | Capabilities |
|---|---|---|
| Untrusted network | Untrusted | Passive eavesdropping, injection, replay |
| Compromised workload | Low | Can attempt invalid SVID requests, spoofing selectors |
| Malicious node operator | Low | Can attempt to bypass attestation, forge node identity |
| Compromised agent | Low | Can attempt to obtain SVIDs for unauthorized workloads |
| External attacker | Zero | Can attempt to access Workload API socket, gRPC endpoints |
| Compromised database | High | Full read access to registrations, policies, audit |
| Operator | High | Full configuration, policy, and audit access |

## Threats and Mitigations

| Threat | STRIDE | Mitigation |
|---|---|---|
| SVID forgery | Spoofing | CA key managed by KeyManager abstraction; AWS KMS never exposes key material |
| Selector spoofing | Tampering | Workload attested via UDS peer credentials; selectors derived from OS identity |
| Replay of SVID | Repudiation | SVIDs are short-lived (<1h); rotation without restart |
| Audit tampering | Tampering | Append-only, idempotent event IDs; never stores secrets |
| /tmp key path | Elevation of privilege | Production config rejects `/tmp` key directories |
| In-memory keys | Information disclosure | KMS backend required in production; disk keys rejected if world-readable |
| Network interception | Eavesdropping | All gRPC uses mTLS; Workload API over UDS |
| Operator compromise | Elevation of privilege | SSO/OIDC, MFA, RBAC, audit-safe CLI output |
| Database exposure | Information disclosure | TLS to database; secrets from secret manager, not env |
| Cross-tenant policy access | Elevation of privilege | Policy lookups scoped by tenant, environment, trust domain, SPIFFE ID |

## Attack Trees

### Obtain CA Private Key
- Path 1: Compromise AWS KMS IAM role → Requires IAM privilege escalation → Mitigated by least-privilege IAM
- Path 2: Read disk key file → File permissions 0o600 enforced → Mitigated by systemd hardening
- Path 3: Memory dump of server process → KeyManager keys held only in process memory; mitigated by process isolation

### Impersonate Another Workload
- Path 1: Connect to Workload API with forged selectors → UDS peer credentials bind to kernel identity → Mitigated by node attestation
- Path 2: Compromise agent → Agent must re-attest on every SVID request → Mitigated by per-request attestation checks
- Path 3: Replay captured SVID → SVID TTL < 1h → Mitigated by short lifetimes and rotation

### Bypass Authorization Policy
- Path 1: Cross-tenant data access → Policies scoped by tenant ID → Mitigated by policy scope enforcement
- Path 2: Race condition on policy eval → Single-writer with revision checks → Mitigated by optimistic locking
- Path 3: Cache poisoning → Cache has strict freshness limits → Mitigated by fail-closed on cache miss