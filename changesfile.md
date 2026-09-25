# Qredin 1.2 — Garage/Workshop Testing & Validation Plan

> **Purpose:** This document lists every test, validation step, and potential fix needed
> before Qredin leaves the workshop and hits the track (production).
> No code changes are included — only the list of *what* needs to happen and *where*.

---

## 🏁 Phase 0 — Environment Setup (Workshop Prep)

Before any testing, the local non-production stack must be bootable and healthy.

| # | Action | Command / Location | Status |
|---|--------|--------------------|--------|
| 0.1 | Install prerequisites (`protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`, `golangci-lint`, `syft`, `govulncheck`) | See [`docs/BUILD.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/docs/BUILD.md) | ☐ |
| 0.2 | Generate protobuf/gRPC bindings | `make proto` | ☐ |
| 0.3 | Verify generated code exists | `make proto-check` | ☐ |
| 0.4 | Tidy modules | `make tidy` | ☐ |
| 0.5 | Build all 5 binaries (`qredin-server`, `qredin-agent`, `qredin-authz`, `qredin`, `qredin-operator`) | `make build` | ☐ |
| 0.6 | Start non-production Docker Compose stack (Postgres + services) | `make dev-up` | ☐ |
| 0.7 | Apply database migrations against dev Postgres | `make migrate` | ☐ |

---

## 🔬 Phase 1 — Static Analysis & Linting Gate

These are fast, zero-infrastructure checks. Every one must pass green before running any tests.

| # | Check | Command | What It Catches |
|---|-------|---------|-----------------|
| 1.1 | `go vet` | `make vet` | Suspicious constructs, misaligned struct tags, printf mismatches |
| 1.2 | `golangci-lint` (35 linters, security-tuned) | `make lint` | Unchecked errors (`errcheck`), fail-open bugs (`nilerr`), leaked contexts (`contextcheck`), banned functions (`forbidigo`), SQL leaks (`sqlclosecheck`), `gosec` security issues |
| 1.3 | `govulncheck` (CVE scan against Go vuln DB) | `make vulncheck` | Known CVEs in dependencies (`pgx`, `aws-sdk-go-v2`, `grpc`, `protobuf`, `yaml.v3`) |
| 1.4 | Format check | `make fmt` | gofumpt formatting consistency |

> **Potential fix area:** If `govulncheck` flags a CVE, the dependency version in
> [`go.mod`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/go.mod) / [`go.sum`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/go.sum) must be bumped.

---

## 🧪 Phase 2 — Unit Tests (Full Suite with Race Detector)

### 2.1 Full test suite

```bash
make test          # go test -race -count=1 ./...
```

This runs **every `_test.go` file** across all packages with Go's race detector enabled.
Must produce **0 failures, 0 data races.**

### 2.2 Security-critical core (fast focused run)

```bash
make test-core     # ./pkg/... ./internal/ca/... ./internal/policy/...
```

Covers the trust-boundary packages where a bug = a security bypass:

| Package | What It Tests |
|---------|---------------|
| [`pkg/spiffeid`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/pkg/spiffeid) | SPIFFE ID parsing, trust-domain isolation, malformed input rejection |
| [`pkg/x509svid`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/pkg/x509svid) | X.509-SVID profile compliance, certificate validation, TLS interop |
| [`pkg/bundle`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/pkg/bundle) | Trust bundle integrity, cross-domain prevention |
| [`internal/ca`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/ca) | CA lifecycle, rotation, node issuance |
| [`internal/policy`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/policy) | Policy model, default deny, explicit deny precedence |

### 2.3 Coverage report

```bash
make cover
```

Generate and review the coverage report. Security-critical packages (`pkg/*`, `internal/ca`, `internal/policy`, `internal/attestation`) should have **≥ 90% coverage.** Anything under 80% is a red flag to investigate before track day.

---

## 🌀 Phase 3 — Fuzz Testing (Trust-Boundary Inputs)

```bash
make fuzz-spiffeid    # go test -fuzz=FuzzParseID -fuzztime=120s ./pkg/spiffeid
```

Run the SPIFFE ID parser fuzzer for at least **2 minutes.** This hammers the trust-boundary input parser with random data looking for panics, hangs, or incorrect accepts.

**Additional fuzz targets to run manually if they exist:**

```bash
# Check for fuzz tests in the bundle package
go test -fuzz=. -fuzztime=120s ./pkg/bundle
```

> **Potential fix area:** Any panic or unexpected accept from fuzzing must be fixed in
> [`pkg/spiffeid`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/pkg/spiffeid) or [`pkg/bundle`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/pkg/bundle) before going to the track.

---

## 🔗 Phase 4 — SPIFFE Conformance Suite

```bash
make conformance    # go test -race -count=1 -tags=conformance ./test/conformance/...
```

Validates that Qredin's X.509-SVID profile, trust bundle handling, and Workload API behavior conform to the **SPIFFE specification.** This is the external interoperability gate.

> **Potential fix areas (from [`workflow.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/workflow.md) Phase 4):**
> - Add interoperability tests with `go-spiffe` workload clients.
> - Add Envoy SDS interoperability tests.
> - Add differential tests proving Qredin never accepts material rejected by the reference validator.

---

## 🗄️ Phase 5 — Integration Tests (Requires Live Postgres)

```bash
export QREDIN_TEST_POSTGRES_DSN="postgres://qredin:password@localhost:5432/qredin_test?sslmode=disable"
make integration    # go test -race -count=1 -tags=integration -timeout=10m ./test/integration/...
```

This is the **big one.** Requires a running PostgreSQL instance (the `make dev-up` stack provides one). Tests cover:

| Area | What It Validates |
|------|-------------------|
| **Durable Store** ([`internal/store`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/store)) | Registration CRUD, optimistic locking, transaction rollback, concurrent writers, pool health, connection limits |
| **Migrations** | Migration ordering, checksums, downgrade paths, compatibility |
| **Backup/Restore** | Encrypted backup creation, restore verification, retention cleanup |
| **Registration Lifecycle** | Active → suspended → revoked transitions, approval workflows, revision checks |
| **Audit Events** | Append-only persistence, idempotent event IDs, tamper-evidence |

> **Potential fix areas (from [`workflow.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/workflow.md) Phase 7):**
> - PostgreSQL rollback and concurrent-writer edge cases.
> - Migration downgrade and compatibility validation.
> - Database connection limits, timeout settings, health checks, and failover behavior.
> - RPO < 24h and RTO < 1h operational validation.

---

## 🏗️ Phase 6 — Component-Level Validation

These are the specific components that need focused workshop inspection.

### 6.1 Attestation Subsystem ([`internal/attestation`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/attestation))

| Attestor | Test Focus | Risk if Broken |
|----------|------------|----------------|
| Unix (`workload/unix`) | UDS peer credentials → PID → identity binding | Workload impersonation |
| Docker (`workload/docker`) | Docker API inspection through node-local socket | Container identity spoofing |
| systemd (`workload/systemd`) | Unit resolution, fragment verification | Service identity spoofing |
| Kubernetes (`workload/kubernetes`) | Pod resolution via authenticated HTTPS client, `TokenReview` validation | Cross-namespace identity leaks |
| Node bootstrap (`node/bootstrap`) | Join token consumption, TTL, rate limits, consume-before-issue | Unauthorized node enrollment |
| Token review (`node/tokenreview`) | Projected SA token validation, audience binding | Node impersonation via stolen token |

> **Changes needed (from [`workflow.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/workflow.md) Phase 6):**
> - Complete node attestation identity issuance and parent-agent bootstrap lifecycle.
> - Persist registration entries, revisions, approvals, suspension, and revocation durably.
> - Add approval records and admin authorization for registration lifecycle changes.
> - Integrate attestation failures with permission denial and credential redaction.

### 6.2 Key Manager ([`internal/keymanager`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/keymanager))

| Backend | Test Focus |
|---------|------------|
| Disk (`disk.go`) | File permissions (0600), recovery, replacement, ownership, corruption handling |
| AWS KMS (`kms.go`) | Outage/throttling/timeout/retry/context-cancellation behavior |

> **Changes needed (from [`workflow.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/workflow.md) Phase 5):**
> - Validate AWS KMS against a real test account with restricted IAM.
> - Add KMS failure-mode and cancellation tests.
> - Persist authority lifecycle state transactionally.
> - Add publish-before-issue rotation orchestration.
> - Add taint/emergency revocation propagation to agents.

### 6.3 CA Lifecycle ([`internal/ca`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/ca))

- Authority rotation: old → new key with overlap based on max SVID TTL.
- Node issuance: agent bootstrap → node SVID → workload SVID chain.
- Revocation propagation: must reach all agents within 5 minutes (per threat model).

### 6.4 Workload API ([`internal/workloadapi`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/workloadapi))

> **Changes needed (from [`workflow.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/workflow.md) Phase 8):**
> - Add standard SPIFFE Workload API protobuf/gRPC bindings (generated via `make proto`).
> - Expose API only through node-local UDS.
> - Enforce required `workload.spiffe.io: true` metadata header.
> - Connect UDS peer credentials to attestation.
> - Implement SVID rotation without workload restarts.
> - Implement bundle rotation, redaction, sequence handling, refresh hints.
> - Implement bounded exponential backoff with jitter for reconnect storms.
> - Stop serving credentials immediately after permission denial or workload loss.
> - Add cancellation, disconnect, malformed-request, and stream-lifecycle tests.

### 6.5 Authorization & Policy ([`internal/authorization`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/authorization), [`internal/policy`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/policy))

> **Changes needed (from [`workflow.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/workflow.md) Phase 9):**
> - Policy validation: default deny, explicit deny precedence, explainability.
> - Scope every policy lookup by tenant, environment, trust domain, SPIFFE ID.
> - Decision caching with strict freshness limits and fail-closed on cache miss.
> - Risk-provider interfaces, signal provenance, freshness, failure behavior.
> - Append-only, tamper-evident audit events with idempotent event IDs.
> - Audit export, backpressure, retention, redaction, and query controls.

### 6.6 Configuration Validation ([`internal/config`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/config))

Verify the following unsafe-combination rejections work:
- In-memory keys in production → **must reject**.
- `/tmp` key paths in production → **must reject**.
- Missing TLS certs in production → **must reject**.
- World-readable key files → **must reject**.

### 6.7 Server & Agent Processes ([`internal/server`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/server), [`internal/agent`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/internal/agent))

> **Changes needed (from [`workflow.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/workflow.md) Phase 8):**
> - Build the Identity Server process and authenticated admin APIs.
> - Build the Node Agent process, reconnect loop, and server trust bootstrap.
> - Complete X.509-SVID and bundle responses (never deltas).

---

## 🛡️ Phase 7 — Security Validation

### 7.1 Threat Model Validation

Cross-reference every threat from [`docs/threat-model.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/docs/threat-model.md):

| Threat | Mitigation | Test |
|--------|------------|------|
| SVID forgery | KMS key isolation | Attempt SVID issuance without valid CA key |
| Selector spoofing | UDS peer credentials | Attempt connection with forged PID/cgroup |
| Replay SVID | Short TTL < 1h | Present expired SVID, verify rejection |
| Audit tampering | Append-only, idempotent IDs | Attempt duplicate event insertion |
| `/tmp` key path | Config rejection | Set key path to `/tmp`, verify startup failure |
| In-memory keys in prod | Config rejection | Set memory backend in prod config, verify failure |
| Cross-tenant policy | Scoped lookup | Attempt policy evaluation with wrong tenant ID |
| Network interception | mTLS enforcement | Attempt plaintext gRPC connection, verify rejection |

### 7.2 Attack-Tree Scenarios (manual pen-test in workshop)

From the threat model:

1. **Obtain CA private key** — attempt IAM privilege escalation, disk key file read, memory dump.
2. **Impersonate another workload** — forge selectors via UDS, replay captured SVID.
3. **Bypass authorization policy** — cross-tenant access, race condition on policy eval, cache poisoning.

### 7.3 Negative Security Tests (from [`workflow.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/workflow.md) Phase 11)

- Wrong trust domains → must reject.
- Cross-tenant access → must deny.
- Selector spoofing → must detect.
- Identity/body mismatch → must reject.
- Malformed certificates → must reject.
- Weak keys → must reject.
- Invalid SANs → must reject.
- Expired chains → must reject.
- Bundle rollback → must handle safely.

---

## 💥 Phase 8 — Chaos & Resilience Testing

These validate fail-safe behavior under duress. Run inside the `make dev-up` stack.

| # | Scenario | How to Simulate | Expected Behavior |
|---|----------|-----------------|-------------------|
| 8.1 | Database primary failover | `docker stop` the Postgres container | Server queues operations, reconnects when DB returns |
| 8.2 | Server restart mid-stream | Kill `qredin-server` while agents are connected | Agents reconnect with bounded exponential backoff + jitter |
| 8.3 | Network partition | `iptables` drop between agent ↔ server | Agent enters reconnect loop, no credential leak |
| 8.4 | Clock skew | Advance system clock by 2h | SVID validation correctly handles time drift |
| 8.5 | Reconnect storm | Kill server, start 50+ agents simultaneously | Rate limiting, backoff prevents thundering herd |
| 8.6 | Resource exhaustion | Limit server to 128MB RAM, 0.5 CPU | Graceful degradation, health endpoint reports unhealthy |
| 8.7 | KMS outage | Block egress to AWS KMS endpoint | Cached keys continue to serve; new issuance queued |
| 8.8 | Database connection pool exhaustion | Set `max_connections=5`, run 20 concurrent requests | Proper queuing, timeout, no leaked connections |

---

## 📋 Phase 9 — Smoke Tests (End-to-End in Workshop Stack)

Run against the `make dev-up` stack. These are the minimum viable checks from [`docs/go-live-checklist.md`](file:///home/nomnom/Desktop/Qredin%201.2%20(Copy)/docs/go-live-checklist.md):

| # | Smoke Test | Pass Criteria |
|---|------------|---------------|
| 9.1 | Server starts without errors | Clean logs, no panics |
| 9.2 | Agent connects to server | Authenticated mTLS session established |
| 9.3 | Workload API responds to valid requests | SVID returned for registered workload |
| 9.4 | Workload API rejects invalid requests | Proper error code, no credential leak |
| 9.5 | SVID issued for test workload | Valid X.509-SVID with correct SPIFFE ID |
| 9.6 | SVID verified by peer | Peer validates SVID against trust bundle |
| 9.7 | Bundle rotation works | New bundle propagated, old bundle still accepted during overlap |
| 9.8 | Authorization decisions returned | Policy evaluation returns allow/deny with correlation ID |
| 9.9 | Audit events recorded | Events persisted in durable store with correct metadata |
| 9.10 | Health/readiness endpoints | `/healthz` and `/readyz` return 200 |
| 9.11 | Metrics endpoint | Prometheus metrics exposed and scrapable |
| 9.12 | Version embedding | `qredin-operator --version` shows correct version, commit, build date |

---

## 📊 Phase 10 — Full Pre-Commit Gate

This is the single command that must pass before the project leaves the workshop:

```bash
make verify    # tidy → vet → lint → test → conformance → vulncheck
```

And the full release gate (if targeting a release):

```bash
make release-gate    # verify + integration + SBOM generation
```

**Both commands must exit 0 with zero failures.**

---

## 📝 Summary — What Must Be Fixed/Changed Before Track Day

### Critical (Must fix — blocks track testing)

| # | Area | Issue | Files Involved |
|---|------|-------|----------------|
| C1 | Phase 8 | Standard SPIFFE Workload API gRPC transport not yet exposed over UDS | `internal/workloadapi/`, `api/proto/` |
| C2 | Phase 8 | Identity Server and Node Agent process binaries need server integration | `internal/server/`, `internal/agent/`, `cmd/qredin-server/`, `cmd/qredin-agent/` |
| C3 | Phase 6 | Node attestation identity issuance + parent-agent bootstrap incomplete | `internal/attestation/node/` |
| C4 | Phase 6 | Attestation failure → permission denial → credential redaction chain not connected | `internal/attestation/`, `internal/workloadapi/` |
| C5 | Phase 8 | SVID rotation without workload restarts not yet implemented | `internal/workloadapi/` |

### High (Should fix — risks safety on track)

| # | Area | Issue | Files Involved |
|---|------|-------|----------------|
| H1 | Phase 7 | PostgreSQL concurrent-writer and rollback integration tests missing | `internal/store/`, `test/integration/` |
| H2 | Phase 7 | Migration downgrade and compatibility tests missing | `internal/store/migrate/` |
| H3 | Phase 5 | AWS KMS live-account validation never performed | `internal/keymanager/kms.go` |
| H4 | Phase 5 | Authority lifecycle persistence not transactional | `internal/ca/`, `internal/store/` |
| H5 | Phase 6 | Durable registration persistence (approvals, revocation) incomplete | `internal/registration/`, `internal/store/registrations/` |
| H6 | Phase 8 | Reconnect backoff with jitter for reconnect storms not implemented | `internal/agent/` |

### Medium (Should address — improves reliability)

| # | Area | Issue | Files Involved |
|---|------|-------|----------------|
| M1 | Phase 7 | DB connection limits, health checks, failover behavior untested | `internal/store/health/`, `internal/store/pool/` |
| M2 | Phase 7 | RPO/RTO operational validation never performed | `internal/store/backup/` |
| M3 | Phase 5 | Publish-before-issue rotation orchestration missing | `internal/ca/` |
| M4 | Phase 5 | Taint/emergency revocation propagation to agents missing | `internal/ca/`, `internal/agent/` |
| M5 | Phase 9 | Risk-provider interfaces and signal provenance not implemented | `internal/authorization/` |
| M6 | Phase 9 | Audit export, backpressure, retention controls not implemented | `internal/store/` |

### Low (Nice to have before track day)

| # | Area | Issue | Files Involved |
|---|------|-------|----------------|
| L1 | Phase 4 | SPIFFE conformance and `go-spiffe` interop tests not yet run | `test/conformance/` |
| L2 | Phase 4 | Envoy SDS interop tests missing | `test/conformance/` |
| L3 | Phase 8 | `go-spiffe`, Envoy SDS compatibility matrix not published | `docs/compatibility.md` |
| L4 | Phase 10 | Operator SSO/OIDC, MFA, RBAC not yet implemented | `cmd/qredin-operator/` |

---

## ✅ Workshop Exit Criteria

The project is ready to leave the garage when ALL of the following are true:

- [ ] `make verify` exits 0 (vet + lint + test + conformance + vulncheck)
- [ ] `make integration` exits 0 against a real Postgres instance
- [ ] `make fuzz-spiffeid` runs for 2+ minutes with 0 failures
- [ ] `make cover` shows ≥ 80% on security-critical packages
- [ ] All 12 smoke tests (Phase 9) pass against `make dev-up` stack
- [ ] All 8 chaos scenarios (Phase 8) produce correct fail-safe behavior
- [ ] All Critical (C1–C5) issues are resolved
- [ ] All High (H1–H6) issues are resolved or have documented mitigations
- [ ] Threat model scenarios manually validated
- [ ] `make release-gate` exits 0 (verify + integration + SBOM)

---

*Generated: 2026-09-25 | No code changes made — this is a read-only validation plan.*
