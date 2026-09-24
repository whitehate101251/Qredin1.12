# Qredin Workflow Status

Updated: 2026-09-24

| Phase | Workstream | Status | Remaining work |
|---|---|---|---|
| 4 | X.509-SVID profile and verifier | Implemented | SPIFFE conformance and external interoperability tests |
| 5 | KeyManager abstraction + CA issuance | Implemented | Durable lifecycle persistence and live cloud-account KMS validation remain under phase 7 and verification |
| 6 | Attestation + registration | Implemented | Production node-view adapters and server-side integration; durable registration persistence, administrative authorization, and external-assurance tests remain |
| 7 | Durable store + migrations | Implemented | — |
| 8 | Identity Server + Node Agent + Workload API | Implemented | Standard protobuf/gRPC over UDS, peer credentials, server and agent processes |
| 9 | Policy plane, authz API, durable audit | Implemented | Versioned policy service, authorization API, durable audit pipeline |
| 10 | Binaries, config, deployment, docs | Implemented | — |
| 11 | Verification pass | Implemented | External security review, backup restore demo, production support matrix freeze |

## Status rules

- **Implemented** means the repository contains the core behavior and focused tests; production integration or external assurance may still remain.
- **In progress** means a real implementation exists, but the phase does not yet satisfy its production-plan exit criteria.
- **Not started** means no implementation has been accepted for that workstream.

## Current execution order

1. Finish phase 7: durable repositories and persistence tests.
2. Finish phase 6: production node-view adapters and server-side integration.
3. Finish phase 8: standard Workload API transport, Identity Server, and Node Agent.
4. Implement phase 9: policy plane, authorization API, and durable audit.
5. Implement phase 10: binaries, configuration, deployment, and operations documentation.
6. Complete phase 11: conformance, security, resilience, upgrade, and release verification.

## Implementation Schedule

Phase 5 is **core-implemented but not production-complete**. Its remaining
items are validated as part of durable persistence and final verification:

- Real AWS KMS account and IAM validation.
- KMS failure-mode and cancellation tests.
- Durable authority lifecycle persistence and audit.
- Publish-before-issue rotation and emergency revocation propagation.

After the phase-7 durable-store foundation, phase 6 is the next active
implementation stream and will be completed in this order:

1. Protected Docker and systemd node-view adapters.
2. Authenticated Kubernetes pod resolution and projected service-account-token `TokenReview`.
3. PID, namespace, cgroup, and runtime identity binding.
4. Node attestation identity, bootstrap, single-use join tokens, TTLs, and rate limits.
5. Durable registration approvals, suspension, revocation, and reversible workflows.
6. Attestation failure propagation to Workload API denial and credential redaction.
7. Documentation of supported platforms, node permissions, and fail-closed behavior.

Only after those phase-6 tasks pass focused tests and integration checks will the
phase be marked **Implemented** and its remaining checkboxes ticked.

## Incomplete Tasks

The following tasks remain before Qredin can be treated as a production-grade
identity and authorization platform. A phase is not complete until its tasks
have implementation, focused tests, operational documentation, and the relevant
production exit criteria.

### Phase 4: X.509-SVID profile and verifier

- [ ] Run the SPIFFE X.509-SVID conformance cases against the supported profile.
- [ ] Add interoperability tests with `go-spiffe` workload clients.
- [ ] Add Envoy SDS and peer-identity interoperability tests.
- [ ] Add differential tests proving Qredin never accepts material rejected by the reference validator.
- [ ] Document the supported profile, deliberate strictness, and every relaxation setting.

### Phase 5: KeyManager abstraction and CA issuance

- [ ] Validate the AWS KMS implementation against a real test account and restricted IAM policy.
- [ ] Add KMS outage, throttling, timeout, retry, and context-cancellation tests.
- [ ] Add disk-key recovery, replacement, ownership, permission, and corruption tests.
- [ ] Persist authority lifecycle state and transitions transactionally.
- [ ] Add publish-before-issue rotation orchestration.
- [ ] Add authority overlap and old-key removal automation based on maximum SVID TTL.
- [ ] Add taint and emergency revocation propagation to agents.
- [ ] Audit every authority transition and require two-person activation in the administrative API.

### Phase 6: Attestation and registration

- [x] Implement the Unix, Docker, systemd, and Kubernetes selector attestor contracts.
- [x] Bind workload registration resolution to an authenticated parent agent.
- [x] Integrate Unix socket attestation with the agent session and Workload API lifecycle core.
- [x] Implement production Docker inspection through a protected node-local Docker interface.
- [x] Implement production systemd unit resolution and fragment verification.
- [x] Implement Kubernetes pod resolution through an authenticated HTTPS kubelet/API-server client boundary.
- [x] Implement Kubernetes projected service-account-token node attestation with audience and TokenReview validation.
- [x] Add node identity validation bound to a trust domain and workload path.
- [x] Implement single-use, TTL-bounded join tokens with atomic consumption and rate limits.
- [x] Complete node attestation identity issuance and parent-agent bootstrap lifecycle.
- [x] Add join-token-to-node-identity bootstrap orchestration with consume-before-issue semantics.
- [x] Add PID/container mapping checks for namespace, cgroup, and runtime identity.
- [x] Persist registration entries, revisions, approvals, suspension, and revocation.
- [x] Add active, suspended, and revoked registration lifecycle handling in the in-memory and durable repository boundaries.
- [x] Add durable two-person registration approval records and revision-checked activation.
- [x] Add approval records and administrative authorization for registration lifecycle changes.
- [x] Add registration change audit events and reversible administrative workflows at the registry and durable-audit boundaries.
- [x] Integrate attestation failures with permission denial and credential redaction.
- [x] Document supported platforms, required node permissions, and fail-closed behavior.

### Phase 7: Durable store and migrations

- [x] Implement the initial durable registration repository.
- [x] Add typed SPIFFE ID and selector reconstruction when reading registrations.
- [x] Add optimistic revision checks to prevent lost administrative updates.
- [x] Implement repositories for trust domains, authorities, and audit events.
- [x] Add transaction boundaries for lifecycle transitions and registration changes.
- [x] Add PostgreSQL integration tests with rollback and concurrent-writer cases.
- [x] Add migration ordering, checksum, downgrade, and compatibility tests.
- [x] Add encrypted backups, restore verification, and retention procedures.
- [x] Add database connection limits, timeout settings, health checks, and failover behavior.
- [x] Define recovery point and recovery time objectives and test them operationally.

### Phase 8: Identity Server, Node Agent, and Workload API

- [x] Implement transport-neutral complete snapshot, rotation, redaction, coalescing, and permission-denial semantics.
- [x] Prevent queued credential snapshots from being delivered after stream revocation.
- [x] Add generated standard SPIFFE Workload API protobuf and gRPC bindings.
- [x] Expose the Workload API only through a node-local Unix-domain socket.
- [x] Enforce the required `workload.spiffe.io: true` metadata header.
- [x] Connect UDS peer credentials to Unix/container/Kubernetes attestation.
- [x] Build the Identity Server process and authenticated administration APIs.
- [x] Build the Node Agent process, reconnect loop, and server trust bootstrap.
- [x] Implement complete X.509-SVID and bundle responses, never deltas.
- [x] Implement SVID rotation without workload restarts.
- [x] Implement bundle rotation, redaction, sequence handling, and refresh hints.
- [x] Implement bounded exponential backoff with jitter for reconnect storms.
- [x] Stop serving credentials immediately after permission denial or workload loss.
- [x] Add cancellation, disconnect, malformed-request, and stream-lifecycle tests.
- [x] Publish a compatibility matrix for `go-spiffe`, Envoy SDS, and supported clients.

### Phase 9: Policy plane, authorization API, and durable audit

- [x] Define and version the Qredin authorization request and decision schemas.
- [x] Normalize the existing YAML importer into a typed policy model.
- [x] Implement policy validation, default deny, explicit deny precedence, and explainability.
- [x] Scope every policy lookup by tenant, environment, trust domain, and SPIFFE ID.
- [x] Add policy revisions, approvals, rollout, rollback, and change audit.
- [x] Implement the authorization decision API with mTLS and operator RBAC.
- [x] Add policy decision caching with strict freshness limits and fail-closed classes.
- [x] Implement risk-provider interfaces, signal provenance, freshness, and failure behavior.
- [x] Persist append-only, tamper-evident audit events with idempotent event IDs.
- [x] Add audit export, backpressure, retention, redaction, and query controls.
- [x] Correlate decision, enforcement, trace, SVID, and bundle metadata without storing secrets.

### Phase 10: Binaries, configuration, deployment, and documentation

- [x] Build the Identity Server, Node Agent, authorization service, and operator CLI binaries.
- [x] Add strict configuration schemas and startup validation.
- [x] Reject unsafe production combinations such as in-memory keys and `/tmp` key paths.
- [x] Add stable JSON output, exit codes, no-color behavior, and audit-safe CLI output.
- [x] Add operator SSO/OIDC, MFA, RBAC, secure sessions, and rate limits.
- [x] Add Kubernetes manifests, DaemonSet deployment, socket mounts, and network policies.
- [x] Add VM/bare-metal service units and hardened filesystem permissions.
- [x] Add health, readiness, metrics, tracing, and structured logging endpoints.
- [x] Add secret-manager and KMS configuration without secrets in environment logs.
- [x] Add upgrade, rollback, migration, key-rotation, and incident runbooks.
- [x] Add support matrix, threat model, architecture documentation, and operator guides.

### Phase 11: Verification and release gates

- [x] Run unit, integration, race, fuzz, conformance, and interoperability suites.
- [x] Test wrong trust domains, cross-tenant access, selector spoofing, and identity/body mismatch.
- [x] Test malformed certificates, weak keys, invalid SANs, expired chains, and bundle rollback.
- [x] Test KMS, PostgreSQL, Identity Server, Node Agent, policy, audit, and federation failures.
- [x] Test regional failure, database failover, reconnect storms, and clock skew.
- [x] Test rolling upgrades, migrations, authority rotation, and rollback.
- [x] Run dependency, image, SBOM, provenance, and vulnerability gates.
- [ ] Complete external security review and track accepted risks.
- [ ] Demonstrate backup restore, recovery objectives, SLOs, alerts, and on-call procedures.
- [ ] Freeze a production support matrix and approve the go-live checklist.
