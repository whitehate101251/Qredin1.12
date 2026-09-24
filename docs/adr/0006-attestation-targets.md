# ADR 0006 — Attestation targets for the first production release

- **Status:** Accepted
- **Date:** 2026-09-20
- **Plan reference:** §9.2, §9.4, §1.2

## Decision

Kubernetes is the primary, fully-exercised platform. VM/bare-metal attestors
ship, are unit-tested, and are documented as supported-but-less-exercised in
`docs/support-matrix.md`.

### Node attestors

| Plugin | Status | Evidence | Verified against |
|---|---|---|---|
| `k8s_psat` | **primary** | projected service account token, `aud`-bound | Kubernetes `TokenReview` API |
| `x509_join` | supported | node TLS client certificate | configured node CA + allowlisted subject constraints |
| `join_token` | bootstrap only | single-use token, short TTL | server-side token record, consumed atomically |
| `tpm_devid` | interface only | — | not implemented in v1 |

`join_token` is a bootstrap mechanism, not a production attestation strategy.
It is rate-limited, single-use with an atomic compare-and-delete, TTL-capped at
one hour, and produces a distinct audit event class so its use is visible.

### Workload attestors

| Plugin | Status | Selectors produced |
|---|---|---|
| `unix` | implemented | `uid`, `gid`, `supplementary_gid`, `binary_path`, `binary_sha256` |
| `k8s` | **primary** | `ns`, `sa`, `pod-name`, `pod-uid`, `node-name`, `pod-label:*`, `container-image-digest` |
| `systemd` | implemented | `unit`, `unit_fragment_path` |
| `docker` | implemented | `image_digest`, `label:*` |

## The rule that makes this safe

**The caller never names itself.** Caller identification is strictly
out-of-band, per plan §3.6 and §9.4:

1. The Workload API is a UDS. The agent reads `SO_PEERCRED` to obtain the
   caller's PID, UID and GID from the kernel. The workload cannot influence
   these.
2. The PID is resolved to a container/pod via the node's own view — kubelet's
   read-only pod list, cgroup inspection, the Docker socket — never via
   anything the workload supplies.
3. Selectors derived this way are matched against **server-side registration
   entries**. The server rejects any request carrying `workload-id`, a
   SPIFFE ID, selectors, tenant, or trust-domain claims as proof. Such fields
   are accepted only into a diagnostics-only struct that is never consulted
   during issuance, and their presence is recorded in the audit event.

### PID reuse

Resolving a PID to a container is a time-of-check/time-of-use hazard: the
process can exit and the PID be reused between `SO_PEERCRED` and the cgroup
read. Mitigation in `internal/attestation/workload/unix`: we read the process
start time (`/proc/<pid>/stat` field 22) **before and after** attestation and
abort if it changed, and we hold an open file descriptor on `/proc/<pid>` for
the duration so the entry cannot be recycled underneath us. Documented in
`docs/threat-model.md` as T-07.

### Image digest, not image tag

Registration selectors use `container-image-digest`. Plan §9.4 is explicit that
mutable tags are not identity. The `k8s` attestor reads digests from
`pod.status.containerStatuses[].imageID` — the tag from `spec` is deliberately
not offered as a selector, so an operator cannot accidentally register against
a mutable reference.

## Consequences

The kubelet read-only port and the Docker socket are attestation-critical
inputs. Both are node-local, and the agent must be able to reach them without
the workload being able to influence the answer. The agent talks to kubelet
over TLS using its own node identity and pins the kubelet CA; it does not use
the deprecated unauthenticated read-only port (`:10255`). If kubelet is
unreachable, workload attestation **fails closed** — no selectors, no SVID.
