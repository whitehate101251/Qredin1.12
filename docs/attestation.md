# Attestation and Registration

Qredin derives workload identity from node-local, independently verified
metadata. A workload never supplies its SPIFFE ID, tenant, trust domain, or
selectors as proof.

## Platform boundaries

- Linux Unix-domain sockets use `SO_PEERCRED`, `/proc` start-time checks, UID,
  GID, supplementary groups, executable path and executable SHA-256.
- Namespace and cgroup selectors bind a PID to its runtime context and protect
  against PID/container confusion.
- Docker access uses a protected node-local Unix socket and accepts repository
  digests only. Mutable image tags are rejected.
- systemd identity includes the unit, fragment path and fragment SHA-256. A
  replacement fragment therefore changes the attested identity.
- Kubernetes pod attestation must use an authenticated kubelet/API-server view.
  Pod status image digests are used; pod spec tags are not identity evidence.
- Kubernetes projected service-account tokens require authenticated
  `TokenReview` and the exact Qredin node audience.

## Registration lifecycle

Registrations are server-side bindings between verified selectors, a parent
agent identity, tenant/environment scope, and a workload SPIFFE ID.

- `active`: selectors may resolve and issuance may proceed.
- `suspended`: the record remains available for administration, but resolution
  fails closed and no new SVID is issued. It may be reactivated after review.
- `revoked`: resolution fails closed permanently for that registration. Create a
  new reviewed registration rather than silently reusing the old binding.

Every lifecycle change must be persisted with a revision and an audit event.
The durable repository is the source of truth; an unavailable database must not
fall back to an in-memory authorization decision.

## Bootstrap and failure behavior

Join tokens are single-use, TTL-bounded, rate-limited bootstrap credentials.
The server consumes a token before issuing node identity, so issuance failure
cannot make the token replayable.

Attestation failure, missing registration, wrong parent agent, stale runtime
metadata, and unauthenticated Kubernetes metadata all fail closed. The agent
must deny the Workload API session and remove any cached SVIDs or bundles for a
workload that loses authorization.

## Required node permissions

- Linux agents require access to peer credentials and the relevant `/proc`
  entries for workload PIDs.
- Docker deployments require access to the protected Docker Unix socket and a
  node-local PID-to-container resolver.
- Kubernetes deployments require an authenticated node/API client, pinned
  endpoint trust, TokenReview permission, and read-only pod status access.
- systemd deployments require read access to cgroup metadata and approved unit
  fragment directories.

No deprecated unauthenticated kubelet read-only endpoint or public Workload API
endpoint is supported.
