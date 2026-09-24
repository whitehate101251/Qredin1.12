# ADR 0002 — First-party SPIFFE core on the standard library

- **Status:** Accepted
- **Date:** 2026-09-20
- **Deciders:** Security engineering
- **Plan reference:** §3.3, §9.3, Phase 2

## Context

Plan §3.3 says:

> Qredin should use an established SPIFFE library, preferably `go-spiffe` for Go
> workloads, rather than maintaining certificate and Workload API logic locally.

That guidance is correct **for workloads consuming identity**. It is the wrong
default for Qredin's own server, and this ADR records a deliberate, bounded
deviation.

Two facts drive the split:

1. `go-spiffe` has **no issuance path**. It is a consumer library. The Identity
   Server has to mint certificates against the X.509-SVID profile regardless of
   what library the client side uses, so the certificate-profile logic must
   exist in first-party code either way.
2. `go-spiffe`'s validator is deliberately **permissive** where the production
   plan requires strictness. It checks `CA=false`, absence of `keyCertSign` and
   `cRLSign`, and exactly one URI SAN. It does not require `digitalSignature`,
   does not enforce EKU semantics, and verifies with `ExtKeyUsageAny`. Plan
   §3.3 requires "required critical key-usage semantics" and "appropriate
   client/server EKU behavior".

## Decision

| Layer | Implementation | Rationale |
|---|---|---|
| `pkg/spiffeid`, `pkg/x509svid`, `pkg/x509bundle` | First-party, **standard library only** | Security-critical trust decision; must be auditable, fuzzable, and strict |
| X.509-SVID issuance (`internal/ca`) | First-party | No library provides it |
| Workload API **wire types** | Generated from the spec `.proto` | Byte-level interop, zero hand-maintained codegen |
| Workload API **semantics** (streaming, redaction, rotation, attestation) | First-party | This is the product |
| **Customer workloads** | `go-spiffe` recommended | Plan §3.3 applies here as written |

The security core takes **no third-party dependency**. It uses `crypto/x509`,
`encoding/json`, `net/url` and nothing else. `google.golang.org/grpc` and
`google.golang.org/protobuf` appear only in the Workload API transport packages.

## Consequences

**Cost:** we maintain an ID parser, a certificate-profile validator, and a JWK
Set codec. These are small but they are exactly the code an attacker attacks.

**Mitigation, and this is the load-bearing part of the ADR:** the first-party
core is only acceptable if it is proven equivalent-or-stricter than the
reference. `test/conformance` therefore asserts, per profile:

- every positive and negative case enumerated in the SPIFFE ID specification;
- the X.509-SVID profile constraints from plan §3.3 and §15.2;
- **differential tests against `go-spiffe`** — a build-tagged suite asserting
  that anything `go-spiffe` rejects, Qredin also rejects. Qredin may be
  strictier; it must never be more permissive. `go-spiffe` is a test-only
  dependency for this purpose and never enters a production binary.

**Rejected alternative:** depending on `go-spiffe` in the server and layering
extra checks on top. This produces two validators with two notions of validity
and a seam between them, which is worse than one strict validator.

## Where we are stricter than `go-spiffe`, and why

These are deliberate and may cause interop friction with non-conforming
issuers. Each is individually controllable via `x509svid.Profile` so an
operator can relax it with an explicit, audited configuration change rather
than a code change. Defaults are strict.

| Check | `go-spiffe` | Qredin default | Justification |
|---|---|---|---|
| Leaf `keyUsage` must include `digitalSignature` | not checked | required | Plan §3.3 |
| Leaf EKU must contain `clientAuth` or `serverAuth` | `ExtKeyUsageAny` | required | Plan §3.3 |
| Signing cert must not carry TLS EKU | not checked | rejected | Prevents a CA being used as a leaf |
| Clock skew | none | bounded, default 30s, max 5m | Plan §3.3 |
| Trust-domain bundle selected before chain build | by API shape | enforced structurally | Plan §3.1 |

See `docs/assumptions.md` for the cases where the specification is ambiguous
and we had to choose.
