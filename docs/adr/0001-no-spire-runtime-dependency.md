# ADR 0001 — Qredin implements SPIFFE; it does not run SPIRE

- **Status:** Accepted
- **Date:** 2026-09-20
- **Deciders:** Security architecture, Platform
- **Plan reference:** §0, §1.1, §1.2

## Context

SPIFFE defines an identity namespace, SVID formats, trust bundles, a Workload
API, and a federation protocol. SPIRE is the CNCF reference implementation of a
SPIFFE identity provider. Qredin needs a SPIFFE identity provider, and also
needs an authorization plane that SPIFFE deliberately does not define.

Three options were available:

1. Deploy SPIRE server + agent, and build Qredin as an authorization layer above it.
2. Vendor or fork SPIRE.
3. Implement the stable SPIFFE contracts as a first-party Qredin identity service.

## Decision

Option 3. Qredin implements the stable SPIFFE contracts itself. SPIRE remains a
**reference implementation and operational benchmark**, not a runtime
dependency, not a vendored library, and not a deployment artifact.

## Consequences

**We take on:** node and workload attestation, registration state, CA and key
lifecycle, SVID issuance, rotation, bundle publication and federation, plus the
conformance burden of proving interoperability rather than asserting it.

**We get:** one operational surface instead of two, an authorization plane that
is not bolted onto a foreign control plane, the ability to bind every issuance
decision to Qredin's own tenant and trust-domain model, and no coupling of our
release cadence to SPIRE's.

**The honest risk:** SPIRE encodes years of adversarial hardening. Re-deriving
it is the single largest source of security risk in this programme. We mitigate
by (a) treating the SPIFFE specifications, not SPIRE's behaviour, as the
contract; (b) shipping a conformance suite (`test/conformance`) and a published
support matrix (`docs/support-matrix.md`) rather than a "SPIFFE-compatible"
claim; (c) requiring external security review before any production trust
domain carries real traffic; (d) interoperability testing against `go-spiffe`
and Envoy SDS as third-party clients.

**Explicitly rejected:** claiming SPIFFE compatibility without per-profile
conformance tests. §1.1 of the plan calls this out and we treat it as binding.

## Scope discipline

The first production release implements the smallest useful stable surface
(plan §4.4): X.509-SVID issuance and validation, per-trust-domain X.509
bundles, the X.509 Workload API profile, registration with verified selectors,
and rotation/reconnect. JWT-SVID, federation, Broker API and WIT-SVID are
feature-gated and default off. WIT-SVID and Broker API are incubating
specifications and are not implemented at all in this release.
