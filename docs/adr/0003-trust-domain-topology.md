# ADR 0003 — Trust-domain topology and tenant isolation

- **Status:** Accepted
- **Date:** 2026-09-20
- **Plan reference:** §3.2, §6

## Decision

**One shared Qredin Identity Service, one trust domain per security boundary.**
This is the middle row of plan §6.2 — strong cryptographic boundary at medium
operational cost.

Naming scheme, organization-controlled to avoid collisions:

```
prod.identity.qredin.example.com
staging.identity.qredin.example.com
dev.identity.qredin.example.com
customer-<stable-id>.identity.qredin.example.com
```

`<stable-id>` is an opaque, immutable, Qredin-assigned identifier. It is **not**
a customer-chosen name, not a DNS label the customer controls, and not
derivable from the customer's brand — renames and acquisitions must not force a
trust-domain migration, and a customer must not be able to squat a name that
collides with an internal domain.

## Rules this imposes on the code

1. Production and non-production are **always** separate trust domains. A
   configuration that names a trust domain containing `dev`/`staging`/`test`
   while `environment: production` is set fails validation at startup.
2. Signing keys are never shared across trust domains. The key manager
   namespaces every key by trust domain; there is no API that returns a key
   without one.
3. Path components carry workload identity. A path is **not** an authorization
   boundary — `spiffe://td/ns/foo/sa/bar` being a prefix of another ID grants
   nothing. Policy matching on paths is exact or explicitly-globbed, never
   implicit-prefix. See `internal/policy`.
4. Trust-domain enrollment is an authenticated, reviewed, two-person operation
   (plan §12.2). A tenant can never self-select a trust domain and have it
   trusted. The admin API models this as propose → approve → activate.
5. Separate Identity Service per tenant (bottom row of §6.2) is supported by
   deployment topology, not by code branching: the same binary runs with a
   single-trust-domain configuration. Customers requiring independent
   administrators get their own deployment.

## Policy lookup key

Per plan §6.3, every policy lookup is keyed on the full tuple:

```
tenant_id + environment_id + trust_domain + spiffe_id
```

There is no lookup path that omits `trust_domain`. Wildcard rules are scoped
within a trust domain and cannot span domains — this is enforced at policy
**compile** time, not at evaluation time, so a cross-domain rule cannot be
deployed at all rather than being caught per-request.

## Consequences

Federation becomes the only mechanism for cross-domain authentication, which is
correct but means it is on the critical path sooner than plan §9.5 assumes.
Federation stays feature-gated and off until one trust domain is operational.
