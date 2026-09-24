# ADR 0004 — Constrained Qredin DSL as the production policy engine

- **Status:** Accepted
- **Date:** 2026-09-20
- **Plan reference:** §7.2

## Context

Plan §7.2 offers OPA/Rego, Cedar, or a constrained Qredin DSL compiled to a
tested evaluator, and prescribes the migration path: keep YAML as an import
format, normalize to a typed internal model, add validation and fixtures, then
introduce an engine behind a decision-provider interface.

## Decision

Ship a **constrained DSL** as the only enabled evaluator in v1, behind the
`PolicyDecisionProvider` interface so an OPA or Cedar provider can be added
without touching call sites.

The DSL is deliberately **not** Turing-complete. It is a typed condition tree
over a fixed attribute set:

```
identity      spiffe_id, trust_domain, path_segments
request       action, resource, method, path, audience
context       tenant_id, environment, time-of-day window, risk score/level
```

Operators: `eq`, `in`, `prefix` (explicit, path-segment-aware), `glob`
(bounded, no backtracking), `cidr`, `time_window`, `risk_below`, and
`and`/`or`/`not`. No user-supplied regular expressions — an operator cannot
introduce catastrophic backtracking into the request path.

## Why not OPA in v1

Rego is the expressive choice and has the best Envoy story, and we will
probably want it. But it puts a large, fast-moving dependency and a general
evaluation engine on the authorization hot path, which means eval timeouts,
memory caps, and sandboxing become security requirements rather than
niceties — and "explainable" turns into "ship a Rego trace", which is not the
same thing as telling an operator which condition failed.

The constrained DSL gives, by construction: **termination** (no loops, no
recursion, finite condition tree → provable bounded evaluation), **totality**
(every input yields a decision; no runtime errors that must be mapped to
deny), **explainability** (every condition node records matched/unmatched, so
`qredin authz check` shows exactly which clause decided), **diffability**
(`qredin policy diff` compares typed trees, not text), and **fuzzability**.

## Non-negotiable evaluation semantics

- **Default deny.** The zero value of a decision is DENY. There is no code path
  that returns ALLOW without an explicitly matched allow rule.
- **Explicit deny precedence.** Any matching deny rule wins over every allow
  rule, evaluated first, regardless of specificity or order.
- **Deterministic.** Evaluation order is fixed by compiled rule index, not by
  map iteration. Two evaluations of the same input against the same revision
  produce byte-identical explanations.
- **Trust domain is never wildcarded across domains** (ADR 0003).

## Migration path preserved

`internal/policy/importer` reads the prototype's YAML and normalizes it into
the typed model, so existing policies are portable. Import is a build-time /
admin-time operation producing a reviewed revision — YAML is never loaded from
disk at request time in production.

## Revisit trigger

Revisit if any of: a tenant needs policy logic the DSL cannot express and the
workaround is rule explosion; we adopt Envoy ext_authz with OPA already in the
mesh; or formal analysis of policies becomes a compliance requirement (which
would favour Cedar).
