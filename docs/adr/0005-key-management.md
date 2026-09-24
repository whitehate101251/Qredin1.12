# ADR 0005 — Signing-authority protection and the KeyManager boundary

- **Status:** Accepted
- **Date:** 2026-09-20
- **Plan reference:** §9.1, §12.3, forbidden pattern "in-memory CA"

## Decision

All signing is performed through a `KeyManager` interface that exposes
`crypto.Signer` semantics and **never returns private key material**. Three
implementations ship:

| Implementation | Allowed environment | Key custody |
|---|---|---|
| `memory` | tests only | process memory, discarded |
| `disk` | non-production, and edge/air-gapped production with a documented exception | file, `0600`, ownership + mode verified on every open |
| `awskms` | production default | key never leaves KMS; Qredin holds key ID + public key only |

## The guardrail that matters

The prototype's in-memory CA is a forbidden pattern, and "don't do that" is not
a control. So it is enforced structurally in three places:

1. `keymanager.Open` takes the deployment environment as a parameter. The
   `memory` manager returns `ErrNotProductionSafe` when the environment is
   `production`. It cannot be configured around.
2. `memory` is registered in the catalog **only** from a `_test.go` file and
   from an explicitly `dev`-tagged build. A production binary does not contain
   a constructor for it.
3. `config.Validate` rejects `environment: production` combined with
   `key_manager.type: memory` or a `disk` manager whose path is under `/tmp`.

Three independent layers because any one of them can be defeated by a hurried
configuration change; all three require a code change plus review.

## KMS specifics

Signing uses `ECDSA_SHA_256` over a **digest** (`MessageType: DIGEST`), not the
raw TBS bytes, so the payload sent to KMS is 32 bytes and request size is not a
scaling concern. Default key spec is `ECC_NIST_P256`; RSA is supported for
compatibility with existing enterprise PKI but is not the default.

`awskms.Signer.Public()` is resolved once at open time via `GetPublicKey` and
cached — it is immutable for the key's lifetime, and a per-signature lookup
would put an extra network round trip on every issuance.

KMS is a hard dependency on the issuance path. The Identity Server therefore
pre-signs nothing and caches no signing capability; a KMS outage stops *new*
issuance but does not invalidate outstanding SVIDs. Agents hold SVIDs with
lifetime well beyond the rotation threshold specifically so a bounded KMS
outage is survivable. See `docs/operations.md`, failure case "signing authority
unavailable".

## Authority lifecycle

Rotation follows the SPIFFE bundle rules in plan §3.7 — publish before issuing,
allow refresh time, remove only after outstanding SVIDs expire:

```
PREPARED  → published in the bundle, not yet signing
ACTIVE    → signing
OLD       → no longer signing, still published (overlap window)
TAINTED   → compromised; published as revoked, forces re-issuance
REVOKED   → removed from the bundle
```

Transitions are explicit operator actions, individually audited, and
`PREPARED → ACTIVE` requires two-person approval (plan §12.2). The overlap
window defaults to `2 × max SVID TTL` and validation refuses to shorten it
below `1 × max SVID TTL`.

## Rejected

- **Vault Transit** — viable, and the right answer for a Vault-centric shop. Not
  chosen because it adds a second secrets system for organisations already on
  KMS. `internal/keymanager` is structured so a Vault implementation is one
  package.
- **PKCS#11** — requires cgo, which conflicts with `CGO_ENABLED=0` static
  builds, and needs SoftHSM in CI. Deferred, not rejected on merit; it remains
  the right answer for on-prem HSM estates.
- **Upstream CA / Qredin-as-intermediate** — supported by the chain assembly in
  `internal/ca` but not the default. When an enterprise PKI owns the root, the
  root's practices become Qredin's practices, and that needs its own review.
