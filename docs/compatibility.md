# Compatibility Matrix

This document describes the compatibility of Qredin with standard SPIFFE clients and tooling.

## SPIFFE Workload API Clients

| Client | Version | Status | Notes |
|---|---|---|---|
| go-spiffe (workloadapi package) | v1.x | Compatible | Uses standard `FetchX509SVID`, `FetchBundle`, `SubscribeX509SVIDs`, `SubscribeBundles` |
| go-spiffe (bundle package) | v1.x | Compatible | Bundle fetching via `FetchBundle` |
| Envoy SDS | v1.x | Compatible | SDS uses FetchX509SVID for node and workload certificates |
| SPIRE Agent (1.8+) | v1.8+ | Compatible | Workload API client behavior |

## Transports

| Transport | Status | Notes |
|---|---|---|
| Unix Domain Socket (UDS) | Primary | Node-local only, enforced via `workload.spiffe.io: true` header |
| TCP/mTLS | Planned | Administrative and cross-node use |

## Protocols

| Protocol | Status | Notes |
|---|---|---|
| Workload API v1 (SPIFFE) | Supported | Protobuf/gRPC generated from `api/workloadapi/v1/workloadapi.proto` |
| JWT-SVID | Partial | `FetchJWTSVID` and `SubscribeJWTSVIDs` implemented; JWT issuer not yet available |

## Attestation Targets

| Target | Status | Notes |
|---|---|---|
| Unix (PID/namespace/cgroup) | Supported | Used for node and workload attestation |
| Docker | Supported | Container runtime identity |
| systemd | Supported | Unit identity |
| Kubernetes | Planned | Pod and projected service account token attestation |

## Trust Domain Requirements

| Requirement | Status | Notes |
|---|---|---|
| SPIFFE ID format validation | Supported | Workload and node IDs validated against trust domain |
| Trust domain isolation | Supported | Cross-tenant access denied at resolver level |
| Bundle sequence validation | Supported | Sequence numbers used for rotation detection |
