# Qredin Architecture

## High-Level Overview

Qredin is a SPIFFE-based identity and authorization platform that issues X.509-SVIDs to workloads and enforces authorization policies via a dedicated policy plane and authorization API.

## Components

| Component | Binary | Role |
|---|---|---|
| Identity Server | `qredin-server` | Issues X.509-SVIDs, serves workload API over UDS, manages registrations, trust bundles, and CAs |
| Node Agent | `qredin-agent` | Attests workload identity on nodes, maintains secure connection to server, delivers SVIDs to workloads |
| Authorization Service | `qredin-authz` | Standalone gRPC authorization service that evaluates policies and returns allow/deny decisions |
| Operator CLI | `qredin-operator` | Administrative CLI for configuration validation, migration, policy management, audit queries |

## Data Flow

1. **Workload → Agent**: Workload connects over UDS socket to query SVIDs.
2. **Agent → Server**: Agent uses mTLS over gRPC to authenticate to server and obtain SVIDs.
3. **Server → CA**: Server signs SVIDs using the CA key manager.
4. **Policy Evaluation**: Authorization service receives policy evaluation requests, evaluates rules, and returns decisions with audit correlation IDs.
5. **Audit**: All decisions and lifecycle changes are persisted as append-only audit events with TraceID and CorrelationID.

## Configuration

All services use `internal/config` for typed configuration loaded from YAML files. The `Config` struct includes:

- `Environment`: production, staging, development
- `LogLevel`, `LogFormat`: structured logging
- `HTTP`: listen address, UDS path, TLS cert/key
- `Postgres`: connection pool settings
- `TrustDomain`: SPIFFE trust domain
- `KeyManager`: disk or AWS KMS backend
- `Server`: authority TTL
- `Agent`: server address, node ID, join token TTL

## Security Model

- All communications use mTLS.
- Workload API is only exposed over node-local UDS.
- Peer credentials are validated against attested node identity.
- Policy decisions require operator RBAC.
- Audit events are append-only and tamper-evident.

## Deployment

- **Kubernetes**: DaemonSet for agents, Deployment for server/authz, NetworkPolicies, service accounts.
- **VM/Bare-metal**: systemd units with hardened permissions, read-only root filesystem.
- **Dev stack**: Docker Compose with PostgreSQL, server, agent, authz services.