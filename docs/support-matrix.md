# Qredin Production Support Matrix

## Overview

This document defines the supported platforms, versions, and configurations for Qredin in production environments.

## Supported Platforms

### Operating Systems

| OS | Version | Architecture | Status | Notes |
|----|---------|--------------|--------|-------|
| Linux | Ubuntu 22.04 LTS | x86_64, arm64 | ✅ Supported | Primary target |
| Linux | Ubuntu 24.04 LTS | x86_64, arm64 | ✅ Supported | Primary target |
| Linux | RHEL 9 / Rocky 9 / AlmaLinux 9 | x86_64, arm64 | ✅ Supported | Enterprise |
| Linux | Debian 12 (Bookworm) | x86_64, arm64 | ✅ Supported | Community |
| Linux | Flatcar Container Linux | x86_64, arm64 | ✅ Supported | Kubernetes nodes |
| Windows | Server 2022 | x86_64 | 🔄 Experimental | Agent only |
| macOS | 13+ (Ventura+) | arm64 (Apple Silicon) | 🔄 Development | Dev/test only |

### Container Runtimes

| Runtime | Version | Status | Notes |
|---------|---------|--------|-------|
| containerd | 1.6+, 1.7+ | ✅ Supported | Primary for K8s |
| Docker Engine | 24.0+, 25.0+ | ✅ Supported | Via containerd shim |
| CRI-O | 1.26+, 1.27+ | ✅ Supported | OpenShift compatible |
| podman | 4.5+ | ⚠️ Limited | Rootless not fully tested |

### Kubernetes Platforms

| Platform | Version | Status | Notes |
|----------|---------|--------|-------|
| Upstream Kubernetes | 1.27, 1.28, 1.29 | ✅ Supported | Standard |
| EKS | 1.27, 1.28, 1.29 | ✅ Supported | AWS |
| GKE | 1.27, 1.28, 1.29 | ✅ Supported | GCP |
| AKS | 1.27, 1.28, 1.29 | ✅ Supported | Azure |
| OpenShift | 4.13, 4.14, 4.15 | ✅ Supported | Red Hat |
| Rancher/RKE2 | 1.27, 1.28 | ✅ Supported | SUSE |
| Tanzu | 2.2, 2.3 | ⚠️ Limited | VMware |

### Service Mesh / Ingress

| Component | Version | Status | Notes |
|-----------|---------|--------|-------|
| Envoy | 1.27+, 1.28+ | ✅ Supported | SDS integration |
| Istio | 1.19, 1.20, 1.21 | ✅ Supported | Via Envoy SDS |
| Linkerd | 2.14, 2.15 | ✅ Supported | Via workload API |
| Cilium | 1.14, 1.15 | ✅ Supported | eBPF-based |
| NGINX Ingress | 1.8, 1.9 | ⚠️ Limited | mTLS passthrough |

### Attestation Platforms

| Platform | Selectors | Status | Notes |
|----------|-----------|--------|-------|
| Linux (systemd) | unix.uid, unix.gid, systemd.unit | ✅ Supported | Native |
| Linux (containerd) | k8s.pod.*, container.id | ✅ Supported | Via CRI |
| Linux (Docker) | docker.id, docker.image.id | ✅ Supported | Via Docker API |
| Kubernetes | k8s.pod.*, k8s.ns.*, k8s.sa.* | ✅ Supported | TokenReview |
| AWS Nitro | aws.instance-id, aws.ami-id | 🔄 Experimental | Enclave attestation |
| Azure Confidential | azure.vm-id, azure.image-id | 🔄 Experimental | CVM attestation |

## Database Support

### PostgreSQL

| Version | Status | Notes |
|---------|--------|-------|
| PostgreSQL 15 | ✅ Supported | Primary |
| PostgreSQL 16 | ✅ Supported | Recommended |
| PostgreSQL 14 | ⚠️ Deprecated | EOL Nov 2024 |
| PostgreSQL 13 | ❌ Unsupported | EOL Nov 2023 |

### Required Extensions

- `uuid-ossp` (for UUID generation)
- `pgcrypto` (for cryptographic functions)
- `btree_gin` (for audit log indexing)

### Connection Pooling

| Pooler | Version | Status |
|--------|---------|--------|
| PgBouncer | 1.21+ | ✅ Supported |
| PgPool-II | 4.4+ | ⚠️ Limited |

### Cloud Managed

| Service | Version | Status |
|---------|---------|--------|
| AWS RDS PostgreSQL | 15, 16 | ✅ Supported |
| AWS Aurora PostgreSQL | 15, 16 | ✅ Supported |
| GCP Cloud SQL PostgreSQL | 15, 16 | ✅ Supported |
| Azure Database for PostgreSQL | 15, 16 | ✅ Supported |

## Key Management Systems

### Hardware Security Modules (HSM)

| Vendor | Model | Interface | Status |
|--------|-------|-----------|--------|
| Thales | Luna 7, Network HSM | PKCS#11 | ✅ Supported |
| nCipher | nShield Connect | PKCS#11 | ✅ Supported |
| AWS CloudHSM | Luna SA | PKCS#11 | ✅ Supported |
| Azure Dedicated HSM | Luna 7 | PKCS#11 | ✅ Supported |
| Google Cloud HSM | Cloud KMS | Cloud KMS API | ✅ Supported |

### Software KMS

| System | Version | Interface | Status |
|--------|---------|-----------|--------|
| HashiCorp Vault | 1.13+, 1.14+ | Transit Engine | ✅ Supported |
| AWS KMS | Current | KMS API | ✅ Supported |
| Azure Key Vault | Current | Key Vault API | ✅ Supported |
| GCP Cloud KMS | Current | Cloud KMS API | ✅ Supported |
| HashiCorp Vault | 1.12 and below | Transit Engine | ⚠️ Limited |

### Disk-Based (Development Only)

| Type | Status | Notes |
|------|--------|-------|
| Encrypted disk (AES-256-GCM) | ✅ Dev/Staging | Not for production |

## TLS Certificates

### Certificate Authorities

| CA Type | Status | Notes |
|---------|--------|-------|
| Public CA (Let's Encrypt, DigiCert, etc.) | ✅ Supported | For public endpoints |
| Private CA (HashiCorp Vault, Smallstep, cfssl) | ✅ Supported | For internal mTLS |
| Self-signed | ⚠️ Dev only | Not for production |

### Certificate Requirements

| Requirement | Value |
|-------------|-------|
| Key Algorithm | ECDSA P-256 (preferred), RSA 2048+ |
| Signature Algorithm | ECDSA with SHA-256, RSA-PSS with SHA-256 |
| Validity Period | ≤ 90 days (recommended), ≤ 398 days (max) |
| Key Usage | Digital Signature, Key Encipherment |
| Extended Key Usage | Client Auth, Server Auth |
| SAN | DNS names, IP addresses, SPIFFE IDs |

## Monitoring & Observability

### Metrics

| System | Version | Status |
|--------|---------|--------|
| Prometheus | 2.45+, 2.47+ | ✅ Supported |
| OpenTelemetry Collector | 0.90+ | ✅ Supported |
| VictoriaMetrics | 1.90+ | ⚠️ Limited |
| Grafana | 10.0+, 10.2+ | ✅ Supported |

### Logging

| System | Version | Status |
|--------|---------|--------|
| Loki | 2.8+, 2.9+ | ✅ Supported |
| Elasticsearch | 8.10+ | ✅ Supported |
| Splunk | 9.0+ | ⚠️ Limited |
| Fluent Bit | 2.0+ | ✅ Supported |
| Vector | 0.30+ | ✅ Supported |

### Tracing

| System | Version | Status |
|--------|---------|--------|
| Jaeger | 1.47+ | ✅ Supported |
| Tempo | 2.2+ | ✅ Supported |
| Zipkin | 2.23+ | ⚠️ Limited |
| AWS X-Ray | Current | ⚠️ Limited |

## Go Version

| Version | Status | Notes |
|---------|--------|-------|
| Go 1.22 | ✅ Supported | Current LTS |
| Go 1.23 | ✅ Supported | Latest |
| Go 1.21 | ⚠️ Deprecated | EOL Aug 2024 |

## Dependencies

### Core Dependencies (Pinned)

| Dependency | Version | Update Policy |
|------------|---------|---------------|
| google.golang.org/grpc | v1.62+ | Minor updates monthly |
| github.com/jackc/pgx/v5 | v5.5+ | Minor updates monthly |
| github.com/aws/aws-sdk-go-v2 | v1.20+ | Minor updates quarterly |
| golang.org/x/crypto | v0.15+ | Minor updates monthly |
| gopkg.in/yaml.v3 | v3.0.1 | Patch only |

### Supply Chain

- All dependencies vendored or checksum-verified
- SBOM generated per release (SPDX 2.3)
- Provenance attestation (SLSA Level 2)
- Vulnerability scan per release (govulncheck)

## Unsupported / Deprecated

| Component | Since | Removal Target | Migration Path |
|-----------|-------|----------------|----------------|
| PostgreSQL 13 | v1.0 | v1.3 | Upgrade to 15+ |
| Go 1.21 | v1.1 | v1.3 | Upgrade to 1.22+ |
| Disk key manager (prod) | v1.0 | v1.2 | Migrate to HSM/KMS |
| Legacy SPIFFE ID format | v1.0 | v1.3 | Use standard format |
| Unencrypted UDS | v1.0 | v1.2 | Require TLS/mTLS |

## Testing Matrix

| Test Type | Platforms | Frequency |
|-----------|-----------|-----------|
| Unit Tests | All | Per commit |
| Integration Tests | Ubuntu 22.04, 24.04 | Per commit |
| E2E Tests | K8s 1.27, 1.28, 1.29 | Daily |
| Conformance | SPIFFE Workload API | Per release |
| Interop | Envoy, Istio, Linkerd | Per release |
| Chaos | DB failover, net partition | Weekly |
| Security | SAST, DAST, SCA | Per commit |

## Support Lifecycle

| Release | Type | Active Support | Security Support |
|---------|------|----------------|------------------|
| v1.x | Minor | 12 months | 18 months |
| v1.0 LTS | LTS | 24 months | 36 months |

---

*Last Updated: 2024-01-15*
*Version: 1.0*