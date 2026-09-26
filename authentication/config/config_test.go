package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigFromFile(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	content := `
environment: production
log_level: info
log_format: json
trust_domain: example.org
http:
  listen_addr: ":443"
  uds_path: /var/run/qredin/workload-api.sock
postgres:
  dsn: postgres://localhost/qredin
  max_conns: 10
  min_conns: 2
  conn_timeout: 5s
key_manager:
  type: disk
  dir: /var/lib/qredin/keys
secret_manager:
  type: none
operator:
  session:
    enabled: false
    max_age: 8h
agent:
  server_addr: "localhost:443"
  node_id: "spiffe://example.org/node/test"
  join_token_ttl: 5m
  join_token_max_retries: 5
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(%q) = %v, want nil", cfgPath, err)
	}
	if cfg.Environment != EnvironmentProduction {
		t.Errorf("Environment = %q, want %q", cfg.Environment, EnvironmentProduction)
	}
	if cfg.TrustDomain != "example.org" {
		t.Errorf("TrustDomain = %q, want %q", cfg.TrustDomain, "example.org")
	}
	if cfg.Postgres.DSN != "postgres://localhost/qredin" {
		t.Errorf("Postgres.DSN = %q, want %q", cfg.Postgres.DSN, "postgres://localhost/qredin")
	}
	if cfg.KeyManager.Type != KeyManagerDisk {
		t.Errorf("KeyManager.Type = %q, want %q", cfg.KeyManager.Type, KeyManagerDisk)
	}
	if cfg.Agent.NodeID != "spiffe://example.org/node/test" {
		t.Errorf("Agent.NodeID = %q, want %q", cfg.Agent.NodeID, "spiffe://example.org/node/test")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	t.Parallel()
	_, err := Load("/nonexistent/path/config.yaml")
	if !errors.Is(err, ErrConfigFileNotFound) {
		t.Fatalf("Load = %v, want ErrConfigFileNotFound", err)
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("not: valid: yaml: ["), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("Load = nil, want error for invalid YAML")
	}
}

func TestLoadConfigMissingRequired(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	content := `trust_domain: example.org
agent:
  node_id: spiffe://example.org/node/test
  server_addr: localhost:443
  join_token_ttl: 5m
  join_token_max_retries: 5
http:
  listen_addr: ":443"
  uds_path: /var/run/qredin/workload-api.sock
secret_manager:
  type: none
operator:
  session:
    enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("Load = nil, want error for missing required fields")
	}
}

func TestLoadConfigRejectsTmpKeyDir(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	content := `
environment: production
log_level: info
log_format: json
trust_domain: example.org
http:
  listen_addr: ":443"
  uds_path: /var/run/qredin/workload-api.sock
postgres:
  dsn: postgres://localhost/qredin
  max_conns: 10
  min_conns: 2
  conn_timeout: 5s
key_manager:
  type: disk
  dir: /tmp/qredin/keys
secret_manager:
  type: none
operator:
  session:
    enabled: false
agent:
  server_addr: localhost:443
  node_id: spiffe://example.org/node/test
  join_token_ttl: 5m
  join_token_max_retries: 5`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(cfgPath)
	if err == nil {
		t.Fatal("Load = nil, want error for /tmp key dir in production")
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	if cfg.Environment != EnvironmentDevelopment {
		t.Errorf("Environment = %q, want %q", cfg.Environment, EnvironmentDevelopment)
	}
	if cfg.KeyManager.Type != KeyManagerDisk {
		t.Errorf("KeyManager.Type = %q, want %q", cfg.KeyManager.Type, KeyManagerDisk)
	}
}

func TestConfigValidateRejects(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.Environment = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate = nil, want error for empty environment")
	}
}

func TestSecretManagerValidation(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.SecretManager.Type = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should fail when secret_manager.type is empty")
	}
	cfg = DefaultConfig()
	cfg.SecretManager.Type = SecretManagerAWSSecretsManager
	cfg.SecretManager.Region = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should fail when aws_secrets_manager backend is missing region")
	}
	cfg = DefaultConfig()
	cfg.SecretManager.Type = SecretManagerVault
	cfg.SecretManager.Addr = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should fail when vault backend is missing addr")
	}
}

func TestOperatorConfigValidation(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.Operator.SSO.Enabled = true
	cfg.Operator.SSO.Provider = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should fail when SSO is enabled but provider is empty")
	}
	cfg = DefaultConfig()
	cfg.Operator.MFA.Enabled = true
	cfg.Operator.MFA.Issuer = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should fail when MFA is enabled but issuer is empty")
	}
	cfg = DefaultConfig()
	cfg.Operator.RBAC.Enabled = true
	cfg.Operator.RBAC.AdminRole = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should fail when RBAC is enabled but admin_role is empty")
	}
	cfg = DefaultConfig()
	cfg.Operator.Session.Enabled = true
	cfg.Operator.Session.MaxAge = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should fail when session.max_age is zero")
	}
	cfg = DefaultConfig()
	cfg.Operator.RateLimit.Enabled = true
	cfg.Operator.RateLimit.Requests = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should fail when rate_limit.requests is zero")
	}
}

func TestConfigSecretsNotInJSON(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.SecretManager.Token = "super-secret-token"
	cfg.Operator.Session.RedisPassword = "super-secret-password"
	// Marshal to JSON - secrets should be omitted
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	jsonStr := string(data)
	if strings.Contains(jsonStr, "super-secret-token") {
		t.Fatal("config JSON should not contain secret_manager token")
	}
	if strings.Contains(jsonStr, "super-secret-password") {
		t.Fatal("config JSON should not contain operator.session.redis_password")
	}
}