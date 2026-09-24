package config

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Environment represents a deployment environment.
type Environment string

const (
	EnvironmentProduction  Environment = "production"
	EnvironmentStaging     Environment = "staging"
	EnvironmentDevelopment Environment = "development"
)

// KeyManagerType represents the key manager backend.
type KeyManagerType string

const (
	KeyManagerDisk   KeyManagerType = "disk"
	KeyManagerAWSKMS KeyManagerType = "aws_kms"
)

// SecretManagerType represents the secret manager backend.
type SecretManagerType string

const (
	SecretManagerNone            SecretManagerType = "none"
	SecretManagerAWSSecretsManager SecretManagerType = "aws_secrets_manager"
	SecretManagerVault           SecretManagerType = "vault"
)

// SecretManagerConfig contains secret manager settings.
type SecretManagerConfig struct {
	Type   SecretManagerType `yaml:"type" json:"type"`
	// AWS Secrets Manager
	Region string            `yaml:"region" json:"region"`
	// HashiCorp Vault
	Addr   string            `yaml:"addr" json:"addr"`
	Token  string            `yaml:"-" json:"-"` // never serialized to JSON/YAML
	// Generic
	Prefix string            `yaml:"prefix" json:"prefix"`
}

// OperatorConfig contains settings for the Operator service.
type OperatorConfig struct {
	SSO        SSOConfig        `yaml:"sso" json:"sso"`
	MFA        MFAConfig        `yaml:"mfa" json:"mfa"`
	RBAC       RBACConfig       `yaml:"rbac" json:"rbac"`
	Session    SessionConfig    `yaml:"session" json:"session"`
	RateLimit  RateLimitConfig  `yaml:"rate_limit" json:"rate_limit"`
}

// SSOConfig contains Single Sign-On settings.
type SSOConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Provider string `yaml:"provider" json:"provider"` // oidc, saml, etc.
	ClientID string `yaml:"client_id" json:"client_id"`
	// ClientSecret is intentionally omitted from config - use secret manager
	RedirectURL string `yaml:"redirect_url" json:"redirect_url"`
}

// MFAConfig contains Multi-Factor Authentication settings.
type MFAConfig struct {
	Enabled       bool   `yaml:"enabled" json:"enabled"`
	Issuer        string `yaml:"issuer" json:"issuer"` // e.g., "Qredin"
	BackupCodes   bool   `yaml:"backup_codes" json:"backup_codes"`
	TrustDuration time.Duration `yaml:"trust_duration" json:"trust_duration"`
}

// RBACConfig contains Role-Based Access Control settings.
type RBACConfig struct {
	Enabled              bool   `yaml:"enabled" json:"enabled"`
	AdminRole            string `yaml:"admin_role" json:"admin_role"`
	OperatorRole         string `yaml:"operator_role" json:"operator_role"`
	AuditorRole          string `yaml:"auditor_role" json:"auditor_role"`
	PolicyUpdateRole     string `yaml:"policy_update_role" json:"policy_update_role"`
	PolicyReadRole       string `yaml:"policy_read_role" json:"policy_read_role"`
	TrustDomainJoinRole  string `yaml:"trust_domain_join_role" json:"trust_domain_join_role"`
}

// SessionConfig contains web session settings.
type SessionConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	Secure       bool          `yaml:"secure" json:"secure"`
	HTTPOnly     bool          `yaml:"http_only" json:"http_only"`
	MaxAge       time.Duration `yaml:"max_age" json:"max_age"`
	SameSite     string        `yaml:"same_site" json:"same_site"` // lax, strict, none
	Name         string        `yaml:"name" json:"name"`
	StoreType    string        `yaml:"store_type" json:"store_type"` // memory, redis, postgres
	RedisAddr    string        `yaml:"redis_addr" json:"redis_addr"`
	RedisPassword string        `yaml:"-" json:"-"` // never serialized
}

// RateLimitConfig contains rate limiting settings.
type RateLimitConfig struct {
	Enabled    bool          `yaml:"enabled" json:"enabled"`
	Requests   int           `yaml:"requests" json:"requests"`
	Window     time.Duration `yaml:"window" json:"window"`
	Strategy   string        `yaml:"strategy" json:"strategy"` // fixed-window, sliding-window, token-bucket
	FailClosed []string      `yaml:"fail_closed" json:"fail_closed"` // policy IDs that should fail closed
}

// Config is the root configuration for all Qredin services.
type Config struct {
	Environment Environment      `yaml:"environment" json:"environment"`
	LogLevel    string           `yaml:"log_level" json:"log_level"`
	LogFormat   string           `yaml:"log_format" json:"log_format"` // json, text
	HTTP        HTTPConfig       `yaml:"http" json:"http"`
	Postgres    PostgresConfig   `yaml:"postgres" json:"postgres"`
	TrustDomain string           `yaml:"trust_domain" json:"trust_domain"`
	KeyManager  KeyManagerConfig `yaml:"key_manager" json:"key_manager"`
	SecretManager SecretManagerConfig `yaml:"secret_manager" json:"secret_manager"`
	Operator    OperatorConfig   `yaml:"operator" json:"operator"`
	Server      ServerConfig     `yaml:"server" json:"server"`
	Agent       AgentConfig      `yaml:"agent" json:"agent"`
}

// HTTPConfig contains HTTP/gRPC server settings.
type HTTPConfig struct {
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`
	UDSPath    string `yaml:"uds_path" json:"uds_path"`
	TLSCert    string `yaml:"tls_cert" json:"tls_cert"`
	TLSKey     string `yaml:"tls_key" json:"tls_key"`
}

// PostgresConfig contains PostgreSQL connection settings.
type PostgresConfig struct {
	DSN             string        `yaml:"dsn" json:"dsn"`
	MaxConns        int           `yaml:"max_conns" json:"max_conns"`
	MinConns        int           `yaml:"min_conns" json:"min_conns"`
	ConnTimeout     time.Duration `yaml:"conn_timeout" json:"conn_timeout"`
	MaxConnIdle     time.Duration `yaml:"max_conn_idle" json:"max_conn_idle"`
	MaxConnLifetime time.Duration `yaml:"max_conn_lifetime" json:"max_conn_lifetime"`
}

// KeyManagerConfig contains key manager settings.
type KeyManagerConfig struct {
	Type   KeyManagerType `yaml:"type" json:"type"`
	Dir    string         `yaml:"dir" json:"dir"`
	Region string         `yaml:"region" json:"region"`
	KeyID  string         `yaml:"key_id" json:"key_id"`
}

// ServerConfig contains Identity Server settings.
type ServerConfig struct {
	AuthorityTTL time.Duration `yaml:"authority_ttl" json:"authority_ttl"`
}

// AgentConfig contains Node Agent settings.
type AgentConfig struct {
	ServerAddr          string        `yaml:"server_addr" json:"server_addr"`
	NodeID              string        `yaml:"node_id" json:"node_id"`
	JoinTokenTTL        time.Duration `yaml:"join_token_ttl" json:"join_token_ttl"`
	JoinTokenMaxRetries int           `yaml:"join_token_max_retries" json:"join_token_max_retries"`
}

// Validate checks the configuration for validity.
func (c Config) Validate() error {
	var errs []error

	if c.Environment == "" {
		errs = append(errs, errors.New("config: environment is required"))
	}
	if c.LogLevel == "" {
		errs = append(errs, errors.New("config: log_level is required"))
	}
	if c.LogFormat == "" {
		errs = append(errs, errors.New("config: log_format is required"))
	}
	if c.TrustDomain == "" {
		errs = append(errs, errors.New("config: trust_domain is required"))
	}

	if err := c.HTTP.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := c.Postgres.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := c.KeyManager.Validate(c.Environment); err != nil {
		errs = append(errs, err)
	}
	if err := c.SecretManager.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := c.Operator.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := c.Agent.Validate(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("config: validation failed: %v", errs)
	}
	return nil
}

func (h HTTPConfig) Validate() error {
	if h.ListenAddr == "" {
		return errors.New("config: http.listen_addr is required")
	}
	if h.UDSPath == "" {
		return errors.New("config: http.uds_path is required")
	}
	return nil
}

func (p PostgresConfig) Validate() error {
	if p.DSN == "" {
		return errors.New("config: postgres.dsn is required")
	}
	if p.MaxConns <= 0 {
		return errors.New("config: postgres.max_conns must be positive")
	}
	if p.MinConns < 0 {
		return errors.New("config: postgres.min_conns must be non-negative")
	}
	if p.ConnTimeout <= 0 {
		return errors.New("config: postgres.conn_timeout must be positive")
	}
	return nil
}

func (k KeyManagerConfig) Validate(env Environment) error {
	if k.Type == "" {
		return errors.New("config: key_manager.type is required")
	}
	if k.Type != KeyManagerDisk && k.Type != KeyManagerAWSKMS {
		return fmt.Errorf("config: invalid key_manager.type: %s", k.Type)
	}
	if k.Type == KeyManagerDisk {
		if k.Dir == "" {
			return errors.New("config: key_manager.dir is required for disk backend")
		}
		if env == EnvironmentProduction {
			if k.Dir == "/tmp" || strings.HasPrefix(k.Dir, "/tmp/") {
				return errors.New("config: key_manager.dir must not be /tmp in production")
			}
		}
	}
	if k.Type == KeyManagerAWSKMS {
		if k.Region == "" {
			return errors.New("config: key_manager.region is required for aws_kms backend")
		}
		if k.KeyID == "" {
			return errors.New("config: key_manager.key_id is required for aws_kms backend")
		}
	}
	return nil
}

func (a AgentConfig) Validate() error {
	if a.NodeID == "" {
		return errors.New("config: agent.node_id is required")
	}
	if a.ServerAddr == "" {
		return errors.New("config: agent.server_addr is required")
	}
	if a.JoinTokenTTL <= 0 {
		return errors.New("config: agent.join_token_ttl must be positive")
	}
	if a.JoinTokenMaxRetries < 0 {
		return errors.New("config: agent.join_token_max_retries must be non-negative")
	}
	return nil
}

func (s SecretManagerConfig) Validate() error {
	if s.Type == "" {
		return errors.New("config: secret_manager.type is required")
	}
	if s.Type != SecretManagerNone && s.Type != SecretManagerAWSSecretsManager && s.Type != SecretManagerVault {
		return fmt.Errorf("config: invalid secret_manager.type: %s", s.Type)
	}
	if s.Type == SecretManagerAWSSecretsManager {
		if s.Region == "" {
			return errors.New("config: secret_manager.region is required for aws_secrets_manager backend")
		}
	}
	if s.Type == SecretManagerVault {
		if s.Addr == "" {
			return errors.New("config: secret_manager.addr is required for vault backend")
		}
	}
	return nil
}

func (o OperatorConfig) Validate() error {
	if err := o.SSO.Validate(); err != nil {
		return err
	}
	if err := o.MFA.Validate(); err != nil {
		return err
	}
	if err := o.RBAC.Validate(); err != nil {
		return err
	}
	if err := o.Session.Validate(); err != nil {
		return err
	}
	if err := o.RateLimit.Validate(); err != nil {
		return err
	}
	return nil
}

func (o SSOConfig) Validate() error {
	if !o.Enabled {
		return nil
	}
	if o.Provider == "" {
		return errors.New("config: operator.sso.provider is required when SSO is enabled")
	}
	if o.ClientID == "" {
		return errors.New("config: operator.sso.client_id is required when SSO is enabled")
	}
	if o.RedirectURL == "" {
		return errors.New("config: operator.sso.redirect_url is required when SSO is enabled")
	}
	return nil
}

func (m MFAConfig) Validate() error {
	if !m.Enabled {
		return nil
	}
	if m.Issuer == "" {
		return errors.New("config: operator.mfa.issuer is required when MFA is enabled")
	}
	if m.TrustDuration <= 0 {
		return errors.New("config: operator.mfa.trust_duration must be positive when MFA is enabled")
	}
	return nil
}

func (r RBACConfig) Validate() error {
	if !r.Enabled {
		return nil
	}
	if r.AdminRole == "" {
		return errors.New("config: operator.rbac.admin_role is required when RBAC is enabled")
	}
	return nil
}

func (s SessionConfig) Validate() error {
	if !s.Enabled && s.Secure {
		return errors.New("config: operator.session.secure should not be true when session is disabled")
	}
	if s.MaxAge <= 0 {
		return errors.New("config: operator.session.max_age must be positive when session is enabled")
	}
	if s.SameSite != "" && s.SameSite != "lax" && s.SameSite != "strict" && s.SameSite != "none" {
		return fmt.Errorf("config: operator.session.same_site must be lax, strict, or none, got %s", s.SameSite)
	}
	return nil
}

func (r RateLimitConfig) Validate() error {
	if !r.Enabled {
		return nil
	}
	if r.Requests <= 0 {
		return errors.New("config: operator.rate_limit.requests must be positive when rate limiting is enabled")
	}
	if r.Window <= 0 {
		return errors.New("config: operator.rate_limit.window must be positive when rate limiting is enabled")
	}
	if r.Strategy != "" && r.Strategy != "fixed-window" && r.Strategy != "sliding-window" && r.Strategy != "token-bucket" {
		return fmt.Errorf("config: operator.rate_limit.strategy must be fixed-window, sliding-window, or token-bucket, got %s", r.Strategy)
	}
	return nil
}

// DefaultConfig returns a default configuration for development.
func DefaultConfig() Config {
	return Config{
		Environment: EnvironmentDevelopment,
		LogLevel:    "info",
		LogFormat:   "json",
		HTTP: HTTPConfig{
			ListenAddr: ":443",
			UDSPath:    "/var/run/qredin/workload-api.sock",
		},
		Postgres: PostgresConfig{
			MaxConns:        10,
			MinConns:        2,
			ConnTimeout:     5 * time.Second,
			MaxConnIdle:     5 * time.Minute,
			MaxConnLifetime: 30 * time.Minute,
		},
		KeyManager: KeyManagerConfig{
			Type: KeyManagerDisk,
			Dir:  "/var/lib/qredin/keys",
		},
		SecretManager: SecretManagerConfig{
			Type: SecretManagerNone,
		},
		Operator: OperatorConfig{
			SSO: SSOConfig{
				Enabled:  false,
				Provider: "oidc",
			},
			MFA: MFAConfig{
				Enabled:       false,
				Issuer:        "Qredin",
				BackupCodes:   true,
				TrustDuration: 24 * time.Hour,
			},
			RBAC: RBACConfig{
				Enabled:             false,
				AdminRole:           "admin",
				OperatorRole:        "operator",
				AuditorRole:         "auditor",
				PolicyUpdateRole:    "policy-updater",
				PolicyReadRole:      "policy-reader",
				TrustDomainJoinRole: "trust-domain-joiner",
			},
			Session: SessionConfig{
				Secure:       true,
				HTTPOnly:     true,
				MaxAge:       8 * time.Hour,
				SameSite:     "lax",
				Name:         "qredin-session",
				StoreType:    "memory",
			},
RateLimit: RateLimitConfig{
			Enabled:    true,
			Requests:   100,
			Window:     time.Minute,
			Strategy:   "fixed-window",
			FailClosed: []string{},
		},
		},
		Server: ServerConfig{
			AuthorityTTL: 24 * time.Hour,
		},
		Agent: AgentConfig{
			ServerAddr:          "localhost:443",
			NodeID:              "",
			JoinTokenTTL:        5 * time.Minute,
			JoinTokenMaxRetries: 5,
		},
	}
}