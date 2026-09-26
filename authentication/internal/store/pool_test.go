package store

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestConfigurePoolDefaults(t *testing.T) {
	t.Parallel()

	config, err := pgxpool.ParseConfig("postgres://user:pass@localhost/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	ConfigurePool(config, DefaultPoolConfig())

	if config.MaxConns != 25 {
		t.Fatalf("MaxConns = %d, want 25", config.MaxConns)
	}
	if config.MinConns != 5 {
		t.Fatalf("MinConns = %d, want 5", config.MinConns)
	}
	if config.MaxConnLifetime != 30*time.Minute {
		t.Fatalf("MaxConnLifetime = %v, want 30m", config.MaxConnLifetime)
	}
	if config.MaxConnIdleTime != 5*time.Minute {
		t.Fatalf("MaxConnIdleTime = %v, want 5m", config.MaxConnIdleTime)
	}
	if config.HealthCheckPeriod != 30*time.Second {
		t.Fatalf("HealthCheckPeriod = %v, want 30s", config.HealthCheckPeriod)
	}
	if config.ConnConfig.ConnectTimeout != 5*time.Second {
		t.Fatalf("ConnectTimeout = %v, want 5s", config.ConnConfig.ConnectTimeout)
	}
}

func TestConfigurePoolNil(t *testing.T) {
	t.Parallel()

	config, err := pgxpool.ParseConfig("postgres://user:pass@localhost/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	ConfigurePool(config, nil)
	// pgxpool has a default MaxConns of 8
	if config.MaxConns != 8 {
		t.Fatalf("MaxConns should remain pgxpool default when cfg is nil, got %d", config.MaxConns)
	}
}

func TestConfigurePoolCustomValues(t *testing.T) {
	t.Parallel()

	config, err := pgxpool.ParseConfig("postgres://user:pass@localhost/db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &PoolConfig{
		MaxConns:          10,
		MinConns:          2,
		MaxConnLifetime:   20 * time.Minute,
		MaxConnIdleTime:   3 * time.Minute,
		HealthCheckPeriod: 15 * time.Second,
		ConnectTimeout:    2 * time.Second,
	}
	ConfigurePool(config, cfg)

	if config.MaxConns != 10 {
		t.Fatalf("MaxConns = %d, want 10", config.MaxConns)
	}
	if config.MinConns != 2 {
		t.Fatalf("MinConns = %d, want 2", config.MinConns)
	}
	if config.MaxConnLifetime != 20*time.Minute {
		t.Fatalf("MaxConnLifetime = %v, want 20m", config.MaxConnLifetime)
	}
	if config.MaxConnIdleTime != 3*time.Minute {
		t.Fatalf("MaxConnIdleTime = %v, want 3m", config.MaxConnIdleTime)
	}
	if config.HealthCheckPeriod != 15*time.Second {
		t.Fatalf("HealthCheckPeriod = %v, want 15s", config.HealthCheckPeriod)
	}
	if config.ConnConfig.ConnectTimeout != 2*time.Second {
		t.Fatalf("ConnectTimeout = %v, want 2s", config.ConnConfig.ConnectTimeout)
	}
}

func TestNewPoolInvalidDSN(t *testing.T) {
	t.Parallel()

	_, err := NewPool(context.Background(), "not-a-valid-dsn", DefaultPoolConfig())
	if err == nil {
		t.Fatal("NewPool with invalid DSN should fail")
	}
}
