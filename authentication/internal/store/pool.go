package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolConfig holds durable store connection-pool tuning parameters.
// These values should be set so the server never exhausts database
// connections under load and so stalled connections are recycled.
type PoolConfig struct {
	// MaxConns is the maximum number of connections in the pool.
	MaxConns int32

	// MinConns is the minimum number of connections kept open.
	MinConns int32

	// MaxConnLifetime is the duration after which a connection is recycled.
	MaxConnLifetime time.Duration

	// MaxConnIdleTime is the maximum time a connection is idle before being closed.
	MaxConnIdleTime time.Duration

	// HealthCheckPeriod is how often the pool pings the database.
	HealthCheckPeriod time.Duration

	// ConnectTimeout is the per-dial timeout used when establishing a connection.
	ConnectTimeout time.Duration
}

// DefaultPoolConfig returns a production-safe pool configuration.
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxConns:          25,
		MinConns:          5,
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: 30 * time.Second,
		ConnectTimeout:    5 * time.Second,
	}
}

// ConfigurePool applies cfg onto config. It is a no-op when cfg is nil.
func ConfigurePool(config *pgxpool.Config, cfg *PoolConfig) {
	if cfg == nil {
		return
	}
	if cfg.MaxConns > 0 {
		config.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		config.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		config.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		config.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.HealthCheckPeriod > 0 {
		config.HealthCheckPeriod = cfg.HealthCheckPeriod
	}
	if cfg.ConnectTimeout > 0 && config.ConnConfig != nil {
		config.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}
}

// NewPool creates a connection pool with the given DSN and pool configuration.
// The pool is health-checked once before being returned so startup failures
// surface as explicit errors instead of stalling the first issuance.
func NewPool(ctx context.Context, dsn string, cfg *PoolConfig) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	ConfigurePool(poolConfig, cfg)
	if cfg != nil && cfg.ConnectTimeout > 0 && poolConfig.ConnConfig != nil {
		poolConfig.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}
