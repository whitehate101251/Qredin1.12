// Package store contains durable Identity Service persistence primitives.
package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

var ErrMigrationChecksum = errors.New("store: migration checksum mismatch")

// ApplyMigrations applies embedded migrations in lexical order. Each migration
// is transactional and its checksum is recorded, so editing an applied
// migration fails closed instead of silently changing the database contract.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("store: postgres pool is required")
	}
	files, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("store: listing migrations: %w", err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return errors.New("store: no migrations embedded")
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS qredin_schema_migrations (
			version BIGINT PRIMARY KEY,
			name TEXT NOT NULL,
			checksum BYTEA NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("store: creating migration table: %w", err)
	}

	for _, name := range files {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		contents, err := migrationFiles.ReadFile(name)
		if err != nil {
			return fmt.Errorf("store: reading %s: %w", name, err)
		}
		checksum := sha256.Sum256(contents)
		var applied []byte
		err = pool.QueryRow(ctx,
			`SELECT checksum FROM qredin_schema_migrations WHERE version = $1`, version).
			Scan(&applied)
		if err == nil {
			if string(applied) != string(checksum[:]) {
				return fmt.Errorf("%w: %s", ErrMigrationChecksum, name)
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: checking migration %s: %w", name, err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("store: beginning migration %s: %w", name, err)
		}
		if _, err = tx.Exec(ctx, string(contents)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: applying migration %s: %w", name, err)
		}
		if _, err = tx.Exec(ctx,
			`INSERT INTO qredin_schema_migrations(version, name, checksum) VALUES ($1, $2, $3)`,
			version, path.Base(name), checksum[:]); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("store: recording migration %s: %w", name, err)
		}
		if err = tx.Commit(ctx); err != nil {
			return fmt.Errorf("store: committing migration %s: %w", name, err)
		}
	}
	return nil
}

func migrationVersion(name string) (int64, error) {
	base := path.Base(name)
	underscore := strings.IndexByte(base, '_')
	if underscore <= 0 {
		return 0, fmt.Errorf("store: invalid migration name %q", base)
	}
	version, err := strconv.ParseInt(base[:underscore], 10, 64)
	if err != nil || version <= 0 {
		return 0, fmt.Errorf("store: invalid migration version %q", base)
	}
	return version, nil
}
