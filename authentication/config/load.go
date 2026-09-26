package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var (
	ErrConfigFileNotFound = errors.New("config: file not found")
	ErrConfigLoad         = errors.New("config: load failed")
)

// Load loads and validates configuration from a YAML file.
func Load(path string) (Config, error) {
	if path == "" {
		return Config{}, errors.New("config: path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, fmt.Errorf("%w: %s", ErrConfigFileNotFound, path)
		}
		return Config{}, fmt.Errorf("%w: %s: %v", ErrConfigLoad, path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("%w: %s: %v", ErrConfigLoad, path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%w: %s: %v", ErrConfigLoad, path, err)
	}
	return cfg, nil
}

// ValidatePath ensures the config file exists and is readable.
func ValidatePath(path string) error {
	if path == "" {
		return errors.New("config: path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrConfigFileNotFound, path)
		}
		return fmt.Errorf("config: stat %s: %v", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("config: %s is a directory", path)
	}
	if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
		return fmt.Errorf("config: %s must have .yaml or .yml extension", path)
	}
	return nil
}

// SetupLogger configures and returns a slog.Logger based on level and format.
func SetupLogger(level, format string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "info":
		l = slog.LevelInfo
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	opts := slog.HandlerOptions{Level: l, AddSource: true}
	var h slog.Handler
	if format == "text" {
		h = slog.NewTextHandler(os.Stdout, &opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, &opts)
	}
	return slog.New(h)
}