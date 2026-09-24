package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/qredin/qredin/internal/config"
	"github.com/qredin/qredin/internal/keymanager"
	"github.com/qredin/qredin/internal/attestation/node"
	"github.com/qredin/qredin/pkg/spiffeid"
)

var (
	configPath = flag.String("config", "", "Path to configuration file (required)")
	version    = flag.Bool("version", false, "Print version and exit")
)

func main() {
	flag.Parse()

	if *version {
		printVersion()
		os.Exit(0)
	}

	if *configPath == "" {
		slog.Error("config path is required; use --config")
		os.Exit(1)
	}

	if err := config.ValidatePath(*configPath); err != nil {
		slog.Error("invalid config path", "error", err)
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := config.SetupLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil {
		slog.Error("invalid trust domain", "error", err)
		os.Exit(1)
	}

	nodeID, err := spiffeid.FromString(cfg.Agent.NodeID)
	if err != nil {
		slog.Error("invalid node ID", "error", err)
		os.Exit(1)
	}

	slog.Info("starting Qredin Node Agent",
		"node_id", nodeID.String(),
		"trust_domain", td.String(),
		"server", cfg.Agent.ServerAddr)

	keyManager, err := keymanager.NewDiskManager(cfg.KeyManager.Dir)
	if err != nil {
		slog.Error("failed to create key manager", "error", err)
		os.Exit(1)
	}
	kmCtx, kmCancel := context.WithCancel(ctx)
	defer kmCancel()

	// Map config environment to keymanager environment
	var kmEnv keymanager.Environment
	switch cfg.Environment {
	case config.EnvironmentProduction:
		kmEnv = keymanager.EnvironmentProduction
	case config.EnvironmentStaging:
		kmEnv = keymanager.EnvironmentStaging
	default:
		kmEnv = keymanager.EnvironmentDevelopment
	}

	if err := keyManager.Open(kmCtx, kmEnv); err != nil {
		slog.Error("failed to open key manager", "error", err)
		os.Exit(1)
	}

	tokenStore, err := node.NewJoinTokenStore(cfg.Agent.JoinTokenMaxRetries, cfg.Agent.JoinTokenTTL)
	if err != nil {
		slog.Error("failed to create join token store", "error", err)
		os.Exit(1)
	}

	slog.Info("starting reconnect loop")
	runReconnectLoop(ctx, td, nodeID, keyManager, tokenStore, logger)
}

func runReconnectLoop(ctx context.Context, td spiffeid.TrustDomain, nodeID spiffeid.ID, keyManager keymanager.Manager, tokenStore *node.JoinTokenStore, logger *slog.Logger) {
	baseDelay := 1 * time.Second
	maxDelay := 60 * time.Second
	var currentDelay time.Duration = baseDelay

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down node agent")
			return
		default:
		}

		if err := attemptConnection(ctx, td, nodeID, keyManager, tokenStore, logger); err != nil {
			logger.Error("connection failed, backing off", "error", err, "retry_in", currentDelay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(currentDelay):
			}
			currentDelay = nextBackoff(currentDelay, maxDelay)
		} else {
			logger.Info("connected to identity server")
			currentDelay = baseDelay
		}
	}
}

func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		next = max
	}
	return next
}

func attemptConnection(ctx context.Context, td spiffeid.TrustDomain, nodeID spiffeid.ID, keyManager keymanager.Manager, tokenStore *node.JoinTokenStore, logger *slog.Logger) error {
	return errors.New("agent connection not implemented")
}

func printVersion() {
	enc, _ := json.MarshalIndent(map[string]string{"version": "dev"}, "", "  ")
	fmt.Println(string(enc))
}