package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"time"

	pb "github.com/qredin/qredin/api/workloadapi/v1"
	"github.com/qredin/qredin/internal/attestation/node"
	"github.com/qredin/qredin/internal/config"
	"github.com/qredin/qredin/internal/keymanager"
	"github.com/qredin/qredin/pkg/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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
	runReconnectLoop(ctx, cfg.Agent.ServerAddr, td, nodeID, keyManager, tokenStore, logger)
}

func runReconnectLoop(ctx context.Context, serverAddr string, td spiffeid.TrustDomain, nodeID spiffeid.ID, keyManager keymanager.Manager, tokenStore *node.JoinTokenStore, logger *slog.Logger) {
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

		if err := attemptConnection(ctx, serverAddr, td, nodeID, keyManager, tokenStore, logger); err != nil {
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
	jitterRange := int64(next) / 2
	if jitterRange > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(jitterRange))
		if err == nil {
			jitter := n.Int64() - (int64(next) / 4)
			next = time.Duration(int64(next) + jitter)
		}
	}
	return next
}

func attemptConnection(ctx context.Context, serverAddr string, td spiffeid.TrustDomain, nodeID spiffeid.ID, keyManager keymanager.Manager, tokenStore *node.JoinTokenStore, logger *slog.Logger) error {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var creds credentials.TransportCredentials = insecure.NewCredentials()
	
	// Add mTLS support using node SVID if available, or insecure for initial bootstrap
	certPEM, err := os.ReadFile("node_svid.pem")
	if err == nil {
		if signer, err := keyManager.Signer(ctx, "node-svid"); err == nil {
			var certs [][]byte
			rest := certPEM
			for len(rest) > 0 {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}
				if block.Type == "CERTIFICATE" {
					certs = append(certs, block.Bytes)
				}
			}
			if len(certs) > 0 {
				tlsCert := tls.Certificate{
					Certificate: certs,
					PrivateKey:  signer,
				}
				creds = credentials.NewTLS(&tls.Config{
					Certificates:       []tls.Certificate{tlsCert},
					InsecureSkipVerify: true,
				})
			}
		}
	}

	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("failed to dial server: %w", err)
	}
	defer conn.Close()

	client := pb.NewWorkloadAPIClient(conn)
	req := &pb.BundleRequest{
		TrustDomain: td.String(),
	}
	
	_, err = client.FetchBundle(dialCtx, req)
	if err != nil {
		return fmt.Errorf("failed to fetch initial bundle: %w", err)
	}

	return nil
}

func printVersion() {
	enc, _ := json.MarshalIndent(map[string]string{"version": "dev"}, "", "  ")
	fmt.Println(string(enc))
}