package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qredin/qredin/internal/config"
	"github.com/qredin/qredin/internal/policy"
	"github.com/qredin/qredin/internal/store"
	"github.com/qredin/qredin/internal/authorization"
	"github.com/qredin/qredin/pkg/spiffeid"
	"google.golang.org/grpc"
)

var (
	configPath = flag.String("config", "", "Path to configuration file (required)")
	version    = flag.Bool("version", false, "Print version and exit")
)

const buildVersion = "dev"

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

	logger := setupLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil {
		slog.Error("invalid trust domain", "error", err)
		os.Exit(1)
	}

	slog.Info("starting Qredin Authorization Service",
		"trust_domain", td.String(),
		"grpc_listen", cfg.HTTP.ListenAddr)

	poolCtx, poolCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer poolCancel()
	poolConfig, err := pgxpool.ParseConfig(cfg.Postgres.DSN)
	if err != nil {
		slog.Error("failed to parse database DSN", "error", err)
		os.Exit(1)
	}
	poolConfig.MaxConns = int32(cfg.Postgres.MaxConns)
	poolConfig.MinConns = int32(cfg.Postgres.MinConns)
	poolConfig.HealthCheckPeriod = cfg.Postgres.ConnTimeout
	pool, err := pgxpool.NewWithConfig(poolCtx, poolConfig)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := store.ApplyMigrations(ctx, pool); err != nil {
		slog.Error("failed to apply migrations", "error", err)
		os.Exit(1)
	}

	healthChecker := store.NewHealthChecker(pool)

	auditRepo, err := store.NewAuditRepository(pool)
	if err != nil {
		slog.Error("failed to create audit repository", "error", err)
		os.Exit(1)
	}

	policyRepo, err := store.NewPolicyRepository(pool)
	if err != nil {
		slog.Error("failed to create policy repository", "error", err)
		os.Exit(1)
	}
	policyApprovalRepo, err := store.NewPolicyApprovalRepository(pool)
	if err != nil {
		slog.Error("failed to create policy approval repository", "error", err)
		os.Exit(1)
	}
	noopRisk := policy.NoopRiskProvider{}
	policySvc := store.NewPolicyService(policyRepo, auditRepo, policyApprovalRepo, healthChecker)
	cache := policy.NewPolicyDecisionCache(1000, 5*time.Minute, []string{})
	dslProvider := policy.NewDSLProvider(cache)
	policySvc.SetDecisionProvider(dslProvider)

	authSvc := authorization.NewAuthServiceProvider(
		&authzService{
			UnimplementedService: authorization.UnimplementedService{},
			policySvc:            policySvc,
			scope: policy.PolicyScope{
				TenantID:      "default",
				EnvironmentID: "production",
				TrustDomain:   td,
			},
			riskProviders: map[string]policy.RiskProvider{"noop": noopRisk},
		},
	)

	adminListener, err := net.Listen("tcp", cfg.HTTP.ListenAddr)
	if err != nil {
		slog.Error("failed to listen on administrative address", "error", err)
		os.Exit(1)
	}
	defer adminListener.Close()
	slog.Info("listening on administrative gRPC", "address", cfg.HTTP.ListenAddr)

	adminServer := grpc.NewServer()
	authorization.RegisterAuthService(adminServer, authSvc)

	httpServer := startHealthServer(healthChecker, pool, logger)

	go func() {
		slog.Info("starting authorization gRPC server")
		if err := grpcServe(adminServer, adminListener); err != nil {
			slog.Error("authorization gRPC server failed", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down authorization service")
	adminServer.GracefulStop()
	if httpServer != nil {
		httpServer.Close()
	}
	slog.Info("authorization service stopped")
}

func grpcServe(s *grpc.Server, l net.Listener) error {
	if err := s.Serve(l); err != nil {
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	}
	return nil
}

func startHealthServer(checker *store.HealthChecker, pool *pgxpool.Pool, logger *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := checker.Check(r.Context()); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "unhealthy", "error": err.Error()})
			return
		}
		stat := pool.Stat()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "ready",
			"conns_total":   stat.TotalConns(),
			"conns_idle":    stat.IdleConns(),
			"conns_acquired": stat.AcquiredConns(),
			"max_conns":     stat.MaxConns(),
		})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		stat := pool.Stat()
		fmt.Fprintf(w, "qredin_db_conns_total{direction=\"total\"} %d\n", stat.TotalConns())
		fmt.Fprintf(w, "qredin_db_conns_idle{direction=\"idle\"} %d\n", stat.IdleConns())
		fmt.Fprintf(w, "qredin_db_conns_acquired{direction=\"acquired\"} %d\n", stat.AcquiredConns())
	})
	srv := &http.Server{Addr: "localhost:9091", Handler: mux}
	go func() {
		slog.Info("health/metrics on :9091")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("health server failed", "error", err)
		}
	}()
	return srv
}

func setupLogger(level, format string) *slog.Logger {
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

func printVersion() {
	bi := struct {
		Version   string `json:"version"`
		GoVersion string `json:"go_version"`
		GOOS      string `json:"goos"`
	}{
		Version:   buildVersion,
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
	}
	enc, _ := json.MarshalIndent(bi, "", "  ")
	fmt.Println(string(enc))
}

type authzService struct {
	authorization.UnimplementedService
	policySvc     *store.PolicyService
	scope         policy.PolicyScope
	riskProviders map[string]policy.RiskProvider
}

func (s *authzService) Check(ctx context.Context, req *policy.AuthorizationRequest) (*policy.AuthorizationDecision, error) {
	decision, err := s.policySvc.Evaluate(ctx, *req, s.scope, s.riskProviders)
	if err != nil {
		return nil, err
	}
	return &decision, nil
}