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
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qredin/qredin/authentication/config"
	"github.com/qredin/qredin/authentication/internal/ca"
	"github.com/qredin/qredin/authentication/internal/keymanager"
	"github.com/qredin/qredin/authentication/internal/server"
	"github.com/qredin/qredin/authentication/internal/store"
	"github.com/qredin/qredin/authentication/internal/workloadapi"
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

	slog.Info("starting Qredin Identity Server",
		"trust_domain", td.String(),
		"uds_path", cfg.HTTP.UDSPath,
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
	poolConfig.MaxConnLifetime = cfg.Postgres.MaxConnLifetime
	poolConfig.MaxConnIdleTime = cfg.Postgres.MaxConnIdle
	poolConfig.HealthCheckPeriod = cfg.Postgres.MaxConnIdle
	poolConfig.ConnConfig.ConnectTimeout = cfg.Postgres.ConnTimeout
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

	keyManager, err := keymanager.NewDiskManager(cfg.KeyManager.Dir)
	if err != nil {
		slog.Error("failed to create key manager", "error", err)
		os.Exit(1)
	}
	keyManagerCtx, keyManagerCancel := context.WithCancel(context.Background())
	defer keyManagerCancel()

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

	if err := keyManager.Open(keyManagerCtx, kmEnv); err != nil {
		slog.Error("failed to open key manager", "error", err)
		os.Exit(1)
	}

	authority, err := ca.NewSelfSigned(keyManagerCtx, keyManager, td, cfg.Server.AuthorityTTL)
	if err != nil {
		slog.Error("failed to create authority", "error", err)
		os.Exit(1)
	}
	slog.Info("created authority",
		"serial_number", authority.Certificate().SerialNumber.String(),
		"not_after", authority.Certificate().NotAfter)

	regRepo, err := store.NewRegistrationRepository(pool)
	if err != nil {
		slog.Error("failed to create registration repository", "error", err)
		os.Exit(1)
	}
	approvalRepo, err := store.NewRegistrationApprovalRepository(pool)
	if err != nil {
		slog.Error("failed to create approval repository", "error", err)
		os.Exit(1)
	}
	auditRepo, err := store.NewAuditRepository(pool)
	if err != nil {
		slog.Error("failed to create audit repository", "error", err)
		os.Exit(1)
	}
	regStore := store.NewRegistrationService(pool, regRepo, approvalRepo, auditRepo)

	workloadResolver := server.NewResolver(td, regStore, authority)
	workloadService := workloadapi.NewWorkloadService(workloadResolver)

	udsConfig := workloadapi.NewUDSListenerConfig()
	udsConfig.SetAllowed(true)

	os.MkdirAll("/var/run/qredin", 0o755)
	udsListener, err := net.Listen("unix", cfg.HTTP.UDSPath)
	if err != nil {
		slog.Error("failed to listen on UDS socket", "error", err)
		os.Exit(1)
	}
	defer udsListener.Close()
	slog.Info("listening on UDS socket", "path", cfg.HTTP.UDSPath)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(workloadapi.RequireHeader()),
		grpc.StreamInterceptor(workloadapi.RequireStreamHeader()),
	)
	workloadService.Register(grpcServer)

	httpServer := startHealthServer(healthChecker, pool, logger, cfg.HTTP.ListenAddr)

	go func() {
		slog.Info("starting Workload API gRPC server on UDS")
		if err := grpcServe(grpcServer, udsListener); err != nil {
			slog.Error("Workload API gRPC server failed", "error", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down identity server")
	grpcServer.GracefulStop()
	if httpServer != nil {
		httpServer.Close()
	}
	slog.Info("identity server stopped")
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

func startHealthServer(checker *store.HealthChecker, pool *pgxpool.Pool, logger *slog.Logger, addr string) *http.Server {
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
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		slog.Info("health/metrics on", "address", addr)
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

type healthHandler struct {
	lg      *slog.Logger
	pool    *pgxpool.Pool
	checker *store.HealthChecker
	mu      sync.RWMutex
	lastErr error
}

func HealthHandler(lg *slog.Logger, pool *pgxpool.Pool, checker *store.HealthChecker) http.Handler {
	h := &healthHandler{lg: lg, pool: pool, checker: checker}
	return h
}

func (h *healthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" || path == "healthz" || path == "readyz" {
		h.serveCheck(w, r, path)
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (h *healthHandler) serveCheck(w http.ResponseWriter, r *http.Request, subpath string) {
	var msg string
	var code int
	var extra map[string]interface{}

	switch subpath {
	case "":
		code = http.StatusOK
		msg = "ok"
	case "readyz":
		if err := h.checker.Check(r.Context()); err != nil {
			h.mu.Lock()
			h.lastErr = err
			h.mu.Unlock()
			code = http.StatusServiceUnavailable
			msg = err.Error()
			extra = map[string]interface{}{"error": err.Error()}
		} else {
			code = http.StatusOK
			msg = "ready"
			stat := h.pool.Stat()
			extra = map[string]interface{}{
				"conns_total":     stat.TotalConns(),
				"conns_idle":      stat.IdleConns(),
				"conns_acquired":  stat.AcquiredConns(),
				"max_conns":       stat.MaxConns(),
				"constructing":    stat.ConstructingConns(),
				"empty_acquires":  stat.EmptyAcquireCount(),
			}
		}
	default:
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if extra == nil {
		extra = map[string]interface{}{}
	}
	extra["status"] = msg
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(extra)
}
