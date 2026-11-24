// Command sftp is Gameplane's optional SFTP endpoint (spec 040). It accepts
// SFTP clients on one address per cluster and sends every login and file
// operation to the Gameplane API as the signed-in user; it never reads a
// game server's volume itself. See specs.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/GameplanePanel/gameplane/sftp/internal/apiclient"
	"github.com/GameplanePanel/gameplane/sftp/internal/sshserver"
	"github.com/GameplanePanel/gameplane/sftp/internal/vfs"
	"github.com/pkg/sftp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "dev"

// errUsage is returned for an unknown or missing subcommand.
var errUsage = errors.New("usage: sftp serve [flags] | sftp version")

// Defaults and environment variable names for the serve subcommand. A flag
// overrides its variable, and the variable overrides the default.
const (
	defaultListen = ":2222"
	// The metrics listener is loopback-only by default: it has no
	// authentication, so exposing it is an explicit choice (the chart binds
	// it to the pod address only when a scrape is configured).
	defaultMetricsAddr         = "127.0.0.1:9102"
	defaultIdleTimeout         = 15 * time.Minute
	defaultMaxSessionsPerUser  = 4
	defaultMaxTransfersPerUser = 8
	defaultMaxPreAuth          = 64
	defaultMaxPreAuthPerIP     = 8

	envListen              = "GAMEPLANE_SFTP_LISTEN"
	envHostKey             = "GAMEPLANE_SFTP_HOST_KEY"
	envAPIURL              = "GAMEPLANE_SFTP_API_URL"
	envSvcAuthFile         = "GAMEPLANE_SFTP_SERVICE_TOKEN_FILE"
	envCAFile              = "GAMEPLANE_SFTP_CA_FILE"
	envAllowInsecureAPI    = "GAMEPLANE_SFTP_ALLOW_INSECURE_API"
	envIdleTimeout         = "GAMEPLANE_SFTP_IDLE_TIMEOUT"
	envMaxSessionsPerUser  = "GAMEPLANE_SFTP_MAX_SESSIONS_PER_USER"
	envMaxTransfersPerUser = "GAMEPLANE_SFTP_MAX_TRANSFERS_PER_USER"
	envMaxPreAuth          = "GAMEPLANE_SFTP_MAX_PREAUTH_CONNECTIONS"
	envMaxPreAuthPerIP     = "GAMEPLANE_SFTP_MAX_PREAUTH_PER_IP"
	envMetricsAddr         = "GAMEPLANE_SFTP_METRICS_ADDR"
	envDefaultNamespace    = "GAMEPLANE_SFTP_DEFAULT_NAMESPACE"

	metricsShutdownTimeout = 5 * time.Second
	metricsReadHeaderLimit = 10 * time.Second
	metricsIOLimit         = 30 * time.Second
)

func main() {
	os.Exit(exitCode(os.Args[1:], os.Stdout, os.Stderr))
}

// exitCode runs one subcommand and returns the process exit code: 0 on
// success, 2 after printing the error to errOut.
func exitCode(args []string, out, errOut io.Writer) int {
	var err error
	if len(args) > 0 && args[0] == "serve" {
		err = runServe(args[1:], os.Getenv, errOut)
	} else {
		err = run(args, out)
	}
	if err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 2
	}
	return 0
}

// run dispatches the subcommands that print and return: version. serve is
// handled by exitCode, which owns the process signals.
func run(args []string, out io.Writer) error {
	if len(args) != 1 || args[0] != "version" {
		return errUsage
	}
	if _, err := fmt.Fprintln(out, Version); err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	return nil
}

// serveConfig is the parsed serve subcommand.
type serveConfig struct {
	Listen           string
	HostKeyPath      string
	APIURL           string
	ServiceTokenFile string
	CAFile           string
	// AllowInsecureAPI accepts an http:// API URL. Off by default.
	AllowInsecureAPI   bool
	IdleTimeout        time.Duration
	MaxSessionsPerUser int
	// MaxTransfersPerUser is handed to the virtual file system's per-user
	// transfer limiter.
	MaxTransfersPerUser int
	// MaxPreAuth caps concurrent connections still before authentication.
	MaxPreAuth int
	// MaxPreAuthPerIP caps those connections per source IP.
	MaxPreAuthPerIP int
	MetricsAddr     string
	// DefaultNamespace is the namespace shown as /<server> at the top of a
	// tree login. It must match the API's default games namespace.
	DefaultNamespace string
}

// parseServeConfig reads the serve flags, falling back to the environment
// and then to the defaults. The required settings are checked here.
func parseServeConfig(args []string, getenv func(string) string, errOut io.Writer) (serveConfig, error) {
	idle, err := envDuration(getenv, envIdleTimeout, defaultIdleTimeout)
	if err != nil {
		return serveConfig{}, err
	}
	maxSessions, err := envInt(getenv, envMaxSessionsPerUser, defaultMaxSessionsPerUser)
	if err != nil {
		return serveConfig{}, err
	}
	maxTransfers, err := envInt(getenv, envMaxTransfersPerUser, defaultMaxTransfersPerUser)
	if err != nil {
		return serveConfig{}, err
	}

	maxPreAuth, err := envInt(getenv, envMaxPreAuth, defaultMaxPreAuth)
	if err != nil {
		return serveConfig{}, err
	}

	maxPreAuthIP, err := envInt(getenv, envMaxPreAuthPerIP, defaultMaxPreAuthPerIP)
	if err != nil {
		return serveConfig{}, err
	}
	allowInsecure, err := envBool(getenv, envAllowInsecureAPI)
	if err != nil {
		return serveConfig{}, err
	}

	var c serveConfig
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&c.Listen, "listen", envString(getenv, envListen, defaultListen), "address to accept SSH connections on")
	fs.StringVar(&c.HostKeyPath, "host-key", getenv(envHostKey), "host key file or directory (required)")
	fs.StringVar(&c.APIURL, "api-url", getenv(envAPIURL), "Gameplane API base URL, for example https://gameplane-api.gameplane.svc:8080 (required)")
	fs.StringVar(&c.ServiceTokenFile, "service-token-file", getenv(envSvcAuthFile), "file holding the service token (required)")
	fs.StringVar(&c.CAFile, "ca-file", getenv(envCAFile), "optional PEM bundle of extra CA certificates for the API")
	fs.BoolVar(&c.AllowInsecureAPI, "allow-insecure-api", allowInsecure, "accept an http:// API URL; credentials then cross the network unencrypted (only for a hop inside one cluster's pod network)")
	fs.DurationVar(&c.IdleTimeout, "idle-timeout", idle, "close a connection with no traffic for this long")
	fs.IntVar(&c.MaxSessionsPerUser, "max-sessions-per-user", maxSessions, "concurrent SSH connections allowed per user")
	fs.IntVar(&c.MaxTransfersPerUser, "max-transfers-per-user", maxTransfers, "concurrent file transfers allowed per user")
	fs.IntVar(&c.MaxPreAuth, "max-preauth-connections", maxPreAuth, "concurrent connections allowed before authentication finishes; more are closed at once")
	fs.IntVar(&c.MaxPreAuthPerIP, "max-preauth-per-ip", maxPreAuthIP, "concurrent connections allowed per source IP before authentication finishes; more are closed at once")
	fs.StringVar(&c.MetricsAddr, "metrics-addr", envString(getenv, envMetricsAddr, defaultMetricsAddr), "address for /metrics; empty disables it")
	fs.StringVar(&c.DefaultNamespace, "default-namespace", envString(getenv, envDefaultNamespace, vfs.DefaultNamespace), "namespace whose servers appear as /<server>; must match the API's default games namespace")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, fmt.Errorf("serve: %w", err)
	}
	if fs.NArg() > 0 {
		return serveConfig{}, fmt.Errorf("serve: unexpected argument %q", fs.Arg(0))
	}
	required := []struct{ flag, value string }{
		{"host-key", c.HostKeyPath},
		{"api-url", c.APIURL},
		{"service-token-file", c.ServiceTokenFile},
	}
	for _, r := range required {
		if r.value == "" {
			return serveConfig{}, fmt.Errorf("serve: --%s is required", r.flag)
		}
	}
	if c.IdleTimeout <= 0 {
		return serveConfig{}, errors.New("serve: --idle-timeout must be positive")
	}
	if c.MaxSessionsPerUser < 1 {
		return serveConfig{}, errors.New("serve: --max-sessions-per-user must be at least 1")
	}
	if c.MaxTransfersPerUser < 1 {
		return serveConfig{}, errors.New("serve: --max-transfers-per-user must be at least 1")
	}
	if c.MaxPreAuth < 1 {
		return serveConfig{}, errors.New("serve: --max-preauth-connections must be at least 1")
	}
	if c.MaxPreAuthPerIP < 1 {
		return serveConfig{}, errors.New("serve: --max-preauth-per-ip must be at least 1")
	}
	return c, nil
}

func envString(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(getenv func(string) string, key string) (bool, error) {
	v := getenv(key)
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}

func envDuration(getenv func(string) string, key string, def time.Duration) (time.Duration, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func envInt(getenv func(string) string, key string, def int) (int, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// runServe starts the SSH/SFTP endpoint and blocks until SIGINT or SIGTERM.
func runServe(args []string, getenv func(string) string, errOut io.Writer) error {
	cfg, err := parseServeConfig(args, getenv, errOut)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(errOut, nil))

	hostKeys, err := sshserver.LoadHostKeys(cfg.HostKeyPath)
	if err != nil {
		return err
	}
	token, err := apiclient.LoadServiceToken(cfg.ServiceTokenFile)
	if err != nil {
		return err
	}
	api, err := apiclient.New(apiclient.Config{BaseURL: cfg.APIURL, ServiceToken: token, CAFile: cfg.CAFile, AllowInsecureHTTP: cfg.AllowInsecureAPI})
	if err != nil {
		return fmt.Errorf("api client: %w", err)
	}

	reg := prometheus.NewRegistry()
	metrics, err := sshserver.NewMetrics(reg)
	if err != nil {
		return err
	}
	limiter := vfs.NewLimiter(cfg.MaxTransfersPerUser)
	// srv is set right below, before Serve starts any connection, so the
	// handlers never see it nil.
	var srv *sshserver.Server
	factory := func(sess apiclient.Session, _ string) sftp.Handlers {
		return vfs.New(api, sess, vfs.Options{
			DefaultNamespace: cfg.DefaultNamespace,
			Limiter:          limiter,
			OnBytes:          metrics.AddBytes,
			Logger:           logger,
			OnUnauthorized:   func() { srv.Revoke(sess.Token) },
		}).Handlers()
	}
	srv, err = sshserver.New(sshserver.Config{
		Addr:                  cfg.Listen,
		HostKeys:              hostKeys,
		IdleTimeout:           cfg.IdleTimeout,
		MaxSessionsPerUser:    cfg.MaxSessionsPerUser,
		MaxPreAuthConnections: cfg.MaxPreAuth,
		MaxPreAuthPerIP:       cfg.MaxPreAuthPerIP,
		Logger:                logger,
		Metrics:               metrics,
	}, api, factory)
	if err != nil {
		return err
	}
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var metricsSrv *http.Server
	if cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		metricsSrv = &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: metricsReadHeaderLimit,
			ReadTimeout:       metricsIOLimit,
			WriteTimeout:      metricsIOLimit,
			IdleTimeout:       metricsIOLimit,
		}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("metrics server failed", "err", err)
			}
		}()
	}

	logger.Info("sftp listening", "addr", l.Addr().String())
	serveErr := srv.Serve(ctx, l)
	if metricsSrv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
		_ = metricsSrv.Shutdown(sctx)
		cancel()
	}
	return serveErr
}
