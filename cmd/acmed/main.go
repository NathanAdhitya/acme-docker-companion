// Command acmed is a Docker sidecar that obtains and renews TLS certificates
// via ACME DNS-01 and delivers them into containers.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/NathanAdhitya/acme-docker-companion/internal/acmex"
	"github.com/NathanAdhitya/acme-docker-companion/internal/config"
	"github.com/NathanAdhitya/acme-docker-companion/internal/dockerx"
	"github.com/NathanAdhitya/acme-docker-companion/internal/httpx"
	"github.com/NathanAdhitya/acme-docker-companion/internal/labels"
	"github.com/NathanAdhitya/acme-docker-companion/internal/reconciler"
	"github.com/NathanAdhitya/acme-docker-companion/internal/store"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "run":
		return cmdRun(args)
	case "check":
		return cmdCheck(args)
	case "healthcheck":
		return cmdHealthcheck(args)
	default:
		fmt.Fprintf(os.Stderr, "acmed: unknown command %q (expected run, check or healthcheck)\n", cmd)
		return 2
	}
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	once := fs.Bool("once", false, "run a single reconcile/renew cycle and exit")
	dryRun := fs.Bool("dry-run", false, "use staging endpoints, a separate state dir, and never deliver or reload")
	logLevel := fs.String("log-level", "", "log level (debug, info, warn, error)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, warnings, err := config.Load(*dryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, "acmed: configuration error:", err)
		return 1
	}
	log := setupLog(cfg.LogLevel, *logLevel)
	for _, w := range warnings {
		log.Warn(w)
	}
	if cfg.DryRun {
		log.Warn("dry-run enabled: staging endpoints only, no delivery, no reload")
	}

	st, err := store.Open(cfg.StateDir)
	if err != nil {
		log.Error("cannot open state directory", "error", err)
		return 1
	}
	defer st.Close()

	docker, err := dockerx.New(cfg.DockerHost)
	if err != nil {
		log.Error("cannot connect to Docker", "error", err)
		return 1
	}
	defer docker.Close()

	issuer, err := acmex.NewManager(cfg, st, log)
	if err != nil {
		log.Error("cannot initialize ACME client", "error", err)
		return 1
	}

	rec := reconciler.New(cfg, docker, issuer, st, log)

	srv := httpx.NewServer(cfg.HTTPAddr, func() any { return rec.Snapshot() })
	srv.Start(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *once {
		rec.Once(ctx)
		shutdown(srv, log)
		return 0
	}

	rec.Run(ctx)
	shutdown(srv, log)
	return 0
}

func shutdown(srv *httpx.Server, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Warn("status endpoint shutdown", "error", err)
	}
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "check as if running with --dry-run")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, warnings, err := config.Load(*dryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, "acmed: configuration error:", err)
		return 1
	}

	fmt.Print(cfg.Redacted())
	for _, w := range warnings {
		fmt.Println("warning:", w)
	}

	docker, derr := dockerx.New(cfg.DockerHost)
	if derr != nil {
		fmt.Println("warning: cannot connect to Docker, skipping label validation:", derr)
		return 0
	}
	defer docker.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	containers, lerr := docker.List(ctx)
	if lerr != nil {
		fmt.Println("warning: cannot list containers:", lerr)
		return 0
	}

	requests := 0
	for _, c := range containers {
		reqs, warns := labels.Parse(cfg.LabelPrefix, c.Labels, cfg.KeyType)
		for _, w := range warns {
			fmt.Printf("warning: container %s: %s\n", c.Name, w)
		}
		for _, req := range reqs {
			requests++
			fmt.Printf("certificate %s in container %s: domains=%s path=%s key-type=%s\n",
				labels.DisplayName(req.CertName), c.Name, strings.Join(req.Domains, ","), req.Path, req.KeyType)
		}
	}
	fmt.Printf("\n%d labeled container(s), %d certificate request(s)\n", len(containers), requests)
	return 0
}

func cmdHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	addr := config.HTTPAddr()
	url := "http://" + addr + "/healthz"
	if strings.HasPrefix(addr, ":") {
		url = "http://127.0.0.1" + addr + "/healthz"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "acmed: healthcheck failed:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "acmed: healthcheck status", resp.StatusCode)
		return 1
	}
	return 0
}

func setupLog(cfgLevel, flagLevel string) *slog.Logger {
	level := cfgLevel
	if flagLevel != "" {
		level = flagLevel
	}
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
