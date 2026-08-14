package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/audit"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/autonomy"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/httpx"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/kubernetes"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/loki"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/prometheus"
	"github.com/riccardomenegazzo/kernel-sentinel/cortex/internal/tempo"
)

func main() {
	configPath := flag.String("config", "/etc/cortex/config.json", "agent config")
	once := flag.Bool("once", false, "run one investigation cycle and exit")
	listen := flag.String("listen", ":8080", "health/status listen address")
	flag.Parse()
	cfg, err := autonomy.LoadFile(*configPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Config.Execute && os.Getenv("CORTEX_ALLOW_AUTONOMOUS") != "true" {
		fatal(fmt.Errorf("execute=true requires CORTEX_ALLOW_AUTONOMOUS=true"))
	}
	cluster, err := kubernetes.InCluster()
	if err != nil {
		fatal(err)
	}
	prom := prometheus.New(cfg.PrometheusURL)
	prom.HTTP, err = httpx.Client(cfg.PrometheusCAFile, 10*time.Second)
	if err != nil {
		fatal(err)
	}
	prom.BearerToken, err = httpx.Secret(cfg.PrometheusBearerToken, cfg.PrometheusBearerTokenEnv, cfg.PrometheusBearerTokenFile)
	if err != nil {
		fatal(err)
	}
	var logSource autonomy.Logs
	if cfg.LokiURL != "" {
		l := loki.New(cfg.LokiURL)
		l.HTTP, err = httpx.Client(cfg.LokiCAFile, 10*time.Second)
		if err != nil {
			fatal(err)
		}
		l.BearerToken, err = httpx.Secret(cfg.LokiBearerToken, cfg.LokiBearerTokenEnv, cfg.LokiBearerTokenFile)
		if err != nil {
			fatal(err)
		}
		logSource = l
	}
	var traceSource autonomy.Traces
	if cfg.TempoURL != "" {
		t := tempo.New(cfg.TempoURL)
		t.HTTP, err = httpx.Client(cfg.TempoCAFile, 10*time.Second)
		if err != nil {
			fatal(err)
		}
		t.BearerToken, err = httpx.Secret(cfg.TempoBearerToken, cfg.TempoBearerTokenEnv, cfg.TempoBearerTokenFile)
		if err != nil {
			fatal(err)
		}
		traceSource = t
	}
	key := []byte(nil)
	if cfg.AuditHMACEnv != "" {
		key = []byte(os.Getenv(cfg.AuditHMACEnv))
	}
	if cfg.Config.Execute && (cfg.AuditPath == "" || len(key) < 32) {
		fatal(fmt.Errorf("autonomous execution requires audit_path and an HMAC key of at least 32 bytes via audit_hmac_env"))
	}
	aud, err := audit.New(cfg.AuditPath, key)
	if err != nil {
		fatal(err)
	}
	ctl := &autonomy.Controller{Config: cfg.Config, Metrics: prom, Traces: traceSource, Logs: logSource, Cluster: cluster, Audit: aud}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *once {
		r, err := ctl.RunOnce(ctx)
		if err != nil {
			fatal(err)
		}
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}

	var mu sync.RWMutex
	var last autonomy.Result
	var ready atomic.Bool
	run := func() {
		r, err := ctl.RunOnce(ctx)
		if err != nil {
			log.Printf("cycle failed: %v", err)
			return
		}
		mu.Lock()
		last = r
		mu.Unlock()
		ready.Store(true)
		b, _ := json.Marshal(r)
		log.Printf("decision %s", b)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, _ *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(last)
	})
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http server: %v", err)
		}
	}()
	run()
	ticker := time.NewTicker(time.Duration(cfg.PollSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(shutdown)
			cancel()
			return
		case <-ticker.C:
			run()
		}
	}
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "cortex-agent:", err); os.Exit(1) }
