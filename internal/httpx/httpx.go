// Package httpx serves the informational /healthz endpoint.
package httpx

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// StatusFunc returns the current status document.
type StatusFunc func() any

// Handler returns an HTTP handler exposing the status as JSON. It always
// responds 200 while the process is alive: ACME or reload failures must not
// make an orchestrator restart the manager. Failure detail lives in the body.
func Handler(status StatusFunc) http.Handler {
	mux := http.NewServeMux()
	serve := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(status())
	}
	mux.HandleFunc("/healthz", serve)
	mux.HandleFunc("/", serve)
	return mux
}

// Server wraps an http.Server with graceful shutdown.
type Server struct {
	srv *http.Server
}

// NewServer builds a server bound to addr.
func NewServer(addr string, status StatusFunc) *Server {
	return &Server{
		srv: &http.Server{
			Addr:              addr,
			Handler:           Handler(status),
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

// Start begins serving in a goroutine.
func (s *Server) Start(log *slog.Logger) {
	go func() {
		log.Info("status endpoint listening", "addr", s.srv.Addr)
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("status endpoint failed", "error", err)
		}
	}()
}

// Shutdown stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
