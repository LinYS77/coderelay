// Package service owns the HTTP server lifecycle and graceful shutdown.
package service

import (
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"

	"github.com/LinYS77/coderelay/internal/api"
	"github.com/LinYS77/coderelay/internal/config"
)

func Serve(ctx context.Context, cfg config.Config, handler *api.Handler, logger *slog.Logger) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if handler == nil {
		return errors.New("API handler is not initialized")
	}
	listener, err := net.Listen("tcp", cfg.Address())
	if err != nil {
		return err
	}
	return serveListener(ctx, cfg, handler, logger, listener)
}

func serveListener(ctx context.Context, cfg config.Config, handler *api.Handler, logger *slog.Logger, listener net.Listener) error {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	listener = newBoundedListener(listener, cfg.Server.MaxInboundConnections)
	defer listener.Close()

	workCtx, cancelWork := context.WithCancel(context.Background())
	defer cancelWork()
	handler.Start(workCtx)
	server := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           handler,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout(),
		ReadTimeout:       cfg.Server.ReadTimeout(),
		WriteTimeout:      cfg.Server.WriteTimeout(),
		IdleTimeout:       cfg.Server.IdleTimeout(),
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context {
			return workCtx
		},
	}

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()
	logger.Info("application_started", "mode", "stateless", "address", listener.Addr().String())

	select {
	case err := <-serveResult:
		handler.BeginShutdown()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	handler.BeginShutdown()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout())
	shutdownErr := server.Shutdown(shutdownCtx)
	cancelShutdown()
	if shutdownErr != nil {
		cancelWork()
		_ = server.Close()
	}
	serveErr := <-serveResult
	cancelWork()
	logger.Info("application_stopped")
	if shutdownErr != nil {
		return shutdownErr
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}
