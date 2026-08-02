package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/LinYS77/coderelay/internal/api"
	"github.com/LinYS77/coderelay/internal/auth"
	"github.com/LinYS77/coderelay/internal/config"
	"github.com/LinYS77/coderelay/internal/secretfile"
	"github.com/LinYS77/coderelay/internal/service"
	"github.com/LinYS77/coderelay/internal/totp"
	"github.com/LinYS77/coderelay/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

func run(arguments []string) error {
	if len(arguments) == 1 && (arguments[0] == "--version" || arguments[0] == "version") {
		fmt.Fprintf(os.Stdout, "CodeRelay Go %s\n", version.Value)
		return nil
	}
	if len(arguments) == 0 {
		return fmt.Errorf("expected serve, validate-config, generate-api-token, or --version")
	}
	switch arguments[0] {
	case "serve":
		return runServe(arguments[1:])
	case "validate-config":
		return runValidate(arguments[1:])
	case "generate-api-token":
		return runGenerateToken(arguments[1:])
	default:
		return fmt.Errorf("unknown command")
	}
}

func runServe(arguments []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "path to Go TOML configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("positional arguments are not allowed")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	verifier, err := auth.LoadVerifier(cfg.Security)
	if err != nil {
		return err
	}
	logger := newLogger(cfg.Server.LogLevel)
	resolver := service.NewResolver(totp.New())
	handler, err := api.NewHandler(cfg, verifier, resolver, logger)
	if err != nil {
		return err
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return service.Serve(signalCtx, cfg, handler, logger)
}

func runValidate(arguments []string) error {
	flags := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "path to Go TOML configuration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("positional arguments are not allowed")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if _, err := auth.LoadVerifier(cfg.Security); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Configuration is valid: %s\n", cfg.ConfigPath)
	fmt.Fprintln(os.Stdout, "- mode: stateless")
	fmt.Fprintln(os.Stdout, "- phase: 1 (totp)")
	return nil
}

func runGenerateToken(arguments []string) error {
	flags := flag.NewFlagSet("generate-api-token", flag.ContinueOnError)
	hashFile := flags.String("hash-file", "", "new mode-0600 file for the API token SHA-256 hash")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("positional arguments are not allowed")
	}
	if *hashFile == "" {
		return fmt.Errorf("--hash-file is required")
	}
	token, hash, err := auth.GenerateToken()
	if err != nil {
		return err
	}
	defer clear(token)
	defer clear(hash)
	if err := secretfile.WriteExclusive(*hashFile, hash); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Token hash written to %s\n", *hashFile)
	_, _ = os.Stdout.Write([]byte("API token (shown once):\n"))
	_, _ = os.Stdout.Write(token)
	_, _ = os.Stdout.Write([]byte{'\n'})
	return nil
}

func defaultConfigPath() string {
	if value := os.Getenv("CODERELAY_CONFIG"); value != "" {
		return value
	}
	return "config.go.toml"
}

func newLogger(level string) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slogLevel}))
}
