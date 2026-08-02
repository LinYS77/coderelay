package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LinYS77/coderelay/prototypes/outlook-go/internal/probe"
)

const prototypeVersion = "0.1.0-phase0"

type oauthReport struct {
	RefreshSucceeded bool `json:"refresh_succeeded"`
	ScopeVerified    bool `json:"scope_verified"`
	RotationReturned bool `json:"rotation_returned"`
	RotationSaved    bool `json:"rotation_saved"`
}

type realReport struct {
	Prototype       string           `json:"prototype"`
	Version         string           `json:"version"`
	Status          string           `json:"status"`
	GoIMAPVersion   string           `json:"go_imap_version"`
	OAuth           oauthReport      `json:"oauth"`
	IMAP            probe.IMAPReport `json:"imap"`
	Leak            probe.LeakReport `json:"leak_check"`
	SensitiveOutput bool             `json:"sensitive_output"`
}

type errorReport struct {
	Prototype string `json:"prototype"`
	Status    string `json:"status"`
	Stage     string `json:"stage"`
	Code      string `json:"code"`
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "real" {
		fmt.Fprintln(os.Stderr, "usage: outlook-phase0 real --credential-file PATH --rotation-output PATH [options]")
		os.Exit(2)
	}
	if err := runReal(os.Args[2:]); err != nil {
		stage, code := probe.SafeErrorFields(err)
		_ = json.NewEncoder(os.Stderr).Encode(errorReport{
			Prototype: "outlook-go-phase0",
			Status:    "fail",
			Stage:     stage,
			Code:      code,
		})
		os.Exit(1)
	}
}

func runReal(arguments []string) error {
	flags := flag.NewFlagSet("real", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	credentialFile := flags.String("credential-file", "", "0600 file containing the four-part Outlook credential")
	rotationOutput := flags.String("rotation-output", "", "0600 output file for a rotated refresh token")
	cycles := flags.Int("cycles", 2, "batch fetch cycles in one request-scoped IMAP session")
	maxMessages := flags.Uint("max-messages", 10, "latest messages fetched per cycle (1-20)")
	leakIterations := flags.Int("leak-iterations", 0, "additional connect/auth/select/noop/close iterations")
	leakDelay := flags.Duration("leak-delay", 500*time.Millisecond, "delay before each real leak-check connection")
	overallTimeout := flags.Duration("overall-timeout", 5*time.Minute, "whole probe timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return &probe.StageError{Stage: "arguments", Code: "POSITIONAL_ARGUMENTS_FORBIDDEN"}
	}
	if *credentialFile == "" || *rotationOutput == "" {
		return &probe.StageError{Stage: "arguments", Code: "SECRET_PATHS_REQUIRED"}
	}
	if *cycles < 2 || *cycles > 3 {
		return &probe.StageError{Stage: "arguments", Code: "INVALID_CYCLES"}
	}
	if *maxMessages < 1 || *maxMessages > 20 {
		return &probe.StageError{Stage: "arguments", Code: "INVALID_MAX_MESSAGES"}
	}
	if *leakIterations < 0 || *leakIterations > 100 {
		return &probe.StageError{Stage: "arguments", Code: "INVALID_LEAK_ITERATIONS"}
	}
	if *leakDelay < 0 || *leakDelay > 5*time.Second {
		return &probe.StageError{Stage: "arguments", Code: "INVALID_LEAK_DELAY"}
	}
	if *overallTimeout < 30*time.Second || *overallTimeout > 30*time.Minute {
		return &probe.StageError{Stage: "arguments", Code: "INVALID_OVERALL_TIMEOUT"}
	}
	if err := probe.ValidateSecretOutputPath(*rotationOutput); err != nil {
		return err
	}

	credential, err := probe.ReadCredentialFile(*credentialFile)
	if err != nil {
		return err
	}
	defer credential.Destroy()

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalCtx, *overallTimeout)
	defer cancel()

	oauthClient := probe.NewMicrosoftOAuthClient()
	defer oauthClient.Close()
	token, err := oauthClient.Refresh(ctx, credential)
	if err != nil {
		return err
	}
	defer token.Destroy()

	report := realReport{
		Prototype:     "outlook-go-phase0",
		Version:       prototypeVersion,
		Status:        "probe_pass",
		GoIMAPVersion: "v2.0.0-beta.8",
		OAuth: oauthReport{
			RefreshSucceeded: true,
			ScopeVerified:    token.ScopeVerified,
			RotationReturned: len(token.RotatedRefreshToken) > 0,
		},
		SensitiveOutput: false,
	}
	if len(token.RotatedRefreshToken) > 0 {
		if err := probe.WriteSecretAtomic(*rotationOutput, token.RotatedRefreshToken); err != nil {
			return err
		}
		report.OAuth.RotationSaved = true
	}

	imapConfig := probe.DefaultIMAPConfig()
	imapConfig.MaxMessages = uint32(*maxMessages)
	imapReport, err := probe.ProbeIMAP(ctx, imapConfig, credential.Email, token.AccessToken, *cycles)
	if err != nil {
		return err
	}
	report.IMAP = imapReport

	// Keep the HTTP transport out of the IMAP-only leak baseline.
	oauthClient.Close()
	if *leakIterations > 0 {
		leakReport, err := probe.RunLeakCheck(ctx, *leakIterations, *leakDelay, func(iterationCtx context.Context) error {
			return probe.SmokeIMAP(iterationCtx, imapConfig, credential.Email, token.AccessToken)
		})
		report.Leak = leakReport
		if err != nil {
			report.Status = "resource_gate_operation_fail"
			_ = writeReport(report)
			return err
		}
		if !leakReport.Passed {
			report.Status = "resource_gate_fail"
			_ = writeReport(report)
			return &probe.StageError{Stage: "resource_leak", Code: "RESOURCE_DELTA"}
		}
		report.Status = "probe_and_resource_gate_pass"
	}
	return writeReport(report)
}

func writeReport(report realReport) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
