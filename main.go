package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	listenAddress        = ":8090"
	healthURL            = "http://127.0.0.1:8090/healthz"
	commandArgumentCount = 2
	healthcheckTimeout   = 2 * time.Second
	shutdownTimeout      = 10 * time.Second
	readHeaderTimeout    = 5 * time.Second
	readTimeout          = 60 * time.Second
	writeTimeout         = 120 * time.Second
	idleTimeout          = 60 * time.Second
	maxHeaderBytes       = 32 << 10
)

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func discardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	cfg := loadConfig()
	if len(args) == 0 {
		return errors.New("command required: serve, healthcheck, init, issue, revoke, list, mode")
	}
	switch args[0] {
	case "init":
		return initializeStore(cfg.StateDir)
	case "mode":
		if len(args) != commandArgumentCount {
			return errors.New("usage: mode closed|preview|public")
		}
		return setMode(cfg.StateDir, args[1])
	case "revoke":
		if len(args) != commandArgumentCount {
			return errors.New("usage: revoke INVITATION_ID")
		}
		return revokeInvitation(cfg.StateDir, args[1])
	case "list":
		return listCommand(cfg.StateDir, out)
	case "issue":
		return issueCommand(cfg, args[1:], out)
	case "healthcheck":
		return healthcheckCommand()
	case "serve":
		return serveCommand(cfg)
	default:
		return errors.New("unknown command")
	}
}

func listCommand(dir string, out io.Writer) error {
	s, err := loadStore(dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Mode: %s\n", s.Mode)
	for _, i := range s.Invitations {
		fmt.Fprintf(out, "%s\t%s\t%s\n", i.ID, i.ExpiresAt.Format(time.RFC3339), i.Label)
	}
	return nil
}

func issueCommand(cfg config, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	label := flags.String("label", "", "recipient label")
	ttl := flags.Duration("ttl", 7*24*time.Hour, "validity, at most 720h")
	if err := flags.Parse(args); err != nil {
		return errors.New("usage: issue -label NAME [-ttl 168h]")
	}
	if cfg.Origin == "" {
		return errors.New("LAUNCH_ORIGIN is required to print an invitation link")
	}
	i, token, err := issueInvitation(cfg.StateDir, *label, *ttl, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(
		out,
		"ID: %s\nExpires: %s\n%s%s#%s\n",
		i.ID,
		i.ExpiresAt.Format(time.RFC3339),
		cfg.Origin,
		entryPath,
		token,
	)
	return nil
}

func healthcheckCommand() error {
	client := http.Client{Timeout: healthcheckTimeout}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, healthURL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("gateway unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("gateway not ready")
	}
	return nil
}

func serveCommand(cfg config) error {
	handler, err := newGateway(cfg)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              listenAddress,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Print("launchgate started")
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
