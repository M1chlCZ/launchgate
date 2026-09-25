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

const listenAddress = ":8090"

const healthURL = "http://127.0.0.1:8090/healthz"

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
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
		if len(args) != 2 {
			return errors.New("usage: mode closed|preview|public")
		}
		return setMode(cfg.StateDir, args[1])
	case "revoke":
		if len(args) != 2 {
			return errors.New("usage: revoke INVITATION_ID")
		}
		return revokeInvitation(cfg.StateDir, args[1])
	case "list":
		s, err := loadStore(cfg.StateDir)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Mode: %s\n", s.Mode)
		for _, i := range s.Invitations {
			fmt.Fprintf(out, "%s\t%s\t%s\n", i.ID, i.ExpiresAt.Format(time.RFC3339), i.Label)
		}
		return nil
	case "issue":
		flags := flag.NewFlagSet("issue", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		label := flags.String("label", "", "recipient label")
		ttl := flags.Duration("ttl", 7*24*time.Hour, "validity, at most 720h")
		if err := flags.Parse(args[1:]); err != nil {
			return errors.New("usage: issue -label NAME [-ttl 168h]")
		}
		if cfg.Origin == "" {
			return errors.New("LAUNCH_ORIGIN is required to print an invitation link")
		}
		i, token, err := issueInvitation(cfg.StateDir, *label, *ttl, time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "ID: %s\nExpires: %s\n%s%s#%s\n", i.ID, i.ExpiresAt.Format(time.RFC3339), cfg.Origin, entryPath, token)
		return nil
	case "healthcheck":
		client := http.Client{Timeout: 2 * time.Second}
		response, err := client.Get(healthURL)
		if err != nil {
			return errors.New("gateway unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return errors.New("gateway not ready")
		}
		return nil
	case "serve":
		handler, err := newGateway(cfg)
		if err != nil {
			return err
		}
		server := &http.Server{Addr: listenAddress, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		}()
		log.Print("launchgate started")
		err = server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	default:
		return errors.New("unknown command")
	}
}
