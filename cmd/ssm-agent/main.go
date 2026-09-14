// ssm-agent is intended to run as a systemd service. Cancellation interrupts HTTP
// requests and hooks; a file publication already in progress finishes atomically.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
	"simplesecretsmanager/internal/agent"
	"simplesecretsmanager/internal/version"
)

func main() {
	if e := run(); e != nil {
		slog.Error("agent stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	v := flag.Bool("v", false, "print installed version")
	config := flag.String("config", "/etc/ssm-agent/config.yaml", "agent configuration")
	once := flag.Bool("once", false, "synchronize once and exit")
	flag.Parse()
	if *v {
		fmt.Println(version.Version)
		return nil
	}
	syscall.Umask(0077)
	c, e := agent.LoadConfig(*config)
	if e != nil {
		return fmt.Errorf("cannot load agent configuration")
	}
	var level slog.Level
	if e = level.UnmarshalText([]byte(c.LogLevel)); e != nil {
		return fmt.Errorf("invalid log_level")
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
	a, e := agent.New(c, log)
	if e != nil {
		return e
	}
	// Hold an advisory lock for the full process lifetime. Two local agents must
	// never race enrollment or independently overwrite the revision journal.
	fd, e := unix.Open(c.StateDir+"/agent.lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return fmt.Errorf("cannot open agent lock")
	}
	defer unix.Close(fd)
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fmt.Errorf("another agent is using this state directory")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("agent starting", "version", version.Version)
	if *once {
		return a.Sync(ctx)
	}
	return a.Run(ctx)
}
