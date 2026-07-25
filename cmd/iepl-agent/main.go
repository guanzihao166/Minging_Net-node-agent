package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/guanzihao166/iepl-node-agent/internal/config"
	"github.com/guanzihao166/iepl-node-agent/internal/control"
	"github.com/guanzihao166/iepl-node-agent/internal/identity"
	"github.com/guanzihao166/iepl-node-agent/internal/maintenance"
	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
	agentruntime "github.com/guanzihao166/iepl-node-agent/internal/runtime"
	"github.com/guanzihao166/iepl-node-agent/internal/secretstore"
	"github.com/guanzihao166/iepl-node-agent/internal/state"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(os.Args[1:], logger); err != nil {
		logger.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string, logger *slog.Logger) error {
	cfg, err := config.Parse(args, version)
	if err != nil {
		return err
	}
	if cfg.Command == "version" {
		fmt.Fprintln(os.Stdout, version)
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if cfg.Command == "enroll" {
		_, err := identity.Enroll(ctx, cfg, nil)
		if err == nil {
			logger.Info("agent enrollment completed")
		}
		return err
	}
	id, certificate, signingKey, err := identity.Load(cfg)
	if err != nil {
		return fmt.Errorf("load agent identity: %w", err)
	}
	if cfg.Command == "maintain" {
		manager, err := maintenance.NewManager(cfg, id, signingKey, version, logger)
		if err != nil {
			return err
		}
		logger.Info("agent maintenance manager started", "version", version, "agent_node_id", id.AgentNodeID)
		return manager.Run(ctx)
	}
	stateStore, err := state.Open(ctx, cfg.StateDBPath())
	if err != nil {
		return fmt.Errorf("open agent state: %w", err)
	}
	defer stateStore.Close()
	secrets, err := secretstore.Open(cfg.ConfigDir, cfg.RuntimeDir)
	if err != nil {
		return fmt.Errorf("open agent secret store: %w", err)
	}
	if cfg.Command == "check" {
		return checkStoredState(ctx, id.AgentNodeID, signingKey, stateStore, secrets)
	}
	runtime, err := agentruntime.NewXray(secrets)
	if err != nil {
		return err
	}
	defer runtime.Close()
	if err := restoreRuntime(ctx, id.AgentNodeID, signingKey, stateStore, secrets, runtime); err != nil {
		return err
	}
	client, err := control.New(cfg, id, certificate, signingKey, stateStore, secrets, runtime, logger)
	if err != nil {
		return err
	}
	logger.Info("agent started", "version", version, "agent_node_id", id.AgentNodeID)
	return client.Run(ctx)
}

func checkStoredState(ctx context.Context, agentNodeID int64, signingKey ed25519.PublicKey, stateStore *state.Store, secrets *secretstore.Store) error {
	signed, err := stateStore.AppliedConfig(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if signed.Config.AgentNodeID != agentNodeID {
		return errors.New("stored config belongs to another agent")
	}
	if err := agentprotocol.VerifySignedConfig(*signed, signingKey); err != nil {
		return err
	}
	for _, ref := range agentprotocol.ReferencedSecretRefs(signed.Config) {
		if _, err := secrets.Resolve(ref); err != nil {
			return fmt.Errorf("resolve %s: %w", ref, err)
		}
	}
	users, err := stateStore.Users(ctx)
	if err != nil {
		return err
	}
	_, err = resolveStoredUsers(users, secrets)
	return err
}

func restoreRuntime(ctx context.Context, agentNodeID int64, signingKey ed25519.PublicKey, stateStore *state.Store, secrets *secretstore.Store, runtime *agentruntime.XrayRuntime) error {
	signed, err := stateStore.AppliedConfig(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if signed.Config.AgentNodeID != agentNodeID {
		return errors.New("stored config belongs to another agent")
	}
	if err := agentprotocol.VerifySignedConfig(*signed, signingKey); err != nil {
		return err
	}
	if err := runtime.ApplyConfig(ctx, signed.Config); err != nil {
		return fmt.Errorf("restore Xray config: %w", err)
	}
	users, err := stateStore.Users(ctx)
	if err != nil {
		return err
	}
	users, err = resolveStoredUsers(users, secrets)
	if err != nil {
		return err
	}
	if err := runtime.ApplyUsers(ctx, users); err != nil {
		return fmt.Errorf("restore Xray users: %w", err)
	}
	return nil
}

func resolveStoredUsers(users []agentprotocol.UserCredential, secrets *secretstore.Store) ([]agentprotocol.UserCredential, error) {
	out := append([]agentprotocol.UserCredential(nil), users...)
	for index := range out {
		plaintext, err := secrets.Resolve(out[index].Value)
		if err != nil {
			return nil, err
		}
		out[index].Value = string(plaintext)
	}
	return out, nil
}
