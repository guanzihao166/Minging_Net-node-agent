package state

import (
	"context"
	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
	"path/filepath"
	"testing"
)

func TestNodePolicySurvivesSchemaUpgradeAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE users DROP COLUMN node_global_limit_bps`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := agentprotocol.UserSnapshot{Revision: 1, Users: []agentprotocol.UserCredential{{SubscriberID: 1, InboundID: 2, Kind: "uuid", Value: "test", SpeedLimitBPS: 25_000_000, NodeGlobalLimitBPS: 12_500_000}}}
	if err := s.ReplaceUsers(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	users, err := s.Users(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("restore: %v %v", users, err)
	}
	if users[0] != snapshot.Users[0] {
		t.Fatal("node or user policy changed after restart")
	}
}
