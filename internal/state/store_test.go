package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

func TestConfigRevisionPersistsBeforeAppliedState(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := agentprotocol.SignConfig(agentprotocol.DesiredConfig{
		SchemaVersion: agentprotocol.SchemaVersion, Version: 1,
		GeneratedAt: time.Now().UTC(), AgentNodeID: 17,
	}, "test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	inserted, err := store.SaveDesiredConfig(ctx, signed)
	if err != nil || !inserted {
		t.Fatalf("SaveDesiredConfig = %v, %v", inserted, err)
	}
	inserted, err = store.SaveDesiredConfig(ctx, signed)
	if err != nil || !inserted {
		t.Fatalf("received SaveDesiredConfig retry = %v, %v", inserted, err)
	}
	if err := store.MarkConfigApplied(ctx, 1, signed.SHA256); err != nil {
		t.Fatal(err)
	}
	state, err := store.RuntimeState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.AppliedConfigVersion != 1 || state.AppliedConfigHash != signed.SHA256 {
		t.Fatalf("state = %#v", state)
	}
	inserted, err = store.SaveDesiredConfig(ctx, signed)
	if err != nil || inserted {
		t.Fatalf("idempotent SaveDesiredConfig = %v, %v", inserted, err)
	}
	conflict := signed
	conflict.SHA256 = strings.Repeat("f", 64)
	if _, err := store.SaveDesiredConfig(ctx, conflict); err == nil {
		t.Fatal("same config version with a different hash was accepted")
	}
}

func TestTrafficWALSurvivesRestartAndRequiresExactAck(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	windowStart := time.Unix(1700000059, 0).UTC()
	windowEnd := time.Unix(1700000060, 0).UTC()
	store.now = func() time.Time { return windowEnd.Add(time.Second) }
	if err := store.AddTrafficWindow(ctx, []TrafficDelta{{
		SubscriberID: 901, InboundID: 81, QuotaGeneration: 8,
		UploadBytes: 1024, DownloadBytes: 8192,
	}}, windowStart, windowEnd); err != nil {
		t.Fatal(err)
	}
	batch, err := store.DrainTraffic(ctx, "82c49a6b-5bd3-4d75-97ca-058d777b3599", 17)
	if err != nil {
		t.Fatal(err)
	}
	if batch == nil || batch.Sequence != 1 || len(batch.Items) != 1 {
		t.Fatalf("batch = %#v", batch)
	}
	if !batch.IntervalStartedAt.Equal(windowStart) || !batch.IntervalEndedAt.Equal(windowEnd) {
		t.Fatalf("traffic window = %s..%s, want %s..%s", batch.IntervalStartedAt, batch.IntervalEndedAt, windowStart, windowEnd)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pending, err := store.PendingTraffic(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].PayloadSHA256 != batch.PayloadSHA256 {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
	if err := store.AcknowledgeTraffic(ctx, batch.BootID, batch.Sequence, strings.Repeat("0", 64)); err == nil {
		t.Fatal("mismatched traffic ACK was accepted")
	}
	if err := store.AcknowledgeTraffic(ctx, batch.BootID, batch.Sequence, batch.PayloadSHA256); err != nil {
		t.Fatal(err)
	}
	pending, err = store.PendingTraffic(ctx, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending after ACK = %#v, %v", pending, err)
	}
	if err := store.AcknowledgeTraffic(ctx, batch.BootID, batch.Sequence, batch.PayloadSHA256); err == nil {
		t.Fatal("duplicate ACK unexpectedly deleted a row")
	}
}

func TestTrafficAccumulatorPreservesFullCollectionWindow(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	firstStart := time.Unix(1700000000, 0).UTC()
	firstEnd := firstStart.Add(time.Second)
	secondEnd := firstEnd.Add(time.Second)
	delta := TrafficDelta{SubscriberID: 901, InboundID: 81, QuotaGeneration: 8, UploadBytes: 100, DownloadBytes: 200}
	if err := store.AddTrafficWindow(ctx, []TrafficDelta{delta}, firstStart, firstEnd); err != nil {
		t.Fatal(err)
	}
	if err := store.AddTrafficWindow(ctx, []TrafficDelta{delta}, firstEnd, secondEnd); err != nil {
		t.Fatal(err)
	}
	batch, err := store.DrainTraffic(ctx, "82c49a6b-5bd3-4d75-97ca-058d777b3599", 17)
	if err != nil {
		t.Fatal(err)
	}
	if batch == nil || len(batch.Items) != 1 || batch.Items[0].UploadBytes != 200 || batch.Items[0].DownloadBytes != 400 {
		t.Fatalf("batch = %#v", batch)
	}
	if !batch.IntervalStartedAt.Equal(firstStart) || !batch.IntervalEndedAt.Equal(secondEnd) {
		t.Fatalf("traffic window = %s..%s, want %s..%s", batch.IntervalStartedAt, batch.IntervalEndedAt, firstStart, secondEnd)
	}
}

func TestAddTrafficWindowRejectsInvalidWindow(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Unix(1700000000, 0).UTC()
	if err := store.AddTrafficWindow(ctx, nil, now, now); err == nil {
		t.Fatal("invalid traffic window was accepted")
	}
}
