package state

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

func TestAccessWALAggregatesDeltasSurvivesRestartAndRequiresExactAck(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "agent.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Unix(1700000000, 0).UTC()
	checkpointAt := startedAt.Add(5 * time.Minute)
	endedAt := checkpointAt.Add(time.Minute)
	key := strings.Repeat("a", 64)
	if err := store.AddAccess(ctx, []agentprotocol.AccessItem{{
		SessionKey: key, SubscriberID: 901, InboundID: 81, Host: "video.example",
		Network: "tcp", Protocol: "tls", DestinationPort: 443,
		StartedAt: startedAt, LastSeenAt: checkpointAt, UploadBytes: 100,
		DownloadBytes: 200, ConnectionCount: 1, Active: true,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddAccess(ctx, []agentprotocol.AccessItem{{
		SessionKey: key, SubscriberID: 901, InboundID: 81, Host: "video.example",
		Network: "tcp", Protocol: "tls", DestinationPort: 443,
		StartedAt: startedAt, LastSeenAt: endedAt, EndedAt: &endedAt,
		UploadBytes: 50, DownloadBytes: 75,
	}}); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return endedAt.Add(time.Second) }
	batch, err := store.DrainAccess(ctx, "21fba3f0-54e3-4284-9dc6-fca218c451bd", 17)
	if err != nil {
		t.Fatal(err)
	}
	if batch == nil || batch.Sequence != 1 || len(batch.Items) != 1 {
		t.Fatalf("batch = %#v", batch)
	}
	item := batch.Items[0]
	if item.Active || item.EndedAt == nil || item.UploadBytes != 150 || item.DownloadBytes != 275 || item.ConnectionCount != 1 {
		t.Fatalf("aggregated item = %#v", item)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pending, err := store.PendingAccess(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].PayloadSHA256 != batch.PayloadSHA256 {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
	if err := store.AcknowledgeAccess(ctx, batch.BootID, batch.Sequence, strings.Repeat("0", 64)); err == nil {
		t.Fatal("mismatched access ACK was accepted")
	}
	if err := store.AcknowledgeAccess(ctx, batch.BootID, batch.Sequence, batch.PayloadSHA256); err != nil {
		t.Fatal(err)
	}
	if batches, bytes, err := store.PendingAccessStats(ctx); err != nil || batches != 0 || bytes != 0 {
		t.Fatalf("pending access stats = %d/%d, %v", batches, bytes, err)
	}
}

func TestPruneAccessWALAppliesBatchAndByteBounds(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for sequence := 1; sequence <= 6; sequence++ {
		if _, err := tx.ExecContext(ctx, `INSERT INTO access_wal
			(boot_id, sequence, payload_sha256, payload_json, created_at) VALUES (?, ?, ?, ?, ?)`,
			"21fba3f0-54e3-4284-9dc6-fca218c451bd", sequence, strings.Repeat("a", 64),
			strings.Repeat("x", 40), time.Unix(int64(sequence), 0).UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneAccessWALTx(ctx, tx, 4, 100); err != nil {
		t.Fatal(err)
	}
	var batches, bytes int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(LENGTH(payload_json)), 0) FROM access_wal`).Scan(&batches, &bytes); err != nil {
		t.Fatal(err)
	}
	if batches > 4 || bytes > 100 {
		t.Fatalf("bounded WAL = %d batches/%d bytes", batches, bytes)
	}
	if err := tx.Commit(); err != nil && err != sql.ErrTxDone {
		t.Fatal(err)
	}
}
