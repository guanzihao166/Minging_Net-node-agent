package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

const (
	maxAccessBatchItems = 1000
	maxAccessWALBatches = 1440
	maxAccessWALBytes   = 64 << 20
)

var (
	accessSessionKeyPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	accessProtocolPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,31}$`)
)

func (s *Store) AddAccess(ctx context.Context, items []agentprotocol.AccessItem) error {
	if len(items) == 0 {
		return nil
	}
	if len(items) > 20000 {
		return errors.New("access accumulator input exceeds the in-memory group limit")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statement, err := tx.PrepareContext(ctx, `INSERT INTO access_accumulator
		(session_key, subscriber_id, inbound_id, host, network, protocol, destination_port,
		 started_at, last_seen_at, ended_at, upload_bytes, download_bytes, connection_count, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_key) DO UPDATE SET
		 subscriber_id = excluded.subscriber_id,
		 inbound_id = excluded.inbound_id,
		 host = excluded.host,
		 network = excluded.network,
		 protocol = excluded.protocol,
		 destination_port = excluded.destination_port,
		 started_at = MIN(started_at, excluded.started_at),
		 last_seen_at = MAX(last_seen_at, excluded.last_seen_at),
		 ended_at = CASE WHEN excluded.is_active = 1 THEN NULL
		   ELSE MAX(COALESCE(ended_at, excluded.ended_at), excluded.ended_at) END,
		 upload_bytes = CASE WHEN upload_bytes > 9223372036854775807 - excluded.upload_bytes
		   THEN 9223372036854775807 ELSE upload_bytes + excluded.upload_bytes END,
		 download_bytes = CASE WHEN download_bytes > 9223372036854775807 - excluded.download_bytes
		   THEN 9223372036854775807 ELSE download_bytes + excluded.download_bytes END,
		 connection_count = MIN(2147483647, connection_count + excluded.connection_count),
		 is_active = excluded.is_active`)
	if err != nil {
		return err
	}
	defer statement.Close()
	for _, item := range items {
		if err := validateLocalAccessItem(item); err != nil {
			return err
		}
		var endedAt any
		if item.EndedAt != nil {
			endedAt = item.EndedAt.UTC().Format(time.RFC3339Nano)
		}
		active := 0
		if item.Active {
			active = 1
		}
		if _, err := statement.ExecContext(ctx,
			item.SessionKey, item.SubscriberID, item.InboundID, item.Host, item.Network,
			item.Protocol, item.DestinationPort, item.StartedAt.UTC().Format(time.RFC3339Nano),
			item.LastSeenAt.UTC().Format(time.RFC3339Nano), endedAt, item.UploadBytes,
			item.DownloadBytes, item.ConnectionCount, active,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DrainAccess(ctx context.Context, bootID string, configVersion uint64) (*agentprotocol.AccessBatch, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT session_key, subscriber_id, inbound_id, host,
		network, protocol, destination_port, started_at, last_seen_at, ended_at,
		upload_bytes, download_bytes, connection_count, is_active
		FROM access_accumulator ORDER BY session_key LIMIT ?`, maxAccessBatchItems)
	if err != nil {
		return nil, err
	}
	items := make([]agentprotocol.AccessItem, 0, maxAccessBatchItems)
	var intervalStart, intervalEnd time.Time
	for rows.Next() {
		var item agentprotocol.AccessItem
		var startedAt, lastSeenAt string
		var endedAt sql.NullString
		var active int
		if err := rows.Scan(&item.SessionKey, &item.SubscriberID, &item.InboundID, &item.Host,
			&item.Network, &item.Protocol, &item.DestinationPort, &startedAt, &lastSeenAt,
			&endedAt, &item.UploadBytes, &item.DownloadBytes, &item.ConnectionCount, &active); err != nil {
			rows.Close()
			return nil, err
		}
		item.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt)
		if err != nil {
			rows.Close()
			return nil, err
		}
		item.LastSeenAt, err = time.Parse(time.RFC3339Nano, lastSeenAt)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if endedAt.Valid {
			parsed, parseErr := time.Parse(time.RFC3339Nano, endedAt.String)
			if parseErr != nil {
				rows.Close()
				return nil, parseErr
			}
			item.EndedAt = &parsed
		}
		item.Active = active == 1
		if intervalStart.IsZero() || item.StartedAt.Before(intervalStart) {
			intervalStart = item.StartedAt
		}
		if item.LastSeenAt.After(intervalEnd) {
			intervalEnd = item.LastSeenAt
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, tx.Commit()
	}
	var sequence uint64
	if err := tx.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) + 1 FROM meta WHERE key = 'access_sequence'`).Scan(&sequence); err != nil {
		return nil, err
	}
	if intervalEnd.IsZero() {
		intervalEnd = s.now().UTC()
	}
	if intervalStart.IsZero() || !intervalEnd.After(intervalStart) {
		intervalStart = intervalEnd.Add(-time.Second)
	}
	batch := agentprotocol.AccessBatch{
		BootID: bootID, Sequence: sequence, ConfigVersion: configVersion,
		IntervalStartedAt: intervalStart, IntervalEndedAt: intervalEnd, Items: items,
	}
	batch.PayloadSHA256, err = agentprotocol.AccessPayloadSHA256(batch)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		return nil, err
	}
	createdAt := s.now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_wal
		(boot_id, sequence, payload_sha256, payload_json, created_at) VALUES (?, ?, ?, ?, ?)`,
		bootID, sequence, batch.PayloadSHA256, raw, createdAt); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE meta SET value = ? WHERE key = 'access_sequence'`, strconv.FormatUint(sequence, 10)); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM access_accumulator
		WHERE session_key IN (SELECT session_key FROM access_accumulator ORDER BY session_key LIMIT ?)`, maxAccessBatchItems); err != nil {
		return nil, err
	}
	if err := pruneAccessWALTx(ctx, tx, maxAccessWALBatches, maxAccessWALBytes); err != nil {
		return nil, err
	}
	return &batch, tx.Commit()
}

func (s *Store) PendingAccess(ctx context.Context, limit int) ([]agentprotocol.AccessBatch, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT payload_json FROM access_wal ORDER BY created_at, sequence LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]agentprotocol.AccessBatch, 0)
	for rows.Next() {
		var raw []byte
		var batch agentprotocol.AccessBatch
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &batch); err != nil {
			return nil, err
		}
		out = append(out, batch)
	}
	return out, rows.Err()
}

func (s *Store) AcknowledgeAccess(ctx context.Context, bootID string, sequence uint64, hash string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM access_wal
		WHERE boot_id = ? AND sequence = ? AND payload_sha256 = ?`, bootID, sequence, hash)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return errors.New("access acknowledgement does not match pending WAL")
	}
	return nil
}

func (s *Store) PendingAccessStats(ctx context.Context) (uint64, uint64, error) {
	var batches, bytes uint64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(LENGTH(payload_json)), 0) FROM access_wal`).Scan(&batches, &bytes)
	return batches, bytes, err
}

func pruneAccessWALTx(ctx context.Context, tx *sql.Tx, maxBatches, maxBytes int64) error {
	if maxBatches <= 0 || maxBytes <= 0 {
		return errors.New("access WAL limits are invalid")
	}
	var batches, bytes int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(LENGTH(payload_json)), 0) FROM access_wal`).Scan(&batches, &bytes); err != nil {
		return err
	}
	if excess := batches - maxBatches; excess > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM access_wal WHERE rowid IN
			(SELECT rowid FROM access_wal ORDER BY created_at, sequence LIMIT ?)`, excess); err != nil {
			return err
		}
		batches = maxBatches
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(LENGTH(payload_json)), 0) FROM access_wal`).Scan(&bytes); err != nil {
			return err
		}
	}
	for batches > 0 && bytes > maxBytes {
		var rowID, size int64
		if err := tx.QueryRowContext(ctx, `SELECT rowid, LENGTH(payload_json) FROM access_wal
			ORDER BY created_at, sequence LIMIT 1`).Scan(&rowID, &size); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM access_wal WHERE rowid = ?`, rowID); err != nil {
			return err
		}
		batches--
		bytes -= size
	}
	return nil
}

func validateLocalAccessItem(item agentprotocol.AccessItem) error {
	if !accessSessionKeyPattern.MatchString(item.SessionKey) || item.SubscriberID <= 0 || item.InboundID <= 0 {
		return errors.New("access item identity is invalid")
	}
	if item.Host != strings.TrimSpace(item.Host) || item.Host == "" || len(item.Host) > 253 {
		return errors.New("access item host is invalid")
	}
	if item.Network != "tcp" && item.Network != "udp" {
		return errors.New("access item network is invalid")
	}
	if !accessProtocolPattern.MatchString(item.Protocol) || item.DestinationPort == 0 {
		return errors.New("access item destination is invalid")
	}
	if item.StartedAt.IsZero() || item.LastSeenAt.Before(item.StartedAt) {
		return errors.New("access item time range is invalid")
	}
	if item.Active && item.EndedAt != nil || !item.Active && item.EndedAt == nil {
		return errors.New("access item active state is inconsistent")
	}
	if item.EndedAt != nil && (item.EndedAt.Before(item.StartedAt) || item.EndedAt.After(item.LastSeenAt.Add(time.Second))) {
		return errors.New("access item end time is invalid")
	}
	if item.UploadBytes > math.MaxInt64 || item.DownloadBytes > math.MaxInt64 || item.ConnectionCount > math.MaxInt32 {
		return fmt.Errorf("access item counters exceed local SQLite limits")
	}
	return nil
}
