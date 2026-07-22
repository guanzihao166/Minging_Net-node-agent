package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"

	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

type Store struct {
	db  *sql.DB
	now func() time.Time
}

type RuntimeState struct {
	AppliedConfigVersion uint64
	AppliedConfigHash    string
	AppliedUserRevision  uint64
}

type TrafficDelta struct {
	SubscriberID    int64
	InboundID       int64
	QuotaGeneration uint64
	UploadBytes     uint64
	DownloadBytes   uint64
}

func (s *Store) ReplaceUsers(ctx context.Context, snapshot agentprotocol.UserSnapshot) error {
	if snapshot.Revision == 0 || len(snapshot.Users) > 100000 {
		return errors.New("user snapshot is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, err := runtimeStateTx(ctx, tx)
	if err != nil {
		return err
	}
	if snapshot.Revision < state.AppliedUserRevision {
		return errors.New("user snapshot revision is stale")
	}
	if snapshot.Revision == state.AppliedUserRevision {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users`); err != nil {
		return err
	}
	for _, user := range snapshot.Users {
		if user.SubscriberID <= 0 || user.InboundID <= 0 || user.Kind == "" || user.Value == "" {
			return errors.New("user snapshot contains an invalid credential")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO users
			(subscriber_id, inbound_id, revision, kind, value, expires_at, speed_limit_bps,
			 device_limit, quota_generation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			user.SubscriberID, user.InboundID, snapshot.Revision, user.Kind, user.Value,
			user.ExpiresAt, user.SpeedLimitBPS, user.DeviceLimit, user.QuotaGeneration)
		if err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE meta SET value = ? WHERE key = 'applied_user_revision'`, strconv.FormatUint(snapshot.Revision, 10)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Users(ctx context.Context) ([]agentprotocol.UserCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subscriber_id, inbound_id, kind, value,
		expires_at, speed_limit_bps, device_limit, quota_generation
		FROM users ORDER BY inbound_id, subscriber_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]agentprotocol.UserCredential, 0)
	for rows.Next() {
		var user agentprotocol.UserCredential
		if err := rows.Scan(&user.SubscriberID, &user.InboundID, &user.Kind, &user.Value,
			&user.ExpiresAt, &user.SpeedLimitBPS, &user.DeviceLimit, &user.QuotaGeneration); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA wal_autocheckpoint=1000",
	} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite %s: %w", pragma, err)
		}
	}
	store := &Store{db: db, now: time.Now}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS config_revisions (
  version INTEGER PRIMARY KEY,
  sha256 TEXT NOT NULL UNIQUE,
  signed_json BLOB NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  applied_at TEXT
);
CREATE TABLE IF NOT EXISTS users (
  subscriber_id INTEGER NOT NULL,
  inbound_id INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  speed_limit_bps INTEGER NOT NULL,
  device_limit INTEGER NOT NULL,
  quota_generation INTEGER NOT NULL,
  PRIMARY KEY (subscriber_id, inbound_id)
);
CREATE TABLE IF NOT EXISTS traffic_accumulator (
  subscriber_id INTEGER NOT NULL,
  inbound_id INTEGER NOT NULL,
  quota_generation INTEGER NOT NULL,
  upload_bytes INTEGER NOT NULL,
  download_bytes INTEGER NOT NULL,
  interval_started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (subscriber_id, inbound_id, quota_generation)
);
CREATE TABLE IF NOT EXISTS traffic_wal (
  boot_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  payload_sha256 TEXT NOT NULL,
  payload_json BLOB NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (boot_id, sequence)
);
CREATE UNIQUE INDEX IF NOT EXISTS traffic_wal_payload ON traffic_wal(boot_id, sequence, payload_sha256);
INSERT INTO meta(key, value) VALUES ('schema_version', '1') ON CONFLICT(key) DO NOTHING;
INSERT INTO meta(key, value) VALUES ('traffic_sequence', '0') ON CONFLICT(key) DO NOTHING;
INSERT INTO meta(key, value) VALUES ('applied_config_version', '0') ON CONFLICT(key) DO NOTHING;
INSERT INTO meta(key, value) VALUES ('applied_config_hash', '') ON CONFLICT(key) DO NOTHING;
INSERT INTO meta(key, value) VALUES ('applied_user_revision', '0') ON CONFLICT(key) DO NOTHING;
`
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

func (s *Store) RuntimeState(ctx context.Context) (RuntimeState, error) {
	values := map[string]string{}
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM meta
		WHERE key IN ('applied_config_version', 'applied_config_hash', 'applied_user_revision')`)
	if err != nil {
		return RuntimeState{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return RuntimeState{}, err
		}
		values[key] = value
	}
	configVersion, _ := strconv.ParseUint(values["applied_config_version"], 10, 64)
	userRevision, _ := strconv.ParseUint(values["applied_user_revision"], 10, 64)
	return RuntimeState{
		AppliedConfigVersion: configVersion,
		AppliedConfigHash:    values["applied_config_hash"],
		AppliedUserRevision:  userRevision,
	}, rows.Err()
}

func (s *Store) SaveDesiredConfig(ctx context.Context, signed agentprotocol.SignedConfig) (bool, error) {
	raw, err := json.Marshal(signed)
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var existingHash, existingStatus string
	err = tx.QueryRowContext(ctx, `SELECT sha256, status FROM config_revisions WHERE version = ?`, signed.Config.Version).
		Scan(&existingHash, &existingStatus)
	if err == nil {
		if existingHash != signed.SHA256 {
			return false, errors.New("config version conflicts with existing hash")
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return existingStatus != "applied", nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	state, err := runtimeStateTx(ctx, tx)
	if err != nil {
		return false, err
	}
	if signed.Config.Version <= state.AppliedConfigVersion {
		return false, errors.New("config version is not newer than applied state")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO config_revisions
		(version, sha256, signed_json, status, created_at) VALUES (?, ?, ?, 'received', ?)`,
		signed.Config.Version, signed.SHA256, raw, s.now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *Store) MarkConfigApplied(ctx context.Context, version uint64, hash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE config_revisions SET status = 'applied', applied_at = ?
		WHERE version = ? AND sha256 = ?`, s.now().UTC().Format(time.RFC3339Nano), version, hash)
	if err != nil {
		return err
	}
	if affected, err := res.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return errors.New("config revision does not exist")
	}
	for key, value := range map[string]string{
		"applied_config_version": strconv.FormatUint(version, 10),
		"applied_config_hash":    hash,
	} {
		if _, err := tx.ExecContext(ctx, `UPDATE meta SET value = ? WHERE key = ?`, value, key); err != nil {
			return err
		}
	}
	_, _ = tx.ExecContext(ctx, `DELETE FROM config_revisions WHERE status != 'applied' OR version < ?`, version)
	return tx.Commit()
}

func (s *Store) AppliedConfig(ctx context.Context) (*agentprotocol.SignedConfig, error) {
	stateValue, err := s.RuntimeState(ctx)
	if err != nil {
		return nil, err
	}
	if stateValue.AppliedConfigVersion == 0 {
		return nil, sql.ErrNoRows
	}
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT signed_json FROM config_revisions
		WHERE version = ? AND status = 'applied'`, stateValue.AppliedConfigVersion).Scan(&raw); err != nil {
		return nil, err
	}
	var signed agentprotocol.SignedConfig
	if err := json.Unmarshal(raw, &signed); err != nil {
		return nil, err
	}
	return &signed, nil
}

func (s *Store) AddTraffic(ctx context.Context, deltas []TrafficDelta) error {
	if len(deltas) == 0 {
		return nil
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, delta := range deltas {
		if delta.SubscriberID <= 0 || delta.InboundID <= 0 {
			return errors.New("traffic identity is invalid")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO traffic_accumulator
			(subscriber_id, inbound_id, quota_generation, upload_bytes, download_bytes, interval_started_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(subscriber_id, inbound_id, quota_generation) DO UPDATE SET
			 upload_bytes = upload_bytes + excluded.upload_bytes,
			 download_bytes = download_bytes + excluded.download_bytes,
			 updated_at = excluded.updated_at`, delta.SubscriberID, delta.InboundID, delta.QuotaGeneration,
			delta.UploadBytes, delta.DownloadBytes, now, now)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DrainTraffic(ctx context.Context, bootID string, configVersion uint64) (*agentprotocol.TrafficBatch, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT subscriber_id, inbound_id, quota_generation,
		upload_bytes, download_bytes, interval_started_at FROM traffic_accumulator
		ORDER BY subscriber_id, inbound_id, quota_generation`)
	if err != nil {
		return nil, err
	}
	items := make([]agentprotocol.TrafficItem, 0)
	var intervalStart time.Time
	for rows.Next() {
		var item agentprotocol.TrafficItem
		var started string
		if err := rows.Scan(&item.SubscriberID, &item.InboundID, &item.QuotaGeneration,
			&item.UploadBytes, &item.DownloadBytes, &started); err != nil {
			rows.Close()
			return nil, err
		}
		parsed, _ := time.Parse(time.RFC3339Nano, started)
		if intervalStart.IsZero() || parsed.Before(intervalStart) {
			intervalStart = parsed
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
	if err := tx.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) + 1 FROM meta WHERE key = 'traffic_sequence'`).Scan(&sequence); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	batch := agentprotocol.TrafficBatch{
		BootID: bootID, Sequence: sequence, ConfigVersion: configVersion,
		IntervalStartedAt: intervalStart, IntervalEndedAt: now, Items: items,
	}
	batch.PayloadSHA256, err = agentprotocol.TrafficPayloadSHA256(batch)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO traffic_wal
		(boot_id, sequence, payload_sha256, payload_json, created_at) VALUES (?, ?, ?, ?, ?)`,
		bootID, sequence, batch.PayloadSHA256, raw, now.Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE meta SET value = ? WHERE key = 'traffic_sequence'`, strconv.FormatUint(sequence, 10)); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_accumulator`); err != nil {
		return nil, err
	}
	return &batch, tx.Commit()
}

func (s *Store) PendingTraffic(ctx context.Context, limit int) ([]agentprotocol.TrafficBatch, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT payload_json FROM traffic_wal ORDER BY created_at, sequence LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]agentprotocol.TrafficBatch, 0)
	for rows.Next() {
		var raw []byte
		var batch agentprotocol.TrafficBatch
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

func (s *Store) AcknowledgeTraffic(ctx context.Context, bootID string, sequence uint64, hash string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM traffic_wal
		WHERE boot_id = ? AND sequence = ? AND payload_sha256 = ?`, bootID, sequence, hash)
	if err != nil {
		return err
	}
	if affected, err := res.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return err
		}
		return errors.New("traffic acknowledgement does not match pending WAL")
	}
	return nil
}

func (s *Store) PendingTrafficStats(ctx context.Context) (uint64, uint64, error) {
	var batches, bytes uint64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(LENGTH(payload_json)), 0) FROM traffic_wal`).Scan(&batches, &bytes)
	return batches, bytes, err
}

func runtimeStateTx(ctx context.Context, tx *sql.Tx) (RuntimeState, error) {
	var versionRaw, hash, revisionRaw string
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT value FROM meta WHERE key = 'applied_config_version'),
		(SELECT value FROM meta WHERE key = 'applied_config_hash'),
		(SELECT value FROM meta WHERE key = 'applied_user_revision')`).Scan(&versionRaw, &hash, &revisionRaw); err != nil {
		return RuntimeState{}, err
	}
	version, _ := strconv.ParseUint(versionRaw, 10, 64)
	revision, _ := strconv.ParseUint(revisionRaw, 10, 64)
	return RuntimeState{AppliedConfigVersion: version, AppliedConfigHash: hash, AppliedUserRevision: revision}, nil
}
