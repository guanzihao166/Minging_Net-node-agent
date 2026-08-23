package agentprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

const ProtocolVersion = 1

const (
	TypeHello          = "hello"
	TypeHelloAck       = "hello_ack"
	TypeDesiredConfig  = "desired_config"
	TypeConfigResult   = "config_result"
	TypeHeartbeat      = "heartbeat"
	TypeHeartbeatAck   = "heartbeat_ack"
	TypeUserSnapshot   = "user_snapshot"
	TypeUserDisconnect = "user_disconnect"
	TypeUserResult     = "user_result"
	TypeTrafficBatch   = "traffic_batch"
	TypeTrafficAck     = "traffic_ack"
	TypeAccessBatch    = "access_batch"
	TypeAccessAck      = "access_ack"
	TypeOnlineSnapshot = "online_snapshot"
	TypeError          = "error"
)

type Envelope struct {
	ID      string          `json:"id"`
	ReplyTo string          `json:"reply_to,omitempty"`
	Type    string          `json:"type"`
	SentAt  time.Time       `json:"sent_at"`
	Payload json.RawMessage `json:"payload"`
}

type Hello struct {
	ProtocolVersion      int    `json:"protocol_version"`
	MachineID            string `json:"machine_id"`
	BootID               string `json:"boot_id"`
	AgentVersion         string `json:"agent_version"`
	AppliedConfigVersion uint64 `json:"applied_config_version"`
	AppliedConfigHash    string `json:"applied_config_hash"`
	AppliedUserRevision  uint64 `json:"applied_user_revision"`
}

type HelloAck struct {
	ProtocolVersion      int       `json:"protocol_version"`
	SessionID            string    `json:"session_id"`
	ServerTime           time.Time `json:"server_time"`
	HeartbeatIntervalSec int       `json:"heartbeat_interval_seconds"`
	DesiredConfigVersion uint64    `json:"desired_config_version"`
	DesiredUserRevision  uint64    `json:"desired_user_revision"`
}

type Heartbeat struct {
	SessionID            string         `json:"session_id"`
	AppliedConfigVersion uint64         `json:"applied_config_version"`
	AppliedConfigHash    string         `json:"applied_config_hash"`
	AppliedUserRevision  uint64         `json:"applied_user_revision"`
	WALPendingBatches    uint64         `json:"wal_pending_batches"`
	WALPendingBytes      uint64         `json:"wal_pending_bytes"`
	XrayRunning          bool           `json:"xray_running"`
	XrayVersion          string         `json:"xray_version,omitempty"`
	SystemMetrics        *SystemMetrics `json:"system_metrics,omitempty"`
}

type SystemMetrics struct {
	SampledAt          time.Time `json:"sampled_at"`
	CPUPercent         float64   `json:"cpu_percent"`
	MemoryPercent      float64   `json:"memory_percent"`
	MemoryUsedBytes    uint64    `json:"memory_used_bytes"`
	MemoryTotalBytes   uint64    `json:"memory_total_bytes"`
	NetworkReceiveBPS  uint64    `json:"network_receive_bps"`
	NetworkTransmitBPS uint64    `json:"network_transmit_bps"`
	UptimeSeconds      uint64    `json:"uptime_seconds"`
}

type ConfigResult struct {
	Version      uint64 `json:"version"`
	SHA256       string `json:"sha256"`
	Status       string `json:"status"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type UserCredential struct {
	SubscriberID    int64  `json:"subscriber_id"`
	InboundID       int64  `json:"inbound_id"`
	Kind            string `json:"kind"`
	Value           string `json:"value"`
	ExpiresAt       int64  `json:"expires_at"`
	SpeedLimitBPS   uint64 `json:"speed_limit_bps"`
	DeviceLimit     uint32 `json:"device_limit"`
	QuotaGeneration uint64 `json:"quota_generation"`
}

type UserSnapshot struct {
	Revision uint64           `json:"revision"`
	Users    []UserCredential `json:"users"`
}

type UserDisconnect struct {
	SubscriberIDs []int64 `json:"subscriber_ids"`
}

type UserResult struct {
	Revision     uint64 `json:"revision"`
	Status       string `json:"status"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type TrafficItem struct {
	SubscriberID    int64  `json:"subscriber_id"`
	InboundID       int64  `json:"inbound_id"`
	QuotaGeneration uint64 `json:"quota_generation"`
	UploadBytes     uint64 `json:"upload_bytes"`
	DownloadBytes   uint64 `json:"download_bytes"`
}

type TrafficBatch struct {
	BootID            string        `json:"boot_id"`
	Sequence          uint64        `json:"sequence"`
	ConfigVersion     uint64        `json:"config_version"`
	IntervalStartedAt time.Time     `json:"interval_started_at"`
	IntervalEndedAt   time.Time     `json:"interval_ended_at"`
	PayloadSHA256     string        `json:"payload_sha256"`
	Items             []TrafficItem `json:"items"`
}

type TrafficAck struct {
	BootID        string `json:"boot_id"`
	Sequence      uint64 `json:"sequence"`
	PayloadSHA256 string `json:"payload_sha256"`
	Status        string `json:"status"`
}

func TrafficPayloadSHA256(batch TrafficBatch) (string, error) {
	canonical := batch
	canonical.PayloadSHA256 = ""
	canonical.Items = append([]TrafficItem(nil), batch.Items...)
	sort.Slice(canonical.Items, func(i, j int) bool {
		left, right := canonical.Items[i], canonical.Items[j]
		if left.SubscriberID != right.SubscriberID {
			return left.SubscriberID < right.SubscriberID
		}
		if left.InboundID != right.InboundID {
			return left.InboundID < right.InboundID
		}
		return left.QuotaGeneration < right.QuotaGeneration
	})
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

type AccessItem struct {
	SessionKey      string     `json:"session_key"`
	SubscriberID    int64      `json:"subscriber_id"`
	InboundID       int64      `json:"inbound_id"`
	Host            string     `json:"host"`
	Network         string     `json:"network"`
	Protocol        string     `json:"protocol"`
	DestinationPort uint16     `json:"destination_port"`
	StartedAt       time.Time  `json:"started_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	UploadBytes     uint64     `json:"upload_bytes"`
	DownloadBytes   uint64     `json:"download_bytes"`
	ConnectionCount uint32     `json:"connection_count"`
	Active          bool       `json:"active"`
}

type AccessBatch struct {
	BootID            string       `json:"boot_id"`
	Sequence          uint64       `json:"sequence"`
	ConfigVersion     uint64       `json:"config_version"`
	IntervalStartedAt time.Time    `json:"interval_started_at"`
	IntervalEndedAt   time.Time    `json:"interval_ended_at"`
	PayloadSHA256     string       `json:"payload_sha256"`
	Items             []AccessItem `json:"items"`
}

type AccessAck struct {
	BootID        string `json:"boot_id"`
	Sequence      uint64 `json:"sequence"`
	PayloadSHA256 string `json:"payload_sha256"`
	Status        string `json:"status"`
}

func AccessPayloadSHA256(batch AccessBatch) (string, error) {
	canonical := batch
	canonical.PayloadSHA256 = ""
	canonical.Items = append([]AccessItem(nil), batch.Items...)
	sort.Slice(canonical.Items, func(i, j int) bool {
		return canonical.Items[i].SessionKey < canonical.Items[j].SessionKey
	})
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

type OnlineSnapshot struct {
	CapturedAt time.Time    `json:"captured_at"`
	Users      []OnlineUser `json:"users"`
}

type OnlineUser struct {
	SubscriberID int64    `json:"subscriber_id"`
	InboundID    int64    `json:"inbound_id"`
	Addresses    []string `json:"addresses"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewEnvelope(id, messageType string, payload any, now time.Time) (Envelope, error) {
	if id == "" || messageType == "" {
		return Envelope{}, errors.New("message id and type are required")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{ID: id, Type: messageType, SentAt: now.UTC(), Payload: raw}, nil
}

func DecodeEnvelope(raw []byte) (Envelope, error) {
	var envelope Envelope
	if err := decodeStrict(raw, &envelope); err != nil {
		return Envelope{}, err
	}
	if envelope.ID == "" || envelope.Type == "" || envelope.SentAt.IsZero() || len(envelope.Payload) == 0 {
		return Envelope{}, errors.New("message envelope is incomplete")
	}
	return envelope, nil
}

func DecodePayload(envelope Envelope, target any) error {
	if target == nil {
		return errors.New("payload target is required")
	}
	if err := decodeStrict(envelope.Payload, target); err != nil {
		return fmt.Errorf("decode %s payload: %w", envelope.Type, err)
	}
	return nil
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}
