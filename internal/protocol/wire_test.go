package agentprotocol

import (
	"strings"
	"testing"
	"time"
)

func TestAccessPayloadHashIsStableAcrossItemOrder(t *testing.T) {
	endedAt := time.Unix(1700000060, 0).UTC()
	batch := AccessBatch{
		BootID: "21fba3f0-54e3-4284-9dc6-fca218c451bd", Sequence: 8, ConfigVersion: 4,
		IntervalStartedAt: endedAt.Add(-time.Minute), IntervalEndedAt: endedAt,
		Items: []AccessItem{
			{SessionKey: strings.Repeat("b", 64), SubscriberID: 2, InboundID: 8, Host: "video.example", Network: "tcp", Protocol: "tls", DestinationPort: 443, StartedAt: endedAt.Add(-time.Second), LastSeenAt: endedAt, EndedAt: &endedAt, ConnectionCount: 1},
			{SessionKey: strings.Repeat("a", 64), SubscriberID: 1, InboundID: 8, Host: "chat.example", Network: "udp", Protocol: "quic", DestinationPort: 443, StartedAt: endedAt.Add(-time.Second), LastSeenAt: endedAt, Active: true},
		},
	}
	first, err := AccessPayloadSHA256(batch)
	if err != nil {
		t.Fatal(err)
	}
	batch.Items[0], batch.Items[1] = batch.Items[1], batch.Items[0]
	batch.PayloadSHA256 = strings.Repeat("f", 64)
	second, err := AccessPayloadSHA256(batch)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("hashes = %q, %q", first, second)
	}
}
