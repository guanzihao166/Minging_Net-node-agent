package runtime

import (
	"context"
	p "github.com/guanzihao166/iepl-node-agent/internal/protocol"
	"testing"
)

func TestSameProtocolTwoListenersKeepSameSubscriberIndependent(t *testing.T) {
	port := availableProtocolPortBlock(t)
	cfg := testDesiredConfig()
	first := cfg.Inbounds[0]
	first.Port = port
	first.TrafficMultiplierMilli = 100
	second := first
	second.ID = first.ID + 1000
	second.Port = port + 1
	second.Name = "second VLESS"
	second.TrafficMultiplierMilli = 2000
	cfg.Inbounds = []p.Inbound{first, second}
	r, err := NewXray(testRuntimeSecrets(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.ApplyConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	users := []p.UserCredential{
		{SubscriberID: 101, InboundID: first.ID, Kind: "uuid", Value: "3e285077-7932-4e8d-b232-9b6d58dd6671"},
		{SubscriberID: 101, InboundID: second.ID, Kind: "uuid", Value: "24c3a5d4-215b-4963-8f54-94ac3b22c53f"},
	}
	if err := r.ApplyUsers(context.Background(), users); err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		limiter, err := r.active.LimiterManager.Get(inboundTag(u.InboundID))
		if err != nil {
			t.Fatal(err)
		}
		if len(limiter.UUIDtoUID) != 1 {
			t.Fatalf("listener %d merged users", u.InboundID)
		}
		if _, ok := limiter.UUIDtoUID[u.Value]; !ok {
			t.Fatalf("listener %d lost own credentials", u.InboundID)
		}
	}
	if len(r.users) != 2 {
		t.Fatalf("same subscriber collapsed across listeners: %v", r.users)
	}
}
