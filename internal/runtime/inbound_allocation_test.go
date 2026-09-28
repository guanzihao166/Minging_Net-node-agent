package runtime

import (
	"context"
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
	ppcore "github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/limiter"

	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

func TestInboundAllocationValidationIsAtomic(t *testing.T) {
	m := limiter.NewManager()
	l := m.Add("inbound-101", []panel.UserInfo{{Id: 4, Uuid: "user", SpeedLimitBPS: 25_000_000}}, nil, "vless")
	r := &XrayRuntime{active: &ppcore.XrayCore{LimiterManager: m}, users: []agentprotocol.UserCredential{{SubscriberID: 4}}}
	valid := agentprotocol.BandwidthAllocation{PerInbound: true, Allocations: []agentprotocol.SubscriberBandwidthAllocation{
		{SubscriberID: 4, InboundID: 101, SpeedLimitBPS: 6_250_000, AllocationActive: true},
	}}
	if err := r.ApplyBandwidthAllocation(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	before := l.SpeedBucket("inbound-101|user")
	if before.Rate() != 6_250_000 {
		t.Fatal("valid allocation not applied")
	}
	for _, invalid := range [][]agentprotocol.SubscriberBandwidthAllocation{
		{{SubscriberID: 4, InboundID: 101, SpeedLimitBPS: 20_000_000, AllocationActive: true}, {SubscriberID: 4, InboundID: 101, AllocationActive: true}},
		{{SubscriberID: 4, InboundID: 101, AllocationActive: true}, {SubscriberID: 4, InboundID: 102}},
		{{SubscriberID: 4, InboundID: 101, AllocationActive: true}, {SubscriberID: 0}},
	} {
		if err := r.ApplyBandwidthAllocation(context.Background(), agentprotocol.BandwidthAllocation{PerInbound: true, Allocations: invalid}); err == nil {
			t.Fatal("invalid allocation accepted")
		}
		if l.SpeedBucket("inbound-101|user") != before {
			t.Fatal("invalid message partially changed the policy")
		}
	}
	if err := r.ApplyBandwidthAllocation(context.Background(), agentprotocol.BandwidthAllocation{PerInbound: true, Allocations: []agentprotocol.SubscriberBandwidthAllocation{{SubscriberID: 4}}}); err != nil {
		t.Fatal(err)
	}
	if l.SpeedBucket("inbound-101|user").Rate() != 25_000_000 || len(r.inboundAllocations) != 0 {
		t.Fatal("inactive allocation retained a cap or cache entry")
	}
}
