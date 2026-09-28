package limiter

import (
	"testing"

	"github.com/perfect-panel/ppanel-node/api/panel"
)

func TestInboundAllocationConstrainsIndependentBuckets(t *testing.T) {
	m := NewManager()
	a := m.Add("a", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 25_000_000, NodeSpeedLimitBPS: 6_250_000}}, nil, "vless")
	b := m.Add("b", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 25_000_000}}, nil, "vless")
	m.SetInboundBandwidthAllocations(1, map[string]uint64{"a": 10_000_000, "b": 15_000_000}, true)
	if a.SpeedBucket("a|one").Rate() != 6_250_000 || b.SpeedBucket("b|one").Rate() != 15_000_000 {
		t.Fatal("allocation or independent node ceiling was ignored")
	}
	first, second := a.SpeedBuckets("a|one")[0], b.SpeedBuckets("b|one")[0]
	if first == second {
		t.Fatal("inbounds share a token bucket")
	}
	m.SetInboundBandwidthAllocations(1, map[string]uint64{"a": 10_000_000, "b": 15_000_000}, true)
	if a.SpeedBuckets("a|one")[0] != first || b.SpeedBuckets("b|one")[0] != second {
		t.Fatal("unchanged allocation reset token buckets")
	}
	m.SetInboundBandwidthAllocations(1, map[string]uint64{"b": 25_000_000}, true)
	if a.SpeedBucket("a|one").Capacity() != 1 || b.SpeedBucket("b|one").Rate() != 25_000_000 {
		t.Fatal("removed inbound retained allocation or hot update failed")
	}
	if ids := m.DrainBandwidthDemands(8); len(ids) != 1 || ids[0] != 1 {
		t.Fatalf("zero-allocation demand = %#v", ids)
	}
	m.SetInboundBandwidthAllocations(1, map[string]uint64{"a": 5_000_000, "b": 20_000_000}, true)
	if a.SpeedBucket("a|one").Rate() != 5_000_000 {
		t.Fatal("paused inbound did not resume")
	}
	m.SetInboundBandwidthAllocations(1, nil, false)
	if b.SpeedBucket("b|one").Rate() != 25_000_000 {
		t.Fatal("cleared allocation did not restore static policy")
	}
}

func TestSpeedExemptionIgnoresStaleInboundAllocation(t *testing.T) {
	m := NewManager()
	l := m.Add("a", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 25_000_000}}, nil, "vless")
	m.SetInboundBandwidthAllocations(1, map[string]uint64{}, true)
	if l.SpeedBucket("a|one").Capacity() != 1 {
		t.Fatal("zero allocation not paused")
	}
	m.UpdateUser("a", []panel.UserInfo{{Id: 1, Uuid: "one"}}, nil)
	if l.SpeedBucket("a|one") != nil {
		t.Fatal("speed exemption retained a stale allocation")
	}
}
