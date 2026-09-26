package limiter

import (
	"github.com/juju/ratelimit"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
	"sync"
	"testing"
)

func TestNodeCeilingIsLocalAndIndependentFromUserAndAllocation(t *testing.T) {
	m := NewManager()
	a := m.Add("a", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 25_000_000, NodeSpeedLimitBPS: 12_500_000}, {Id: 2, Uuid: "two", SpeedLimitBPS: 25_000_000, NodeSpeedLimitBPS: 12_500_000}}, map[int]int{}, "vless")
	b := m.Add("b", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 25_000_000}}, map[int]int{}, "vless")
	if got := a.SpeedBucket("a|one").Rate(); got != 12_500_000 {
		t.Fatalf("node a = %v", got)
	}
	if got := b.SpeedBucket("b|one").Rate(); got != 25_000_000 {
		t.Fatalf("node a contaminated node b: %v", got)
	}
	first, second := a.SpeedBuckets("a|one"), a.SpeedBuckets("a|two")
	if first[1] == second[1] {
		t.Fatal("different subscribers share a node ceiling bucket")
	}
	if a.SpeedBuckets("a|one")[0] == b.SpeedBuckets("b|one")[0] {
		t.Fatal("different inbounds share the user bucket")
	}
	m.SetGlobalBandwidthAllocation(1, 40_000_000, true)
	if a.SpeedBucket("a|one").Rate() != 12_500_000 {
		t.Fatal("allocation raised node ceiling")
	}
	m.SetGlobalBandwidthAllocation(1, 6_250_000, true)
	if a.SpeedBucket("a|one").Rate() != 12_500_000 {
		t.Fatal("aggregate allocation leaked into inbound limit")
	}
	m.SetGlobalBandwidthAllocation(1, 0, true)
	if a.SpeedBucket("a|one").Rate() != 12_500_000 {
		t.Fatal("zero aggregate allocation leaked into inbound limit")
	}
	m.SetGlobalBandwidthAllocation(1, 0, false)
	for _, node := range []uint64{6_250_000, 37_500_000, 0, 12_500_000} {
		m.UpdateUser("a", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 25_000_000, NodeSpeedLimitBPS: node}}, nil)
		want := minPositive(25_000_000, node)
		if got := a.SpeedBucket("a|one").Rate(); got != float64(want) {
			t.Fatalf("node %d: %v != %d", node, got, want)
		}
		if b.SpeedBucket("b|one").Rate() != 25_000_000 {
			t.Fatal("hot update contaminated node b")
		}
	}
}

func TestConcurrentFirstWritesUseOneBucket(t *testing.T) {
	m := NewManager()
	l := m.Add("a", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 25_000_000, NodeSpeedLimitBPS: 12_500_000}}, map[int]int{}, "vless")
	const count = 128
	result := make(chan []*ratelimit.Bucket, count)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; result <- l.SpeedBuckets(format.UserTag("a", "one")) }()
	}
	close(start)
	wg.Wait()
	close(result)
	var baseline []*ratelimit.Bucket
	for buckets := range result {
		if baseline == nil {
			baseline = buckets
		}
		for i, b := range buckets {
			if b != baseline[i] {
				t.Fatal("parallel writes created duplicate budgets")
			}
		}
	}
	m.UpdateUser("a", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 25_000_000, NodeSpeedLimitBPS: 12_500_000}}, nil)
	for i, b := range l.SpeedBuckets("a|one") {
		if b != baseline[i] {
			t.Fatal("unchanged policy reset token budget")
		}
	}
}

func TestReplacingInboundRemovesItsOldSubscriberPolicy(t *testing.T) {
	m := NewManager()
	m.Add("a", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 25_000_000, NodeSpeedLimitBPS: 12_500_000}}, map[int]int{}, "vless")
	l := m.Add("a", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 40_000_000}}, map[int]int{}, "vless")
	if got := l.SpeedBucket("a|one").Rate(); got != 40_000_000 {
		t.Fatalf("replacement retained old node policy: %v", got)
	}
}

func TestExactBytesPerSecondSurvivesRuntimePolicy(t *testing.T) {
	m := NewManager()
	l := m.Add("a", []panel.UserInfo{{Id: 1, Uuid: "one", SpeedLimitBPS: 12345}}, map[int]int{}, "vless")
	rate := l.SpeedBucket("a|one").Rate()
	if rate > 12345.01 || rate < 12344.9 {
		t.Fatalf("rate rounded to Mbps: %v", rate)
	}
}
