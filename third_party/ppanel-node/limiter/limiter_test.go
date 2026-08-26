package limiter

import (
	"testing"
	"time"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
)

const (
	testTag  = "test-node"
	testUUID = "test-user"
	testUID  = 1
	testIP   = "198.51.100.1"
)

func newTestLimiter(nodeType string, deviceLimit int, alive int) *Limiter {
	return NewManager().Add(testTag, []panel.UserInfo{{
		Id:          testUID,
		Uuid:        testUUID,
		DeviceLimit: deviceLimit,
	}}, map[int]int{testUID: alive}, nodeType)
}

func TestLimiter_tracks_online_device_when_transport_requires_tracking(t *testing.T) {
	tests := []struct {
		name        string
		nodeType    string
		noUDPSource bool
		wantTracked bool
	}{
		{name: "AnyTLS TCP", nodeType: "anytls", noUDPSource: true, wantTracked: true},
		{name: "Hysteria2 UDP", nodeType: "hysteria2", noUDPSource: false, wantTracked: true},
		{name: "Hysteria UDP alias", nodeType: "hysteria", noUDPSource: false, wantTracked: true},
		{name: "TUIC UDP", nodeType: "tuic", noUDPSource: false, wantTracked: true},
		{name: "Shadowsocks TCP", nodeType: "shadowsocks", noUDPSource: true, wantTracked: true},
		{name: "Shadowsocks UDP", nodeType: "shadowsocks", noUDPSource: false, wantTracked: false},
		{name: "unknown UDP", nodeType: "unknown", noUDPSource: false, wantTracked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			l := newTestLimiter(tt.nodeType, 0, 0)

			// When
			_, rejected := l.CheckLimit(format.UserTag(testTag, testUUID), testIP, tt.noUDPSource)

			// Then
			if rejected {
				t.Fatal("CheckLimit() rejected a known user")
			}
			onlineDevices, err := l.GetOnlineDevice()
			if err != nil {
				t.Fatalf("GetOnlineDevice() error = %v", err)
			}
			if got := len(*onlineDevices) > 0; got != tt.wantTracked {
				t.Errorf("online device tracked = %t, want %t", got, tt.wantTracked)
				return
			}
			if tt.wantTracked && ((*onlineDevices)[0].UID != testUID || (*onlineDevices)[0].IP != testIP) {
				t.Errorf("online device = %+v, want UID %d and IP %s", (*onlineDevices)[0], testUID, testIP)
			}
		})
	}
}

func TestLimiter_rejects_at_capacity_only_when_transport_requires_tracking(t *testing.T) {
	tests := []struct {
		name        string
		nodeType    string
		noUDPSource bool
		wantReject  bool
		wantTracked bool
	}{
		{name: "AnyTLS TCP", nodeType: "anytls", noUDPSource: true, wantReject: true, wantTracked: false},
		{name: "Hysteria2 UDP", nodeType: "hysteria2", noUDPSource: false, wantReject: true, wantTracked: false},
		{name: "Hysteria UDP alias", nodeType: "hysteria", noUDPSource: false, wantReject: true, wantTracked: false},
		{name: "TUIC UDP", nodeType: "tuic", noUDPSource: false, wantReject: true, wantTracked: false},
		{name: "Shadowsocks TCP", nodeType: "shadowsocks", noUDPSource: true, wantReject: true, wantTracked: false},
		{name: "Shadowsocks UDP", nodeType: "shadowsocks", noUDPSource: false, wantReject: false, wantTracked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			l := newTestLimiter(tt.nodeType, 1, 1)

			// When
			_, rejected := l.CheckLimit(format.UserTag(testTag, testUUID), testIP, tt.noUDPSource)

			// Then
			if rejected != tt.wantReject {
				t.Errorf("CheckLimit() rejected = %t, want %t", rejected, tt.wantReject)
			}
			onlineDevices, err := l.GetOnlineDevice()
			if err != nil {
				t.Fatalf("GetOnlineDevice() error = %v", err)
			}
			if got := len(*onlineDevices) > 0; got != tt.wantTracked {
				t.Errorf("online device tracked = %t, want %t", got, tt.wantTracked)
				return
			}
		})
	}
}

func TestManagerSpeedBucketFollowsReplacedUserPolicy(t *testing.T) {
	manager := NewManager()
	taguuid := format.UserTag(testTag, testUUID)
	manager.Add(testTag, []panel.UserInfo{{Id: testUID, Uuid: testUUID, SpeedLimit: 20}}, map[int]int{}, "vless")
	current, err := manager.Get(testTag)
	if err != nil {
		t.Fatal(err)
	}
	if bucket := current.SpeedBucket(taguuid); bucket == nil || bucket.Capacity() != 250_000 {
		t.Fatalf("20 Mbps bucket = %#v", bucket)
	}

	manager.Delete(testTag)
	manager.Add(testTag, []panel.UserInfo{{Id: testUID, Uuid: testUUID, SpeedLimit: 1}}, map[int]int{}, "vless")
	current, err = manager.Get(testTag)
	if err != nil {
		t.Fatal(err)
	}
	if bucket := current.SpeedBucket(taguuid); bucket == nil || bucket.Capacity() != 12_500 {
		t.Fatalf("1 Mbps bucket = %#v", bucket)
	}

	manager.Delete(testTag)
	manager.Add(testTag, []panel.UserInfo{{Id: testUID, Uuid: testUUID}}, map[int]int{}, "vless")
	current, err = manager.Get(testTag)
	if err != nil {
		t.Fatal(err)
	}
	if bucket := current.SpeedBucket(taguuid); bucket != nil {
		t.Fatalf("unlimited bucket = %#v", bucket)
	}
}

func TestManagerSharesBandwidthBucketAcrossInbounds(t *testing.T) {
	manager := NewManager()
	first := manager.Add("inbound-1", []panel.UserInfo{{Id: testUID, Uuid: "user-a", SpeedLimit: 20}}, map[int]int{}, "vless")
	second := manager.Add("inbound-2", []panel.UserInfo{{Id: testUID, Uuid: "user-b", SpeedLimit: 20}}, map[int]int{}, "trojan")

	firstBucket := first.SpeedBucket(format.UserTag("inbound-1", "user-a"))
	secondBucket := second.SpeedBucket(format.UserTag("inbound-2", "user-b"))
	if firstBucket == nil || secondBucket == nil {
		t.Fatal("expected shared bandwidth bucket")
	}
	if firstBucket != secondBucket {
		t.Fatal("same subscriber received separate inbound bandwidth buckets")
	}
	if firstBucket.Capacity() != 250_000 {
		t.Fatalf("100ms burst capacity = %d, want 250000", firstBucket.Capacity())
	}
	if available := firstBucket.Available(); available != 0 {
		t.Fatalf("new bucket started with %d tokens, want 0", available)
	}
	if globalSpeedBurstWindow != 100*time.Millisecond || globalSpeedFillWindow != 10*time.Millisecond {
		t.Fatalf("speed bucket timing = burst %s, fill %s", globalSpeedBurstWindow, globalSpeedFillWindow)
	}
	if rate := firstBucket.Rate(); rate != 2_500_000 {
		t.Fatalf("20 Mbps bucket rate = %f, want 2500000 bytes/s", rate)
	}
}

func TestManagerAppliesControlPlaneBandwidthAllocation(t *testing.T) {
	manager := NewManager()
	current := manager.Add(testTag, []panel.UserInfo{{Id: testUID, Uuid: testUUID, SpeedLimit: 20}}, map[int]int{}, "vless")
	taguuid := format.UserTag(testTag, testUUID)
	manager.SetGlobalBandwidthAllocation(testUID, 1_250_000, true)
	allocated := current.SpeedBucket(taguuid)
	if allocated == nil || allocated.Capacity() != 125_000 {
		bucket := allocated
		t.Fatalf("allocated 10 Mbps bucket = %#v", bucket)
	}
	manager.SetGlobalBandwidthAllocation(testUID, 1_250_000, true)
	if current.SpeedBucket(taguuid) != allocated {
		t.Fatal("unchanged allocation replaced the active bandwidth bucket")
	}
	manager.SetGlobalBandwidthAllocation(testUID, 0, true)
	if bucket := current.SpeedBucket(taguuid); bucket == nil || bucket.Capacity() != 1 {
		t.Fatalf("active zero allocation bucket = %#v", bucket)
	}
	manager.SetGlobalBandwidthAllocation(testUID, 0, false)
	if bucket := current.SpeedBucket(taguuid); bucket == nil || bucket.Capacity() != 250_000 {
		t.Fatalf("cleared allocation bucket = %#v", bucket)
	}
}

func TestManagerSignalsZeroAllocationDemandOnceUntilDrained(t *testing.T) {
	manager := NewManager()
	current := manager.Add(testTag, []panel.UserInfo{{Id: testUID, Uuid: testUUID, SpeedLimit: 20}}, map[int]int{}, "vless")
	taguuid := format.UserTag(testTag, testUUID)
	manager.SetGlobalBandwidthAllocation(testUID, 0, true)
	_ = current.SpeedBucket(taguuid)
	_ = current.SpeedBucket(taguuid)
	demands := manager.DrainBandwidthDemands(8)
	if len(demands) != 1 || demands[0] != testUID {
		t.Fatalf("initial demands = %#v", demands)
	}
	_ = current.SpeedBucket(taguuid)
	demands = manager.DrainBandwidthDemands(8)
	if len(demands) != 1 || demands[0] != testUID {
		t.Fatalf("demand after drain = %#v", demands)
	}
}

func TestManagerUpdateUserReplacesGlobalBandwidthPolicy(t *testing.T) {
	manager := NewManager()
	current := manager.Add(testTag, []panel.UserInfo{{Id: testUID, Uuid: testUUID, SpeedLimit: 20}}, map[int]int{}, "vless")
	taguuid := format.UserTag(testTag, testUUID)
	before := current.SpeedBucket(taguuid)
	if before == nil || before.Capacity() != 250_000 {
		t.Fatalf("initial bucket = %#v", before)
	}

	manager.UpdateUser(testTag, []panel.UserInfo{{Id: testUID, Uuid: testUUID, SpeedLimit: 1}}, nil)
	after := current.SpeedBucket(taguuid)
	if after == nil || after.Capacity() != 12_500 {
		t.Fatalf("updated bucket = %#v", after)
	}
	if after == before {
		t.Fatal("policy update retained the stale bandwidth bucket")
	}
}
