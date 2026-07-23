package dispatcher

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestLinkManagerActiveIPsFollowConnectionLifetime(t *testing.T) {
	manager := &LinkManager{links: make(map[*ManagedWriter]buf.Reader)}
	first := &ManagedWriter{manager: manager}
	second := &ManagedWriter{manager: manager}
	third := &ManagedWriter{manager: manager}
	manager.AddLink(first, nil, "::ffff:198.51.100.10")
	manager.AddLink(second, nil, "198.51.100.10")
	manager.AddLink(third, nil, "2001:db8::10")

	assertActiveIPs(t, manager.ActiveIPs(), "198.51.100.10", "2001:db8::10")
	manager.RemoveWriter(first)
	assertActiveIPs(t, manager.ActiveIPs(), "198.51.100.10", "2001:db8::10")
	manager.RemoveWriter(second)
	assertActiveIPs(t, manager.ActiveIPs(), "2001:db8::10")
	manager.RemoveWriter(third)
	assertActiveIPs(t, manager.ActiveIPs())
}

func assertActiveIPs(t *testing.T, actual []string, expected ...string) {
	t.Helper()
	got := make(map[string]struct{}, len(actual))
	for _, address := range actual {
		got[address] = struct{}{}
	}
	if len(got) != len(expected) {
		t.Fatalf("ActiveIPs() = %v, want %v", actual, expected)
	}
	for _, address := range expected {
		if _, ok := got[address]; !ok {
			t.Fatalf("ActiveIPs() = %v, missing %s", actual, address)
		}
	}
}
