package hostnetwork

import (
	"net"
	"testing"
)

func TestPublicAddressesSelectsGlobalIPv4AndIPv6(t *testing.T) {
	addresses := []net.Addr{
		mustCIDR(t, "127.0.0.1/8"), mustCIDR(t, "10.0.0.2/24"),
		mustCIDR(t, "203.0.113.19/24"), mustCIDR(t, "198.51.100.7/24"),
		mustCIDR(t, "fe80::1/64"), mustCIDR(t, "fd00::1/64"),
		mustCIDR(t, "2001:db8::19/64"), mustCIDR(t, "2001:db8::7/64"),
	}
	got := publicAddresses(addresses)
	if got.IPv4 != "198.51.100.7" || got.IPv6 != "2001:db8::7" {
		t.Fatalf("publicAddresses() = %#v", got)
	}
}

func TestPublicAddressesRejectsNonPublicAddresses(t *testing.T) {
	got := publicAddresses([]net.Addr{mustCIDR(t, "::1/128"), mustCIDR(t, "169.254.1.1/16"), mustCIDR(t, "fc00::1/7")})
	if got != (Addresses{}) {
		t.Fatalf("publicAddresses() = %#v", got)
	}
}

func mustCIDR(t *testing.T, value string) *net.IPNet {
	t.Helper()
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatal(err)
	}
	network.IP = ip
	return network
}
