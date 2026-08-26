// Package hostnetwork reports the public addresses directly assigned to the
// Agent host. It deliberately avoids third-party echo services so heartbeats
// remain available while the control-plane is the only reachable endpoint.
package hostnetwork

import (
	"bytes"
	"net"
	"sort"
)

type Addresses struct {
	IPv4 string
	IPv6 string
}

func PublicAddresses() Addresses {
	interfaces, err := net.Interfaces()
	if err != nil {
		return Addresses{}
	}
	var candidates []net.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err == nil {
			candidates = append(candidates, addresses...)
		}
	}
	return publicAddresses(candidates)
}

func publicAddresses(addresses []net.Addr) Addresses {
	var ipv4, ipv6 []net.IP
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || !isGlobalPublic(ip) {
			continue
		}
		if ip.To4() != nil {
			ipv4 = append(ipv4, append(net.IP(nil), ip.To4()...))
		} else {
			ipv6 = append(ipv6, append(net.IP(nil), ip...))
		}
	}
	sort.Slice(ipv4, func(i, j int) bool { return bytes.Compare(ipv4[i], ipv4[j]) < 0 })
	sort.Slice(ipv6, func(i, j int) bool { return bytes.Compare(ipv6[i], ipv6[j]) < 0 })
	result := Addresses{}
	if len(ipv4) > 0 {
		result.IPv4 = ipv4[0].String()
	}
	if len(ipv6) > 0 {
		result.IPv6 = ipv6[0].String()
	}
	return result
}

func isGlobalPublic(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !ip.IsMulticast() && !ip.IsUnspecified()
}
