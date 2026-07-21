package core

import (
	"net"

	outboundbuilder "github.com/perfect-panel/ppanel-node/core/outbound"

	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/core"
)

// hasPublicIPv6 checks if the machine has a public IPv6 address
func hasPublicIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Check if it's IPv6, not loopback, not link-local, not private/ULA
		if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

func GetCustomConfig(serverconfig *panel.ServerConfigResponse) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, error) {
	result, err := outboundbuilder.Build(serverconfig, hasPublicIPv6())
	if err != nil {
		return nil, nil, nil, err
	}
	return result.DNS, result.Outbounds, result.Router, nil
}
