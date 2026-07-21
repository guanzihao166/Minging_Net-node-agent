package inbound

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/perfect-panel/ppanel-node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func buildHysteria2(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "hysteria"
	settings := &coreConf.HysteriaServerConfig{
		Version: 2,
	}
	t := coreConf.TransportProtocol("hysteria")
	up := coreConf.Bandwidth(strconv.Itoa(nodeInfo.Protocol.UpMbps) + "mbps")
	down := coreConf.Bandwidth(strconv.Itoa(nodeInfo.Protocol.DownMbps) + "mbps")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	hysteriasetting := &coreConf.HysteriaConfig{
		Version: 2,
	}

	finalmask := &coreConf.FinalMask{}
	obfs := nodeInfo.Protocol.Obfs
	obfs_password := nodeInfo.Protocol.ObfsPassword
	if obfs != "" {
		if obfs == "none" {
			obfs = ""
			obfs_password = ""
		}
	}
	if nodeInfo.Protocol.UpMbps > 0 || nodeInfo.Protocol.DownMbps > 0 {
		finalmask.QuicParams = &coreConf.QuicParamsConfig{
			Congestion: "force-brutal",
			BrutalUp:   up,
			BrutalDown: down,
		}
	}
	if obfs != "" && obfs_password != "" {
		rawobfsJSON := json.RawMessage(fmt.Sprintf(`{"password":"%s"}`, obfs_password))
		udp := []coreConf.Mask{
			{
				Type:     obfs,
				Settings: &rawobfsJSON,
			},
		}
		finalmask.Udp = udp
	}

	inbound.StreamSetting.FinalMask = finalmask
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	inbound.StreamSetting.HysteriaSettings = hysteriasetting
	if err != nil {
		return fmt.Errorf("marshal hysteria2 settings error: %s", err)
	}
	return nil
}
