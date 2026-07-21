package inbound

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func buildVLess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "vless"
	var err error
	decryption, err := buildVlessDecryption(nodeInfo.Protocol)
	if err != nil {
		return err
	}
	s, err := json.Marshal(&coreConf.VLessInboundConfig{
		Decryption: decryption,
	})
	if err != nil {
		return fmt.Errorf("marshal vless config error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	stream, err := buildTransportSetting(nodeInfo)
	if err != nil {
		return err
	}
	inbound.StreamSetting = stream
	return nil
}

func buildVlessDecryption(protocol *panel.Protocol) (string, error) {
	if protocol.Encryption == "" || protocol.Encryption == "none" {
		return "none", nil
	}
	switch protocol.Encryption {
	case "mlkem768x25519plus":
		parts := []string{
			"mlkem768x25519plus",
			protocol.EncryptionMode,
			normalizeVlessTicket(protocol.EncryptionTicket),
		}
		if protocol.EncryptionServerPadding != "" {
			parts = append(parts, strings.Split(protocol.EncryptionServerPadding, ".")...)
		}
		parts = append(parts, protocol.EncryptionPrivateKey)
		return strings.Join(parts, "."), nil
	default:
		return "", fmt.Errorf("vless decryption method %s is not support", protocol.Encryption)
	}
}

func normalizeVlessTicket(ticket string) string {
	ticket = strings.TrimSpace(ticket)
	if ticket == "" {
		return ""
	}
	last := ticket[len(ticket)-1]
	if last >= '0' && last <= '9' {
		return ticket + "s"
	}
	return ticket
}
