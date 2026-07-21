package inbound

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/perfect-panel/ppanel-node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func buildShadowsocks(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "shadowsocks"
	cipher := nodeInfo.Protocol.Cipher
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: cipher,
	}
	p := make([]byte, 32)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)

	if nodeInfo.Protocol.ServerKey != "" && strings.Contains(cipher, "2022") {
		nodeInfo.Protocol.ServerKey = base64.StdEncoding.EncodeToString([]byte(nodeInfo.Protocol.ServerKey))
		settings.Password = nodeInfo.Protocol.ServerKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}

	if nodeInfo.Protocol.Obfs != "" && nodeInfo.Protocol.Obfs == "http" {
		if nodeInfo.Protocol.ObfsPath != "" || nodeInfo.Protocol.ObfsHost != "" {
			settings.NetworkList = &coreConf.NetworkList{"tcp"}
		}
		t := coreConf.TransportProtocol("tcp")
		inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
		inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{
			AcceptProxyProtocol: nodeInfo.Protocol.AcceptProxyProtocol,
		}

		httpHeader := map[string]interface{}{
			"type":    "http",
			"request": map[string]interface{}{},
		}
		request := httpHeader["request"].(map[string]interface{})

		path := nodeInfo.Protocol.ObfsPath
		if path == "" {
			path = "/"
		}
		request["path"] = []string{path}

		if nodeInfo.Protocol.ObfsHost != "" {
			request["headers"] = map[string]interface{}{
				"Host": []string{nodeInfo.Protocol.ObfsHost},
			}
		}
		headerJSON, err := json.Marshal(httpHeader)
		if err == nil {
			inbound.StreamSetting.TCPSettings.HeaderConfig = json.RawMessage(headerJSON)
		}
	}

	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal shadowsocks settings error: %s", err)
	}
	return nil
}
