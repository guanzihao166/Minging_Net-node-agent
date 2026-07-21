package runtime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	ppcore "github.com/perfect-panel/ppanel-node/core"
	inboundbuilder "github.com/perfect-panel/ppanel-node/core/inbound"

	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
	"github.com/guanzihao166/iepl-node-agent/internal/secretstore"
	"github.com/guanzihao166/iepl-node-agent/internal/state"
)

const embeddedXrayVersion = "wyx2685-xray-20260414"

type XrayRuntime struct {
	mu      sync.Mutex
	secrets *secretstore.Store
	active  *ppcore.XrayCore
	config  *agentprotocol.DesiredConfig
	users   []agentprotocol.UserCredential
}

func NewXray(secrets *secretstore.Store) (*XrayRuntime, error) {
	if secrets == nil {
		return nil, errors.New("Xray secret store is required")
	}
	return &XrayRuntime{secrets: secrets}, nil
}

func (r *XrayRuntime) ApplyConfig(_ context.Context, desired agentprotocol.DesiredConfig) error {
	if err := agentprotocol.ValidateDesiredConfig(desired); err != nil {
		return err
	}
	nodes, err := r.buildNodes(desired)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if _, err := inboundbuilder.Build(node.info, node.tag); err != nil {
			return fmt.Errorf("validate %s: %w", node.tag, err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	previousConfig := r.config
	previousUsers := append([]agentprotocol.UserCredential(nil), r.users...)
	if r.active != nil {
		if err := r.active.Close(); err != nil {
			return err
		}
		r.active = nil
	}
	candidate, err := r.startCore(nodes, desired, r.users)
	if err != nil {
		if previousConfig != nil {
			if previousNodes, buildErr := r.buildNodes(*previousConfig); buildErr == nil {
				r.active, _ = r.startCore(previousNodes, *previousConfig, previousUsers)
			}
		}
		return err
	}
	r.active = candidate
	copyDesired := desired
	r.config = &copyDesired
	return nil
}

func (r *XrayRuntime) ApplyUsers(_ context.Context, users []agentprotocol.UserCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.config == nil {
		if len(users) == 0 {
			r.users = nil
			return nil
		}
		return errors.New("Xray config must be applied before users")
	}
	grouped, err := panelUsersByInbound(*r.config, users)
	if err != nil {
		return err
	}
	oldGrouped, err := panelUsersByInbound(*r.config, r.users)
	if err != nil {
		return err
	}
	for _, inbound := range r.config.Inbounds {
		if !inbound.Enabled {
			continue
		}
		tag := inboundTag(inbound.ID)
		nodeInfo, err := r.panelNodeForInbound(*r.config, inbound)
		if err != nil {
			return err
		}
		oldUsers := oldGrouped[inbound.ID]
		newUsers := grouped[inbound.ID]
		if len(oldUsers) > 0 {
			if err := r.active.DelUsers(oldUsers, tag, nodeInfo); err != nil {
				return fmt.Errorf("remove users from %s: %w", tag, err)
			}
		}
		r.active.LimiterManager.Delete(tag)
		limiter := r.active.LimiterManager.Add(tag, newUsers, map[int]int{}, nodeInfo.Type)
		if len(newUsers) > 0 {
			if _, err := r.active.AddUsers(&ppcore.AddUsersParams{Tag: tag, Users: newUsers, NodeInfo: nodeInfo}); err != nil {
				if len(oldUsers) > 0 {
					r.active.LimiterManager.Delete(tag)
					r.active.LimiterManager.Add(tag, oldUsers, map[int]int{}, nodeInfo.Type)
					_, _ = r.active.AddUsers(&ppcore.AddUsersParams{Tag: tag, Users: oldUsers, NodeInfo: nodeInfo})
				}
				return fmt.Errorf("add users to %s: %w", tag, err)
			}
		}
		applyExpiryAndLimits(limiter, tag, users, inbound.ID)
	}
	r.users = append([]agentprotocol.UserCredential(nil), users...)
	return nil
}

func (r *XrayRuntime) CollectTraffic(_ context.Context) ([]state.TrafficDelta, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.config == nil {
		return nil, nil
	}
	quota := make(map[string]uint64, len(r.users))
	for _, user := range r.users {
		quota[fmt.Sprintf("%d/%d", user.InboundID, user.SubscriberID)] = user.QuotaGeneration
	}
	deltas := make([]state.TrafficDelta, 0)
	for _, inbound := range r.config.Inbounds {
		if !inbound.Enabled {
			continue
		}
		traffic, err := r.active.GetUserTrafficSlice(inboundTag(inbound.ID), 0)
		if err != nil {
			return nil, err
		}
		for _, sample := range traffic {
			if sample.Upload < 0 || sample.Download < 0 {
				continue
			}
			deltas = append(deltas, state.TrafficDelta{
				SubscriberID: int64(sample.UID), InboundID: inbound.ID,
				QuotaGeneration: quota[fmt.Sprintf("%d/%d", inbound.ID, sample.UID)],
				UploadBytes:     uint64(sample.Upload), DownloadBytes: uint64(sample.Download),
			})
		}
	}
	return deltas, nil
}

func (r *XrayRuntime) CollectOnline(_ context.Context) ([]agentprotocol.OnlineUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.config == nil {
		return nil, nil
	}
	out := make([]agentprotocol.OnlineUser, 0)
	for _, inbound := range r.config.Inbounds {
		if !inbound.Enabled {
			continue
		}
		limiter, err := r.active.LimiterManager.Get(inboundTag(inbound.ID))
		if err != nil {
			continue
		}
		online, err := limiter.GetOnlineDevice()
		if err != nil {
			return nil, err
		}
		grouped := make(map[int64][]string)
		for _, item := range *online {
			grouped[int64(item.UID)] = append(grouped[int64(item.UID)], item.IP)
		}
		for subscriberID, addresses := range grouped {
			out = append(out, agentprotocol.OnlineUser{
				SubscriberID: subscriberID, InboundID: inbound.ID, Addresses: addresses,
			})
		}
	}
	return out, nil
}

func (r *XrayRuntime) Status(context.Context) Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Status{Running: r.active != nil, Version: embeddedXrayVersion}
}

func (r *XrayRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		return nil
	}
	err := r.active.Close()
	r.active = nil
	return err
}

type runtimeNode struct {
	tag  string
	info *panel.NodeInfo
}

func (r *XrayRuntime) buildNodes(desired agentprotocol.DesiredConfig) ([]runtimeNode, error) {
	nodes := make([]runtimeNode, 0, len(desired.Inbounds))
	for _, inbound := range desired.Inbounds {
		if !inbound.Enabled {
			continue
		}
		info, err := r.panelNodeForInbound(desired, inbound)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, runtimeNode{tag: inboundTag(inbound.ID), info: info})
	}
	return nodes, nil
}

func (r *XrayRuntime) panelNodeForInbound(desired agentprotocol.DesiredConfig, inbound agentprotocol.Inbound) (*panel.NodeInfo, error) {
	protocol := panel.Protocol{
		Port: inbound.Port, Enable: inbound.Enabled, Transport: inbound.Transport.Type,
		Host: inbound.Transport.Host, Path: inbound.Transport.Path,
		ServiceName: inbound.Transport.ServiceName,
	}
	info := &panel.NodeInfo{Id: int(inbound.ID), PushInterval: 60, PullInterval: 315360000, Protocol: &protocol}
	switch inbound.Protocol {
	case agentprotocol.ProtocolVLESS:
		info.Type = "vless"
		protocol.Type = "vless"
		protocol.Flow = inbound.VLESS.Flow
		protocol.Encryption = inbound.VLESS.Decryption
	case agentprotocol.ProtocolTrojan:
		info.Type, protocol.Type = "trojan", "trojan"
	case agentprotocol.ProtocolSS2022:
		info.Type, protocol.Type = "shadowsocks", "shadowsocks"
		protocol.Cipher = inbound.SS2022.Method
		serverKey, err := r.secrets.Resolve(inbound.SS2022.ServerKeyRef)
		if err != nil {
			return nil, fmt.Errorf("resolve SS2022 server key: %w", err)
		}
		protocol.ServerKey = strings.TrimSpace(string(serverKey))
	case agentprotocol.ProtocolTUIC:
		info.Type, protocol.Type = "tuic", "tuic"
		protocol.CongestionController = inbound.TUIC.CongestionControl
		protocol.ReduceRTT = inbound.TUIC.ZeroRTTHandshake
		protocol.UDPRelayMode = inbound.TUIC.UDPRelayMode
	case agentprotocol.ProtocolHysteria2:
		info.Type, protocol.Type = "hysteria2", "hysteria2"
		protocol.UpMbps, protocol.DownMbps = inbound.Hysteria2.UpMbps, inbound.Hysteria2.DownMbps
		protocol.Obfs, protocol.HopPorts, protocol.HopInterval = inbound.Hysteria2.Obfs, inbound.Hysteria2.HopPorts, inbound.Hysteria2.HopIntervalSeconds
		if inbound.Hysteria2.ObfsPasswordRef != "" {
			obfsPassword, err := r.secrets.Resolve(inbound.Hysteria2.ObfsPasswordRef)
			if err != nil {
				return nil, fmt.Errorf("resolve Hysteria2 obfuscation password: %w", err)
			}
			protocol.ObfsPassword = strings.TrimSpace(string(obfsPassword))
		}
	default:
		return nil, errors.New("unsupported Xray protocol")
	}
	if inbound.SecurityProfileID != 0 {
		profile, ok := securityProfile(desired.Security, inbound.SecurityProfileID)
		if !ok {
			return nil, errors.New("security profile was not found")
		}
		protocol.Security = profile.Type
		switch profile.Type {
		case agentprotocol.SecurityTLS:
			protocol.SNI = profile.TLS.ServerNames[0]
			protocol.CertMode = "file"
			protocol.TLSMinVersion = profile.TLS.MinVersion
			protocol.TLSMaxVersion = profile.TLS.MaxVersion
			protocol.TLSALPN = append([]string(nil), profile.TLS.ALPN...)
			certificateFile, err := r.secrets.Materialize(profile.TLS.CertificateRef, ".crt", 0o644)
			if err != nil {
				return nil, fmt.Errorf("materialize TLS certificate: %w", err)
			}
			privateKeyFile, err := r.secrets.Materialize(profile.TLS.PrivateKeyRef, ".key", 0o600)
			if err != nil {
				return nil, fmt.Errorf("materialize TLS private key: %w", err)
			}
			protocol.CertificateFile, protocol.PrivateKeyFile = certificateFile, privateKeyFile
		case agentprotocol.SecurityReality:
			host, portRaw, _ := net.SplitHostPort(profile.Reality.Destination)
			port, _ := strconv.Atoi(portRaw)
			privateKey, err := r.secrets.Resolve(profile.Reality.PrivateKeyRef)
			if err != nil {
				return nil, fmt.Errorf("resolve REALITY private key: %w", err)
			}
			protocol.SNI = profile.Reality.ServerNames[0]
			protocol.RealityServerAddr, protocol.RealityServerPort = host, port
			protocol.RealityPrivateKey = strings.TrimSpace(string(privateKey))
			protocol.RealityPublicKey = profile.Reality.PublicKey
			protocol.RealityShortID = profile.Reality.ShortIDs[0]
			protocol.Fingerprint = profile.Reality.Fingerprint
		}
	}
	info.Protocol = &protocol
	return info, nil
}

func (r *XrayRuntime) startCore(nodes []runtimeNode, desired agentprotocol.DesiredConfig, users []agentprotocol.UserCredential) (*ppcore.XrayCore, error) {
	configuration := conf.New()
	configuration.LogConfig.Level = "warning"
	configuration.LogConfig.Access = "none"
	protocols := []panel.Protocol{}
	serverConfig := &panel.ServerConfigResponse{Data: &panel.Data{
		PullInterval: 315360000, PushInterval: 60, Protocols: &protocols,
	}}
	core := ppcore.New(configuration, nil)
	if err := core.Start(serverConfig); err != nil {
		return nil, err
	}
	for _, node := range nodes {
		if err := core.AddNode(node.tag, node.info); err != nil {
			_ = core.Close()
			return nil, err
		}
		core.LimiterManager.Add(node.tag, nil, map[int]int{}, node.info.Type)
	}
	grouped, err := panelUsersByInbound(desired, users)
	if err != nil {
		_ = core.Close()
		return nil, err
	}
	for _, node := range nodes {
		inboundID, _ := strconv.ParseInt(strings.TrimPrefix(node.tag, "inbound-"), 10, 64)
		panelUsers := grouped[inboundID]
		if len(panelUsers) == 0 {
			continue
		}
		if _, err := core.AddUsers(&ppcore.AddUsersParams{Tag: node.tag, Users: panelUsers, NodeInfo: node.info}); err != nil {
			_ = core.Close()
			return nil, err
		}
		limiter, _ := core.LimiterManager.Get(node.tag)
		applyExpiryAndLimits(limiter, node.tag, users, inboundID)
	}
	return core, nil
}

func panelUsersByInbound(desired agentprotocol.DesiredConfig, users []agentprotocol.UserCredential) (map[int64][]panel.UserInfo, error) {
	inbounds := make(map[int64]agentprotocol.Inbound, len(desired.Inbounds))
	for _, inbound := range desired.Inbounds {
		if inbound.Enabled {
			inbounds[inbound.ID] = inbound
		}
	}
	grouped := make(map[int64][]panel.UserInfo)
	now := time.Now().Unix()
	for _, user := range users {
		inbound, ok := inbounds[user.InboundID]
		if !ok {
			return nil, fmt.Errorf("user %d references an unavailable inbound", user.SubscriberID)
		}
		if user.SubscriberID <= 0 || user.Value == "" || (user.ExpiresAt > 0 && user.ExpiresAt <= now) {
			continue
		}
		if err := validateRuntimeCredential(inbound, user.Value); err != nil {
			return nil, fmt.Errorf("user %d: %w", user.SubscriberID, err)
		}
		speedMbps := 0
		if user.SpeedLimitBPS > 0 {
			speedMbps = int(math.Ceil(float64(user.SpeedLimitBPS*8) / 1000000))
		}
		grouped[user.InboundID] = append(grouped[user.InboundID], panel.UserInfo{
			Id: int(user.SubscriberID), Uuid: user.Value,
			SpeedLimit: speedMbps, DeviceLimit: int(user.DeviceLimit),
		})
	}
	return grouped, nil
}

func validateRuntimeCredential(inbound agentprotocol.Inbound, value string) error {
	switch inbound.Protocol {
	case agentprotocol.ProtocolVLESS, agentprotocol.ProtocolTUIC:
		if uuid.Validate(value) != nil {
			return errors.New("credential must be a UUID")
		}
	case agentprotocol.ProtocolSS2022:
		length := 32
		if inbound.SS2022.Method == "2022-blake3-aes-128-gcm" {
			length = 16
		}
		if len(value) < length {
			return errors.New("SS2022 credential is too short")
		}
	case agentprotocol.ProtocolTrojan, agentprotocol.ProtocolHysteria2:
		if len(value) < 8 || len(value) > 255 {
			return errors.New("password length is invalid")
		}
	}
	return nil
}

func applyExpiryAndLimits(limiter interface {
	GetOnlineDevice() (*[]panel.OnlineUser, error)
}, _ string, _ []agentprotocol.UserCredential, _ int64) {
	// PPanel enforces configured speed/device values during LimiterManager.Add.
	// Expired users are excluded before they reach the limiter or Xray.
	_ = limiter
}

func securityProfile(profiles []agentprotocol.SecurityProfile, id int64) (agentprotocol.SecurityProfile, bool) {
	for _, profile := range profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return agentprotocol.SecurityProfile{}, false
}

func inboundTag(id int64) string { return fmt.Sprintf("inbound-%d", id) }
