package runtime

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	ppcore "github.com/perfect-panel/ppanel-node/core"
	"github.com/perfect-panel/ppanel-node/core/app/dispatcher"
	inboundbuilder "github.com/perfect-panel/ppanel-node/core/inbound"

	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
	"github.com/guanzihao166/iepl-node-agent/internal/secretstore"
	"github.com/guanzihao166/iepl-node-agent/internal/state"
)

const embeddedXrayVersion = "wyx2685-xray-20260414"

type XrayRuntime struct {
	mu             sync.Mutex
	secrets        *secretstore.Store
	active         *ppcore.XrayCore
	coreGeneration uint64
	config         *agentprotocol.DesiredConfig
	users          []agentprotocol.UserCredential
	pendingAccess  []agentprotocol.AccessItem
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
	candidateUsers := usersAvailableInConfig(desired, r.users)
	if r.active != nil {
		previous := r.active
		closeErr := previous.Close()
		r.pendingAccess = append(r.pendingAccess, accessSamplesToItems(previous.GetUserAccessSlice())...)
		if closeErr != nil {
			return closeErr
		}
		r.active = nil
	}
	candidate, err := r.startCore(nodes, desired, candidateUsers)
	if err != nil {
		if previousConfig != nil {
			if previousNodes, buildErr := r.buildNodes(*previousConfig); buildErr == nil {
				if restored, restoreErr := r.startCore(previousNodes, *previousConfig, previousUsers); restoreErr == nil {
					r.active = restored
					r.coreGeneration++
				}
			}
		}
		return err
	}
	r.active = candidate
	r.coreGeneration++
	copyDesired := desired
	r.config = &copyDesired
	r.users = candidateUsers
	return nil
}

func usersAvailableInConfig(desired agentprotocol.DesiredConfig, users []agentprotocol.UserCredential) []agentprotocol.UserCredential {
	available := make(map[int64]struct{}, len(desired.Inbounds))
	for _, inbound := range desired.Inbounds {
		if inbound.Enabled {
			available[inbound.ID] = struct{}{}
		}
	}
	filtered := make([]agentprotocol.UserCredential, 0, len(users))
	for _, user := range users {
		if _, ok := available[user.InboundID]; ok {
			filtered = append(filtered, user)
		}
	}
	return filtered
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
	if err := r.applyUsersIncrementalLocked(users); err == nil {
		return nil
	} else {
		// A failed diff can leave an inbound manager partially updated. The
		// established full rebuild remains the convergence fallback; normal
		// user edits never enter this path.
		return r.rebuildUsersLocked(users, err)
	}
}

// ApplyBandwidthAllocation updates only the shared limiter budget. It leaves
// the Xray user manager and every live data-plane link untouched.
func (r *XrayRuntime) ApplyBandwidthAllocation(_ context.Context, allocation agentprotocol.BandwidthAllocation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		return nil
	}
	for _, item := range allocation.Allocations {
		r.active.LimiterManager.SetGlobalBandwidthAllocation(int(item.SubscriberID), item.SpeedLimitBPS, item.AllocationActive)
	}
	return nil
}

// DrainBandwidthDemands exposes zero-allocation write attempts without
// rebuilding Xray or collecting a traffic batch.
func (r *XrayRuntime) DrainBandwidthDemands(_ context.Context) []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.active.LimiterManager == nil {
		return nil
	}
	demands := r.active.LimiterManager.DrainBandwidthDemands(256)
	result := make([]int64, 0, len(demands))
	for _, subscriberID := range demands {
		if subscriberID > 0 {
			result = append(result, int64(subscriberID))
		}
	}
	return result
}

func (r *XrayRuntime) ApplyUserDelta(_ context.Context, delta agentprotocol.UserDelta) ([]agentprotocol.UserCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if delta.Revision == 0 {
		return nil, errors.New("user delta revision is invalid")
	}
	if r.active == nil || r.config == nil {
		return nil, errors.New("Xray config must be applied before users")
	}
	next := make(map[string]agentprotocol.UserCredential, len(r.users)+len(delta.Upserts))
	for _, user := range r.users {
		next[userKey(user)] = user
	}
	for _, removed := range delta.Removals {
		delete(next, fmt.Sprintf("%d/%d", removed.InboundID, removed.SubscriberID))
	}
	for _, user := range delta.Upserts {
		if user.InboundID <= 0 || user.SubscriberID <= 0 || strings.TrimSpace(user.Value) == "" {
			return nil, errors.New("user delta contains an invalid credential")
		}
		next[userKey(user)] = user
	}
	users := make([]agentprotocol.UserCredential, 0, len(next))
	for _, user := range next {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		if users[i].InboundID != users[j].InboundID {
			return users[i].InboundID < users[j].InboundID
		}
		return users[i].SubscriberID < users[j].SubscriberID
	})
	if err := r.applyUsersIncrementalLocked(users); err != nil {
		if err := r.rebuildUsersLocked(users, err); err != nil {
			return nil, err
		}
	}
	return append([]agentprotocol.UserCredential(nil), r.users...), nil
}

func (r *XrayRuntime) applyUsersIncrementalLocked(users []agentprotocol.UserCredential) error {
	nextGrouped, err := panelUsersByInbound(*r.config, users)
	if err != nil {
		return err
	}
	previousGrouped, err := panelUsersByInbound(*r.config, r.users)
	if err != nil {
		return err
	}
	previous := make(map[string]agentprotocol.UserCredential, len(r.users))
	next := make(map[string]agentprotocol.UserCredential, len(users))
	for _, user := range r.users {
		previous[userKey(user)] = user
	}
	for _, user := range users {
		next[userKey(user)] = user
	}
	removed := make(map[int64][]panel.UserInfo)
	added := make(map[int64][]panel.UserInfo)
	policyUpdates := make(map[int64][]panel.UserInfo)
	stale := make([]agentprotocol.UserCredential, 0)
	for key, oldUser := range previous {
		newUser, exists := next[key]
		if exists && sameRuntimeIdentity(oldUser, newUser) {
			continue
		}
		if info, ok := panelUserByKey(previousGrouped[oldUser.InboundID], oldUser.SubscriberID); ok {
			removed[oldUser.InboundID] = append(removed[oldUser.InboundID], info)
			stale = append(stale, oldUser)
		}
	}
	for key, newUser := range next {
		oldUser, exists := previous[key]
		if exists && sameRuntimeIdentity(oldUser, newUser) {
			if !sameRuntimePolicy(oldUser, newUser) {
				if info, ok := panelUserByKey(nextGrouped[newUser.InboundID], newUser.SubscriberID); ok {
					policyUpdates[newUser.InboundID] = append(policyUpdates[newUser.InboundID], info)
				}
			}
			continue
		}
		if info, ok := panelUserByKey(nextGrouped[newUser.InboundID], newUser.SubscriberID); ok {
			added[newUser.InboundID] = append(added[newUser.InboundID], info)
		}
	}
	if len(removed) == 0 && len(added) == 0 && len(policyUpdates) == 0 {
		r.users = append([]agentprotocol.UserCredential(nil), users...)
		return nil
	}
	if err := r.disconnectUsersLocked(stale); err != nil {
		return err
	}
	for inboundID, removedUsers := range removed {
		node, err := r.panelNodeForInbound(*r.config, findInbound(*r.config, inboundID))
		if err != nil {
			return err
		}
		tag := inboundTag(inboundID)
		if err := r.active.DelUsers(removedUsers, tag, node); err != nil {
			return fmt.Errorf("remove users from %s: %w", tag, err)
		}
		if _, err := r.active.LimiterManager.Get(tag); err == nil {
			r.active.LimiterManager.UpdateUser(tag, nil, removedUsers)
		}
	}
	for inboundID, addedUsers := range added {
		node, err := r.panelNodeForInbound(*r.config, findInbound(*r.config, inboundID))
		if err != nil {
			return err
		}
		tag := inboundTag(inboundID)
		if _, err := r.active.AddUsers(&ppcore.AddUsersParams{Tag: tag, Users: addedUsers, NodeInfo: node}); err != nil {
			return fmt.Errorf("add users to %s: %w", tag, err)
		}
		if _, err := r.active.LimiterManager.Get(tag); err == nil {
			r.active.LimiterManager.UpdateUser(tag, addedUsers, nil)
		}
	}
	for inboundID, updatedUsers := range policyUpdates {
		tag := inboundTag(inboundID)
		if _, err := r.active.LimiterManager.Get(tag); err == nil {
			r.active.LimiterManager.UpdateUser(tag, updatedUsers, nil)
		}
	}
	r.users = append([]agentprotocol.UserCredential(nil), users...)
	return nil
}

func panelUserByKey(users []panel.UserInfo, subscriberID int64) (panel.UserInfo, bool) {
	for _, user := range users {
		if int64(user.Id) == subscriberID {
			return user, true
		}
	}
	return panel.UserInfo{}, false
}

func (r *XrayRuntime) rebuildUsersLocked(users []agentprotocol.UserCredential, incrementalErr error) error {
	nodes, err := r.buildNodes(*r.config)
	if err != nil {
		return err
	}
	previousUsers := append([]agentprotocol.UserCredential(nil), r.users...)
	previous := r.active
	closeErr := previous.Close()
	r.pendingAccess = append(r.pendingAccess, accessSamplesToItems(previous.GetUserAccessSlice())...)
	r.active = nil
	if closeErr != nil {
		if restored, restoreErr := r.startCore(nodes, *r.config, previousUsers); restoreErr == nil {
			r.active = restored
			r.coreGeneration++
		}
		return fmt.Errorf("incremental apply failed: %w; close fallback core: %v", incrementalErr, closeErr)
	}
	candidate, rebuildErr := r.startCore(nodes, *r.config, users)
	if rebuildErr != nil {
		restored, restoreErr := r.startCore(nodes, *r.config, previousUsers)
		r.active = restored
		if restoreErr != nil {
			return fmt.Errorf("incremental apply failed: %w; rebuild: %v; restore previous users: %v", incrementalErr, rebuildErr, restoreErr)
		}
		r.coreGeneration++
		return fmt.Errorf("incremental apply failed: %w; rebuild: %v", incrementalErr, rebuildErr)
	}
	r.active = candidate
	r.coreGeneration++
	r.users = append([]agentprotocol.UserCredential(nil), users...)
	return nil
}

// DisconnectUsers explicitly tears down links for credentials that disappear
// or whose authentication state changes. Policy-only changes stay connected and
// are applied by the dynamic bandwidth limiter.
func (r *XrayRuntime) DisconnectUsers(_ context.Context, nextUsers []agentprotocol.UserCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.config == nil || len(r.users) == 0 {
		return nil
	}

	next := make(map[string]agentprotocol.UserCredential, len(nextUsers))
	for _, user := range nextUsers {
		next[userKey(user)] = user
	}
	stale := make([]agentprotocol.UserCredential, 0)
	for _, previous := range r.users {
		current, ok := next[userKey(previous)]
		if !ok || !sameRuntimeIdentity(previous, current) {
			stale = append(stale, previous)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	return r.disconnectUsersLocked(stale)
}

// DisconnectSubscribers tears down only the selected subscribers' links.
// The active Xray core remains running, so unrelated users keep their sessions.
func (r *XrayRuntime) DisconnectSubscribers(_ context.Context, subscriberIDs []int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil || r.config == nil || len(r.users) == 0 || len(subscriberIDs) == 0 {
		return nil
	}
	wanted := make(map[int64]struct{}, len(subscriberIDs))
	for _, id := range subscriberIDs {
		if id > 0 {
			wanted[id] = struct{}{}
		}
	}
	stale := make([]agentprotocol.UserCredential, 0)
	for _, user := range r.users {
		if _, ok := wanted[user.SubscriberID]; ok {
			stale = append(stale, user)
		}
	}
	return r.disconnectUsersLocked(stale)
}

func (r *XrayRuntime) disconnectUsersLocked(stale []agentprotocol.UserCredential) error {
	if len(stale) == 0 {
		return nil
	}
	grouped := make(map[int64][]panel.UserInfo)
	for _, user := range stale {
		if user.InboundID <= 0 || user.SubscriberID <= 0 || strings.TrimSpace(user.Value) == "" {
			continue
		}
		// Expiry is deliberately ignored here: an expired credential still has
		// to have its existing links closed. The credential itself stays loaded
		// so a targeted bandwidth action does not break new connections.
		grouped[user.InboundID] = append(grouped[user.InboundID], panel.UserInfo{
			Id: int(user.SubscriberID), Uuid: user.Value,
		})
	}
	var firstErr error
	for inboundID, users := range grouped {
		if len(users) == 0 {
			continue
		}
		if err := r.active.CloseUserLinks(users, inboundTag(inboundID)); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("disconnect users on inbound %d: %w", inboundID, err)
		}
	}
	return firstErr
}

func userKey(user agentprotocol.UserCredential) string {
	return fmt.Sprintf("%d/%d", user.InboundID, user.SubscriberID)
}

func sameRuntimeCredential(left, right agentprotocol.UserCredential) bool {
	return sameRuntimeIdentity(left, right) && sameRuntimePolicy(left, right)
}

func sameRuntimeIdentity(left, right agentprotocol.UserCredential) bool {
	return left.Kind == right.Kind && left.Value == right.Value &&
		left.ExpiresAt == right.ExpiresAt && left.QuotaGeneration == right.QuotaGeneration
}

func sameRuntimePolicy(left, right agentprotocol.UserCredential) bool {
	return left.SpeedLimitBPS == right.SpeedLimitBPS && left.DeviceLimit == right.DeviceLimit
}

func findInbound(desired agentprotocol.DesiredConfig, id int64) agentprotocol.Inbound {
	for _, inbound := range desired.Inbounds {
		if inbound.ID == id {
			return inbound
		}
	}
	return agentprotocol.Inbound{ID: id}
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

func (r *XrayRuntime) CollectAccess(_ context.Context) ([]agentprotocol.AccessItem, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	items := append([]agentprotocol.AccessItem(nil), r.pendingAccess...)
	r.pendingAccess = nil
	if r.active != nil {
		items = append(items, accessSamplesToItems(r.active.GetUserAccessSlice())...)
	}
	return items, nil
}

func (r *XrayRuntime) RequeueAccess(items []agentprotocol.AccessItem) {
	if r == nil || len(items) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pendingAccess)+len(items) > 20000 {
		items = items[len(items)-(20000-len(r.pendingAccess)):]
	}
	r.pendingAccess = append(r.pendingAccess, items...)
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
		online := r.active.GetOnlineDevices(inboundTag(inbound.ID))
		grouped := make(map[int64][]string)
		for _, item := range online {
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
	return Status{Running: r.active != nil, Version: embeddedXrayVersion, CoreGeneration: r.coreGeneration}
}

func (r *XrayRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		return nil
	}
	active := r.active
	err := active.Close()
	r.pendingAccess = append(r.pendingAccess, accessSamplesToItems(active.GetUserAccessSlice())...)
	r.active = nil
	return err
}

func accessSamplesToItems(samples []dispatcher.AccessSample) []agentprotocol.AccessItem {
	items := make([]agentprotocol.AccessItem, 0, len(samples))
	for _, sample := range samples {
		item := agentprotocol.AccessItem{
			SessionKey: sample.SessionKey, SubscriberID: sample.SubscriberID, InboundID: sample.InboundID,
			Host: sample.Host, Network: sample.Network, Protocol: sample.Protocol,
			DestinationPort: sample.DestinationPort, StartedAt: sample.StartedAt, LastSeenAt: sample.LastSeenAt,
			UploadBytes: sample.UploadBytes, DownloadBytes: sample.DownloadBytes,
			ConnectionCount: sample.ConnectionCount, Active: sample.Active,
		}
		if sample.EndedAt != nil {
			endedAt := *sample.EndedAt
			item.EndedAt = &endedAt
		}
		items = append(items, item)
	}
	return items
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
		ServiceName: inbound.Transport.ServiceName, AcceptProxyProtocol: inbound.Transport.AcceptProxyProtocol,
	}
	info := &panel.NodeInfo{Id: int(inbound.ID), PushInterval: 60, PullInterval: 315360000, Protocol: &protocol}
	switch inbound.Protocol {
	case agentprotocol.ProtocolVLESS:
		info.Type = "vless"
		protocol.Type = "vless"
		protocol.Flow = inbound.VLESS.Flow
		protocol.Encryption = inbound.VLESS.Decryption
	case agentprotocol.ProtocolVMess:
		info.Type, protocol.Type = "vmess", "vmess"
	case agentprotocol.ProtocolTrojan:
		info.Type, protocol.Type = "trojan", "trojan"
	case agentprotocol.ProtocolSS2022:
		info.Type, protocol.Type = "shadowsocks", "shadowsocks"
		protocol.Cipher = inbound.SS2022.Method
		serverKey, err := r.secrets.Resolve(inbound.SS2022.ServerKeyRef)
		if err != nil {
			return nil, fmt.Errorf("resolve SS2022 server key: %w", err)
		}
		serverKey, err = normalizeSS2022Key(inbound.SS2022.Method, serverKey)
		if err != nil {
			return nil, fmt.Errorf("normalize SS2022 server key: %w", err)
		}
		protocol.ServerKey = string(serverKey)
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
	grouped, err := panelUsersByInbound(desired, users)
	if err != nil {
		_ = core.Close()
		return nil, err
	}
	for _, node := range nodes {
		if err := core.AddNode(node.tag, node.info); err != nil {
			_ = core.Close()
			return nil, err
		}
		inboundID, _ := strconv.ParseInt(strings.TrimPrefix(node.tag, "inbound-"), 10, 64)
		core.LimiterManager.Add(node.tag, grouped[inboundID], map[int]int{}, node.info.Type)
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
	case agentprotocol.ProtocolVLESS, agentprotocol.ProtocolVMess, agentprotocol.ProtocolTUIC:
		if uuid.Validate(value) != nil {
			return errors.New("credential must be a UUID")
		}
	case agentprotocol.ProtocolSS2022:
		if _, err := normalizeSS2022Key(inbound.SS2022.Method, []byte(value)); err != nil {
			return errors.New("SS2022 credential is invalid")
		}
	case agentprotocol.ProtocolTrojan, agentprotocol.ProtocolHysteria2:
		if len(value) < 8 || len(value) > 255 {
			return errors.New("password length is invalid")
		}
	}
	return nil
}

func normalizeSS2022Key(method string, material []byte) ([]byte, error) {
	length := 32
	if method == "2022-blake3-aes-128-gcm" {
		length = 16
	}
	if len(material) == length {
		return append([]byte(nil), material...), nil
	}
	encoded := strings.TrimSpace(string(material))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil || len(decoded) != length {
		return nil, errors.New("key length does not match the SS2022 method")
	}
	return decoded, nil
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
