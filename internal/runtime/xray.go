package runtime

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
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
	"github.com/guanzihao166/iepl-node-agent/internal/sniguard"
	"github.com/guanzihao166/iepl-node-agent/internal/state"
)

const embeddedXrayVersion = "wyx2685-xray-20260414"

// MNET_REALITY_SNI_GUARD=off disables the fronting SNI guard as an operations
// escape hatch; the default is on for every REALITY inbound.
const realitySniGuardEnv = "MNET_REALITY_SNI_GUARD"

type XrayRuntime struct {
	mu                 sync.Mutex
	secrets            *secretstore.Store
	active             *ppcore.XrayCore
	coreGeneration     uint64
	config             *agentprotocol.DesiredConfig
	users              []agentprotocol.UserCredential
	pendingAccess      []agentprotocol.AccessItem
	inboundAllocations map[int64]map[string]uint64

	// portMu guards the loopback backend ports handed to Xray behind the SNI
	// guard. It is separate from mu because panelNodeForInbound runs before
	// ApplyConfig takes the runtime lock.
	portMu       sync.Mutex
	backendPorts map[int64]int

	guards map[int64]*sniguard.Proxy
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
		r.restorePreviousCore(previousConfig, previousUsers)
		return err
	}
	if err := r.reconcileGuardsLocked(desired); err != nil {
		r.pendingAccess = append(r.pendingAccess, accessSamplesToItems(candidate.GetUserAccessSlice())...)
		_ = candidate.Close()
		r.restorePreviousCore(previousConfig, previousUsers)
		return err
	}
	r.active = candidate
	r.coreGeneration++
	copyDesired := desired
	r.config = &copyDesired
	r.users = candidateUsers
	return nil
}

func (r *XrayRuntime) restorePreviousCore(previousConfig *agentprotocol.DesiredConfig, previousUsers []agentprotocol.UserCredential) {
	if previousConfig == nil {
		return
	}
	if previousNodes, buildErr := r.buildNodes(*previousConfig); buildErr == nil {
		if restored, restoreErr := r.startCore(previousNodes, *previousConfig, previousUsers); restoreErr == nil {
			r.active = restored
			r.coreGeneration++
		}
	}
	_ = r.reconcileGuardsLocked(*previousConfig)
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
	if allocation.PerInbound {
		shares := make(map[int64]map[string]uint64)
		active := make(map[int64]bool)
		for _, item := range allocation.Allocations {
			if item.SubscriberID <= 0 || item.InboundID < 0 {
				return errors.New("invalid inbound bandwidth allocation")
			}
			if shares[item.SubscriberID] == nil {
				shares[item.SubscriberID] = make(map[string]uint64)
				active[item.SubscriberID] = item.AllocationActive
			} else if active[item.SubscriberID] != item.AllocationActive {
				return errors.New("inconsistent inbound bandwidth allocation")
			}
			if item.InboundID > 0 {
				tag := "inbound-" + strconv.FormatInt(item.InboundID, 10)
				if _, duplicate := shares[item.SubscriberID][tag]; duplicate {
					return errors.New("duplicate inbound bandwidth allocation")
				}
				shares[item.SubscriberID][tag] = item.SpeedLimitBPS
			}
		}
		for uid, byTag := range shares {
			if r.inboundAllocations == nil {
				r.inboundAllocations = make(map[int64]map[string]uint64)
			}
			if active[uid] {
				r.inboundAllocations[uid] = byTag
			} else {
				delete(r.inboundAllocations, uid)
			}
			r.active.LimiterManager.SetInboundBandwidthAllocations(int(uid), byTag, active[uid])
		}
		r.pruneInboundAllocationsLocked()
		return nil
	}
	for _, item := range allocation.Allocations {
		r.active.LimiterManager.SetGlobalBandwidthAllocation(int(item.SubscriberID), item.SpeedLimitBPS, item.AllocationActive)
	}
	return nil
}

func (r *XrayRuntime) pruneInboundAllocationsLocked() {
	if len(r.inboundAllocations) == 0 {
		return
	}
	present := make(map[int64]struct{}, len(r.users))
	for _, user := range r.users {
		present[user.SubscriberID] = struct{}{}
	}
	for uid := range r.inboundAllocations {
		if _, ok := present[uid]; !ok {
			delete(r.inboundAllocations, uid)
		}
	}
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
		r.pruneInboundAllocationsLocked()
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
	r.pruneInboundAllocationsLocked()
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
	return left.SpeedLimitBPS == right.SpeedLimitBPS && left.NodeGlobalLimitBPS == right.NodeGlobalLimitBPS && left.DeviceLimit == right.DeviceLimit
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
	var guardRejected uint64
	for _, proxy := range r.guards {
		guardRejected += proxy.Stats().Rejected
	}
	return Status{
		Running: r.active != nil, Version: embeddedXrayVersion,
		CoreGeneration: r.coreGeneration, GuardedInbounds: len(r.guards),
		GuardRejected: guardRejected,
	}
}

func (r *XrayRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, proxy := range r.guards {
		_ = proxy.Close()
		delete(r.guards, id)
	}
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
		ServiceName: inbound.Transport.ServiceName, XHTTPMode: inbound.Transport.XHTTPMode,
		XHTTPExtra: inbound.Transport.XHTTPExtra, AcceptProxyProtocol: inbound.Transport.AcceptProxyProtocol,
	}
	info := &panel.NodeInfo{Id: int(inbound.ID), PushInterval: 60, PullInterval: 315360000, Protocol: &protocol}
	switch inbound.Protocol {
	case agentprotocol.ProtocolVLESS:
		info.Type = "vless"
		protocol.Type = "vless"
		protocol.Flow = inbound.VLESS.Flow
		protocol.Encryption = inbound.VLESS.Decryption
		protocol.EncryptionMode = inbound.VLESS.EncryptionMode
		protocol.EncryptionTicket = inbound.VLESS.EncryptionTicket
		protocol.EncryptionServerPadding = inbound.VLESS.EncryptionServerPadding
		if inbound.VLESS.EncryptionPrivateKeyRef != "" {
			privateKey, err := r.secrets.Resolve(inbound.VLESS.EncryptionPrivateKeyRef)
			if err != nil {
				return nil, fmt.Errorf("resolve VLESS encryption private key: %w", err)
			}
			protocol.EncryptionPrivateKey = strings.TrimSpace(string(privateKey))
		}
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
			// Every declared server name must be acceptable to Xray itself;
			// previously only ServerNames[0] was propagated, so clients
			// dialing any other declared name fell to the fallback path.
			protocol.RealityServerNames = append([]string(nil), profile.Reality.ServerNames...)
			if realitySniGuardEnabled() {
				// The guard owns the public port and forwards surviving
				// connections here, so Xray binds loopback instead.
				backend := r.realityBackendPort(desired, inbound.ID)
				if backend == 0 {
					return nil, fmt.Errorf("no free loopback port for the REALITY guard backend of inbound %d", inbound.ID)
				}
				protocol.ListenAddress = "127.0.0.1"
				protocol.Port = backend
				if transportAcceptsProxyProtocol(inbound.Transport.Type) {
					// Preserve the real client address for access records
					// and per-IP limits across the guard hop.
					protocol.AcceptProxyProtocol = true
				}
			}
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
	for _, user := range users {
		if shares, active := r.inboundAllocations[user.SubscriberID]; active {
			core.LimiterManager.SetInboundBandwidthAllocations(int(user.SubscriberID), shares, true)
		}
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
			speedMbps = int(user.SpeedLimitBPS / 125_000)
		}
		panelUser := panel.UserInfo{
			Id: int(user.SubscriberID), Uuid: user.Value,
			SpeedLimit: speedMbps, DeviceLimit: int(user.DeviceLimit),
			SpeedLimitBPS: user.SpeedLimitBPS, NodeSpeedLimitBPS: user.NodeGlobalLimitBPS,
		}
		if inbound.Protocol == agentprotocol.ProtocolVLESS && inbound.VLESS != nil {
			panelUser.Encryption = inbound.VLESS.EncryptionClientConfig
		}
		grouped[user.InboundID] = append(grouped[user.InboundID], panelUser)
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

func realitySniGuardEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(realitySniGuardEnv))) {
	case "off", "0", "false", "disable", "disabled":
		return false
	}
	return true
}

// transportAcceptsProxyProtocol reports whether the Xray transport of this
// fork can consume a PROXY-protocol header on the inbound. gRPC and XHTTP
// transports have no accept_proxy_protocol support, so the guard forwards
// without the header there (Xray records 127.0.0.1 as the client address).
func transportAcceptsProxyProtocol(transport string) bool {
	switch transport {
	case agentprotocol.TransportTCP, agentprotocol.TransportWebSocket, agentprotocol.TransportHTTPUpgrade:
		return true
	}
	return false
}

// realityBackendPort hands out a stable loopback port for the Xray inbound
// behind the guard of one REALITY inbound. Ports are assigned once per inbound
// ID and cached for the process lifetime, because the incremental user paths
// rebuild node info and must hit the exact port the running core listens on.
func (r *XrayRuntime) realityBackendPort(desired agentprotocol.DesiredConfig, inboundID int64) int {
	r.portMu.Lock()
	defer r.portMu.Unlock()
	if r.backendPorts == nil {
		r.backendPorts = make(map[int64]int)
	}
	if port, ok := r.backendPorts[inboundID]; ok {
		return port
	}
	used := make(map[int]struct{})
	for _, inbound := range desired.Inbounds {
		if inbound.Enabled {
			used[inbound.Port] = struct{}{}
		}
	}
	for _, port := range r.backendPorts {
		used[port] = struct{}{}
	}
	for attempt := 0; attempt < 64; attempt++ {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := probe.Addr().(*net.TCPAddr).Port
		_ = probe.Close()
		if _, taken := used[port]; taken {
			continue
		}
		r.backendPorts[inboundID] = port
		return port
	}
	return 0
}

// guardSpecFor builds the guard spec of a REALITY inbound, or false when the
// inbound does not need a guard.
func (r *XrayRuntime) guardSpecFor(desired agentprotocol.DesiredConfig, inbound agentprotocol.Inbound) (sniguard.Spec, bool) {
	if inbound.SecurityProfileID == 0 {
		return sniguard.Spec{}, false
	}
	profile, ok := securityProfile(desired.Security, inbound.SecurityProfileID)
	if !ok || profile.Type != agentprotocol.SecurityReality || profile.Reality == nil {
		return sniguard.Spec{}, false
	}
	backend := r.realityBackendPort(desired, inbound.ID)
	if backend == 0 {
		return sniguard.Spec{}, false
	}
	listen := inbound.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	return sniguard.Spec{
		ListenAddr:    net.JoinHostPort(listen, strconv.Itoa(inbound.Port)),
		BackendAddr:   net.JoinHostPort("127.0.0.1", strconv.Itoa(backend)),
		AllowedSNIs:   append([]string(nil), profile.Reality.ServerNames...),
		ProxyProtocol: transportAcceptsProxyProtocol(inbound.Transport.Type),
	}, true
}

// reconcileGuardsLocked aligns the running SNI guards with a desired config:
// guards of removed or reconfigured inbounds stop, missing guards start. It
// must run only while the core serving the same config is up, otherwise
// allowed traffic would reach a closed backend.
func (r *XrayRuntime) reconcileGuardsLocked(desired agentprotocol.DesiredConfig) error {
	specs := make(map[int64]sniguard.Spec)
	if realitySniGuardEnabled() {
		for _, inbound := range desired.Inbounds {
			if !inbound.Enabled {
				continue
			}
			if spec, ok := r.guardSpecFor(desired, inbound); ok {
				specs[inbound.ID] = spec
			}
		}
	}
	for id, proxy := range r.guards {
		spec, wanted := specs[id]
		if !wanted || !spec.Equal(proxy.Spec()) {
			_ = proxy.Close()
			delete(r.guards, id)
		}
	}
	var firstErr error
	for id, spec := range specs {
		if _, running := r.guards[id]; running {
			continue
		}
		proxy, err := sniguard.Start(spec)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("start SNI guard for inbound %d: %w", id, err)
			}
			continue
		}
		if r.guards == nil {
			r.guards = make(map[int64]*sniguard.Proxy)
		}
		r.guards[id] = proxy
	}
	return firstErr
}
