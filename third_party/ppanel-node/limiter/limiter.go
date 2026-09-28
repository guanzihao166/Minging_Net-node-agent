package limiter

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
)

type Manager struct {
	lock             sync.RWMutex
	limiters         map[string]*Limiter
	globalLock       sync.Mutex
	globalUserLimits map[int]map[string]uint64
	globalUserRates  sync.Map                  // Key: subscriber ID, value: bytes per second
	globalAllocated  sync.Map                  // Key: subscriber ID, value: allocated BPS
	inboundAllocated map[int]map[string]uint64 // nil entry falls back to static policy
	globalSpeed      sync.Map                  // Keys: user:<uid>, node:<tag>, allocation:<uid>, effective:<tag>|<uid>
	bandwidthDemands chan int
	pendingDemands   sync.Map // Key: subscriber ID, value: struct{}
}

const (
	globalSpeedBurstWindow = 100 * time.Millisecond
	globalSpeedFillWindow  = 10 * time.Millisecond
)

func NewManager() *Manager {
	return &Manager{
		limiters:         make(map[string]*Limiter),
		globalUserLimits: make(map[int]map[string]uint64),
		inboundAllocated: make(map[int]map[string]uint64),
		bandwidthDemands: make(chan int, 1024),
	}
}

// DrainBandwidthDemands returns each zero-allocation subscriber at most once.
// It is a control-plane hint only and never affects traffic accounting.
func (m *Manager) DrainBandwidthDemands(max int) []int {
	if m == nil || max <= 0 {
		return nil
	}
	result := make([]int, 0, max)
	for len(result) < max {
		select {
		case uid := <-m.bandwidthDemands:
			m.pendingDemands.Delete(uid)
			result = append(result, uid)
		default:
			return result
		}
	}
	return result
}

func (m *Manager) signalBandwidthDemand(uid int) {
	if m == nil || uid <= 0 {
		return
	}
	if _, loaded := m.pendingDemands.LoadOrStore(uid, struct{}{}); loaded {
		return
	}
	select {
	case m.bandwidthDemands <- uid:
	default:
		m.pendingDemands.Delete(uid)
	}
}

type Limiter struct {
	manager       *Manager
	stateMu       sync.RWMutex
	NodeType      string
	SpeedLimit    int
	UserOnlineIP  *sync.Map      // Key: TagUUID, value: {Key: Ip, value: Uid}
	OldUserOnline *sync.Map      // Key: Ip, value: Uid
	UUIDtoUID     map[string]int // Key: UUID, value: Uid
	UserLimitInfo *sync.Map      // Key: TagUUID, value: UserLimitInfo
	SpeedLimiter  *sync.Map      // key: TagUUID, value: *ratelimit.Bucket
	AliveList     map[int]int    // Key: Uid, value: alive_ip
}

type UserLimitInfo struct {
	UID               int
	SpeedLimit        int
	SpeedLimitBPS     uint64
	NodeSpeedLimitBPS uint64
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
	OverLimit         bool
}

func (m *Manager) Add(tag string, users []panel.UserInfo, aliveList map[int]int, nodeType string) *Limiter {
	// A config refresh can recreate an existing inbound tag. Remove the old
	// policy first so its subscriber/node entries cannot survive and affect the
	// replacement or another inbound.
	m.Delete(tag)
	info := &Limiter{
		manager:       m,
		NodeType:      nodeType,
		UserOnlineIP:  new(sync.Map),
		UserLimitInfo: new(sync.Map),
		SpeedLimiter:  new(sync.Map),
		AliveList:     aliveList,
		OldUserOnline: new(sync.Map),
	}
	uuidmap := make(map[string]int)
	for i := range users {
		uuidmap[users[i].Uuid] = users[i].Id
		userLimit := &UserLimitInfo{}
		userLimit.UID = users[i].Id
		userLimit.SpeedLimitBPS = users[i].SpeedLimitBPS
		userLimit.NodeSpeedLimitBPS = users[i].NodeSpeedLimitBPS
		if users[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = users[i].SpeedLimit
		}
		if users[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = users[i].DeviceLimit
		}
		userLimit.OverLimit = false
		info.UserLimitInfo.Store(format.UserTag(tag, users[i].Uuid), userLimit)
	}
	info.UUIDtoUID = uuidmap
	m.lock.Lock()
	m.limiters[tag] = info
	m.lock.Unlock()
	for i := range users {
		m.updateGlobalUserLimit(tag, users[i], false)
	}
	return info
}

func (m *Manager) Get(tag string) (info *Limiter, err error) {
	m.lock.RLock()
	info, ok := m.limiters[tag]
	m.lock.RUnlock()
	if !ok {
		return nil, errors.New("not found")
	}
	return info, nil
}

func (m *Manager) Delete(tag string) {
	m.lock.Lock()
	delete(m.limiters, tag)
	m.lock.Unlock()
	m.removeGlobalTag(tag)
}

// UpdateUser refreshes an inbound policy without removing the Xray user or
// closing its live links. Buckets are shared by subscriber ID across inbounds.
func (m *Manager) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo) {
	limiter, err := m.Get(tag)
	if err != nil {
		return
	}
	limiter.UpdateUser(tag, added, deleted)
}

// SetGlobalBandwidthAllocation applies the control-plane share for one
// subscriber. An active zero share pauses this Agent for the subscriber; only
// an inactive allocation falls back to the local static policy.
func (m *Manager) SetGlobalBandwidthAllocation(uid int, speedLimitBPS uint64, active bool) {
	if uid <= 0 {
		return
	}
	m.globalLock.Lock()
	defer m.globalLock.Unlock()
	if !active {
		if _, present := m.globalAllocated.Load(uid); !present {
			return
		}
		m.globalAllocated.Delete(uid)
	} else {
		if current, present := m.globalAllocated.Load(uid); present && current.(uint64) == speedLimitBPS {
			return
		}
		m.globalAllocated.Store(uid, speedLimitBPS)
	}
	// Dynamic writers resolve the bucket for every write. Removing the current
	// bucket makes the next write pick up the new allocation without a reconnect.
	m.globalSpeed.Delete(allocationBucketKey(uid))
}

// A complete per-subscriber snapshot makes absent inbounds zero-allocation,
// rather than allowing an old inbound to retain a share of the global budget.
func (m *Manager) SetInboundBandwidthAllocations(uid int, allocations map[string]uint64, active bool) {
	if uid <= 0 {
		return
	}
	m.globalLock.Lock()
	defer m.globalLock.Unlock()
	m.globalAllocated.Delete(uid)
	if !active {
		delete(m.inboundAllocated, uid)
		return
	}
	copy := make(map[string]uint64, len(allocations))
	for tag, rate := range allocations {
		copy[tag] = rate
	}
	m.inboundAllocated[uid] = copy
}

func (l *Limiter) UpdateUser(tag string, added []panel.UserInfo, deleted []panel.UserInfo) {
	l.stateMu.Lock()
	for i := range deleted {
		l.UserLimitInfo.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.UserOnlineIP.Delete(format.UserTag(tag, deleted[i].Uuid))
		l.SpeedLimiter.Delete(format.UserTag(tag, deleted[i].Uuid))
		delete(l.UUIDtoUID, deleted[i].Uuid)
		delete(l.AliveList, deleted[i].Id)
	}
	for i := range added {
		userLimit := &UserLimitInfo{
			UID:               added[i].Id,
			SpeedLimitBPS:     added[i].SpeedLimitBPS,
			NodeSpeedLimitBPS: added[i].NodeSpeedLimitBPS,
		}
		if added[i].SpeedLimit != 0 {
			userLimit.SpeedLimit = added[i].SpeedLimit
			userLimit.ExpireTime = 0
		}
		if added[i].DeviceLimit != 0 {
			userLimit.DeviceLimit = added[i].DeviceLimit
		}
		userLimit.OverLimit = false
		l.UserLimitInfo.Store(format.UserTag(tag, added[i].Uuid), userLimit)
		l.UUIDtoUID[added[i].Uuid] = added[i].Id
	}
	l.stateMu.Unlock()
	if l.manager == nil {
		return
	}
	for i := range deleted {
		l.manager.updateGlobalUserLimit(tag, deleted[i], true)
	}
	for i := range added {
		l.manager.updateGlobalUserLimit(tag, added[i], false)
	}
}

func (l *Limiter) CheckLimit(taguuid string, ip string, noUDPSource bool) (Bucket *ratelimit.Bucket, Reject bool) {
	// check if ipv4 mapped ipv6
	ip = strings.TrimPrefix(ip, "::ffff:")

	// Admission checks do not mutate bandwidth policy or allocate tokens.
	deviceLimit := 0
	var uid int
	if v, ok := l.UserLimitInfo.Load(taguuid); ok {
		u := v.(*UserLimitInfo)
		deviceLimit, uid = u.DeviceLimit, u.UID
	} else {
		return nil, true
	}
	l.stateMu.RLock()
	aliveIP := l.AliveList[uid]
	l.stateMu.RUnlock()
	if noUDPSource || l.NodeType == "hysteria" || l.NodeType == "hysteria2" || l.NodeType == "tuic" {
		// Store online user for device limit
		ipMap := new(sync.Map)
		ipMap.Store(ip, uid)
		aliveIp := aliveIP
		// If any device is online
		if v, ok := l.UserOnlineIP.LoadOrStore(taguuid, ipMap); ok {
			ipMap := v.(*sync.Map)
			// If this is a new ip
			if _, ok := ipMap.LoadOrStore(ip, uid); !ok {
				if deviceLimit > 0 {
					if deviceLimit <= aliveIp {
						ipMap.Delete(ip)
						return nil, true
					}
				}
			}
		} else if v, ok := l.OldUserOnline.Load(ip); ok {
			if v.(int) == uid {
				l.OldUserOnline.Delete(ip)
			}
		} else {
			if deviceLimit > 0 {
				if deviceLimit <= aliveIp {
					l.UserOnlineIP.Delete(taguuid)
					return nil, true
				}
			}
		}
	}

	return l.SpeedBucket(taguuid), false
}

func (l *Limiter) GetOnlineDevice() (*[]panel.OnlineUser, error) {
	var onlineUser []panel.OnlineUser
	l.UserOnlineIP.Range(func(key, value interface{}) bool {
		taguuid := key.(string)
		ipMap := value.(*sync.Map)
		ipMap.Range(func(key, value interface{}) bool {
			uid := value.(int)
			ip := key.(string)
			l.OldUserOnline.Store(ip, uid)
			onlineUser = append(onlineUser, panel.OnlineUser{UID: uid, IP: ip})
			return true
		})
		l.UserOnlineIP.Delete(taguuid) // Reset online device
		return true
	})

	return &onlineUser, nil
}

type UserIpList struct {
	Uid    int      `json:"Uid"`
	IpList []string `json:"Ips"`
}
