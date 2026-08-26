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
	globalUserLimits map[int]map[string]int
	globalUserRates  sync.Map // Key: subscriber ID, value: effective Mbps
	globalSpeed      sync.Map // Key: subscriber ID, value: *ratelimit.Bucket
}

func NewManager() *Manager {
	return &Manager{
		limiters:         make(map[string]*Limiter),
		globalUserLimits: make(map[int]map[string]int),
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
	DeviceLimit       int
	DynamicSpeedLimit int
	ExpireTime        int64
	OverLimit         bool
}

func (m *Manager) Add(tag string, users []panel.UserInfo, aliveList map[int]int, nodeType string) *Limiter {
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
			UID: added[i].Id,
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

	// check and gen speed limit Bucket
	nodeLimit := l.SpeedLimit
	userLimit := 0
	deviceLimit := 0
	var uid int
	if v, ok := l.UserLimitInfo.Load(taguuid); ok {
		u := v.(*UserLimitInfo)
		deviceLimit = u.DeviceLimit
		uid = u.UID
		if u.ExpireTime < time.Now().Unix() && u.ExpireTime != 0 {
			if u.SpeedLimit != 0 {
				userLimit = u.SpeedLimit
				u.DynamicSpeedLimit = 0
				u.ExpireTime = 0
			} else {
				l.UserLimitInfo.Delete(taguuid)
			}
		} else {
			userLimit = determineSpeedLimit(u.SpeedLimit, u.DynamicSpeedLimit)
		}
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

	return l.SpeedBucketWithLimits(taguuid, nodeLimit, userLimit), false
}

// SpeedBucketWithLimits returns a shared bucket for the current policy. It
// replaces a stale bucket when the effective byte rate changes, allowing
// existing dynamic writers to observe a new limit immediately.
func (l *Limiter) SpeedBucketWithLimits(taguuid string, nodeLimit, userLimit int) *ratelimit.Bucket {
	if l.manager == nil {
		return nil
	}
	value, ok := l.UserLimitInfo.Load(taguuid)
	if !ok {
		return nil
	}
	user := value.(*UserLimitInfo)
	return l.manager.globalSpeedBucket(user.UID, determineSpeedLimit(nodeLimit, userLimit))
}

// SpeedBucket resolves a user's current node and user policy without applying
// connection admission checks. It is used by writers that outlive a snapshot.
func (l *Limiter) SpeedBucket(taguuid string) *ratelimit.Bucket {
	nodeLimit := l.SpeedLimit
	userLimit := 0
	if value, ok := l.UserLimitInfo.Load(taguuid); ok {
		user := value.(*UserLimitInfo)
		if user.ExpireTime < time.Now().Unix() && user.ExpireTime != 0 {
			if user.SpeedLimit != 0 {
				userLimit = user.SpeedLimit
				user.DynamicSpeedLimit = 0
				user.ExpireTime = 0
			} else {
				l.UserLimitInfo.Delete(taguuid)
			}
		} else {
			userLimit = determineSpeedLimit(user.SpeedLimit, user.DynamicSpeedLimit)
		}
	} else {
		return nil
	}
	return l.SpeedBucketWithLimits(taguuid, nodeLimit, userLimit)
}

func (m *Manager) updateGlobalUserLimit(tag string, user panel.UserInfo, remove bool) {
	if user.Id <= 0 {
		return
	}
	key := format.UserTag(tag, user.Uuid)
	m.globalLock.Lock()
	entries := m.globalUserLimits[user.Id]
	if entries == nil {
		entries = make(map[string]int)
		m.globalUserLimits[user.Id] = entries
	}
	if remove {
		delete(entries, key)
	} else {
		entries[key] = user.SpeedLimit
	}
	m.refreshGlobalUserRateLocked(user.Id)
	m.globalLock.Unlock()
}

func (m *Manager) removeGlobalTag(tag string) {
	prefix := tag + "|"
	m.globalLock.Lock()
	for uid, entries := range m.globalUserLimits {
		for key := range entries {
			if strings.HasPrefix(key, prefix) {
				delete(entries, key)
			}
		}
		m.refreshGlobalUserRateLocked(uid)
	}
	m.globalLock.Unlock()
}

func (m *Manager) refreshGlobalUserRateLocked(uid int) {
	entries := m.globalUserLimits[uid]
	if len(entries) == 0 {
		delete(m.globalUserLimits, uid)
		m.globalUserRates.Delete(uid)
		m.globalSpeed.Delete(uid)
		return
	}
	rate := 0
	for _, candidate := range entries {
		rate = determineSpeedLimit(rate, candidate)
	}
	if rate <= 0 {
		m.globalUserRates.Delete(uid)
		m.globalSpeed.Delete(uid)
		return
	}
	m.globalUserRates.Store(uid, rate)
}

// globalSpeedBucket returns the one bandwidth budget consumed by every active
// protocol and inbound for a subscriber on this Agent. Its capacity is 100ms
// of traffic, keeping policy-change and connection-start bursts bounded.
func (m *Manager) globalSpeedBucket(uid int, fallbackRate int) *ratelimit.Bucket {
	if uid <= 0 {
		return nil
	}
	rate := fallbackRate
	if stored, ok := m.globalUserRates.Load(uid); ok {
		rate = stored.(int)
	}
	limit := int64(rate) * 1_000_000 / 8
	if limit <= 0 {
		m.globalSpeed.Delete(uid)
		return nil
	}
	burst := limit / 10
	if burst < 1 {
		burst = 1
	}
	if value, ok := m.globalSpeed.Load(uid); ok {
		if bucket, valid := value.(*ratelimit.Bucket); valid && bucket.Capacity() == burst {
			return bucket
		}
	}
	bucket := ratelimit.NewBucketWithQuantum(100*time.Millisecond, burst, burst)
	m.globalSpeed.Store(uid, bucket)
	return bucket
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
