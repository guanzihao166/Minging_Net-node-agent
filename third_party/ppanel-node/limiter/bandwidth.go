package limiter

import (
	"strconv"
	"strings"
	"time"

	"github.com/juju/ratelimit"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/common/format"
)

func minPositive(a, b uint64) uint64 {
	if a == 0 || (b > 0 && b < a) {
		return b
	}
	return a
}

func mbpsBytes(rate int) uint64 {
	if rate <= 0 {
		return 0
	}
	return uint64(rate) * 125_000
}

func userRate(user panel.UserInfo) uint64 {
	if user.SpeedLimitBPS > 0 {
		return user.SpeedLimitBPS
	}
	return mbpsBytes(user.SpeedLimit)
}

func userBucketKey(tag string, uid int) string { return "user:" + tag + "|" + strconv.Itoa(uid) }
func allocationBucketKey(uid int) string       { return "allocation:" + strconv.Itoa(uid) }
func nodeBucketKey(tag string, uid int) string { return "node:" + tag + "|" + strconv.Itoa(uid) }

func (m *Manager) updateGlobalUserLimit(tag string, user panel.UserInfo, remove bool) {
	if user.Id <= 0 {
		return
	}
	m.globalLock.Lock()
	defer m.globalLock.Unlock()
	entries := m.globalUserLimits[user.Id]
	if entries == nil {
		entries = make(map[string]uint64)
		m.globalUserLimits[user.Id] = entries
	}
	key := format.UserTag(tag, user.Uuid)
	if remove {
		delete(entries, key)
		m.globalSpeed.Delete(nodeBucketKey(tag, user.Id))
	} else {
		entries[key] = userRate(user)
	}
	m.refreshGlobalUserRateLocked(user.Id)
}

func (m *Manager) removeGlobalTag(tag string) {
	m.globalLock.Lock()
	defer m.globalLock.Unlock()
	for uid, entries := range m.globalUserLimits {
		for key := range entries {
			if strings.HasPrefix(key, tag+"|") {
				delete(entries, key)
			}
		}
		m.globalSpeed.Delete(nodeBucketKey(tag, uid))
		m.refreshGlobalUserRateLocked(uid)
	}
}

func (m *Manager) refreshGlobalUserRateLocked(uid int) {
	entries := m.globalUserLimits[uid]
	if len(entries) == 0 {
		delete(m.globalUserLimits, uid)
		m.globalUserRates.Delete(uid)
		m.globalAllocated.Delete(uid)
		delete(m.inboundAllocated, uid)
		m.globalSpeed.Delete(allocationBucketKey(uid))
		return
	}
	var rate uint64
	for _, candidate := range entries {
		rate = minPositive(rate, candidate)
	}
	// Unchanged snapshots must not refill or replace a bucket with active traffic.
	m.globalUserRates.Store(uid, rate)
}

// SpeedBuckets keeps the subscriber policy and allocation separate from the
// ceiling on this inbound. A node ceiling applies per subscriber on this node;
// it never becomes the subscriber's global policy on other nodes.
func (l *Limiter) SpeedBuckets(taguuid string) []*ratelimit.Bucket {
	if l == nil || l.manager == nil {
		return nil
	}
	value, ok := l.UserLimitInfo.Load(taguuid)
	if !ok {
		return nil
	}
	u := value.(*UserLimitInfo)
	userLimit := u.SpeedLimitBPS
	if userLimit == 0 {
		userLimit = mbpsBytes(u.SpeedLimit)
	}
	if u.DynamicSpeedLimit > 0 && (u.ExpireTime == 0 || u.ExpireTime > time.Now().Unix()) {
		userLimit = minPositive(userLimit, mbpsBytes(u.DynamicSpeedLimit))
	}
	nodeLimit := minPositive(u.NodeSpeedLimitBPS, mbpsBytes(l.SpeedLimit))
	tag, _, _ := strings.Cut(taguuid, "|")
	return l.manager.speedBuckets(u.UID, tag, userLimit, nodeLimit)
}

// SpeedBucket is an inspection/admission helper. Writers consume every
// independent bucket from SpeedBuckets, not just the smallest current rate.
func (l *Limiter) SpeedBucket(taguuid string) *ratelimit.Bucket {
	var result *ratelimit.Bucket
	for _, bucket := range l.SpeedBuckets(taguuid) {
		if result == nil || bucket.Rate() < result.Rate() {
			result = bucket
		}
	}
	return result
}

func (m *Manager) speedBuckets(uid int, tag string, userRate, nodeRate uint64) []*ratelimit.Bucket {
	if uid <= 0 {
		return nil
	}
	m.globalLock.Lock()
	defer m.globalLock.Unlock()
	if allocations, active := m.inboundAllocated[uid]; active && userRate > 0 {
		share := allocations[tag]
		if share == 0 {
			m.signalBandwidthDemand(uid)
			key := userBucketKey(tag, uid)
			if cached, ok := m.globalSpeed.Load(key); ok && cached.(*ratelimit.Bucket).Capacity() == 1 {
				return []*ratelimit.Bucket{cached.(*ratelimit.Bucket)}
			}
			paused := ratelimit.NewBucketWithQuantum(100*time.Millisecond, 1, 1)
			paused.TakeAvailable(1)
			m.globalSpeed.Store(key, paused)
			return []*ratelimit.Bucket{paused}
		}
		userRate = minPositive(userRate, share)
	}
	buckets := make([]*ratelimit.Bucket, 0, 3)
	for _, policy := range []struct {
		key  string
		rate uint64
	}{
		{userBucketKey(tag, uid), userRate}, {nodeBucketKey(tag, uid), nodeRate},
	} {
		if b := m.bucketForRateLocked(policy.key, policy.rate); b != nil {
			buckets = append(buckets, b)
		}
	}
	// Both directions and all streams on this inbound consume these same buckets.
	return buckets
}

// Creation and replacement are serialized with policy updates. Without this
// lock concurrent first writes can obtain different buckets for the same key.
func (m *Manager) bucketForRateLocked(key string, rate uint64) *ratelimit.Bucket {
	if rate == 0 {
		m.globalSpeed.Delete(key)
		return nil
	}
	burst := int64(rate / 10)
	if burst < 2 {
		burst = 2
	}
	quantum := int64(rate / 100)
	if quantum < 1 {
		quantum = 1
	}
	interval := time.Duration(float64(time.Second) * float64(quantum) / float64(rate))
	if interval < time.Nanosecond {
		interval = time.Nanosecond
	}
	if cached, ok := m.globalSpeed.Load(key); ok {
		b := cached.(*ratelimit.Bucket)
		if b.Capacity() == burst && b.Rate() == float64(quantum)*float64(time.Second)/float64(interval) {
			return b
		}
	}
	b := ratelimit.NewBucketWithQuantum(interval, burst, quantum)
	b.TakeAvailable(burst)
	m.globalSpeed.Store(key, b)
	return b
}
