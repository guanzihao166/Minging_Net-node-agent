package dispatcher

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

const (
	accessBucketDuration       = 5 * time.Minute
	accessCheckpointInterval   = 5 * time.Minute
	defaultAccessMaxSessions   = 20000
	defaultAccessDomainsPerKey = 128
	accessOverflowHost         = "other.invalid"
)

type AccessIdentityResolver func(userKey, inboundTag string) (subscriberID, inboundID int64, ok bool)

type AccessSample struct {
	SessionKey      string
	SubscriberID    int64
	InboundID       int64
	Host            string
	Network         string
	Protocol        string
	DestinationPort uint16
	StartedAt       time.Time
	LastSeenAt      time.Time
	EndedAt         *time.Time
	UploadBytes     uint64
	DownloadBytes   uint64
	ConnectionCount uint32
	Active          bool
}

type AccessRecorder struct {
	mu                   sync.Mutex
	resolverMu           sync.RWMutex
	resolver             AccessIdentityResolver
	active               map[*AccessSession]struct{}
	admittedDomains      map[string]map[string]struct{}
	now                  func() time.Time
	checkpointInterval   time.Duration
	maxSessions          int
	maxDomainsPerUserKey int
	droppedSessions      atomic.Uint64
}

type AccessSession struct {
	recorder       *AccessRecorder
	subscriberID   int64
	inboundID      int64
	startedAt      time.Time
	metadataMu     sync.RWMutex
	host           string
	network        string
	protocol       string
	port           uint16
	uploadBytes    atomic.Uint64
	downloadBytes  atomic.Uint64
	connections    atomic.Uint32
	lastCheckpoint atomic.Int64
	endedAt        atomic.Int64
	closed         atomic.Bool
	closeOnce      sync.Once
}

func NewAccessRecorder() *AccessRecorder {
	return &AccessRecorder{
		active:               make(map[*AccessSession]struct{}),
		admittedDomains:      make(map[string]map[string]struct{}),
		now:                  time.Now,
		checkpointInterval:   accessCheckpointInterval,
		maxSessions:          defaultAccessMaxSessions,
		maxDomainsPerUserKey: defaultAccessDomainsPerKey,
	}
}

func (r *AccessRecorder) SetIdentityResolver(resolver AccessIdentityResolver) {
	if r == nil {
		return
	}
	r.resolverMu.Lock()
	r.resolver = resolver
	r.resolverMu.Unlock()
}

func (r *AccessRecorder) Start(userKey, inboundTag, host, network string, port uint16) *AccessSession {
	if r == nil || port == 0 {
		return nil
	}
	host, ok := normalizeAccessHost(host)
	if !ok {
		return nil
	}
	network = normalizeAccessNetwork(network)
	if network == "" {
		return nil
	}
	r.resolverMu.RLock()
	resolver := r.resolver
	r.resolverMu.RUnlock()
	if resolver == nil {
		return nil
	}
	subscriberID, inboundID, ok := resolver(userKey, inboundTag)
	if !ok || subscriberID <= 0 || inboundID <= 0 {
		return nil
	}
	startedAt := r.now().UTC()
	session := &AccessSession{
		recorder: r, subscriberID: subscriberID, inboundID: inboundID,
		startedAt: startedAt, host: host, network: network, protocol: "unknown", port: port,
	}
	session.connections.Store(1)
	session.lastCheckpoint.Store(startedAt.UnixNano())
	r.mu.Lock()
	if len(r.active) >= r.maxSessions {
		r.mu.Unlock()
		r.droppedSessions.Add(1)
		return nil
	}
	r.active[session] = struct{}{}
	r.mu.Unlock()
	return session
}

func (s *AccessSession) UpdateTarget(host, protocol string) {
	if s == nil || s.closed.Load() {
		return
	}
	normalizedHost, ok := normalizeAccessHost(host)
	s.metadataMu.Lock()
	if ok {
		s.host = normalizedHost
	}
	if normalizedProtocol := normalizeAccessProtocol(protocol); normalizedProtocol != "unknown" || s.protocol == "" {
		s.protocol = normalizedProtocol
	}
	s.metadataMu.Unlock()
}

func (s *AccessSession) AddUpload(bytes uint64) {
	if s != nil && bytes > 0 {
		s.uploadBytes.Add(bytes)
	}
}

func (s *AccessSession) AddDownload(bytes uint64) {
	if s != nil && bytes > 0 {
		s.downloadBytes.Add(bytes)
	}
}

func (s *AccessSession) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		endedAt := s.recorder.now().UTC()
		if endedAt.Before(s.startedAt) {
			endedAt = s.startedAt
		}
		s.endedAt.Store(endedAt.UnixNano())
		s.closed.Store(true)
	})
}

func (r *AccessRecorder) Drain() []AccessSample {
	if r == nil {
		return nil
	}
	now := r.now().UTC()
	r.mu.Lock()
	r.cleanupDomainBucketsLocked(now)
	grouped := make(map[string]*AccessSample)
	for session := range r.active {
		closed := session.closed.Load()
		lastCheckpoint := time.Unix(0, session.lastCheckpoint.Load()).UTC()
		if !closed && now.Sub(lastCheckpoint) < r.checkpointInterval {
			continue
		}
		if closed {
			delete(r.active, session)
		} else {
			session.lastCheckpoint.Store(now.UnixNano())
		}
		sample := session.snapshot(now, !closed)
		sample.Host = r.boundHostLocked(sample)
		sample.SessionKey = accessSessionKey(sample)
		mergeAccessSample(grouped, sample)
	}
	r.mu.Unlock()
	out := make([]AccessSample, 0, len(grouped))
	for _, sample := range grouped {
		out = append(out, *sample)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionKey < out[j].SessionKey })
	return out
}

func (r *AccessRecorder) Close() []AccessSample {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	active := make([]*AccessSession, 0, len(r.active))
	for session := range r.active {
		active = append(active, session)
	}
	r.mu.Unlock()
	for _, session := range active {
		session.Close()
	}
	return r.Drain()
}

func (r *AccessRecorder) DroppedSessions() uint64 {
	if r == nil {
		return 0
	}
	return r.droppedSessions.Load()
}

func (s *AccessSession) snapshot(now time.Time, active bool) AccessSample {
	s.metadataMu.RLock()
	sample := AccessSample{
		SubscriberID: s.subscriberID, InboundID: s.inboundID, Host: s.host,
		Network: s.network, Protocol: normalizeAccessProtocol(s.protocol), DestinationPort: s.port,
		StartedAt: s.startedAt, LastSeenAt: now, UploadBytes: s.uploadBytes.Swap(0),
		DownloadBytes: s.downloadBytes.Swap(0), ConnectionCount: s.connections.Swap(0), Active: active,
	}
	s.metadataMu.RUnlock()
	if endedNanos := s.endedAt.Load(); endedNanos > 0 {
		endedAt := time.Unix(0, endedNanos).UTC()
		sample.EndedAt = &endedAt
		sample.LastSeenAt = endedAt
	}
	if sample.LastSeenAt.Before(sample.StartedAt) {
		sample.LastSeenAt = sample.StartedAt
	}
	return sample
}

func (r *AccessRecorder) boundHostLocked(sample AccessSample) string {
	bucket := sample.StartedAt.UTC().Truncate(accessBucketDuration)
	key := strconv.FormatInt(sample.SubscriberID, 10) + "/" + strconv.FormatInt(sample.InboundID, 10) + "/" + strconv.FormatInt(bucket.Unix(), 10)
	domains := r.admittedDomains[key]
	if domains == nil {
		domains = make(map[string]struct{})
		r.admittedDomains[key] = domains
	}
	if _, exists := domains[sample.Host]; exists {
		return sample.Host
	}
	if len(domains) >= r.maxDomainsPerUserKey {
		return accessOverflowHost
	}
	domains[sample.Host] = struct{}{}
	return sample.Host
}

func (r *AccessRecorder) cleanupDomainBucketsLocked(now time.Time) {
	cutoff := now.Add(-3 * accessBucketDuration).Truncate(accessBucketDuration).Unix()
	for key := range r.admittedDomains {
		separator := strings.LastIndexByte(key, '/')
		if separator < 0 {
			delete(r.admittedDomains, key)
			continue
		}
		bucket, err := strconv.ParseInt(key[separator+1:], 10, 64)
		if err != nil || bucket < cutoff {
			delete(r.admittedDomains, key)
		}
	}
}

func mergeAccessSample(grouped map[string]*AccessSample, incoming AccessSample) {
	existing := grouped[incoming.SessionKey]
	if existing == nil {
		copyValue := incoming
		grouped[incoming.SessionKey] = &copyValue
		return
	}
	if incoming.StartedAt.Before(existing.StartedAt) {
		existing.StartedAt = incoming.StartedAt
	}
	if incoming.LastSeenAt.After(existing.LastSeenAt) {
		existing.LastSeenAt = incoming.LastSeenAt
	}
	existing.UploadBytes = saturatingAccessUint64(existing.UploadBytes, incoming.UploadBytes)
	existing.DownloadBytes = saturatingAccessUint64(existing.DownloadBytes, incoming.DownloadBytes)
	existing.ConnectionCount = saturatingAccessUint32(existing.ConnectionCount, incoming.ConnectionCount)
	existing.Active = existing.Active || incoming.Active
	if existing.Active {
		existing.EndedAt = nil
	} else if incoming.EndedAt != nil && (existing.EndedAt == nil || incoming.EndedAt.After(*existing.EndedAt)) {
		endedAt := *incoming.EndedAt
		existing.EndedAt = &endedAt
	}
}

func accessSessionKey(sample AccessSample) string {
	bucket := sample.StartedAt.UTC().Truncate(accessBucketDuration)
	value := strings.Join([]string{
		strconv.FormatInt(sample.SubscriberID, 10), strconv.FormatInt(sample.InboundID, 10),
		sample.Host, sample.Network, sample.Protocol, strconv.Itoa(int(sample.DestinationPort)),
		strconv.FormatInt(bucket.Unix(), 10),
	}, "\x00")
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func normalizeAccessHost(value string) (string, bool) {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > 253 {
		return "", false
	}
	if address, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return address.Unmap().String(), true
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", false
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if ascii == "" || len(ascii) > 253 {
		return "", false
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return "", false
			}
		}
	}
	return ascii, true
}

func normalizeAccessNetwork(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	default:
		return ""
	}
}

func normalizeAccessProtocol(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 32 {
		return "unknown"
	}
	for index, char := range value {
		valid := char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '+' || char == '.' || char == '_' || char == '-'
		if !valid || index == 0 && !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9') {
			return "unknown"
		}
	}
	return value
}

func accessNetworkName(network uint32) string {
	if network == 2 {
		return "udp"
	}
	return "tcp"
}

func saturatingAccessUint64(left, right uint64) uint64 {
	if ^uint64(0)-left < right {
		return ^uint64(0)
	}
	return left + right
}

func saturatingAccessUint32(left, right uint32) uint32 {
	if ^uint32(0)-left < right {
		return ^uint32(0)
	}
	return left + right
}

type accessWriter struct {
	writer buf.Writer
	add    func(uint64)
}

func (w *accessWriter) WriteMultiBuffer(buffers buf.MultiBuffer) error {
	size := buffers.Len()
	if err := w.writer.WriteMultiBuffer(buffers); err != nil {
		return err
	}
	if size > 0 && w.add != nil {
		w.add(uint64(size))
	}
	return nil
}

func (w *accessWriter) Close() error { return common.Close(w.writer) }
