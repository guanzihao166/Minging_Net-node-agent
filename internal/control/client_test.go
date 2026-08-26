package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/guanzihao166/iepl-node-agent/internal/config"
	"github.com/guanzihao166/iepl-node-agent/internal/hostmetrics"
	"github.com/guanzihao166/iepl-node-agent/internal/hostnetwork"
	"github.com/guanzihao166/iepl-node-agent/internal/identity"
	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
	agentruntime "github.com/guanzihao166/iepl-node-agent/internal/runtime"
	"github.com/guanzihao166/iepl-node-agent/internal/secretstore"
	"github.com/guanzihao166/iepl-node-agent/internal/state"
)

func TestControlSessionAppliesSignedStateAndAcknowledgesTraffic(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := state.Open(ctx, filepath.Join(root, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	secrets, err := secretstore.Open(filepath.Join(root, "config"), filepath.Join(root, "run"))
	if err != nil {
		t.Fatal(err)
	}
	envelopeKey := make([]byte, 32)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := agentprotocol.SignConfig(agentprotocol.DesiredConfig{
		SchemaVersion: agentprotocol.SchemaVersion, Version: 1,
		GeneratedAt: time.Now().UTC(), AgentNodeID: 17,
	}, "test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		var helloEnvelope agentprotocol.Envelope
		if err := connection.ReadJSON(&helloEnvelope); err != nil {
			t.Error(err)
			return
		}
		if helloEnvelope.Type != agentprotocol.TypeHello {
			t.Errorf("first message type = %q", helloEnvelope.Type)
			return
		}
		writeProtocolEnvelope(t, connection, agentprotocol.TypeHelloAck, agentprotocol.HelloAck{
			ProtocolVersion: agentprotocol.ProtocolVersion, SessionID: "session-1",
			ServerTime: time.Now().UTC(), HeartbeatIntervalSec: 1,
		})
		secretEnvelope, err := agentprotocol.SealSecretEnvelope(envelopeKey, 17, 1, nil)
		if err != nil {
			t.Error(err)
			return
		}
		writeProtocolEnvelope(t, connection, agentprotocol.TypeSecretBundle, secretEnvelope)
		writeProtocolEnvelope(t, connection, agentprotocol.TypeDesiredConfig, desired)
		configApplied := false
		usersApplied := false
		for {
			var envelope agentprotocol.Envelope
			if err := connection.ReadJSON(&envelope); err != nil {
				t.Error(err)
				return
			}
			switch envelope.Type {
			case agentprotocol.TypeConfigResult:
				configApplied = true
				writeProtocolEnvelope(t, connection, agentprotocol.TypeUserSnapshot, agentprotocol.UserSnapshot{
					Revision: 1,
					Users: []agentprotocol.UserCredential{{
						SubscriberID: 901, InboundID: 81, Kind: "uuid",
						Value: "d342d11e-d424-4583-b36e-524ab1f0afa4", QuotaGeneration: 1,
					}},
				})
			case agentprotocol.TypeUserResult:
				usersApplied = true
				writeProtocolEnvelope(t, connection, agentprotocol.TypeBandwidthAllocation, agentprotocol.BandwidthAllocation{
					Allocations: []agentprotocol.SubscriberBandwidthAllocation{{
						SubscriberID: 901, SpeedLimitBPS: 1_250_000, AllocationActive: true,
					}},
				})
			case agentprotocol.TypeHeartbeat:
				var heartbeat agentprotocol.Heartbeat
				if err := agentprotocol.DecodePayload(envelope, &heartbeat); err != nil {
					t.Error(err)
					return
				}
				if heartbeat.SystemMetrics == nil || heartbeat.SystemMetrics.CPUPercent != 42.5 || heartbeat.SystemMetrics.NetworkReceiveBPS != 2048 {
					t.Errorf("heartbeat system metrics = %#v", heartbeat.SystemMetrics)
					return
				}
				if heartbeat.ReportedIPv4 != "198.51.100.17" || heartbeat.ReportedIPv6 != "2001:db8::17" {
					t.Errorf("heartbeat addresses = %q, %q", heartbeat.ReportedIPv4, heartbeat.ReportedIPv6)
					return
				}
				writeProtocolEnvelope(t, connection, agentprotocol.TypeHeartbeatAck, map[string]any{"ok": true})
			case agentprotocol.TypeTrafficBatch:
				var batch agentprotocol.TrafficBatch
				if err := agentprotocol.DecodePayload(envelope, &batch); err != nil {
					t.Error(err)
					return
				}
				if !configApplied || !usersApplied {
					t.Error("traffic arrived before desired state was applied")
				}
				if duration := batch.IntervalEndedAt.Sub(batch.IntervalStartedAt); duration < 10*time.Millisecond || duration > time.Second {
					t.Errorf("traffic window = %s, want the real collection interval", duration)
					return
				}
				writeProtocolEnvelope(t, connection, agentprotocol.TypeTrafficAck, agentprotocol.TrafficAck{
					BootID: batch.BootID, Sequence: batch.Sequence,
					PayloadSHA256: batch.PayloadSHA256, Status: "accepted",
				})
				close(done)
				time.Sleep(100 * time.Millisecond)
				return
			}
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	runtime := &fakeRuntime{}
	cfg := config.Config{
		Version: "test", HeartbeatInterval: 20 * time.Millisecond, TrafficInterval: 30 * time.Millisecond,
		ReconnectMin: time.Millisecond, ReconnectMax: time.Second, MaxFrameBytes: 1024 * 1024,
	}
	id := &identity.Identity{
		AgentNodeID: 17, MachineID: "82c49a6b-5bd3-4d75-97ca-058d777b3599",
		WSSURL: "wss" + strings.TrimPrefix(server.URL, "https"), ConfigSigningKeyID: "test-key",
		ConfigSigningPublicKey: base64.RawStdEncoding.EncodeToString(publicKey),
		SecretEnvelopeKey:      base64.RawStdEncoding.EncodeToString(envelopeKey),
	}
	client, err := New(cfg, id, tlsCertificateForTest(), publicKey, store, secrets, runtime, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = roots
	client.bootID = "21fba3f0-54e3-4284-9dc6-fca218c451bd"
	client.hostMetrics = staticHostMetricsSampler{snapshot: hostmetrics.Snapshot{
		SampledAt: time.Now().UTC(), CPUPercent: 42.5, MemoryPercent: 37.5,
		MemoryUsedBytes: 3, MemoryTotalBytes: 8, NetworkReceiveBPS: 2048,
		NetworkTransmitBPS: 1024, UptimeSeconds: 600,
	}}
	client.publicAddresses = func() hostnetwork.Addresses {
		return hostnetwork.Addresses{IPv4: "198.51.100.17", IPv6: "2001:db8::17"}
	}
	established := make(chan struct{}, 1)
	_ = client.runSessionWithEstablished(ctx, func() { established <- struct{}{} })
	select {
	case <-done:
	default:
		t.Fatal("server never accepted traffic")
	}
	select {
	case <-established:
	default:
		t.Fatal("acknowledged heartbeat did not establish the reconnect session")
	}
	runtimeState, err := store.RuntimeState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeState.AppliedConfigVersion != 1 || runtimeState.AppliedUserRevision != 1 {
		t.Fatalf("runtime state = %#v", runtimeState)
	}
	pending, _, err := store.PendingTrafficStats(ctx)
	if err != nil || pending != 0 {
		t.Fatalf("pending WAL = %d, %v", pending, err)
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.configApplies != 1 || runtime.disconnects != 1 || runtime.userApplies != 1 || runtime.allocations != 1 {
		t.Fatalf("runtime applies = config %d disconnects %d users %d allocations %d", runtime.configApplies, runtime.disconnects, runtime.userApplies, runtime.allocations)
	}
}

func TestControlSessionLoadsStateBeforeDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	store, err := state.Open(ctx, filepath.Join(root, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	secrets, err := secretstore.Open(filepath.Join(root, "config"), filepath.Join(root, "run"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dialed := make(chan struct{}, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		dialed <- struct{}{}
		connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			return
		}
		defer connection.Close()
		var hello agentprotocol.Envelope
		if readErr := connection.ReadJSON(&hello); readErr != nil {
			return
		}
		writeProtocolEnvelope(t, connection, agentprotocol.TypeHelloAck, agentprotocol.HelloAck{
			ProtocolVersion: agentprotocol.ProtocolVersion, SessionID: "slow-store-session", ServerTime: time.Now().UTC(),
		})
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	id := &identity.Identity{
		AgentNodeID: 17, MachineID: "82c49a6b-5bd3-4d75-97ca-058d777b3599",
		WSSURL:             "wss" + strings.TrimPrefix(server.URL, "https"),
		ConfigSigningKeyID: "test-key", ConfigSigningPublicKey: base64.RawStdEncoding.EncodeToString(publicKey),
		SecretEnvelopeKey: base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
	}
	client, err := New(config.Config{
		Version: "test", HeartbeatInterval: time.Second, TrafficInterval: time.Second,
		ReconnectMin: time.Millisecond, ReconnectMax: time.Second, MaxFrameBytes: 1024 * 1024,
	}, id, tlsCertificateForTest(), publicKey, store, secrets, &fakeRuntime{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.rootCAs = roots
	stateLoadStarted := make(chan struct{})
	releaseStateLoad := make(chan struct{})
	client.loadRuntimeState = func(loadCtx context.Context) (state.RuntimeState, error) {
		close(stateLoadStarted)
		select {
		case <-releaseStateLoad:
			return store.RuntimeState(loadCtx)
		case <-loadCtx.Done():
			return state.RuntimeState{}, loadCtx.Err()
		}
	}
	done := make(chan error, 1)
	go func() { done <- client.runSession(ctx) }()
	<-stateLoadStarted
	select {
	case <-dialed:
		t.Fatal("control WSS dialed before local runtime state was ready")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseStateLoad)
	select {
	case <-dialed:
	case <-time.After(time.Second):
		t.Fatal("control WSS was not dialed after local runtime state loaded")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control session did not stop")
	}
}

func TestReconnectScheduleResetsAfterEstablishedSession(t *testing.T) {
	minimum := time.Second
	maximum := time.Minute

	wait, next := reconnectSchedule(maximum, minimum, maximum, true)
	if wait != minimum || next != 2*minimum {
		t.Fatalf("established reconnect schedule = %s, %s; want %s, %s", wait, next, minimum, 2*minimum)
	}

	wait, next = reconnectSchedule(next, minimum, maximum, false)
	if wait != 2*minimum || next != 4*minimum {
		t.Fatalf("pre-handshake failure schedule = %s, %s; want %s, %s", wait, next, 2*minimum, 4*minimum)
	}

	wait, next = reconnectSchedule(maximum, minimum, maximum, false)
	if wait != maximum || next != maximum {
		t.Fatalf("capped reconnect schedule = %s, %s; want %s, %s", wait, next, maximum, maximum)
	}
}

func writeProtocolEnvelope(t *testing.T, connection *websocket.Conn, messageType string, payload any) {
	t.Helper()
	envelope, err := agentprotocol.NewEnvelope("server-message", messageType, payload, time.Now().UTC())
	if err != nil {
		t.Error(err)
		return
	}
	if err := connection.WriteJSON(envelope); err != nil {
		t.Error(err)
	}
}

func tlsCertificateForTest() (certificate tls.Certificate) { return certificate }

type fakeRuntime struct {
	mu            sync.Mutex
	configApplies int
	disconnects   int
	userApplies   int
	allocations   int
	trafficSent   bool
}

func (f *fakeRuntime) ApplyConfig(context.Context, agentprotocol.DesiredConfig) error {
	f.mu.Lock()
	f.configApplies++
	f.mu.Unlock()
	return nil
}

func (f *fakeRuntime) ApplyUsers(context.Context, []agentprotocol.UserCredential) error {
	f.mu.Lock()
	f.userApplies++
	f.mu.Unlock()
	return nil
}

func (f *fakeRuntime) ApplyUserDelta(_ context.Context, delta agentprotocol.UserDelta) ([]agentprotocol.UserCredential, error) {
	f.mu.Lock()
	f.userApplies++
	f.mu.Unlock()
	return append([]agentprotocol.UserCredential(nil), delta.Upserts...), nil
}

func (f *fakeRuntime) ApplyBandwidthAllocation(context.Context, agentprotocol.BandwidthAllocation) error {
	f.mu.Lock()
	f.allocations++
	f.mu.Unlock()
	return nil
}

func (f *fakeRuntime) DisconnectUsers(context.Context, []agentprotocol.UserCredential) error {
	f.mu.Lock()
	f.disconnects++
	f.mu.Unlock()
	return nil
}

func (f *fakeRuntime) DisconnectSubscribers(context.Context, []int64) error {
	f.mu.Lock()
	f.disconnects++
	f.mu.Unlock()
	return nil
}

func (f *fakeRuntime) CollectTraffic(context.Context) ([]state.TrafficDelta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.trafficSent || f.userApplies == 0 {
		return nil, nil
	}
	f.trafficSent = true
	return []state.TrafficDelta{{SubscriberID: 901, InboundID: 81, UploadBytes: 100}}, nil
}

func (f *fakeRuntime) CollectAccess(context.Context) ([]agentprotocol.AccessItem, error) {
	return nil, nil
}

func (f *fakeRuntime) RequeueAccess([]agentprotocol.AccessItem) {}

func (f *fakeRuntime) Status(context.Context) agentruntime.Status {
	return agentruntime.Status{Running: true, Version: "test"}
}

func (f *fakeRuntime) CollectOnline(context.Context) ([]agentprotocol.OnlineUser, error) {
	return nil, nil
}

func (f *fakeRuntime) Close() error { return nil }

type staticHostMetricsSampler struct {
	snapshot hostmetrics.Snapshot
	err      error
}

func (s staticHostMetricsSampler) Sample() (hostmetrics.Snapshot, error) {
	return s.snapshot, s.err
}
