package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	inboundbuilder "github.com/perfect-panel/ppanel-node/core/inbound"

	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
	"github.com/guanzihao166/iepl-node-agent/internal/secretstore"
)

func TestBuildsAllRequiredXrayProtocolFamilies(t *testing.T) {
	secrets := testRuntimeSecrets(t)
	runtime, err := NewXray(secrets)
	if err != nil {
		t.Fatal(err)
	}
	desired := testDesiredConfig()
	if err := agentprotocol.ValidateDesiredConfig(desired); err != nil {
		t.Fatalf("fixture is invalid: %v", err)
	}
	nodes, err := runtime.buildNodes(desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 5 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	for _, node := range nodes {
		if _, err := inboundbuilder.Build(node.info, node.tag); err != nil {
			t.Fatalf("build %s: %v", node.tag, err)
		}
	}
	serverKey := nodes[2].info.Protocol.ServerKey
	if _, err := inboundbuilder.Build(nodes[2].info, nodes[2].tag); err != nil {
		t.Fatalf("build SS2022 twice: %v", err)
	}
	if nodes[2].info.Protocol.ServerKey != serverKey {
		t.Fatal("SS2022 builder mutated the raw server key")
	}
	if nodes[0].info.Protocol.Security != "reality" || nodes[0].info.Protocol.RealityPrivateKey == "" {
		t.Fatalf("VLESS REALITY mapping = %#v", nodes[0].info.Protocol)
	}
	if nodes[1].info.Protocol.Security != "tls" || nodes[1].info.Protocol.CertificateFile == "" || nodes[1].info.Protocol.TLSMinVersion != "1.2" {
		t.Fatalf("Trojan TLS mapping = %#v", nodes[1].info.Protocol)
	}
	if nodes[2].info.Protocol.Cipher != "2022-blake3-aes-256-gcm" || nodes[2].info.Protocol.ServerKey == "" {
		t.Fatalf("SS2022 mapping = %#v", nodes[2].info.Protocol)
	}
	if nodes[3].info.Type != "tuic" || nodes[3].info.Protocol.CongestionController != "bbr" {
		t.Fatalf("TUIC mapping = %#v", nodes[3].info.Protocol)
	}
	if nodes[4].info.Type != "hysteria2" || nodes[4].info.Protocol.HopPorts != "30000-30002" || nodes[4].info.Protocol.ObfsPassword == "" {
		t.Fatalf("Hysteria2 mapping = %#v", nodes[4].info.Protocol)
	}
}

func TestStartsAllRequiredXrayProtocolsAndAppliesUsers(t *testing.T) {
	base := availableProtocolPortBlock(t)
	desired := testDesiredConfig()
	desired.Inbounds[0].Port = base
	desired.Inbounds[1].Port = base + 1
	desired.Inbounds[2].Port = base + 2
	desired.Inbounds[3].Port = base + 3
	desired.Inbounds[4].Port = base + 4
	desired.Inbounds[4].Hysteria2.HopPorts = fmt.Sprintf("%d-%d", base+5, base+7)
	runtime, err := NewXray(testRuntimeSecrets(t))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := runtime.ApplyConfig(context.Background(), desired); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	users := []agentprotocol.UserCredential{
		{SubscriberID: 101, InboundID: 31, Kind: "uuid", Value: "3e285077-7932-4e8d-b232-9b6d58dd6671"},
		{SubscriberID: 102, InboundID: 41, Kind: "password", Value: "trojan-test-password"},
		{SubscriberID: 103, InboundID: 51, Kind: "key", Value: "12345678901234567890123456789012"},
		{SubscriberID: 104, InboundID: 61, Kind: "tuic", Value: "8712f32c-6655-464c-ba44-77939c2a828a"},
		{SubscriberID: 105, InboundID: 71, Kind: "password", Value: "hysteria-test-password"},
	}
	if err := runtime.ApplyUsers(context.Background(), users); err != nil {
		t.Fatalf("ApplyUsers: %v", err)
	}
	desired.Version++
	desired.Inbounds[1].Transport.Path = "/trojan-v2"
	if err := runtime.ApplyConfig(context.Background(), desired); err != nil {
		t.Fatalf("hot ApplyConfig: %v", err)
	}
	for _, inbound := range desired.Inbounds {
		limiter, err := runtime.active.LimiterManager.Get(inboundTag(inbound.ID))
		if err != nil {
			t.Fatalf("hot config limiter %d: %v", inbound.ID, err)
		}
		if len(limiter.UUIDtoUID) != 1 {
			t.Fatalf("hot config limiter %d lost users: %#v", inbound.ID, limiter.UUIDtoUID)
		}
	}
	desired.Version++
	desired.Inbounds = desired.Inbounds[1:]
	if err := runtime.ApplyConfig(context.Background(), desired); err != nil {
		t.Fatalf("ApplyConfig removing an inbound with stale users: %v", err)
	}
	if len(runtime.users) != len(users)-1 {
		t.Fatalf("users after inbound removal = %#v", runtime.users)
	}
	for _, user := range runtime.users {
		if user.InboundID == 31 {
			t.Fatalf("removed inbound user was retained: %#v", user)
		}
	}
	if status := runtime.Status(context.Background()); !status.Running || status.Version == "" {
		t.Fatalf("status = %#v", status)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func testDesiredConfig() agentprotocol.DesiredConfig {
	return agentprotocol.DesiredConfig{
		SchemaVersion: agentprotocol.SchemaVersion, Version: 1,
		GeneratedAt: time.Now().UTC(), AgentNodeID: 17,
		Security: []agentprotocol.SecurityProfile{
			{ID: 1, Name: "tls", Type: agentprotocol.SecurityTLS, TLS: &agentprotocol.TLSProfile{
				ServerNames:    []string{"node.example.com"},
				CertificateRef: "agent-secret:tls-cert:21:1", PrivateKeyRef: "agent-secret:tls-key:21:1",
				MinVersion: "1.2", MaxVersion: "1.3", ALPN: []string{"h2", "http/1.1"},
			}},
			{ID: 3, Name: "quic-tls", Type: agentprotocol.SecurityTLS, TLS: &agentprotocol.TLSProfile{
				ServerNames:    []string{"node.example.com"},
				CertificateRef: "agent-secret:tls-cert:21:1", PrivateKeyRef: "agent-secret:tls-key:21:1",
				MinVersion: "1.3", MaxVersion: "1.3", ALPN: []string{"h3"},
			}},
			{ID: 2, Name: "reality", Type: agentprotocol.SecurityReality, Reality: &agentprotocol.RealityProfile{
				ServerNames: []string{"www.cloudflare.com"}, Destination: "www.cloudflare.com:443",
				PrivateKeyRef: "agent-secret:reality-key:31:1",
				PublicKey:     "test-public-key", ShortIDs: []string{"0123456789abcdef"}, Fingerprint: "chrome",
			}},
		},
		Inbounds: []agentprotocol.Inbound{
			{ID: 31, Name: "vless-reality", Protocol: agentprotocol.ProtocolVLESS, Listen: "0.0.0.0", Port: 21001, Network: "tcp", Enabled: true,
				Transport: agentprotocol.Transport{Type: agentprotocol.TransportTCP}, SecurityProfileID: 2, TrafficMultiplierMilli: 1000,
				VLESS: &agentprotocol.VLESSConfig{Decryption: "none", Flow: "xtls-rprx-vision"}},
			{ID: 41, Name: "trojan-wss", Protocol: agentprotocol.ProtocolTrojan, Listen: "0.0.0.0", Port: 21002, Network: "tcp", Enabled: true,
				Transport: agentprotocol.Transport{Type: agentprotocol.TransportWebSocket, Path: "/trojan"}, SecurityProfileID: 1, TrafficMultiplierMilli: 1000,
				Trojan: &agentprotocol.TrojanConfig{}},
			{ID: 51, Name: "ss2022", Protocol: agentprotocol.ProtocolSS2022, Listen: "0.0.0.0", Port: 21003, Network: "tcp", Enabled: true,
				Transport: agentprotocol.Transport{Type: agentprotocol.TransportTCP}, TrafficMultiplierMilli: 1000,
				SS2022: &agentprotocol.SS2022Config{Method: "2022-blake3-aes-256-gcm", ServerKeyRef: "agent-secret:ss2022-server:51:1", Network: "tcp,udp"}},
			{ID: 61, Name: "tuic", Protocol: agentprotocol.ProtocolTUIC, Listen: "0.0.0.0", Port: 21004, Network: "udp", Enabled: true,
				Transport: agentprotocol.Transport{Type: agentprotocol.TransportQUIC}, SecurityProfileID: 3, TrafficMultiplierMilli: 1000,
				TUIC: &agentprotocol.TUICConfig{Version: 5, CongestionControl: "bbr", HeartbeatSeconds: 10, UDPRelayMode: "native"}},
			{ID: 71, Name: "hysteria2", Protocol: agentprotocol.ProtocolHysteria2, Listen: "0.0.0.0", Port: 21005, Network: "udp", Enabled: true,
				Transport: agentprotocol.Transport{Type: agentprotocol.TransportQUIC}, SecurityProfileID: 3, TrafficMultiplierMilli: 1000,
				Hysteria2: &agentprotocol.Hysteria2Config{UpMbps: 100, DownMbps: 100, Obfs: "salamander", ObfsPasswordRef: "agent-secret:hy2-obfs:71:1", HopPorts: "30000-30002", HopIntervalSeconds: 30}},
		},
	}
}

func availableProtocolPortBlock(t *testing.T) int {
	t.Helper()
	for base := 32000; base < 59000; base += 10 {
		listeners := make([]net.Listener, 0, 3)
		packets := make([]net.PacketConn, 0, 7)
		ok := true
		for _, port := range []int{base, base + 1, base + 2} {
			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				ok = false
				break
			}
			listeners = append(listeners, listener)
		}
		if ok {
			for _, port := range []int{base + 2, base + 3, base + 4, base + 5, base + 6, base + 7} {
				packet, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
				if err != nil {
					ok = false
					break
				}
				packets = append(packets, packet)
			}
		}
		for _, listener := range listeners {
			_ = listener.Close()
		}
		for _, packet := range packets {
			_ = packet.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("no free TCP/UDP port block")
	return 0
}

func testRuntimeSecrets(t *testing.T) *secretstore.Store {
	t.Helper()
	root := t.TempDir()
	store, err := secretstore.Open(filepath.Join(root, "config"), filepath.Join(root, "run"))
	if err != nil {
		t.Fatal(err)
	}
	certificate, privateKey := testTLSMaterial(t)
	privateReality := make([]byte, 32)
	if _, err := rand.Read(privateReality); err != nil {
		t.Fatal(err)
	}
	materials := map[string][]byte{
		"agent-secret:tls-cert:21:1":      certificate,
		"agent-secret:tls-key:21:1":       privateKey,
		"agent-secret:reality-key:31:1":   []byte(base64.RawURLEncoding.EncodeToString(privateReality)),
		"agent-secret:ss2022-server:51:1": []byte("0123456789abcdef0123456789abcdef"),
		"agent-secret:hy2-obfs:71:1":      []byte("test-salamander-password"),
	}
	for ref, material := range materials {
		if err := store.Put(ref, material); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func testTLSMaterial(t *testing.T) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node.example.com"},
		DNSNames: []string{"node.example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}
