package runtime

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

func guardedRealityConfig(t *testing.T, destinationHost string, destinationPort int) agentprotocol.DesiredConfig {
	t.Helper()
	desired := testDesiredConfig()
	base := availableProtocolPortBlock(t)
	reality := &desired.Inbounds[0]
	reality.Port = base
	reality.Transport = agentprotocol.Transport{Type: agentprotocol.TransportTCP}
	profile, ok := securityProfile(desired.Security, reality.SecurityProfileID)
	if !ok || profile.Reality == nil {
		t.Fatal("fixture reality profile missing")
	}
	// Point the fallback dest at a closed loopback port so tests never dial
	// the real internet; the guard's verdict does not depend on it.
	profile.Reality.Destination = net.JoinHostPort(destinationHost, strconv.Itoa(destinationPort))
	desired.Inbounds = desired.Inbounds[:1]
	return desired
}

// realityDestination returns a public-looking destination that never answers:
// TEST-NET-1 (192.0.2.0/24) is reserved for documentation and routable-looking
// enough for the config validator, while connections to it fail fast enough
// for tests and never touch the real internet.
func realityDestination(t *testing.T) (string, int) {
	t.Helper()
	return "192.0.2.1", 443
}

func dialGuardWithSNI(t *testing.T, addr, serverName string) error {
	t.Helper()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRealityInboundIsFrontedBySNIGuard(t *testing.T) {
	destHost, destPort := realityDestination(t)
	desired := guardedRealityConfig(t, destHost, destPort)
	runtime, err := NewXray(testRuntimeSecrets(t))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := runtime.ApplyConfig(context.Background(), desired); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}

	status := runtime.Status(context.Background())
	if status.GuardedInbounds != 1 {
		t.Fatalf("GuardedInbounds = %d, want 1", status.GuardedInbounds)
	}

	guardAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(desired.Inbounds[0].Port))

	// Non-declared SNI is dropped by the guard: the TLS handshake fails and
	// the connection closes before REALITY ever sees it. This is the exact
	// traffic-theft path (fake SNI relayed to a SNI-routing dest).
	if err := dialGuardWithSNI(t, guardAddr, "thief.example.net"); err == nil {
		t.Fatal("non-declared SNI must be dropped by the guard")
	}
	waitFor(t, "rejection counter", func() bool {
		return runtime.Status(context.Background()).GuardRejected == 1
	})

	// The declared SNI passes the guard and reaches Xray; what happens next
	// (REALITY auth failure, fallback dial to the dest) is environment
	// dependent, so the verdict is proven by the guard counters alone: the
	// accepted connection must never be counted as rejected.
	_ = dialGuardWithSNI(t, guardAddr, "www.cloudflare.com")
	status = runtime.Status(context.Background())
	if status.GuardRejected != 1 {
		t.Fatalf("GuardRejected = %d, want exactly 1 (declared SNI must pass the guard)", status.GuardRejected)
	}

	// A hot re-apply keeps the guard listener (same spec) and the same
	// loopback backend, so live clients are not shuffled between ports.
	if err := runtime.ApplyConfig(context.Background(), desired); err != nil {
		t.Fatalf("hot ApplyConfig: %v", err)
	}
	if status := runtime.Status(context.Background()); status.GuardedInbounds != 1 || status.CoreGeneration != 2 {
		t.Fatalf("hot apply: guards=%d generation=%d, want 1 and 2", status.GuardedInbounds, status.CoreGeneration)
	}

	// Disabling the inbound must retire the guard listener.
	desired.Inbounds[0].Enabled = false
	if err := runtime.ApplyConfig(context.Background(), desired); err != nil {
		t.Fatalf("ApplyConfig disabling inbound: %v", err)
	}
	if status := runtime.Status(context.Background()); status.GuardedInbounds != 0 {
		t.Fatalf("GuardedInbounds after disable = %d, want 0", status.GuardedInbounds)
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", desired.Inbounds[0].Port))
	if err != nil {
		t.Fatalf("public port must be released after the guard retires: %v", err)
	}
	_ = listener.Close()
}

func TestRealityGuardChangesAllowlistOnReapply(t *testing.T) {
	destHost, destPort := realityDestination(t)
	desired := guardedRealityConfig(t, destHost, destPort)
	runtime, err := NewXray(testRuntimeSecrets(t))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := runtime.ApplyConfig(context.Background(), desired); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}

	guardAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(desired.Inbounds[0].Port))
	_ = dialGuardWithSNI(t, guardAddr, "www.cloudflare.com")

	// Swap the declared server name; the guard must enforce the new list.
	for i := range desired.Security {
		if desired.Security[i].Type == agentprotocol.SecurityReality {
			desired.Security[i].Reality.ServerNames = []string{"rotated.example.org"}
		}
	}
	if err := runtime.ApplyConfig(context.Background(), desired); err != nil {
		t.Fatalf("ApplyConfig rotating server names: %v", err)
	}
	// The old declared name is now foreign and must be dropped by the guard.
	before := runtime.Status(context.Background()).GuardRejected
	if err := dialGuardWithSNI(t, guardAddr, "www.cloudflare.com"); err == nil {
		t.Fatal("retired server name must be dropped after rotation")
	}
	waitFor(t, "rejection counter after rotation", func() bool {
		return runtime.Status(context.Background()).GuardRejected == before+1
	})
}

func TestPanelNodeForRealityUsesLoopbackAndFullServerNames(t *testing.T) {
	destHost, destPort := realityDestination(t)
	desired := guardedRealityConfig(t, destHost, destPort)
	for i := range desired.Security {
		if desired.Security[i].Type == agentprotocol.SecurityReality {
			desired.Security[i].Reality.ServerNames = []string{"one.example.org", "two.example.org"}
		}
	}
	runtime, err := NewXray(testRuntimeSecrets(t))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	node, err := runtime.panelNodeForInbound(desired, desired.Inbounds[0])
	if err != nil {
		t.Fatal(err)
	}
	protocol := node.Protocol
	if protocol.ListenAddress != "127.0.0.1" {
		t.Fatalf("ListenAddress = %q, want 127.0.0.1", protocol.ListenAddress)
	}
	if protocol.Port == desired.Inbounds[0].Port {
		t.Fatalf("loopback backend port must differ from the public port %d", protocol.Port)
	}
	if len(protocol.RealityServerNames) != 2 || protocol.RealityServerNames[0] != "one.example.org" || protocol.RealityServerNames[1] != "two.example.org" {
		t.Fatalf("RealityServerNames = %#v, want both declared names", protocol.RealityServerNames)
	}
	if !protocol.AcceptProxyProtocol {
		t.Fatal("TCP transport behind the guard must accept proxy protocol to keep real client addresses")
	}
	// The fallback dest stays the real SNI target, not the guard backend.
	if protocol.RealityServerAddr != destHost || protocol.RealityServerPort != destPort {
		t.Fatalf("dest = %s:%d, want %s:%d", protocol.RealityServerAddr, protocol.RealityServerPort, destHost, destPort)
	}
}
