package sniguard

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGuardForwardsDeclaredSNIAndDropsTheRest(t *testing.T) {
	backend, backendHits := startTLSBackend(t)
	defer backend.Close()

	proxy, err := Start(Spec{
		ListenAddr:   loopbackAddr(t),
		BackendAddr:  backend.Addr().String(),
		AllowedSNIs:  []string{"allowed.example.com"},
		ProxyProtocol: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	// A client with the declared SNI completes a TLS handshake through the
	// guard and talks to the backend.
	if err := probeTLS(t, proxy.Addr().String(), "allowed.example.com"); err != nil {
		t.Fatalf("declared SNI must reach the backend: %v", err)
	}
	if hits := backendHits(); hits != 1 {
		t.Fatalf("backend connections = %d, want 1", hits)
	}

	// A client with any other SNI is dropped before the backend sees it.
	if err := probeTLS(t, proxy.Addr().String(), "thief.example.net"); err == nil {
		t.Fatal("non-declared SNI must be rejected")
	}
	if hits := backendHits(); hits != 1 {
		t.Fatalf("backend connections after rejected probe = %d, want 1", hits)
	}
	if got := proxy.Stats().Accepted; got != 1 {
		t.Fatalf("accepted = %d, want 1", got)
	}
	if got := proxy.Stats().Rejected; got != 1 {
		t.Fatalf("rejected = %d, want 1", got)
	}
}

func TestGuardMatchIsCaseSensitiveLikeReality(t *testing.T) {
	// REALITY matches server names with a case-sensitive map lookup, so a
	// casing difference must not slip through the guard either.
	backend, _ := startTLSBackend(t)
	defer backend.Close()
	proxy, err := Start(Spec{
		ListenAddr:   loopbackAddr(t),
		BackendAddr:  backend.Addr().String(),
		AllowedSNIs:  []string{"Allowed.Example.COM"},
		ProxyProtocol: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if err := probeTLS(t, proxy.Addr().String(), "allowed.example.com"); err == nil {
		t.Fatal("case-different SNI must be rejected")
	}
}

func TestGuardDropsNonTLSAndGarbage(t *testing.T) {
	backend, _ := startTLSBackend(t)
	defer backend.Close()
	proxy, err := Start(Spec{
		ListenAddr:   loopbackAddr(t),
		BackendAddr:  backend.Addr().String(),
		AllowedSNIs:  []string{"allowed.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	for name, payload := range map[string][]byte{
		"http":       []byte("GET / HTTP/1.1\r\nHost: thief\r\n\r\n"),
		"garbage":    bytes.Repeat([]byte{0xa5}, 64),
		"wrong-type": {0x14, 0x03, 0x03, 0x00, 0x01, 0x00},
	} {
		conn, dialErr := net.Dial("tcp", proxy.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		if _, writeErr := conn.Write(payload); writeErr != nil {
			t.Fatal(writeErr)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, readErr := conn.Read(make([]byte, 16))
		_ = conn.Close()
		if readErr == nil {
			t.Fatalf("%s payload must be dropped", name)
		}
	}
}

func TestGuardPassesClientAddressWithProxyProtocol(t *testing.T) {
	var clientAddr atomic.Value
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				header, err := proxyprotoReadHeader(conn)
				if err != nil {
					return
				}
				clientAddr.Store(header)
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()

	proxy, err := Start(Spec{
		ListenAddr:   loopbackAddr(t),
		BackendAddr:  backend.Addr().String(),
		AllowedSNIs:  []string{"allowed.example.com"},
		ProxyProtocol: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	// Raw dial with a hand-built ClientHello; the dumb backend answers
	// nothing, so success is defined purely by what the backend observed.
	conn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hello := buildClientHello(t, "allowed.example.com")
	record := make([]byte, 5+len(hello))
	record[0] = 0x16
	record[1], record[2] = 0x03, 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(hello)))
	copy(record[5:], hello)
	if _, err := conn.Write(record); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := clientAddr.Load().(string); ok && v != "" {
			if v != conn.LocalAddr().String() {
				t.Fatalf("PROXY header source = %q, want the real client %q", v, conn.LocalAddr().String())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("backend never observed a PROXY protocol header")
}

func TestReadClientHelloSNIParsesHandShakeWithExtensions(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		hello := buildClientHello(t, "sni.example.org")
		record := make([]byte, 5+len(hello))
		record[0] = 0x16
		record[1], record[2] = 0x03, 0x01
		binary.BigEndian.PutUint16(record[3:5], uint16(len(hello)))
		copy(record[5:], hello)
		_, _ = client.Write(record)
		_ = client.Close()
	}()
	name, replay, err := ReadClientHelloSNI(server)
	if err != nil {
		t.Fatal(err)
	}
	if name != "sni.example.org" {
		t.Fatalf("SNI = %q", name)
	}
	if len(replay) == 0 || replay[0] != 0x16 {
		t.Fatalf("replay buffer is not a TLS record: % x", replay[:min(8, len(replay))])
	}
}

func loopbackAddr(t *testing.T) string {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	return addr
}

func probeTLS(t *testing.T, addr, serverName string) error {
	t.Helper()
	conn, err := tlsDialRaw(t, addr, serverName)
	if err != nil {
		return err
	}
	return conn.Close()
}

func tlsDialRaw(t *testing.T, addr, serverName string) (*tls.Conn, error) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func startTLSBackend(t *testing.T) (net.Listener, func() int32) {
	t.Helper()
	certPEM, keyPEM := backendPEM(t)
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	var hits int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&hits, 1)
			go func() {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 4096)
				for {
					if _, err := conn.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener, func() int32 { return atomic.LoadInt32(&hits) }
}

var (
	backendCertOnce sync.Once
	backendPEMCert []byte
	backendPEMKey  []byte
)

func backendPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	backendCertOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "backend"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			DNSNames:     []string{"allowed.example.com", "thief.example.net", "allowed.example.org", "Allowed.Example.COM"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		backendPEMCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		backendPEMKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	})
	return backendPEMCert, backendPEMKey
}

// proxyprotoReadHeader reads one PROXY protocol v2 header (signature only
// parsing; enough to recover the source address textually below we instead use
// the library indirectly). Kept minimal: the runtime tests rely on
// proxyproto.ReadTimeout for full validation.
func proxyprotoReadHeader(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	signature := make([]byte, 12)
	if _, err := io.ReadFull(reader, signature); err != nil {
		return "", err
	}
	if !bytes.Equal(signature, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
		return "", fmt.Errorf("missing PROXY v2 signature")
	}
	rest := make([]byte, 4)
	if _, err := io.ReadFull(reader, rest); err != nil {
		return "", err
	}
	length := binary.BigEndian.Uint16(rest[2:4])
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return "", err
	}
	if len(body) < 12 { // AF_INET src(4) dst(4) port(4)
		return "", fmt.Errorf("short PROXY header body")
	}
	src := net.IPv4(body[0], body[1], body[2], body[3])
	srcPort := binary.BigEndian.Uint16(body[8:10])
	return net.JoinHostPort(src.String(), fmt.Sprint(srcPort)), nil
}
