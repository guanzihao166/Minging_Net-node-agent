package sniguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
)

// buildClientHello assembles a minimal TLS 1.2/1.3-shaped ClientHello
// handshake message carrying the given SNI extension.
func buildClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	type extension struct {
		kind uint16
		data []byte
	}
	sniEntry := make([]byte, 3+len(serverName))
	sniEntry[0] = 0x00 // host_name
	binary.BigEndian.PutUint16(sniEntry[1:3], uint16(len(serverName)))
	copy(sniEntry[3:], serverName)
	sniList := make([]byte, 2+len(sniEntry))
	binary.BigEndian.PutUint16(sniList[0:2], uint16(len(sniEntry)))
	copy(sniList[2:], sniEntry)

	extensions := []extension{{kind: 0x0000, data: sniList}}
	var extBytes []byte
	for _, ext := range extensions {
		extBytes = append(extBytes, byte(ext.kind>>8), byte(ext.kind))
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(ext.data)))
		extBytes = append(extBytes, length[:]...)
		extBytes = append(extBytes, ext.data...)
	}

	hello := make([]byte, 0, 64)
	hello = append(hello, 0x03, 0x03)             // legacy_version
	hello = append(hello, make([]byte, 32)...)    // random
	hello = append(hello, 0x00)                   // empty session_id
	hello = append(hello, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	hello = append(hello, 0x01, 0x00)             // null compression
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(extBytes)))
	hello = append(hello, extLen[:]...)
	hello = append(hello, extBytes...)

	message := make([]byte, 4+len(hello))
	message[0] = 0x01 // client hello
	messageLen := len(hello)
	message[1] = byte(messageLen >> 16)
	message[2] = byte(messageLen >> 8)
	message[3] = byte(messageLen)
	copy(message[4:], hello)
	return message
}

func TestParseServerName(t *testing.T) {
	cases := []struct {
		name    string
		sni     string
		want    string
		wantErr error
	}{
		{name: "plain", sni: "www.example.com", want: "www.example.com"},
		{name: "case preserved", sni: "Mixed.CASE.example", want: "Mixed.CASE.example"},
		{name: "no sni falls to other extensions", sni: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hello := buildClientHello(t, tc.sni)
			if tc.sni == "" {
				hello = stripSNIExtension(t, hello)
			}
			got, err := parseServerName(hello[4:])
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("SNI = %q, want %q", got, tc.want)
			}
		})
	}
}

func stripSNIExtension(t *testing.T, message []byte) []byte {
	t.Helper()
	// Rebuild the hello without the SNI extension by writing zero extensions.
	hello := message[4:]
	// locate end of fixed prefix: version(2)+random(32)+sid(1)
	i := 34
	i += 1 + int(hello[i]) // session id
	i += 2 + int(hello[i])<<8 + int(hello[i+1])
	i += 1 + int(hello[i])
	// replace extensions block with an empty one
	stripped := make([]byte, i)
	copy(stripped, hello[:i])
	stripped = append(stripped, 0x00, 0x00)
	out := make([]byte, 4+len(stripped))
	copy(out, message[:4])
	messageLen := len(stripped)
	out[1] = byte(messageLen >> 16)
	out[2] = byte(messageLen >> 8)
	out[3] = byte(messageLen)
	copy(out[4:], stripped)
	return out
}

func TestReadClientHelloSNIRejectsMalformed(t *testing.T) {
	full := buildClientHello(t, "ok.example.com")

	records := func(chunks ...[]byte) net.Conn {
		client, server := net.Pipe()
		go func() {
			defer client.Close()
			for _, chunk := range chunks {
				if _, err := client.Write(chunk); err != nil {
					return
				}
			}
		}()
		return server
	}

	recordFor := func(body []byte, contentType byte) []byte {
		record := make([]byte, 5+len(body))
		record[0] = contentType
		record[1], record[2] = 0x03, 0x03
		binary.BigEndian.PutUint16(record[3:5], uint16(len(body)))
		copy(record[5:], body)
		return record
	}

	splitPoint := 5 + 40 // inside the random block of the first record
	wholeRecord := recordFor(full, 0x16)
	splitConn := records(wholeRecord[:splitPoint], wholeRecord[splitPoint:])
	name, _, err := ReadClientHelloSNI(splitConn)
	if err != nil || name != "ok.example.com" {
		t.Fatalf("split record: name=%q err=%v", name, err)
	}

	// handshake message split across two records
	half := len(full) / 2
	multiConn := records(
		recordFor(full[:half], 0x16),
		recordFor(full[half:], 0x16),
	)
	name, _, err = ReadClientHelloSNI(multiConn)
	if err != nil || name != "ok.example.com" {
		t.Fatalf("multi record: name=%q err=%v", name, err)
	}

	oversized := recordFor(full, 0x16)
	binary.BigEndian.PutUint16(oversized[3:5], 0xFFFF)
	name, _, err = ReadClientHelloSNI(records(oversized))
	if err == nil || name != "" {
		t.Fatalf("oversized record must be rejected, got name=%q err=%v", name, err)
	}

	if _, _, err := ReadClientHelloSNI(records(recordFor(full, 0x17))); err == nil {
		t.Fatal("application-data record must be rejected")
	}

	// handshake message of excessive declared length
	bogus := make([]byte, 8)
	bogus[0] = 0x01
	bogus[1] = 0x01 // 1<<16 < declared length < 1<<24
	bogus[2] = 0x00
	bogus[3] = 0x00
	if _, _, err := ReadClientHelloSNI(records(recordFor(bogus, 0x16))); err == nil {
		t.Fatal("oversized handshake must be rejected")
	}

	// first handshake message that is not a ClientHello
	bogus = make([]byte, 8)
	bogus[0] = 0x02 // server hello
	if _, _, err := ReadClientHelloSNI(records(recordFor(bogus, 0x16))); err == nil {
		t.Fatal("non ClientHello first message must be rejected")
	}
}

func TestReadClientHelloSNIRejectsNonTLS(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\n"))
		_ = client.Close()
	}()
	if _, _, err := ReadClientHelloSNI(server); err == nil {
		t.Fatal("plaintext HTTP must be rejected")
	}
}

func TestSpecEqual(t *testing.T) {
	base := Spec{ListenAddr: "0.0.0.0:443", BackendAddr: "127.0.0.1:40000", AllowedSNIs: []string{"a.example", "b.example"}, ProxyProtocol: true}
	if !base.Equal(Spec{ListenAddr: "0.0.0.0:443", BackendAddr: "127.0.0.1:40000", AllowedSNIs: []string{"a.example", "b.example"}, ProxyProtocol: true}) {
		t.Fatal("identical specs must be equal")
	}
	mutations := []Spec{
		{ListenAddr: "0.0.0.0:8443", BackendAddr: "127.0.0.1:40000", AllowedSNIs: []string{"a.example", "b.example"}, ProxyProtocol: true},
		{ListenAddr: "0.0.0.0:443", BackendAddr: "127.0.0.1:40001", AllowedSNIs: []string{"a.example", "b.example"}, ProxyProtocol: true},
		{ListenAddr: "0.0.0.0:443", BackendAddr: "127.0.0.1:40000", AllowedSNIs: []string{"a.example"}, ProxyProtocol: true},
		{ListenAddr: "0.0.0.0:443", BackendAddr: "127.0.0.1:40000", AllowedSNIs: []string{"a.example", "c.example"}, ProxyProtocol: true},
		{ListenAddr: "0.0.0.0:443", BackendAddr: "127.0.0.1:40000", AllowedSNIs: []string{"b.example", "a.example"}, ProxyProtocol: true},
		{ListenAddr: "0.0.0.0:443", BackendAddr: "127.0.0.1:40000", AllowedSNIs: []string{"a.example", "b.example"}},
	}
	for i, mutated := range mutations {
		if base.Equal(mutated) {
			t.Fatalf("mutation %d must not be equal", i)
		}
	}
}

var _ = fmt.Sprintf
