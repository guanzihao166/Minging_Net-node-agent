package runtime

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

type zeroSource struct{}

func (zeroSource) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// Measure completed transfers through the real VLESS inbound and dispatcher.
// Upload timing waits for the destination's acknowledgement, not socket writes.
func TestVLESSNodeBandwidthEndToEnd(t *testing.T) {
	ctx := context.Background()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(45 * time.Second))
				for {
					header := make([]byte, 5)
					if _, err := io.ReadFull(c, header); err != nil {
						return
					}
					n := int64(binary.BigEndian.Uint32(header[1:]))
					if header[0] == 1 {
						if _, err := io.CopyN(c, zeroSource{}, n); err != nil {
							return
						}
					} else {
						if _, err := io.CopyN(io.Discard, c, n); err != nil {
							return
						}
						if _, err := c.Write([]byte{1}); err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	desired := testDesiredConfig()
	port := availableProtocolPortBlock(t)
	a := desired.Inbounds[0]
	a.Port = port
	a.Listen = "127.0.0.1"
	a.SecurityProfileID = 0
	a.VLESS = &agentprotocol.VLESSConfig{Decryption: "none"}
	b := a
	b.ID++
	b.Port++
	b.Name = "second-node"
	desired.Inbounds = []agentprotocol.Inbound{a, b}
	desired.Security = nil
	runtime, err := NewXray(testRuntimeSecrets(t))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := runtime.ApplyConfig(ctx, desired); err != nil {
		t.Fatal(err)
	}
	id := "3e285077-7932-4e8d-b232-9b6d58dd6671"
	users := []agentprotocol.UserCredential{{SubscriberID: 101, InboundID: a.ID, Kind: "uuid", Value: id, SpeedLimitBPS: 25_000_000, NodeGlobalLimitBPS: 12_500_000}, {SubscriberID: 101, InboundID: b.ID, Kind: "uuid", Value: id, SpeedLimitBPS: 25_000_000}}
	if err := runtime.ApplyUsers(ctx, users); err != nil {
		t.Fatal(err)
	}
	dial := func(nodePort int) (net.Conn, error) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", nodePort), 3*time.Second)
		if err != nil {
			return nil, err
		}
		_ = c.SetDeadline(time.Now().Add(45 * time.Second))
		header := []byte{0}
		u := uuid.MustParse(id)
		header = append(header, u[:]...)
		header = append(header, 0, 1)
		header = binary.BigEndian.AppendUint16(header, uint16(target.Addr().(*net.TCPAddr).Port))
		header = append(header, 1, 127, 0, 0, 1)
		header = append(header, 0, 0, 0, 0, 0)
		if _, err = c.Write(header); err != nil {
			c.Close()
			return nil, err
		}
		response := make([]byte, 3)
		if _, err = io.ReadFull(c, response); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	transfer := func(c net.Conn, download bool, size int64) error {
		header := make([]byte, 5)
		if download {
			header[0] = 1
		}
		binary.BigEndian.PutUint32(header[1:], uint32(size))
		if _, err := c.Write(header); err != nil {
			return err
		}
		if download {
			_, err := io.CopyN(io.Discard, c, size)
			return err
		}
		if _, err := io.CopyN(c, zeroSource{}, size); err != nil {
			return err
		}
		_, err := io.ReadFull(c, make([]byte, 1))
		return err
	}
	measure := func(name string, nodePort int, download bool, streams int, size int64, want float64) {
		t.Helper()
		connections := make([]net.Conn, streams)
		for i := range connections {
			connections[i], err = dial(nodePort)
			if err != nil {
				t.Fatal(err)
			}
			defer connections[i].Close()
		}
		start := time.Now()
		var wg sync.WaitGroup
		errs := make(chan error, streams)
		for _, c := range connections {
			wg.Add(1)
			go func(c net.Conn) { defer wg.Done(); errs <- transfer(c, download, size) }(c)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		rate := float64(size*int64(streams)) * 8 / time.Since(start).Seconds() / 1e6
		t.Logf("%s %.2f Mbps (ceiling %.0f)", name, rate, want)
		if rate > want*1.15 || rate < want*.5 {
			t.Fatalf("%s throughput %.2f outside expected range around %.0f", name, rate, want)
		}
	}
	measure("A upload", a.Port, false, 1, 25_000_000, 100)
	measure("A download", a.Port, true, 1, 25_000_000, 100)
	measure("A parallel download", a.Port, true, 8, 3_125_000, 100)
	measure("B independent download", b.Port, true, 1, 25_000_000, 200)
	users[0].NodeGlobalLimitBPS = 6_250_000
	if _, err := runtime.ApplyUserDelta(ctx, agentprotocol.UserDelta{Revision: 2, Upserts: users[:1]}); err != nil {
		t.Fatal(err)
	}
	measure("A lower cap", a.Port, true, 1, 12_500_000, 50)
	users[0].NodeGlobalLimitBPS = 0
	if err := runtime.ApplyUsers(ctx, users); err != nil {
		t.Fatal(err)
	}
	measure("A cap removed", a.Port, true, 1, 25_000_000, 200)
}
