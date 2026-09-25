// Package sniguard fronts REALITY inbounds with a TCP listener that filters
// TLS ClientHellos by SNI before they reach Xray.
//
// REALITY forwards authentication-failed connections to its configured dest,
// replaying the client's SNI. When dest is a CDN that routes (rather than
// validates) SNI, an attacker can proxy arbitrary traffic through the node.
// The official Xray guidance (xtls.github.io, REALITY doc, "防偷流量") is to
// filter SNI in front of the server; this package is that filter: only the
// declared server names reach Xray, everything else is dropped.
package sniguard

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
)

const (
	defaultHelloTimeout = 10 * time.Second
	backendDialTimeout  = 5 * time.Second
)

// Spec describes one guarded REALITY inbound.
type Spec struct {
	// ListenAddr is the public address the guard owns (the inbound's former
	// listen address, e.g. "0.0.0.0:443").
	ListenAddr string
	// BackendAddr is the loopback address Xray's REALITY inbound listens on.
	BackendAddr string
	// AllowedSNIs is the exact server-name allowlist. Matching is
	// case-sensitive, mirroring the REALITY server's own map lookup.
	AllowedSNIs []string
	// ProxyProtocol prepends a PROXY-protocol v2 header when forwarding so
	// Xray records the real client address. Only set it when the backend
	// transport actually accepts proxy protocol.
	ProxyProtocol bool
	// HelloTimeout bounds how long the guard waits for a ClientHello.
	HelloTimeout time.Duration
}

// Equal reports whether two specs describe the same guard, i.e. whether a
// running guard can keep serving after a config reapply.
func (s Spec) Equal(other Spec) bool {
	if s.ListenAddr != other.ListenAddr || s.BackendAddr != other.BackendAddr || s.ProxyProtocol != other.ProxyProtocol {
		return false
	}
	if len(s.AllowedSNIs) != len(other.AllowedSNIs) {
		return false
	}
	for i := range s.AllowedSNIs {
		if s.AllowedSNIs[i] != other.AllowedSNIs[i] {
			return false
		}
	}
	return true
}

// Stats exposes per-guard counters for status reporting.
type Stats struct {
	Accepted uint64
	Rejected uint64
}

// Proxy is a running SNI guard listener.
type Proxy struct {
	spec    Spec
	allowed map[string]struct{}

	listener net.Listener
	closed   atomic.Bool

	conns sync.Map // net.Conn -> struct{}

	acceptWG  sync.WaitGroup
	accepted  atomic.Uint64
	rejected  atomic.Uint64
	closeOnce sync.Once
	closeErr  error
}

// Start binds the public listener and begins serving connections. The guard
// must not start before the backend is listening, or allowed clients would be
// dropped during the window between guard accept and backend dial.
func Start(spec Spec) (*Proxy, error) {
	if spec.HelloTimeout <= 0 {
		spec.HelloTimeout = defaultHelloTimeout
	}
	listener, err := net.Listen("tcp", spec.ListenAddr)
	if err != nil {
		return nil, err
	}
	proxy := &Proxy{
		spec:    spec,
		allowed: make(map[string]struct{}, len(spec.AllowedSNIs)),
		listener: listener,
	}
	for _, name := range spec.AllowedSNIs {
		proxy.allowed[name] = struct{}{}
	}
	proxy.acceptWG.Add(1)
	go proxy.acceptLoop()
	return proxy, nil
}

// Spec returns the spec the proxy was started with.
func (p *Proxy) Spec() Spec { return p.spec }

// Addr returns the address the guard is listening on.
func (p *Proxy) Addr() net.Addr { return p.listener.Addr() }

// Stats returns the accepted/rejected counters.
func (p *Proxy) Stats() Stats {
	return Stats{Accepted: p.accepted.Load(), Rejected: p.rejected.Load()}
}

// Close stops the listener, drops every tracked connection, and waits for the
// handlers to finish. It is idempotent.
func (p *Proxy) Close() error {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		p.closeErr = p.listener.Close()
		p.conns.Range(func(key, _ any) bool {
			if conn, ok := key.(net.Conn); ok {
				_ = conn.Close()
			}
			return true
		})
	})
	p.acceptWG.Wait()
	return p.closeErr
}

func (p *Proxy) acceptLoop() {
	defer p.acceptWG.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		if p.closed.Load() {
			_ = conn.Close()
			return
		}
		p.conns.Store(conn, struct{}{})
		p.acceptWG.Add(1)
		go func() {
			defer p.acceptWG.Done()
			defer p.conns.Delete(conn)
			p.handle(conn)
		}()
	}
}

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()

	_ = client.SetReadDeadline(time.Now().Add(p.spec.HelloTimeout))
	serverName, replay, err := ReadClientHelloSNI(client)
	if err != nil {
		p.rejected.Add(1)
		return
	}
	// An empty SNI can never authenticate against REALITY's server_names map;
	// drop it here rather than let it reach the fallback path.
	if _, ok := p.allowed[serverName]; !ok {
		p.rejected.Add(1)
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	backend, err := net.DialTimeout("tcp", p.spec.BackendAddr, backendDialTimeout)
	if err != nil {
		p.rejected.Add(1)
		return
	}
	if p.spec.ProxyProtocol {
		header := proxyproto.HeaderProxyFromAddrs(2, client.RemoteAddr(), client.LocalAddr())
		if _, err := header.WriteTo(backend); err != nil {
			_ = backend.Close()
			p.rejected.Add(1)
			return
		}
	}
	if _, err := backend.Write(replay); err != nil {
		_ = backend.Close()
		p.rejected.Add(1)
		return
	}
	p.accepted.Add(1)
	pipe(client, backend)
}

// pipe copies both directions and tears the pair down as soon as either side
// finishes, so a half-closed client does not keep the backend connection open.
func pipe(client, backend net.Conn) {
	done := make(chan struct{}, 2)
	copyDirection := func(from, to net.Conn) {
		_, _ = io.Copy(to, from)
		if closeWriter, ok := to.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyDirection(client, backend)
	go copyDirection(backend, client)
	<-done
	_ = client.Close()
	_ = backend.Close()
	<-done
}
