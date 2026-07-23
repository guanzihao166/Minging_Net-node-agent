package dispatcher

import (
	strings "strings"
	sync "sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type ManagedWriter struct {
	writer   buf.Writer
	manager  *LinkManager
	remoteIP string
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	w.manager.RemoveWriter(w)
	return common.Close(w.writer)
}

type LinkManager struct {
	links map[*ManagedWriter]buf.Reader
	mu    sync.Mutex
}

func (m *LinkManager) AddLink(writer *ManagedWriter, reader buf.Reader, remoteIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	writer.remoteIP = strings.TrimPrefix(strings.TrimSpace(remoteIP), "::ffff:")
	m.links[writer] = reader
}

func (m *LinkManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.links, writer)
}

func (m *LinkManager) CloseAll() {
	m.mu.Lock()
	links := make(map[*ManagedWriter]buf.Reader, len(m.links))
	for writer, reader := range m.links {
		links[writer] = reader
	}
	m.mu.Unlock()
	for w, r := range links {
		common.Close(w)
		common.Interrupt(r)
	}
}

func (m *LinkManager) ActiveIPs() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := make(map[string]struct{}, len(m.links))
	for writer := range m.links {
		if writer == nil || writer.remoteIP == "" {
			continue
		}
		seen[writer.remoteIP] = struct{}{}
	}
	addresses := make([]string, 0, len(seen))
	for address := range seen {
		addresses = append(addresses, address)
	}
	return addresses
}
