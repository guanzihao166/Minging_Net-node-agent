package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/guanzihao166/iepl-node-agent/internal/config"
	"github.com/guanzihao166/iepl-node-agent/internal/identity"
	p "github.com/guanzihao166/iepl-node-agent/internal/protocol"
	"github.com/guanzihao166/iepl-node-agent/internal/state"
)

type boundaryRuntime struct {
	fakeRuntime
	store *state.Store
	fail  bool
	t     *testing.T
}

func (r *boundaryRuntime) CollectTraffic(context.Context) ([]state.TrafficDelta, error) {
	if r.fail {
		return nil, errors.New("sample unavailable")
	}
	return []state.TrafficDelta{{SubscriberID: 901, InboundID: 81, QuotaGeneration: 1, UploadBytes: 1000}}, nil
}
func (r *boundaryRuntime) ApplyConfig(ctx context.Context, cfg p.DesiredConfig) error {
	batches, err := r.store.PendingTraffic(ctx, 10)
	if err != nil || len(batches) != 1 || batches[0].ConfigVersion != 1 || batches[0].Items[0].UploadBytes != 1000 {
		r.t.Fatalf("old traffic not sealed before apply: %+v %v", batches, err)
	}
	return r.fakeRuntime.ApplyConfig(ctx, cfg)
}
func TestConfigChangeSealsOldTrafficAndAbortsOnCollectionFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "flush", true: "abort"}[fail], func(t *testing.T) {
			ctx := context.Background()
			st, err := state.Open(ctx, filepath.Join(t.TempDir(), "agent.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			old, _ := p.SignConfig(p.DesiredConfig{SchemaVersion: p.SchemaVersion, AgentNodeID: 17, Version: 1, GeneratedAt: time.Now()}, "test", key)
			if _, err := st.SaveDesiredConfig(ctx, old); err != nil {
				t.Fatal(err)
			}
			if err := st.MarkConfigApplied(ctx, 1, old.SHA256); err != nil {
				t.Fatal(err)
			}
			runtime := &boundaryRuntime{store: st, fail: fail, t: t}
			c := &Client{cfg: config.Config{TrafficInterval: time.Second}, identity: &identity.Identity{AgentNodeID: 17, ConfigSigningKeyID: "test"}, store: st, runtime: runtime, signingKey: pub, bootID: "21fba3f0-54e3-4284-9dc6-fca218c451bd", now: time.Now}
			accepted := make(chan *websocket.Conn, 1)
			u := websocket.Upgrader{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, e := u.Upgrade(w, r, nil)
				if e == nil {
					accepted <- conn
				}
			}))
			defer server.Close()
			client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			peer := <-accepted
			defer peer.Close()
			next := old.Config
			next.Version = 2
			signed, _ := p.SignConfig(next, "test", key)
			envelope, _ := p.NewEnvelope("config", p.TypeDesiredConfig, signed, time.Now())
			err = c.applyDesiredConfig(ctx, &sessionWriter{connection: peer, now: time.Now}, envelope, map[uint64]struct{}{2: {}})
			stateValue, _ := st.RuntimeState(ctx)
			if fail {
				if err == nil || runtime.configApplies != 0 || stateValue.AppliedConfigVersion != 1 {
					t.Fatalf("failed flush applied config: %v %+v", err, stateValue)
				}
			} else {
				if err != nil || runtime.configApplies != 1 || stateValue.AppliedConfigVersion != 2 {
					t.Fatalf("apply: %v %+v", err, stateValue)
				}
			}
		})
	}
}
