package identity

import (
	"encoding/json"
	"github.com/guanzihao166/iepl-node-agent/internal/config"
	"os"
	"testing"
)

func TestControlEndpointMigrationPersistsIdentityAndRejectsUnsafeLocations(t *testing.T) {
	cfg := config.Config{ConfigDir: t.TempDir()}
	id := &Identity{AgentNodeID: 17, MachineID: "machine", WSSURL: "wss://old.example.test/api/v1/agent/connect", SecretEnvelopeKey: "preserved"}
	for _, endpoint := range []string{"ws://example.test/api/v1/agent/connect", "wss://user:password@example.test/api/v1/agent/connect", "wss://example.test/other", "wss://example.test:22/api/v1/agent/connect", "wss://example.test/api/v1/agent/connect?token=x"} {
		if err := UpdateControlEndpoint(cfg, id, endpoint); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
	endpoint := "wss://www.example.test/api/v1/agent/connect"
	if err := UpdateControlEndpoint(cfg, id, endpoint); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(cfg.IdentityPath())
	if err != nil {
		t.Fatal(err)
	}
	var saved Identity
	if err = json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.WSSURL != endpoint || id.WSSURL != endpoint || saved.SecretEnvelopeKey != "preserved" {
		t.Fatal("identity was not preserved")
	}
}
