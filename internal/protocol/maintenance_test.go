package agentprotocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMaintenanceSignatureBindsActionTargetAndExpiry(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	signed, err := SignMaintenanceCommand(MaintenanceCommand{
		CommandID: uuid.NewString(), AgentNodeID: 17, Action: MaintenanceActionUpdate,
		TargetVersion: "v0.1.15", IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}, "test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedMaintenanceCommand(signed, "test-key", publicKey, now); err != nil {
		t.Fatal(err)
	}
	tampered := signed
	tampered.Command.Action = MaintenanceActionUninstall
	tampered.Command.TargetVersion = ""
	if err := VerifySignedMaintenanceCommand(tampered, "test-key", publicKey, now); err == nil {
		t.Fatal("tampered maintenance action was accepted")
	}
	if err := VerifySignedMaintenanceCommand(signed, "test-key", publicKey, now.Add(3*time.Minute)); err == nil {
		t.Fatal("expired maintenance command was accepted")
	}
}
