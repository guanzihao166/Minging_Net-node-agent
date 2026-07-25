package maintenance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guanzihao166/iepl-node-agent/internal/config"
	"github.com/guanzihao166/iepl-node-agent/internal/identity"
	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

func TestControllerChecksLatestReleaseAndQueuesOnlySignedFixedAction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/releases/latest" {
			http.Redirect(writer, request, "/releases/tag/v0.1.16", http.StatusFound)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg := config.Config{
		StateDir: filepath.Join(root, "state"), MaintenanceDir: filepath.Join(root, "run"),
		MaintenanceStateDir: filepath.Join(root, "maintenance-state"),
	}
	id := &identity.Identity{AgentNodeID: 17, ConfigSigningKeyID: "test-key"}
	controller, err := NewController(cfg, id, publicKey, "v0.1.15")
	if err != nil {
		t.Fatal(err)
	}
	controller.latestURL = server.URL + "/releases/latest"
	checked := controller.CheckUpdate(context.Background(), uuid.NewString())
	if checked.Status != "checked" || checked.LatestVersion != "v0.1.16" || !checked.UpdateAvailable {
		t.Fatalf("check result = %#v", checked)
	}
	now := time.Now().UTC()
	signed, err := agentprotocol.SignMaintenanceCommand(agentprotocol.MaintenanceCommand{
		CommandID: uuid.NewString(), AgentNodeID: 17, Action: agentprotocol.MaintenanceActionUpdate,
		TargetVersion: "v0.1.16", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}, "test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.MaintenanceStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.MaintenanceReadyPath(), []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	accepted := controller.HandleCommand(context.Background(), signed)
	if accepted.Status != "accepted" {
		t.Fatalf("accepted result = %#v", accepted)
	}
	requestPath := filepath.Join(cfg.MaintenanceRequestDir(), signed.Command.CommandID+".json")
	raw, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	var stored agentprotocol.SignedMaintenanceCommand
	if err := json.Unmarshal(raw, &stored); err != nil || stored.Signature != signed.Signature {
		t.Fatalf("stored command = %#v, error = %v", stored, err)
	}
	tampered := signed
	tampered.Command.TargetVersion = "v9.9.9"
	failed := controller.HandleCommand(context.Background(), tampered)
	if failed.Status != "failed" {
		t.Fatalf("tampered result = %#v", failed)
	}
}

func TestChecksumParserRequiresExactAsset(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := checksumForAsset([]byte(digest+"  iepl-agent-linux-amd64\n"), "iepl-agent-linux-amd64")
	if err != nil || got != digest {
		t.Fatalf("checksum = %q, error = %v", got, err)
	}
	if _, err := checksumForAsset([]byte(digest+"  iepl-agent-linux-amd64.evil\n"), "iepl-agent-linux-amd64"); err == nil {
		t.Fatal("prefix-matching checksum entry was accepted")
	}
}

func TestReleaseBinaryDownloadStreamsToFileAndHashes(t *testing.T) {
	payload := []byte("streamed-release-binary")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = writer.Write(payload)
	}))
	defer server.Close()
	root := t.TempDir()
	destination, err := os.Create(filepath.Join(root, "agent.new"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	manager := &Manager{version: "v0.1.16", client: server.Client()}
	digest, err := manager.downloadToFile(context.Background(), server.URL, destination, int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := destination.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	stored, err := io.ReadAll(destination)
	expected := sha256.Sum256(payload)
	if err != nil || string(stored) != string(payload) || digest != hex.EncodeToString(expected[:]) {
		t.Fatalf("stored=%q digest=%q error=%v", stored, digest, err)
	}
}

func TestReleaseBinaryDownloadRejectsStreamingSizeOverflow(t *testing.T) {
	payload := []byte("asset-larger-than-limit")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Del("Content-Length")
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = writer.Write(payload)
	}))
	defer server.Close()
	destination, err := os.Create(filepath.Join(t.TempDir(), "agent.new"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	manager := &Manager{version: "v0.1.16", client: server.Client()}
	if _, err := manager.downloadToFile(context.Background(), server.URL, destination, 5); err == nil {
		t.Fatal("oversized streamed asset was accepted")
	}
}
