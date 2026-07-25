package agentprotocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	TypeMaintenanceCommand = "maintenance_command"
	TypeMaintenanceResult  = "maintenance_result"

	MaintenanceActionCheckUpdate = "check_update"
	MaintenanceActionUpdate      = "update"
	MaintenanceActionUninstall   = "uninstall"
)

var maintenanceVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

type MaintenanceCommand struct {
	CommandID     string    `json:"command_id"`
	AgentNodeID   int64     `json:"agent_node_id"`
	Action        string    `json:"action"`
	TargetVersion string    `json:"target_version,omitempty"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type SignedMaintenanceCommand struct {
	KeyID     string             `json:"key_id"`
	SHA256    string             `json:"sha256"`
	Signature string             `json:"signature"`
	Command   MaintenanceCommand `json:"command"`
}

type MaintenanceResult struct {
	CommandID       string    `json:"command_id"`
	Action          string    `json:"action"`
	Status          string    `json:"status"`
	CurrentVersion  string    `json:"current_version,omitempty"`
	LatestVersion   string    `json:"latest_version,omitempty"`
	UpdateAvailable bool      `json:"update_available"`
	Message         string    `json:"message,omitempty"`
	OccurredAt      time.Time `json:"occurred_at"`
}

func ValidateMaintenanceCommand(command MaintenanceCommand) error {
	command.Action = strings.ToLower(strings.TrimSpace(command.Action))
	command.TargetVersion = strings.TrimSpace(command.TargetVersion)
	if uuid.Validate(command.CommandID) != nil || command.AgentNodeID <= 0 || command.IssuedAt.IsZero() || command.ExpiresAt.IsZero() {
		return errors.New("maintenance command identity or time is invalid")
	}
	if !command.ExpiresAt.After(command.IssuedAt) || command.ExpiresAt.Sub(command.IssuedAt) > 5*time.Minute {
		return errors.New("maintenance command validity window is invalid")
	}
	switch command.Action {
	case MaintenanceActionCheckUpdate, MaintenanceActionUninstall:
		if command.TargetVersion != "" {
			return errors.New("maintenance target version is not allowed for this action")
		}
	case MaintenanceActionUpdate:
		if !maintenanceVersionPattern.MatchString(command.TargetVersion) {
			return errors.New("maintenance target version is invalid")
		}
	default:
		return errors.New("maintenance action is invalid")
	}
	return nil
}

func SignMaintenanceCommand(command MaintenanceCommand, keyID string, privateKey ed25519.PrivateKey) (SignedMaintenanceCommand, error) {
	if err := ValidateMaintenanceCommand(command); err != nil {
		return SignedMaintenanceCommand{}, err
	}
	if strings.TrimSpace(keyID) == "" || len(privateKey) != ed25519.PrivateKeySize {
		return SignedMaintenanceCommand{}, errors.New("maintenance signing key is invalid")
	}
	payload, err := json.Marshal(command)
	if err != nil {
		return SignedMaintenanceCommand{}, err
	}
	digest := sha256.Sum256(payload)
	return SignedMaintenanceCommand{
		KeyID: keyID, SHA256: hex.EncodeToString(digest[:]),
		Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
		Command:   command,
	}, nil
}

func VerifySignedMaintenanceCommand(signed SignedMaintenanceCommand, keyID string, publicKey ed25519.PublicKey, now time.Time) error {
	if signed.KeyID != strings.TrimSpace(keyID) || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("maintenance verification key is invalid")
	}
	if err := ValidateMaintenanceCommand(signed.Command); err != nil {
		return err
	}
	now = now.UTC()
	if now.Before(signed.Command.IssuedAt.Add(-30*time.Second)) || !now.Before(signed.Command.ExpiresAt) {
		return errors.New("maintenance command is outside its validity window")
	}
	payload, err := json.Marshal(signed.Command)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if !strings.EqualFold(signed.SHA256, hex.EncodeToString(digest[:])) {
		return errors.New("maintenance command digest mismatch")
	}
	signature, err := base64.RawStdEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("maintenance command signature is invalid")
	}
	return nil
}

func ValidateMaintenanceResult(result MaintenanceResult) error {
	if uuid.Validate(result.CommandID) != nil || result.OccurredAt.IsZero() {
		return errors.New("maintenance result identity or time is invalid")
	}
	switch strings.ToLower(strings.TrimSpace(result.Action)) {
	case MaintenanceActionCheckUpdate, MaintenanceActionUpdate, MaintenanceActionUninstall:
	default:
		return errors.New("maintenance result action is invalid")
	}
	switch strings.ToLower(strings.TrimSpace(result.Status)) {
	case "accepted", "succeeded", "failed", "checked":
	default:
		return errors.New("maintenance result status is invalid")
	}
	if result.CurrentVersion != "" && result.CurrentVersion != "dev" && !maintenanceVersionPattern.MatchString(result.CurrentVersion) {
		return errors.New("maintenance current version is invalid")
	}
	if result.LatestVersion != "" && !maintenanceVersionPattern.MatchString(result.LatestVersion) {
		return errors.New("maintenance latest version is invalid")
	}
	return nil
}
