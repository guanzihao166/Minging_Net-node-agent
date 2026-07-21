package agentprotocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

type SignedConfig struct {
	KeyID     string        `json:"key_id"`
	SHA256    string        `json:"sha256"`
	Signature string        `json:"signature"`
	Config    DesiredConfig `json:"config"`
}

func SignConfig(config DesiredConfig, keyID string, privateKey ed25519.PrivateKey) (SignedConfig, error) {
	if err := ValidateDesiredConfig(config); err != nil {
		return SignedConfig{}, err
	}
	if keyID == "" || len(privateKey) != ed25519.PrivateKeySize {
		return SignedConfig{}, errors.New("config signing key is invalid")
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return SignedConfig{}, err
	}
	digest := sha256.Sum256(payload)
	return SignedConfig{
		KeyID:     keyID,
		SHA256:    hex.EncodeToString(digest[:]),
		Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
		Config:    config,
	}, nil
}

func VerifySignedConfig(signed SignedConfig, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("config verification key is invalid")
	}
	if err := ValidateDesiredConfig(signed.Config); err != nil {
		return err
	}
	payload, err := json.Marshal(signed.Config)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	if signed.SHA256 != hex.EncodeToString(digest[:]) {
		return errors.New("config digest mismatch")
	}
	signature, err := base64.RawStdEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("config signature is invalid")
	}
	return nil
}
