package agentprotocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const TypeSecretBundle = "secret_bundle"

type SecretMaterial struct {
	Ref   string `json:"ref"`
	Value string `json:"value"`
}

type SecretEnvelope struct {
	AgentNodeID   int64  `json:"agent_node_id"`
	ConfigVersion uint64 `json:"config_version"`
	SHA256        string `json:"sha256"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
}

func SealSecretEnvelope(key []byte, agentNodeID int64, configVersion uint64, materials []SecretMaterial) (SecretEnvelope, error) {
	if len(key) != 32 || agentNodeID <= 0 || configVersion == 0 || len(materials) > 1000 {
		return SecretEnvelope{}, errors.New("secret envelope input is invalid")
	}
	canonical, err := canonicalSecretMaterials(materials)
	if err != nil {
		return SecretEnvelope{}, err
	}
	plaintext, err := json.Marshal(canonical)
	if err != nil {
		return SecretEnvelope{}, err
	}
	digest := sha256.Sum256(plaintext)
	aead, err := secretAEAD(key)
	if err != nil {
		return SecretEnvelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return SecretEnvelope{}, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, secretAAD(agentNodeID, configVersion))
	return SecretEnvelope{
		AgentNodeID: agentNodeID, ConfigVersion: configVersion,
		SHA256:     hex.EncodeToString(digest[:]),
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	}, nil
}

func OpenSecretEnvelope(key []byte, envelope SecretEnvelope) ([]SecretMaterial, error) {
	if len(key) != 32 || envelope.AgentNodeID <= 0 || envelope.ConfigVersion == 0 {
		return nil, errors.New("secret envelope identity is invalid")
	}
	aead, err := secretAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce, nonceErr := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	ciphertext, ciphertextErr := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if nonceErr != nil || ciphertextErr != nil || len(nonce) != aead.NonceSize() {
		return nil, errors.New("secret envelope encoding is invalid")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, secretAAD(envelope.AgentNodeID, envelope.ConfigVersion))
	if err != nil {
		return nil, errors.New("secret envelope authentication failed")
	}
	digest := sha256.Sum256(plaintext)
	if !strings.EqualFold(envelope.SHA256, hex.EncodeToString(digest[:])) {
		return nil, errors.New("secret envelope digest mismatch")
	}
	var materials []SecretMaterial
	decoder := json.NewDecoder(strings.NewReader(string(plaintext)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&materials); err != nil {
		return nil, errors.New("secret envelope payload is invalid")
	}
	return canonicalSecretMaterials(materials)
}

func canonicalSecretMaterials(materials []SecretMaterial) ([]SecretMaterial, error) {
	canonical := append([]SecretMaterial(nil), materials...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Ref < canonical[j].Ref })
	for index := range canonical {
		if strings.TrimSpace(canonical[index].Ref) == "" || strings.TrimSpace(canonical[index].Value) == "" {
			return nil, errors.New("secret material is incomplete")
		}
		if index > 0 && canonical[index-1].Ref == canonical[index].Ref {
			return nil, errors.New("secret material reference is duplicated")
		}
		if _, err := base64.RawStdEncoding.DecodeString(canonical[index].Value); err != nil {
			return nil, errors.New("secret material value is invalid")
		}
	}
	return canonical, nil
}

func secretAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func secretAAD(agentNodeID int64, configVersion uint64) []byte {
	return []byte(fmt.Sprintf("iepl-agent-secret:v1:%d:%d", agentNodeID, configVersion))
}
