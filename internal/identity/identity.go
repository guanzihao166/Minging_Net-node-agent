package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/guanzihao166/iepl-node-agent/internal/config"
)

type Identity struct {
	AgentNodeID            int64  `json:"agent_node_id"`
	MachineID              string `json:"machine_id"`
	WSSURL                 string `json:"wss_url"`
	ConfigSigningKeyID     string `json:"config_signing_key_id"`
	ConfigSigningPublicKey string `json:"config_signing_public_key"`
	CertificateNotAfter    string `json:"certificate_not_after"`
	SecretEnvelopeKey      string `json:"secret_envelope_key"`
}

type enrollmentRequest struct {
	Token     string `json:"token"`
	MachineID string `json:"machine_id"`
	CSRPEM    string `json:"csr_pem"`
}

type enrollmentResponse struct {
	AgentNodeID            int64  `json:"agent_node_id"`
	WSSURL                 string `json:"wss_url"`
	CertificatePEM         string `json:"certificate_pem"`
	CACertificatePEM       string `json:"ca_certificate_pem"`
	ConfigSigningKeyID     string `json:"config_signing_key_id"`
	ConfigSigningPublicKey string `json:"config_signing_public_key"`
	CertificateNotAfter    string `json:"certificate_not_after"`
	SecretEnvelopeKey      string `json:"secret_envelope_key"`
}

func EnsureMachineID(path string) (string, error) {
	if raw, err := os.ReadFile(path); err == nil {
		value := strings.TrimSpace(string(raw))
		if uuid.Validate(value) != nil {
			return "", errors.New("stored machine id is invalid")
		}
		return value, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	value := uuid.NewString()
	if err := atomicWrite(path, []byte(value+"\n"), 0o600); err != nil {
		return "", err
	}
	return value, nil
}

func Enroll(ctx context.Context, cfg config.Config, client *http.Client) (*Identity, error) {
	enrollmentURL, err := url.Parse(strings.TrimSpace(cfg.EnrollmentURL))
	if err != nil || enrollmentURL.Scheme != "https" || enrollmentURL.Host == "" {
		return nil, errors.New("enrollment URL must be absolute HTTPS")
	}
	tokenRaw, err := os.ReadFile(cfg.EnrollmentTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read enrollment token: %w", err)
	}
	if len(tokenRaw) > 4096 || strings.TrimSpace(string(tokenRaw)) == "" {
		return nil, errors.New("enrollment token file is invalid")
	}
	machineID, err := EnsureMachineID(cfg.MachineIDPath())
	if err != nil {
		return nil, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "iepl-agent-" + machineID},
	}, privateKey)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(enrollmentRequest{
		Token: strings.TrimSpace(string(tokenRaw)), MachineID: machineID,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollmentURL.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("enroll agent: %w", err)
	}
	defer response.Body.Close()
	responseRaw, err := io.ReadAll(io.LimitReader(response.Body, 128*1024))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("enroll agent: server returned HTTP %d", response.StatusCode)
	}
	var result enrollmentResponse
	decoder := json.NewDecoder(bytes.NewReader(responseRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, errors.New("enrollment response is invalid")
	}
	identity, err := validateEnrollmentResult(result, machineID, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	identityRaw, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.ConfigDir, 0o700); err != nil {
		return nil, err
	}
	for _, file := range []struct {
		path string
		raw  []byte
		mode os.FileMode
	}{
		{cfg.ClientKeyPath(), privatePEM, 0o600},
		{cfg.ClientCertPath(), []byte(result.CertificatePEM), 0o644},
		{cfg.CACertPath(), []byte(result.CACertificatePEM), 0o644},
		{cfg.IdentityPath(), append(identityRaw, '\n'), 0o600},
	} {
		if err := atomicWrite(file.path, file.raw, file.mode); err != nil {
			return nil, err
		}
	}
	if err := os.Remove(cfg.EnrollmentTokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove consumed enrollment token: %w", err)
	}
	return identity, nil
}

func Load(cfg config.Config) (*Identity, tls.Certificate, ed25519.PublicKey, error) {
	identityRaw, err := os.ReadFile(cfg.IdentityPath())
	if err != nil {
		return nil, tls.Certificate{}, nil, err
	}
	var identity Identity
	decoder := json.NewDecoder(bytes.NewReader(identityRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identity); err != nil {
		return nil, tls.Certificate{}, nil, errors.New("stored identity is invalid")
	}
	certificate, err := tls.LoadX509KeyPair(cfg.ClientCertPath(), cfg.ClientKeyPath())
	if err != nil {
		return nil, tls.Certificate{}, nil, err
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(identity.ConfigSigningPublicKey)
	envelopeKey, envelopeErr := base64.RawStdEncoding.DecodeString(identity.SecretEnvelopeKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || envelopeErr != nil || len(envelopeKey) != 32 || identity.AgentNodeID <= 0 || uuid.Validate(identity.MachineID) != nil {
		return nil, tls.Certificate{}, nil, errors.New("stored identity fields are invalid")
	}
	wssURL, err := url.Parse(identity.WSSURL)
	if err != nil || wssURL.Scheme != "wss" || wssURL.Host == "" {
		return nil, tls.Certificate{}, nil, errors.New("stored WSS URL is invalid")
	}
	return &identity, certificate, ed25519.PublicKey(publicKey), nil
}

func validateEnrollmentResult(result enrollmentResponse, machineID string, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (*Identity, error) {
	if result.AgentNodeID <= 0 || strings.TrimSpace(result.ConfigSigningKeyID) == "" {
		return nil, errors.New("enrollment response identity is incomplete")
	}
	wssURL, err := url.Parse(result.WSSURL)
	if err != nil || wssURL.Scheme != "wss" || wssURL.Host == "" || wssURL.User != nil {
		return nil, errors.New("enrollment WSS URL is invalid")
	}
	signingKey, err := base64.RawStdEncoding.DecodeString(result.ConfigSigningPublicKey)
	if err != nil || len(signingKey) != ed25519.PublicKeySize {
		return nil, errors.New("enrollment config signing key is invalid")
	}
	envelopeKey, err := base64.RawStdEncoding.DecodeString(result.SecretEnvelopeKey)
	if err != nil || len(envelopeKey) != 32 {
		return nil, errors.New("enrollment secret envelope key is invalid")
	}
	caCertificate, err := parseCertificate([]byte(result.CACertificatePEM))
	if err != nil || !caCertificate.IsCA {
		return nil, errors.New("enrollment CA certificate is invalid")
	}
	clientCertificate, err := parseCertificate([]byte(result.CertificatePEM))
	if err != nil || !publicKey.Equal(clientCertificate.PublicKey) || !privateKey.Public().(ed25519.PublicKey).Equal(clientCertificate.PublicKey) {
		return nil, errors.New("enrollment client certificate does not match local key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	if _, err := clientCertificate.Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now(),
	}); err != nil {
		return nil, errors.New("enrollment client certificate chain is invalid")
	}
	notAfter, err := time.Parse(time.RFC3339, result.CertificateNotAfter)
	if err != nil || !notAfter.Equal(clientCertificate.NotAfter) {
		return nil, errors.New("enrollment certificate expiry is invalid")
	}
	return &Identity{
		AgentNodeID: result.AgentNodeID, MachineID: machineID, WSSURL: result.WSSURL,
		ConfigSigningKeyID:     result.ConfigSigningKeyID,
		ConfigSigningPublicKey: result.ConfigSigningPublicKey,
		CertificateNotAfter:    result.CertificateNotAfter,
		SecretEnvelopeKey:      result.SecretEnvelopeKey,
	}, nil
}

func parseCertificate(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate PEM is invalid")
	}
	return x509.ParseCertificate(block.Bytes)
}

func atomicWrite(path string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".iepl-agent-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
