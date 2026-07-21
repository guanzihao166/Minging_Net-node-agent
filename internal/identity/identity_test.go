package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guanzihao166/iepl-node-agent/internal/config"
)

func TestEnrollPersistsVerifiedIdentityAndConsumesToken(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caCertificate, caPrivate, caPEM := testCA(t, now)
	signingPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("token") != "" {
			t.Error("enrollment token was placed in URL")
		}
		var input enrollmentRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(input.CSRPEM))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Error("invalid CSR")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: csr.Subject,
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, csr.PublicKey, caPrivate)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(writer).Encode(enrollmentResponse{
			AgentNodeID:            17,
			WSSURL:                 "wss://agent.example.test/api/v1/agent/connect",
			CertificatePEM:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			CACertificatePEM:       string(caPEM),
			ConfigSigningKeyID:     "test-key",
			ConfigSigningPublicKey: base64.RawStdEncoding.EncodeToString(signingPublic),
			CertificateNotAfter:    template.NotAfter.Format(time.RFC3339),
			SecretEnvelopeKey:      base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
		})
	}))
	defer server.Close()
	root := t.TempDir()
	cfg := config.Config{
		StateDir: filepath.Join(root, "state"), ConfigDir: filepath.Join(root, "config"),
		EnrollmentURL:       server.URL + "/api/v1/agent/enroll",
		EnrollmentTokenFile: filepath.Join(root, "token"),
	}
	if err := os.WriteFile(cfg.EnrollmentTokenFile, []byte("one-time-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Enroll(context.Background(), cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentNodeID != 17 || got.MachineID == "" {
		t.Fatalf("identity = %#v", got)
	}
	if _, err := os.Stat(cfg.EnrollmentTokenFile); !os.IsNotExist(err) {
		t.Fatalf("token file still exists: %v", err)
	}
	loaded, certificate, loadedSigningKey, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MachineID != got.MachineID || len(certificate.Certificate) == 0 || !loadedSigningKey.Equal(signingPublic) {
		t.Fatalf("loaded identity does not match enrollment")
	}
}

func testCA(t *testing.T, now time.Time) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test agent CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
