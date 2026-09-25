package control

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

func proveSession(connection *websocket.Conn, certificate tls.Certificate, endpoint string, now time.Time) error {
	_ = connection.SetReadDeadline(now.Add(10 * time.Second))
	_ = connection.SetWriteDeadline(now.Add(10 * time.Second))
	var envelope agentprotocol.Envelope
	if err := connection.ReadJSON(&envelope); err != nil {
		return err
	}
	if envelope.Type != "auth_challenge" {
		return errors.New("control authentication challenge is required")
	}
	var challenge struct {
		Nonce    string `json:"nonce"`
		Audience string `json:"audience"`
	}
	if err := agentprotocol.DecodePayload(envelope, &challenge); err != nil {
		return err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	address, parseErr := url.Parse(endpoint)
	if err != nil || len(nonce) != 32 || parseErr != nil || address.Host != challenge.Audience {
		return errors.New("control authentication challenge is invalid")
	}
	key, ok := certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(certificate.Certificate) == 0 {
		return errors.New("client proof key is unavailable")
	}
	message := []byte("Minging_Net-agent-session-v1\n" + challenge.Audience + "\n" + challenge.Nonce)
	proof := struct {
		CertificatePEM string `json:"certificate_pem"`
		Signature      string `json:"signature"`
	}{
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})),
		Signature:      base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message)),
	}
	response, err := agentprotocol.NewEnvelope("session-proof", "auth_proof", proof, now)
	if err != nil {
		return err
	}
	if err = connection.WriteJSON(response); err != nil {
		return err
	}
	if err = connection.ReadJSON(&envelope); err != nil {
		return err
	}
	if envelope.Type != "auth_ok" || envelope.ReplyTo != response.ID {
		return errors.New("control authentication was rejected")
	}
	return nil
}
