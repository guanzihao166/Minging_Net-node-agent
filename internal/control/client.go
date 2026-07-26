package control

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/guanzihao166/iepl-node-agent/internal/config"
	"github.com/guanzihao166/iepl-node-agent/internal/hostmetrics"
	"github.com/guanzihao166/iepl-node-agent/internal/identity"
	"github.com/guanzihao166/iepl-node-agent/internal/maintenance"
	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
	agentruntime "github.com/guanzihao166/iepl-node-agent/internal/runtime"
	"github.com/guanzihao166/iepl-node-agent/internal/secretstore"
	"github.com/guanzihao166/iepl-node-agent/internal/state"
)

type Client struct {
	cfg             config.Config
	identity        *identity.Identity
	cert            tls.Certificate
	signingKey      ed25519.PublicKey
	store           *state.Store
	secrets         *secretstore.Store
	runtime         agentruntime.Runtime
	logger          *slog.Logger
	bootID          string
	now             func() time.Time
	rootCAs         *x509.CertPool
	maintenance     *maintenance.Controller
	maintenanceMu   sync.Mutex
	runtimeSyncMu   sync.RWMutex
	lastUpdateCheck time.Time
	hostMetrics     hostMetricsSampler
}

type hostMetricsSampler interface {
	Sample() (hostmetrics.Snapshot, error)
}

func New(cfg config.Config, id *identity.Identity, certificate tls.Certificate, signingKey ed25519.PublicKey, store *state.Store, secrets *secretstore.Store, runtime agentruntime.Runtime, logger *slog.Logger) (*Client, error) {
	if id == nil || id.AgentNodeID <= 0 || len(signingKey) != ed25519.PublicKeySize || store == nil || secrets == nil || runtime == nil {
		return nil, errors.New("control client dependencies are incomplete")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.UpdateCheckInterval < time.Minute {
		cfg.UpdateCheckInterval = time.Hour
	}
	maintenanceController, err := maintenance.NewController(cfg, id, signingKey, cfg.Version)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg: cfg, identity: id, cert: certificate, signingKey: append(ed25519.PublicKey(nil), signingKey...),
		store: store, secrets: secrets, runtime: runtime, logger: logger, bootID: uuid.NewString(), now: time.Now,
		maintenance: maintenanceController, hostMetrics: hostmetrics.NewCollector(),
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	delay := c.cfg.ReconnectMin
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		err := c.runSession(ctx)
		if ctx.Err() != nil {
			return nil
		}
		c.logger.Warn("agent control session ended", "error", err, "retry_in", delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		delay *= 2
		if delay > c.cfg.ReconnectMax {
			delay = c.cfg.ReconnectMax
		}
	}
}

type sessionWriter struct {
	mu         sync.Mutex
	connection *websocket.Conn
	now        func() time.Time
}

func (w *sessionWriter) send(messageType string, payload any) error {
	envelope, err := agentprotocol.NewEnvelope(uuid.NewString(), messageType, payload, w.now())
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.connection.SetWriteDeadline(w.now().Add(10 * time.Second))
	return w.connection.WriteJSON(envelope)
}

func (c *Client) runSession(ctx context.Context) error {
	dialer := websocket.Dialer{
		Proxy: http.ProxyFromEnvironment, HandshakeTimeout: 15 * time.Second,
		EnableCompression: false,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{c.cert},
			RootCAs:      c.rootCAs,
		},
	}
	connection, response, err := dialer.DialContext(ctx, c.identity.WSSURL, nil)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return fmt.Errorf("dial control WSS: %w", err)
	}
	defer connection.Close()
	connection.SetReadLimit(c.cfg.MaxFrameBytes)
	writer := &sessionWriter{connection: connection, now: c.now}
	runtimeState, err := c.store.RuntimeState(ctx)
	if err != nil {
		return err
	}
	hello := agentprotocol.Hello{
		ProtocolVersion: agentprotocol.ProtocolVersion,
		MachineID:       c.identity.MachineID, BootID: c.bootID, AgentVersion: c.cfg.Version,
		AppliedConfigVersion: runtimeState.AppliedConfigVersion,
		AppliedConfigHash:    runtimeState.AppliedConfigHash,
		AppliedUserRevision:  runtimeState.AppliedUserRevision,
	}
	if err := writer.send(agentprotocol.TypeHello, hello); err != nil {
		return err
	}
	_ = connection.SetReadDeadline(c.now().Add(30 * time.Second))
	var ackEnvelope agentprotocol.Envelope
	if err := connection.ReadJSON(&ackEnvelope); err != nil {
		return err
	}
	if ackEnvelope.Type != agentprotocol.TypeHelloAck {
		return errors.New("control server did not acknowledge hello")
	}
	var helloAck agentprotocol.HelloAck
	if err := agentprotocol.DecodePayload(ackEnvelope, &helloAck); err != nil || helloAck.ProtocolVersion != agentprotocol.ProtocolVersion || helloAck.SessionID == "" {
		return errors.New("control hello acknowledgement is invalid")
	}
	if err := c.sendPendingTraffic(ctx, writer); err != nil {
		return err
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 3)
	go c.runHeartbeatAndTraffic(sessionCtx, writer, helloAck.SessionID, errCh)
	go c.runMaintenance(sessionCtx, writer, errCh)
	go func() {
		<-sessionCtx.Done()
		_ = connection.Close()
	}()
	secretVersions := make(map[uint64]struct{})
	for {
		_ = connection.SetReadDeadline(c.now().Add(2*c.cfg.HeartbeatInterval + 30*time.Second))
		messageType, raw, err := connection.ReadMessage()
		if err != nil {
			return err
		}
		if messageType != websocket.TextMessage {
			return errors.New("control server sent a non-text frame")
		}
		envelope, err := agentprotocol.DecodeEnvelope(raw)
		if err != nil {
			return err
		}
		switch envelope.Type {
		case agentprotocol.TypeSecretBundle:
			version, err := c.applySecretEnvelope(envelope)
			if err != nil {
				return err
			}
			secretVersions[version] = struct{}{}
		case agentprotocol.TypeDesiredConfig:
			if err := c.applyDesiredConfig(sessionCtx, writer, envelope, secretVersions); err != nil {
				c.logger.Warn("desired config rejected", "error", err)
			}
		case agentprotocol.TypeUserSnapshot:
			if err := c.applyUserSnapshot(sessionCtx, writer, envelope); err != nil {
				c.logger.Warn("user snapshot rejected", "error", err)
			}
		case agentprotocol.TypeTrafficAck:
			var ack agentprotocol.TrafficAck
			if err := agentprotocol.DecodePayload(envelope, &ack); err != nil {
				return err
			}
			if ack.Status != "accepted" && ack.Status != "already_accepted" {
				return errors.New("control server rejected a traffic batch")
			}
			if err := c.store.AcknowledgeTraffic(sessionCtx, ack.BootID, ack.Sequence, ack.PayloadSHA256); err != nil {
				return err
			}
		case agentprotocol.TypeHeartbeatAck:
		case agentprotocol.TypeMaintenanceCommand:
			var command agentprotocol.SignedMaintenanceCommand
			if err := agentprotocol.DecodePayload(envelope, &command); err != nil {
				return err
			}
			result := c.maintenance.HandleCommand(sessionCtx, command)
			if err := writer.send(agentprotocol.TypeMaintenanceResult, result); err != nil {
				return err
			}
		case agentprotocol.TypeError:
			return errors.New("control server returned an error")
		default:
			return errors.New("control server sent an unsupported message")
		}
		select {
		case err := <-errCh:
			return err
		default:
		}
	}
}

func (c *Client) runMaintenance(ctx context.Context, writer *sessionWriter, errCh chan<- error) {
	checkPollInterval := c.cfg.UpdateCheckInterval
	if checkPollInterval > time.Minute {
		checkPollInterval = time.Minute
	}
	checkTicker := time.NewTicker(checkPollInterval)
	resultTicker := time.NewTicker(3 * time.Second)
	defer checkTicker.Stop()
	defer resultTicker.Stop()
	check := func() bool {
		c.maintenanceMu.Lock()
		if !c.lastUpdateCheck.IsZero() && c.now().Sub(c.lastUpdateCheck) < c.cfg.UpdateCheckInterval {
			c.maintenanceMu.Unlock()
			return true
		}
		c.lastUpdateCheck = c.now()
		c.maintenanceMu.Unlock()
		result := c.maintenance.CheckUpdate(ctx, uuid.NewString())
		if err := writer.send(agentprotocol.TypeMaintenanceResult, result); err != nil {
			sendSessionError(errCh, err)
			return false
		}
		return true
	}
	takeResult := func() bool {
		result, err := c.maintenance.CompletedResult()
		if err != nil {
			c.logger.Warn("read completed maintenance result", "error", err)
			return true
		}
		if result == nil {
			return true
		}
		if err := writer.send(agentprotocol.TypeMaintenanceResult, *result); err != nil {
			sendSessionError(errCh, err)
			return false
		}
		if err := c.maintenance.ClearCompletedResult(result.CommandID); err != nil {
			c.logger.Warn("acknowledge completed maintenance result", "error", err)
		}
		return true
	}
	// The completion result is sent last so a reconnecting upgrade is not
	// immediately hidden by the routine release check status.
	if !check() || !takeResult() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-checkTicker.C:
			if !check() {
				return
			}
		case <-resultTicker.C:
			if !takeResult() {
				return
			}
		}
	}
}

func (c *Client) runHeartbeatAndTraffic(ctx context.Context, writer *sessionWriter, sessionID string, errCh chan<- error) {
	heartbeatTicker := time.NewTicker(c.cfg.HeartbeatInterval)
	trafficTicker := time.NewTicker(c.cfg.TrafficInterval)
	defer heartbeatTicker.Stop()
	defer trafficTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeatTicker.C:
			stateValue, err := c.store.RuntimeState(ctx)
			if err != nil {
				sendSessionError(errCh, err)
				return
			}
			pendingBatches, pendingBytes, err := c.store.PendingTrafficStats(ctx)
			if err != nil {
				sendSessionError(errCh, err)
				return
			}
			runtimeStatus := c.runtime.Status(ctx)
			var systemMetrics *agentprotocol.SystemMetrics
			if c.hostMetrics != nil {
				sample, sampleErr := c.hostMetrics.Sample()
				if sampleErr != nil {
					c.logger.Warn("collect host metrics", "error", sampleErr)
				} else {
					systemMetrics = &agentprotocol.SystemMetrics{
						SampledAt: sample.SampledAt, CPUPercent: sample.CPUPercent,
						MemoryPercent: sample.MemoryPercent, MemoryUsedBytes: sample.MemoryUsedBytes,
						MemoryTotalBytes:  sample.MemoryTotalBytes,
						NetworkReceiveBPS: sample.NetworkReceiveBPS, NetworkTransmitBPS: sample.NetworkTransmitBPS,
						UptimeSeconds: sample.UptimeSeconds,
					}
				}
			}
			err = writer.send(agentprotocol.TypeHeartbeat, agentprotocol.Heartbeat{
				SessionID:            sessionID,
				AppliedConfigVersion: stateValue.AppliedConfigVersion,
				AppliedConfigHash:    stateValue.AppliedConfigHash,
				AppliedUserRevision:  stateValue.AppliedUserRevision,
				WALPendingBatches:    pendingBatches, WALPendingBytes: pendingBytes,
				XrayRunning: runtimeStatus.Running, XrayVersion: runtimeStatus.Version,
				SystemMetrics: systemMetrics,
			})
			if err != nil {
				sendSessionError(errCh, err)
				return
			}
		case <-trafficTicker.C:
			if err := c.collectAndSendTraffic(ctx, writer); err != nil {
				sendSessionError(errCh, err)
				return
			}
			if err := c.collectAndSendOnline(ctx, writer); err != nil {
				sendSessionError(errCh, err)
				return
			}
		}
	}
}

func (c *Client) collectAndSendOnline(ctx context.Context, writer *sessionWriter) error {
	c.runtimeSyncMu.RLock()
	online, err := c.runtime.CollectOnline(ctx)
	c.runtimeSyncMu.RUnlock()
	if err != nil {
		return err
	}
	return writer.send(agentprotocol.TypeOnlineSnapshot, agentprotocol.OnlineSnapshot{
		CapturedAt: c.now().UTC(), Users: online,
	})
}

func (c *Client) applyDesiredConfig(ctx context.Context, writer *sessionWriter, envelope agentprotocol.Envelope, secretVersions map[uint64]struct{}) error {
	var signed agentprotocol.SignedConfig
	if err := agentprotocol.DecodePayload(envelope, &signed); err != nil {
		return err
	}
	if signed.KeyID != c.identity.ConfigSigningKeyID || signed.Config.AgentNodeID != c.identity.AgentNodeID {
		return errors.New("desired config identity is invalid")
	}
	if err := agentprotocol.VerifySignedConfig(signed, c.signingKey); err != nil {
		return err
	}
	if _, ok := secretVersions[signed.Config.Version]; !ok {
		return errors.New("desired config secret envelope is missing")
	}
	c.runtimeSyncMu.Lock()
	defer c.runtimeSyncMu.Unlock()
	inserted, err := c.store.SaveDesiredConfig(ctx, signed)
	if err != nil {
		return err
	}
	if inserted {
		if err := c.runtime.ApplyConfig(ctx, signed.Config); err != nil {
			_ = writer.send(agentprotocol.TypeConfigResult, agentprotocol.ConfigResult{
				Version: signed.Config.Version, SHA256: signed.SHA256, Status: "failed",
				ErrorCode: "xray_apply_failed", ErrorMessage: "candidate runtime state was rejected",
			})
			return err
		}
		if err := c.store.MarkConfigApplied(ctx, signed.Config.Version, signed.SHA256); err != nil {
			return err
		}
	}
	return writer.send(agentprotocol.TypeConfigResult, agentprotocol.ConfigResult{
		Version: signed.Config.Version, SHA256: signed.SHA256, Status: "succeeded",
	})
}

func (c *Client) applySecretEnvelope(envelope agentprotocol.Envelope) (uint64, error) {
	var sealed agentprotocol.SecretEnvelope
	if err := agentprotocol.DecodePayload(envelope, &sealed); err != nil {
		return 0, err
	}
	if sealed.AgentNodeID != c.identity.AgentNodeID {
		return 0, errors.New("secret envelope agent identity is invalid")
	}
	envelopeKey, err := base64.RawStdEncoding.DecodeString(c.identity.SecretEnvelopeKey)
	if err != nil || len(envelopeKey) != 32 {
		return 0, errors.New("local secret envelope key is invalid")
	}
	materials, err := agentprotocol.OpenSecretEnvelope(envelopeKey, sealed)
	if err != nil {
		return 0, err
	}
	for _, material := range materials {
		plaintext, err := base64.RawStdEncoding.DecodeString(material.Value)
		if err != nil || len(plaintext) == 0 {
			return 0, errors.New("secret material is invalid")
		}
		if err := c.secrets.Put(material.Ref, plaintext); err != nil {
			return 0, err
		}
	}
	return sealed.ConfigVersion, nil
}

func (c *Client) applyUserSnapshot(ctx context.Context, writer *sessionWriter, envelope agentprotocol.Envelope) error {
	var snapshot agentprotocol.UserSnapshot
	if err := agentprotocol.DecodePayload(envelope, &snapshot); err != nil {
		return err
	}
	c.runtimeSyncMu.Lock()
	defer c.runtimeSyncMu.Unlock()
	if err := c.runtime.ApplyUsers(ctx, snapshot.Users); err != nil {
		_ = writer.send(agentprotocol.TypeUserResult, agentprotocol.UserResult{
			Revision: snapshot.Revision, Status: "failed", ErrorCode: "user_apply_failed",
			ErrorMessage: "runtime rejected user snapshot",
		})
		return err
	}
	storedSnapshot := snapshot
	storedSnapshot.Users = append([]agentprotocol.UserCredential(nil), snapshot.Users...)
	for index := range storedSnapshot.Users {
		user := &storedSnapshot.Users[index]
		secretRef := fmt.Sprintf("user-secret:%s_%d:%d:%d", normalizedCredentialKind(user.Kind), user.InboundID, user.SubscriberID, snapshot.Revision)
		if err := c.secrets.Put(secretRef, []byte(user.Value)); err != nil {
			return err
		}
		user.Value = secretRef
	}
	if err := c.store.ReplaceUsers(ctx, storedSnapshot); err != nil {
		return err
	}
	return writer.send(agentprotocol.TypeUserResult, agentprotocol.UserResult{Revision: snapshot.Revision, Status: "succeeded"})
}

func normalizedCredentialKind(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_' || char == '-' {
			out.WriteRune(char)
		}
	}
	if out.Len() == 0 {
		return "credential"
	}
	return out.String()
}

func (c *Client) collectAndSendTraffic(ctx context.Context, writer *sessionWriter) error {
	c.runtimeSyncMu.RLock()
	deltas, err := c.runtime.CollectTraffic(ctx)
	c.runtimeSyncMu.RUnlock()
	if err != nil {
		return err
	}
	if err := c.store.AddTraffic(ctx, deltas); err != nil {
		return err
	}
	runtimeState, err := c.store.RuntimeState(ctx)
	if err != nil {
		return err
	}
	if _, err := c.store.DrainTraffic(ctx, c.bootID, runtimeState.AppliedConfigVersion); err != nil {
		return err
	}
	return c.sendPendingTraffic(ctx, writer)
}

func (c *Client) sendPendingTraffic(ctx context.Context, writer *sessionWriter) error {
	pending, err := c.store.PendingTraffic(ctx, 100)
	if err != nil {
		return err
	}
	for _, batch := range pending {
		if err := writer.send(agentprotocol.TypeTrafficBatch, batch); err != nil {
			return err
		}
	}
	return nil
}

func sendSessionError(channel chan<- error, err error) {
	select {
	case channel <- err:
	default:
	}
}
