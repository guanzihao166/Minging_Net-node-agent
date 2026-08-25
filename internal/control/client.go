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
	cfg                    config.Config
	identity               *identity.Identity
	cert                   tls.Certificate
	signingKey             ed25519.PublicKey
	store                  *state.Store
	secrets                *secretstore.Store
	runtime                agentruntime.Runtime
	logger                 *slog.Logger
	bootID                 string
	now                    func() time.Time
	rootCAs                *x509.CertPool
	maintenance            *maintenance.Controller
	maintenanceMu          sync.Mutex
	runtimeSyncMu          sync.RWMutex
	lastUpdateCheck        time.Time
	hostMetrics            hostMetricsSampler
	loadRuntimeState       func(context.Context) (state.RuntimeState, error)
	trafficWindowStartedAt time.Time
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
	if cfg.AccessInterval <= 0 {
		cfg.AccessInterval = time.Minute
	}
	maintenanceController, err := maintenance.NewController(cfg, id, signingKey, cfg.Version)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg: cfg, identity: id, cert: certificate, signingKey: append(ed25519.PublicKey(nil), signingKey...),
		store: store, secrets: secrets, runtime: runtime, logger: logger, bootID: uuid.NewString(), now: time.Now,
		maintenance: maintenanceController, hostMetrics: hostmetrics.NewCollector(), loadRuntimeState: store.RuntimeState,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	delay := c.cfg.ReconnectMin
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		established := false
		err := c.runSessionWithEstablished(ctx, func() { established = true })
		if ctx.Err() != nil {
			return nil
		}
		wait, next := reconnectSchedule(delay, c.cfg.ReconnectMin, c.cfg.ReconnectMax, established)
		c.logger.Warn("agent control session ended", "error", err, "retry_in", wait, "session_established", established)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		delay = next
	}
}

func reconnectSchedule(current, minimum, maximum time.Duration, established bool) (time.Duration, time.Duration) {
	if established || current < minimum {
		current = minimum
	}
	next := current * 2
	if current >= maximum || next < current || next > maximum {
		next = maximum
	}
	return current, next
}

type sessionWriter struct {
	mu         sync.Mutex
	connection *websocket.Conn
	now        func() time.Time
}

func (w *sessionWriter) ping() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	deadline := w.now().Add(10 * time.Second)
	return w.connection.WriteControl(websocket.PingMessage, nil, deadline)
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
	return c.runSessionWithEstablished(ctx, nil)
}

func (c *Client) runSessionWithEstablished(ctx context.Context, onEstablished func()) error {
	loadRuntimeState := c.loadRuntimeState
	if loadRuntimeState == nil {
		loadRuntimeState = c.store.RuntimeState
	}
	runtimeState, err := loadRuntimeState(ctx)
	if err != nil {
		return err
	}
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
	if err := c.sendPendingAccess(ctx, writer); err != nil {
		c.logger.Warn("send pending access WAL", "error", err)
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 4)
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(c.now().Add(2*c.cfg.HeartbeatInterval + 30*time.Second))
	})
	go c.runHeartbeatAndTraffic(sessionCtx, writer, helloAck.SessionID, errCh)
	go c.runMaintenance(sessionCtx, writer, errCh)
	go c.runControlKeepalive(sessionCtx, writer, errCh)
	go func() {
		<-sessionCtx.Done()
		_ = connection.Close()
	}()
	secretVersions := make(map[uint64]struct{})
	established := false
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
		case agentprotocol.TypeUserDelta:
			if err := c.applyUserDelta(sessionCtx, writer, envelope); err != nil {
				c.logger.Warn("user delta rejected", "error", err)
			}
		case agentprotocol.TypeUserDisconnect:
			if err := c.applyUserDisconnect(sessionCtx, writer, envelope); err != nil {
				c.logger.Warn("targeted user disconnect failed", "error", err)
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
		case agentprotocol.TypeAccessAck:
			var ack agentprotocol.AccessAck
			if err := agentprotocol.DecodePayload(envelope, &ack); err != nil {
				return err
			}
			switch ack.Status {
			case "accepted", "already_accepted", "discarded", "already_discarded", "partially_applied", "already_partially_applied":
				if err := c.store.AcknowledgeAccess(sessionCtx, ack.BootID, ack.Sequence, ack.PayloadSHA256); err != nil {
					return err
				}
			case "retry_later":
				c.logger.Warn("control server deferred access WAL", "sequence", ack.Sequence)
			default:
				return errors.New("control server returned an invalid access acknowledgement")
			}
		case agentprotocol.TypeHeartbeatAck:
			if !established {
				established = true
				if onEstablished != nil {
					onEstablished()
				}
			}
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

func (c *Client) runControlKeepalive(ctx context.Context, writer *sessionWriter, errCh chan<- error) {
	interval := 20 * time.Second
	if c.cfg.HeartbeatInterval > 0 && 2*c.cfg.HeartbeatInterval < interval {
		interval = 2 * c.cfg.HeartbeatInterval
	}
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := writer.ping(); err != nil {
				sendSessionError(errCh, err)
				return
			}
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
	accessTicker := time.NewTicker(c.cfg.AccessInterval)
	defer heartbeatTicker.Stop()
	defer trafficTicker.Stop()
	defer accessTicker.Stop()
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
			accessBatches, accessBytes, err := c.store.PendingAccessStats(ctx)
			if err != nil {
				sendSessionError(errCh, err)
				return
			}
			pendingBatches += accessBatches
			pendingBytes += accessBytes
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
		case <-accessTicker.C:
			if err := c.collectAndSendAccess(ctx, writer); err != nil {
				c.logger.Warn("collect or send access WAL", "error", err)
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
	if err := c.runtime.DisconnectUsers(ctx, snapshot.Users); err != nil {
		// ApplyUsers performs the existing full-core rebuild as a compatibility
		// fallback. Keep applying the snapshot even if Xray reports a stale user
		// during the explicit close step.
		c.logger.Warn("explicitly disconnect stale user links", "error", err)
	}
	if err := c.runtime.ApplyUsers(ctx, snapshot.Users); err != nil {
		_ = writer.send(agentprotocol.TypeUserResult, agentprotocol.UserResult{
			Revision: snapshot.Revision, Status: "failed", ErrorCode: "user_apply_failed",
			ErrorMessage: "runtime rejected user snapshot",
		})
		return err
	}
	return c.persistAppliedUsers(ctx, snapshot.Revision, snapshot.Users, writer)
}

func (c *Client) applyUserDelta(ctx context.Context, writer *sessionWriter, envelope agentprotocol.Envelope) error {
	var delta agentprotocol.UserDelta
	if err := agentprotocol.DecodePayload(envelope, &delta); err != nil {
		return err
	}
	c.runtimeSyncMu.Lock()
	defer c.runtimeSyncMu.Unlock()
	users, err := c.runtime.ApplyUserDelta(ctx, delta)
	if err != nil {
		_ = writer.send(agentprotocol.TypeUserResult, agentprotocol.UserResult{Revision: delta.Revision, Status: "failed", ErrorCode: "user_delta_apply_failed", ErrorMessage: "runtime rejected user delta"})
		return err
	}
	return c.persistAppliedUsers(ctx, delta.Revision, users, writer)
}

func (c *Client) persistAppliedUsers(ctx context.Context, revision uint64, users []agentprotocol.UserCredential, writer *sessionWriter) error {
	storedSnapshot := agentprotocol.UserSnapshot{Revision: revision, Users: append([]agentprotocol.UserCredential(nil), users...)}
	for index := range storedSnapshot.Users {
		user := &storedSnapshot.Users[index]
		secretRef := fmt.Sprintf("user-secret:%s_%d:%d:%d", normalizedCredentialKind(user.Kind), user.InboundID, user.SubscriberID, revision)
		if err := c.secrets.Put(secretRef, []byte(user.Value)); err != nil {
			return err
		}
		user.Value = secretRef
	}
	if err := c.store.ReplaceUsers(ctx, storedSnapshot); err != nil {
		return err
	}
	return writer.send(agentprotocol.TypeUserResult, agentprotocol.UserResult{Revision: revision, Status: "succeeded"})
}

func (c *Client) applyUserDisconnect(ctx context.Context, writer *sessionWriter, envelope agentprotocol.Envelope) error {
	var request agentprotocol.UserDisconnect
	if err := agentprotocol.DecodePayload(envelope, &request); err != nil {
		return err
	}
	c.runtimeSyncMu.Lock()
	defer c.runtimeSyncMu.Unlock()
	if err := c.runtime.DisconnectSubscribers(ctx, request.SubscriberIDs); err != nil {
		_ = writer.send(agentprotocol.TypeUserResult, agentprotocol.UserResult{Status: "failed", ErrorCode: "targeted_disconnect_failed", ErrorMessage: "runtime rejected targeted disconnect"})
		return err
	}
	return writer.send(agentprotocol.TypeUserResult, agentprotocol.UserResult{Status: "succeeded"})
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
	intervalEndedAt := c.now().UTC()
	intervalStartedAt := c.trafficWindowStartedAt
	if intervalStartedAt.IsZero() || !intervalEndedAt.After(intervalStartedAt) {
		intervalStartedAt = intervalEndedAt.Add(-c.cfg.TrafficInterval)
	}
	if err := c.store.AddTrafficWindow(ctx, deltas, intervalStartedAt, intervalEndedAt); err != nil {
		return err
	}
	c.trafficWindowStartedAt = intervalEndedAt
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

func (c *Client) collectAndSendAccess(ctx context.Context, writer *sessionWriter) error {
	c.runtimeSyncMu.RLock()
	items, err := c.runtime.CollectAccess(ctx)
	c.runtimeSyncMu.RUnlock()
	if err != nil {
		return err
	}
	if len(items) > 0 {
		if err := c.store.AddAccess(ctx, items); err != nil {
			c.runtime.RequeueAccess(items)
			return err
		}
	}
	runtimeState, err := c.store.RuntimeState(ctx)
	if err != nil {
		return err
	}
	if _, err := c.store.DrainAccess(ctx, c.bootID, runtimeState.AppliedConfigVersion); err != nil {
		return err
	}
	return c.sendPendingAccess(ctx, writer)
}

func (c *Client) sendPendingAccess(ctx context.Context, writer *sessionWriter) error {
	pending, err := c.store.PendingAccess(ctx, 100)
	if err != nil {
		return err
	}
	for _, batch := range pending {
		if err := writer.send(agentprotocol.TypeAccessBatch, batch); err != nil {
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
