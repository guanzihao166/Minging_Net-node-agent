package maintenance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/guanzihao166/iepl-node-agent/internal/config"
	"github.com/guanzihao166/iepl-node-agent/internal/identity"
	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

const (
	releaseDownloadBase        = "https://github.com/guanzihao166/iepl-node-agent/releases/download"
	releaseDownloadAttempts    = 3
	releaseDownloadRetryDelay  = 2 * time.Second
	agentServiceStartupTimeout = 60 * time.Second
)

var errManagerUninstalled = errors.New("agent uninstalled")

type releaseDownloadHTTPError struct {
	statusCode int
}

func (e releaseDownloadHTTPError) Error() string {
	return fmt.Sprintf("release download returned HTTP %d", e.statusCode)
}

type Manager struct {
	cfg        config.Config
	identity   *identity.Identity
	signingKey ed25519.PublicKey
	version    string
	logger     *slog.Logger
	now        func() time.Time
	client     *http.Client
	retryDelay func(int) time.Duration
}

func NewManager(cfg config.Config, id *identity.Identity, signingKey ed25519.PublicKey, version string, logger *slog.Logger) (*Manager, error) {
	if id == nil || id.AgentNodeID <= 0 || len(signingKey) != ed25519.PublicKeySize || strings.TrimSpace(version) == "" {
		return nil, errors.New("maintenance manager dependencies are incomplete")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		cfg: cfg, identity: id, signingKey: append(ed25519.PublicKey(nil), signingKey...),
		version: strings.TrimSpace(version), logger: logger, now: time.Now,
		client: &http.Client{Timeout: 2 * time.Minute},
		retryDelay: func(attempt int) time.Duration {
			return time.Duration(attempt) * releaseDownloadRetryDelay
		},
	}, nil
}

func (m *Manager) Run(ctx context.Context) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("maintenance manager requires Linux root")
	}
	if err := os.MkdirAll(m.cfg.MaintenanceStateDir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(m.cfg.MaintenanceStateDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.MaintenanceProcessedDir(), 0o700); err != nil {
		return err
	}
	if err := m.refreshReady(); err != nil {
		return err
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	cleanupTicker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	defer cleanupTicker.Stop()
	for {
		if err := m.refreshReady(); err != nil {
			m.logger.Error("refresh maintenance readiness", "error", err)
		}
		if err := m.processRequests(ctx); err != nil {
			if errors.Is(err, errManagerUninstalled) {
				return nil
			}
			m.logger.Error("maintenance request processing failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-cleanupTicker.C:
			m.cleanupProcessed()
		}
	}
}

func (m *Manager) refreshReady() error {
	if err := os.WriteFile(m.cfg.MaintenanceReadyPath(), []byte(m.now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Chmod(m.cfg.MaintenanceReadyPath(), 0o644)
}

func (m *Manager) processRequests(ctx context.Context) error {
	entries, err := os.ReadDir(m.cfg.MaintenanceRequestDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if info, infoErr := entry.Info(); infoErr != nil || info.ModTime().After(m.now().Add(-2*time.Second)) {
			continue
		}
		path := filepath.Join(m.cfg.MaintenanceRequestDir(), entry.Name())
		if err := m.processRequest(ctx, path); err != nil {
			if errors.Is(err, errManagerUninstalled) {
				return err
			}
			m.logger.Warn("maintenance request rejected", "file", entry.Name(), "error", err)
		}
		_ = os.Remove(path)
	}
	return nil
}

func (m *Manager) processRequest(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return errors.New("maintenance request is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return errors.New("maintenance request changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return err
	}
	if len(raw) > 64*1024 {
		return errors.New("maintenance request is too large")
	}
	var signed agentprotocol.SignedMaintenanceCommand
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return err
	}
	if signed.Command.AgentNodeID != m.identity.AgentNodeID {
		return errors.New("maintenance request belongs to another Agent")
	}
	if err := agentprotocol.VerifySignedMaintenanceCommand(signed, m.identity.ConfigSigningKeyID, m.signingKey, m.now()); err != nil {
		return err
	}
	marker := filepath.Join(m.cfg.MaintenanceProcessedDir(), signed.Command.CommandID)
	if _, err := os.Stat(marker); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if signed.Command.Action == agentprotocol.MaintenanceActionUninstall {
		if err := m.markProcessed(marker); err != nil {
			return err
		}
		if err := m.uninstall(ctx); err != nil {
			_ = m.writeResult(agentprotocol.MaintenanceResult{
				CommandID: signed.Command.CommandID, Action: signed.Command.Action, Status: "failed",
				CurrentVersion: m.version, Message: "彻底卸载执行失败：" + compactMessage(err.Error(), 300), OccurredAt: m.now().UTC(),
			})
			return err
		}
		return errManagerUninstalled
	}
	if signed.Command.Action != agentprotocol.MaintenanceActionUpdate {
		return errors.New("maintenance request action is not handled by the root manager")
	}
	result := agentprotocol.MaintenanceResult{
		CommandID: signed.Command.CommandID, Action: signed.Command.Action,
		Status: "succeeded", CurrentVersion: signed.Command.TargetVersion,
		LatestVersion: signed.Command.TargetVersion, Message: "Agent 已更新并重新连接",
		OccurredAt: m.now().UTC(),
	}
	if err := m.installRelease(ctx, signed.Command.TargetVersion); err != nil {
		result.Status = "failed"
		result.CurrentVersion = m.version
		result.Message = "Agent 更新失败，已保留原版本：" + compactMessage(err.Error(), 300)
	}
	if err := m.markProcessed(marker); err != nil {
		return err
	}
	if err := m.writeResult(result); err != nil {
		return err
	}
	if result.Status == "succeeded" {
		m.version = signed.Command.TargetVersion
		arguments := []string{
			"/opt/iepl-agent/bin/iepl-agent", "maintain",
			"--state-dir", m.cfg.StateDir,
			"--config-dir", m.cfg.ConfigDir,
			"--runtime-dir", m.cfg.RuntimeDir,
			"--maintenance-dir", m.cfg.MaintenanceDir,
			"--maintenance-state-dir", m.cfg.MaintenanceStateDir,
		}
		if err := replaceProcess(arguments[0], arguments, os.Environ()); err != nil {
			return fmt.Errorf("activate updated maintenance manager: %w", err)
		}
	}
	return nil
}

func (m *Manager) installRelease(ctx context.Context, targetVersion string) error {
	if !validReleaseVersion(targetVersion) || !versionNewer(targetVersion, m.version) {
		return errors.New("target release is not newer than the running version")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
	}
	asset := "iepl-agent-linux-" + runtime.GOARCH
	base := releaseDownloadBase + "/" + targetVersion
	checksums, err := m.download(ctx, base+"/checksums.txt", 1024*1024)
	if err != nil {
		return err
	}
	expected, err := checksumForAsset(checksums, asset)
	if err != nil {
		return err
	}
	binDir := "/opt/iepl-agent/bin"
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(binDir, ".iepl-agent-update-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o755); err != nil {
		temporary.Close()
		return err
	}
	digest, err := m.downloadToFile(ctx, base+"/"+asset, temporary, 256*1024*1024)
	if err != nil {
		temporary.Close()
		return err
	}
	if !strings.EqualFold(expected, digest) {
		temporary.Close()
		return errors.New("release binary checksum mismatch")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	versionCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	output, err := exec.CommandContext(versionCtx, temporaryPath, "version").CombinedOutput()
	cancel()
	if err != nil || strings.TrimSpace(string(output)) != targetVersion {
		return errors.New("release binary version check failed")
	}
	current := filepath.Join(binDir, "iepl-agent")
	previous := filepath.Join(binDir, "iepl-agent.previous")
	_ = os.Remove(previous)
	if err := os.Rename(current, previous); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, current); err != nil {
		_ = os.Rename(previous, current)
		return err
	}
	if err := restartAgentService(ctx); err != nil {
		_ = os.Remove(current)
		_ = os.Rename(previous, current)
		_ = restartAgentService(context.Background())
		return err
	}
	if err := waitAgentService(ctx, targetVersion); err != nil {
		_ = os.Remove(current)
		_ = os.Rename(previous, current)
		_ = restartAgentService(context.Background())
		return err
	}
	return nil
}

func (m *Manager) download(ctx context.Context, source string, limit int64) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= releaseDownloadAttempts; attempt++ {
		raw, err := m.downloadOnce(ctx, source, limit)
		if err == nil {
			return raw, nil
		}
		lastErr = err
		if !shouldRetryReleaseRequest(ctx, err) || attempt == releaseDownloadAttempts {
			break
		}
		if err := waitForReleaseRetry(ctx, releaseRetryDelayFor(attempt, m.retryDelay)); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (m *Manager) downloadOnce(ctx context.Context, source string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Minging-Agents-Maintenance/"+m.version)
	response, err := m.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, releaseDownloadHTTPError{statusCode: response.StatusCode}
	}
	if response.ContentLength > limit {
		return nil, errors.New("release asset exceeds size limit")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("release asset exceeds size limit")
	}
	return raw, nil
}

func (m *Manager) downloadToFile(ctx context.Context, source string, destination *os.File, limit int64) (string, error) {
	if destination == nil || limit <= 0 {
		return "", errors.New("release download destination is invalid")
	}
	var lastErr error
	for attempt := 1; attempt <= releaseDownloadAttempts; attempt++ {
		if err := destination.Truncate(0); err != nil {
			return "", err
		}
		if _, err := destination.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		digest, err := m.downloadToFileOnce(ctx, source, destination, limit)
		if err == nil {
			return digest, nil
		}
		lastErr = err
		if !shouldRetryReleaseRequest(ctx, err) || attempt == releaseDownloadAttempts {
			break
		}
		if err := waitForReleaseRetry(ctx, releaseRetryDelayFor(attempt, m.retryDelay)); err != nil {
			return "", err
		}
	}
	return "", lastErr
}

func (m *Manager) downloadToFileOnce(ctx context.Context, source string, destination *os.File, limit int64) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "Minging-Agents-Maintenance/"+m.version)
	response, err := m.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", releaseDownloadHTTPError{statusCode: response.StatusCode}
	}
	if response.ContentLength > limit {
		return "", errors.New("release asset exceeds size limit")
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hasher), io.LimitReader(response.Body, limit+1))
	if err != nil {
		return "", err
	}
	if written > limit {
		return "", errors.New("release asset exceeds size limit")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func shouldRetryReleaseRequest(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	var responseErr releaseDownloadHTTPError
	if errors.As(err, &responseErr) {
		return responseErr.statusCode == http.StatusRequestTimeout || responseErr.statusCode == http.StatusTooManyRequests || responseErr.statusCode >= http.StatusInternalServerError
	}
	return true
}

func releaseRetryDelayFor(attempt int, retryDelay func(int) time.Duration) time.Duration {
	if retryDelay != nil {
		return retryDelay(attempt)
	}
	return time.Duration(attempt) * releaseDownloadRetryDelay
}

func waitForReleaseRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func checksumForAsset(raw []byte, asset string) (string, error) {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == asset && len(fields[0]) == 64 {
			if _, err := hex.DecodeString(fields[0]); err == nil {
				return strings.ToLower(fields[0]), nil
			}
		}
	}
	return "", errors.New("release checksum entry is missing")
}

func restartAgentService(ctx context.Context) error {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return runFirst(ctx, [][]string{{"/bin/systemctl", "restart", "iepl-agent.service"}, {"/usr/bin/systemctl", "restart", "iepl-agent.service"}})
	}
	return runFirst(ctx, [][]string{{"/sbin/rc-service", "iepl-agent", "restart"}, {"/usr/sbin/rc-service", "iepl-agent", "restart"}})
}

func waitAgentService(ctx context.Context, targetVersion string) error {
	deadline := time.Now().Add(agentServiceStartupTimeout)
	for time.Now().Before(deadline) {
		versionCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		output, versionErr := exec.CommandContext(versionCtx, "/opt/iepl-agent/bin/iepl-agent", "version").CombinedOutput()
		cancel()
		activeErr := agentServiceActive(ctx)
		if versionErr == nil && strings.TrimSpace(string(output)) == targetVersion && activeErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("updated Agent service did not become healthy")
}

func agentServiceActive(ctx context.Context) error {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return runFirst(ctx, [][]string{{"/bin/systemctl", "is-active", "--quiet", "iepl-agent.service"}, {"/usr/bin/systemctl", "is-active", "--quiet", "iepl-agent.service"}})
	}
	return runFirst(ctx, [][]string{{"/sbin/rc-service", "iepl-agent", "status"}, {"/usr/sbin/rc-service", "iepl-agent", "status"}})
}

func (m *Manager) uninstall(ctx context.Context) error {
	var serviceErr error
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		serviceErr = runFirst(ctx, [][]string{{"/bin/systemctl", "stop", "iepl-agent.service"}, {"/usr/bin/systemctl", "stop", "iepl-agent.service"}})
		_ = runFirst(ctx, [][]string{{"/bin/systemctl", "disable", "iepl-agent.service", "iepl-agent-maintenance.service"}, {"/usr/bin/systemctl", "disable", "iepl-agent.service", "iepl-agent-maintenance.service"}})
		_ = os.Remove("/etc/systemd/system/iepl-agent.service")
		_ = os.Remove("/etc/systemd/system/iepl-agent-maintenance.service")
		_ = os.Remove("/etc/systemd/system/iepl-agent.service.previous")
		_ = os.Remove("/etc/systemd/system/iepl-agent-maintenance.service.previous")
		_ = runFirst(ctx, [][]string{{"/bin/systemctl", "daemon-reload"}, {"/usr/bin/systemctl", "daemon-reload"}})
	} else {
		serviceErr = runFirst(ctx, [][]string{{"/sbin/rc-service", "iepl-agent", "stop"}, {"/usr/sbin/rc-service", "iepl-agent", "stop"}})
		_ = runFirst(ctx, [][]string{{"/sbin/rc-update", "del", "iepl-agent", "default"}, {"/usr/sbin/rc-update", "del", "iepl-agent", "default"}})
		_ = runFirst(ctx, [][]string{{"/sbin/rc-update", "del", "iepl-agent-maintenance", "default"}, {"/usr/sbin/rc-update", "del", "iepl-agent-maintenance", "default"}})
		_ = os.Remove("/etc/init.d/iepl-agent")
		_ = os.Remove("/etc/init.d/iepl-agent-maintenance")
		_ = os.Remove("/etc/init.d/iepl-agent.previous")
		_ = os.Remove("/etc/init.d/iepl-agent-maintenance.previous")
	}
	if serviceErr != nil {
		return serviceErr
	}
	for _, path := range []string{
		"/etc/iepl-agent", "/var/lib/iepl-agent", "/var/lib/iepl-agent-maintenance",
		"/var/log/iepl-agent", "/run/iepl-agent", "/opt/iepl-agent",
	} {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	_ = runFirst(ctx, [][]string{{"/usr/sbin/userdel", "iepl-agent"}, {"/usr/sbin/deluser", "iepl-agent"}, {"/sbin/deluser", "iepl-agent"}})
	_ = runFirst(ctx, [][]string{{"/usr/sbin/groupdel", "iepl-agent"}, {"/usr/sbin/delgroup", "iepl-agent"}, {"/sbin/delgroup", "iepl-agent"}})
	return nil
}

func runFirst(ctx context.Context, candidates [][]string) error {
	var lastErr error
	for _, candidate := range candidates {
		if len(candidate) == 0 {
			continue
		}
		if _, err := os.Stat(candidate[0]); err != nil {
			lastErr = err
			continue
		}
		commandCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		output, err := exec.CommandContext(commandCtx, candidate[0], candidate[1:]...).CombinedOutput()
		cancel()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("%s: %w: %s", filepath.Base(candidate[0]), err, compactMessage(string(output), 300))
	}
	if lastErr == nil {
		lastErr = errors.New("service command was not found")
	}
	return lastErr
}

func (m *Manager) markProcessed(path string) error {
	return os.WriteFile(path, []byte(m.now().UTC().Format(time.RFC3339Nano)+"\n"), 0o600)
}

func (m *Manager) writeResult(result agentprotocol.MaintenanceResult) error {
	if err := agentprotocol.ValidateMaintenanceResult(result); err != nil {
		return err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	path := m.cfg.MaintenanceResultPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".maintenance-result-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(raw, '\n')); err != nil {
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
	if account, lookupErr := user.Lookup("iepl-agent"); lookupErr == nil {
		uid, uidErr := strconv.Atoi(account.Uid)
		gid, gidErr := strconv.Atoi(account.Gid)
		if uidErr == nil && gidErr == nil {
			_ = os.Chown(temporaryPath, uid, gid)
		}
	}
	return os.Rename(temporaryPath, path)
}

func (m *Manager) cleanupProcessed() {
	entries, err := os.ReadDir(m.cfg.MaintenanceProcessedDir())
	if err != nil {
		return
	}
	cutoff := m.now().Add(-7 * 24 * time.Hour)
	for _, entry := range entries {
		if info, infoErr := entry.Info(); infoErr == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(m.cfg.MaintenanceProcessedDir(), entry.Name()))
		}
	}
}
