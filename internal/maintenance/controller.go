package maintenance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/guanzihao166/iepl-node-agent/internal/config"
	"github.com/guanzihao166/iepl-node-agent/internal/identity"
	agentprotocol "github.com/guanzihao166/iepl-node-agent/internal/protocol"
)

const latestReleaseURL = "https://github.com/guanzihao166/iepl-node-agent/releases/latest"

type Controller struct {
	cfg        config.Config
	identity   *identity.Identity
	signingKey ed25519.PublicKey
	version    string
	now        func() time.Time
	client     *http.Client
	latestURL  string
	retryDelay func(int) time.Duration
}

func NewController(cfg config.Config, id *identity.Identity, signingKey ed25519.PublicKey, version string) (*Controller, error) {
	if id == nil || id.AgentNodeID <= 0 || len(signingKey) != ed25519.PublicKeySize || strings.TrimSpace(version) == "" {
		return nil, errors.New("maintenance controller dependencies are incomplete")
	}
	return &Controller{
		cfg: cfg, identity: id, signingKey: append(ed25519.PublicKey(nil), signingKey...),
		version: strings.TrimSpace(version), now: time.Now,
		client: &http.Client{Timeout: 20 * time.Second}, latestURL: latestReleaseURL,
		retryDelay: func(attempt int) time.Duration {
			return time.Duration(attempt) * releaseDownloadRetryDelay
		},
	}, nil
}

func (c *Controller) CheckUpdate(ctx context.Context, commandID string) agentprotocol.MaintenanceResult {
	if uuid.Validate(commandID) != nil {
		commandID = uuid.NewString()
	}
	result := agentprotocol.MaintenanceResult{
		CommandID: commandID, Action: agentprotocol.MaintenanceActionCheckUpdate,
		Status: "checked", CurrentVersion: c.version, OccurredAt: c.now().UTC(),
	}
	if !validReleaseVersion(c.version) {
		result.Status = "failed"
		result.Message = "当前构建版本不是可发布版本"
		return result
	}
	latest, err := c.latestVersion(ctx)
	if err != nil {
		result.Status = "failed"
		result.Message = "检查 GitHub 最新版本失败：" + compactMessage(err.Error(), 300)
		return result
	}
	result.LatestVersion = latest
	result.UpdateAvailable = versionNewer(latest, c.version)
	if result.UpdateAvailable {
		result.Message = "发现新版本 " + latest
	} else {
		result.Message = "当前已是最新版本"
	}
	return result
}

func (c *Controller) HandleCommand(ctx context.Context, signed agentprotocol.SignedMaintenanceCommand) agentprotocol.MaintenanceResult {
	command := signed.Command
	result := agentprotocol.MaintenanceResult{
		CommandID: command.CommandID, Action: command.Action, Status: "failed",
		CurrentVersion: c.version, OccurredAt: c.now().UTC(),
	}
	if command.AgentNodeID != c.identity.AgentNodeID || signed.KeyID != c.identity.ConfigSigningKeyID {
		result.Message = "维护指令身份不匹配"
		return result
	}
	if err := agentprotocol.VerifySignedMaintenanceCommand(signed, c.identity.ConfigSigningKeyID, c.signingKey, c.now()); err != nil {
		result.Message = "维护指令签名校验失败"
		return result
	}
	if command.Action == agentprotocol.MaintenanceActionCheckUpdate {
		return c.CheckUpdate(ctx, command.CommandID)
	}
	ready, err := os.Stat(c.cfg.MaintenanceReadyPath())
	readyAge := time.Duration(0)
	if err == nil {
		readyAge = c.now().Sub(ready.ModTime())
	}
	if err != nil || readyAge < -5*time.Second || readyAge > 5*time.Second {
		result.Message = "本机签名维护服务未就绪"
		return result
	}
	if err := c.writeRequest(signed); err != nil {
		result.Message = "维护任务写入失败：" + compactMessage(err.Error(), 300)
		return result
	}
	result.Status = "accepted"
	if command.Action == agentprotocol.MaintenanceActionUpdate {
		result.LatestVersion = command.TargetVersion
		result.UpdateAvailable = versionNewer(command.TargetVersion, c.version)
		result.Message = "升级任务已安全写入本机维护队列"
	} else {
		result.Message = "彻底卸载任务已安全写入本机维护队列"
	}
	return result
}

func (c *Controller) CompletedResult() (*agentprotocol.MaintenanceResult, error) {
	raw, err := os.ReadFile(c.cfg.MaintenanceResultPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result agentprotocol.MaintenanceResult
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	if err := agentprotocol.ValidateMaintenanceResult(result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Controller) ClearCompletedResult(commandID string) error {
	result, err := c.CompletedResult()
	if err != nil || result == nil {
		return err
	}
	if result.CommandID != commandID {
		return errors.New("completed maintenance result changed before acknowledgement")
	}
	if err := os.Remove(c.cfg.MaintenanceResultPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (c *Controller) latestVersion(ctx context.Context) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= releaseDownloadAttempts; attempt++ {
		version, err := c.latestVersionOnce(ctx)
		if err == nil {
			return version, nil
		}
		lastErr = err
		if !shouldRetryReleaseRequest(ctx, err) || attempt == releaseDownloadAttempts {
			break
		}
		if err := waitForReleaseRetry(ctx, releaseRetryDelayFor(attempt, c.retryDelay)); err != nil {
			return "", err
		}
	}
	return "", lastErr
}

func (c *Controller) latestVersionOnce(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, c.latestURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept", "text/html")
	request.Header.Set("User-Agent", "Minging-Agents/"+c.version)
	response, err := c.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", releaseDownloadHTTPError{statusCode: response.StatusCode}
	}
	version := strings.TrimSpace(path.Base(response.Request.URL.Path))
	if !strings.Contains(response.Request.URL.Path, "/releases/tag/") || !validReleaseVersion(version) {
		return "", errors.New("GitHub release tag is invalid")
	}
	return version, nil
}

func (c *Controller) writeRequest(signed agentprotocol.SignedMaintenanceCommand) error {
	if err := os.MkdirAll(c.cfg.MaintenanceRequestDir(), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	path := filepath.Join(c.cfg.MaintenanceRequestDir(), signed.Command.CommandID+".json")
	temporary, err := os.CreateTemp(c.cfg.MaintenanceRequestDir(), ".request-*")
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
	return os.Rename(temporaryPath, path)
}

func versionNewer(candidate, current string) bool {
	left, leftOK := parseVersion(candidate)
	right, rightOK := parseVersion(current)
	if !leftOK || !rightOK {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return left[index] > right[index]
		}
	}
	return false
}

func validReleaseVersion(value string) bool {
	_, ok := parseVersion(value)
	return ok && strings.HasPrefix(strings.TrimSpace(value), "v")
}

func parseVersion(value string) ([3]int, bool) {
	var parsed [3]int
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if separator := strings.IndexAny(value, "-+"); separator >= 0 {
		value = value[:separator]
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return parsed, false
	}
	for index := range parts {
		number, err := strconv.Atoi(parts[index])
		if err != nil || number < 0 {
			return parsed, false
		}
		parsed[index] = number
	}
	return parsed, true
}

func compactMessage(value string, limit int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}
