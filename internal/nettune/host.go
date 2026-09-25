package nettune

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type linuxHost struct{}

func (linuxHost) Read(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}
func (linuxHost) Write(path, value string) error { return os.WriteFile(path, []byte(value+"\n"), 0644) }
func (linuxHost) Load(ctx context.Context, module string) error {
	// Kernel modules are host-global, even inside network namespaces.
	for _, path := range []string{"/.dockerenv", "/run/.containerenv", "/run/systemd/container", "/proc/vz"} {
		if _, err := os.Stat(path); err == nil {
			return errors.New("container: module loading skipped")
		}
	}
	return command(ctx, []string{"/sbin/modprobe", "/usr/sbin/modprobe", "/bin/modprobe", "/usr/bin/modprobe"}, "--", module)
}
func (linuxHost) Persist(path, body string) error {
	if old, err := os.Lstat(path); err == nil {
		if !old.Mode().IsRegular() {
			return errors.New("refusing to replace a non-regular tuning file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(data), marker) {
			return errors.New("tuning path contains unmanaged configuration")
		}
		if string(data) == body {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".iepl-bbr-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0644); err == nil {
		_, err = f.WriteString(body)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func (linuxHost) RemoveManaged(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("refusing to remove non-regular tuning file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(data), marker) {
		return errors.New("refusing to remove unmanaged tuning file")
	}
	return os.Remove(path)
}

func command(ctx context.Context, paths []string, args ...string) error {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		output, err := exec.CommandContext(bounded, path, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %w: %.300s", filepath.Base(path), err, output)
		}
		return nil
	}
	return errors.New("required system tool is unavailable")
}

// Apply is invoked by a root oneshot helper (systemd), or directly by the
// root maintenance process (OpenRC). Failure never blocks Agent availability.
func Apply(ctx context.Context, logger *slog.Logger) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		logger.Warn("agent network tuning skipped", "reason", "requires Linux root")
		return
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	r := apply(bounded, linuxHost{})
	logger.Info("agent network tuning", "status", r.Status, "algorithm", r.Algorithm, "previous", r.Previous, "persisted", r.Persisted, "warnings", r.Warnings)
}

const unitPath = "/etc/systemd/system/iepl-agent-network-tuning.service"
const tuningUnit = `[Unit]
Description=IEPL Agent best-effort BBR network tuning
After=systemd-sysctl.service

[Service]
Type=oneshot
User=root
ExecStart=/opt/iepl-agent/bin/iepl-agent tune-network
TimeoutStartSec=25s
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_MODULE CAP_DAC_OVERRIDE
`

// On old installations the maintenance manager runs with
// ProtectKernelTunables/Modules=true. A fixed root-owned oneshot started by
// PID 1 gets its own privileges without weakening the long-running Agent.
func Start(ctx context.Context, logger *slog.Logger) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		Apply(ctx, logger)
		return
	}
	if err := startSystemd(ctx); err != nil {
		logger.Warn("agent network tuning helper unavailable", "error", err)
	}
}

func startSystemd(ctx context.Context) error {
	// The managed unit is never enabled independently; maintenance starts it
	// once on boot/update, so uninstall/rollback cannot leave a boot blocker.
	if err := (linuxHost{}).Persist(unitPath, marker+tuningUnit); err != nil {
		return err
	}
	ctl := []string{"/bin/systemctl", "/usr/bin/systemctl"}
	if err := command(ctx, ctl, "daemon-reload"); err != nil {
		return err
	}
	return command(ctx, ctl, "start", "--no-block", "iepl-agent-network-tuning.service")
}

// Cleanup removes only files owned by this feature. The current algorithm is
// retained so uninstall does not unexpectedly change host TCP behavior.
func Cleanup() {
	h := linuxHost{}
	_ = h.RemoveManaged(configPath)
	_ = h.RemoveManaged(unitPath)
}
