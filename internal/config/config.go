package config

import (
	"errors"
	"flag"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Command             string
	StateDir            string
	ConfigDir           string
	RuntimeDir          string
	EnrollmentURL       string
	EnrollmentTokenFile string
	Version             string
	HeartbeatInterval   time.Duration
	TrafficInterval     time.Duration
	ReconnectMin        time.Duration
	ReconnectMax        time.Duration
	MaxFrameBytes       int64
}

func Parse(args []string, version string) (Config, error) {
	cfg := Config{Version: version}
	if len(args) == 0 {
		return cfg, errors.New("command is required: enroll, run, or check")
	}
	cfg.Command = strings.ToLower(strings.TrimSpace(args[0]))
	set := flag.NewFlagSet("iepl-agent "+cfg.Command, flag.ContinueOnError)
	set.StringVar(&cfg.StateDir, "state-dir", "/var/lib/iepl-agent", "durable state directory")
	set.StringVar(&cfg.ConfigDir, "config-dir", "/etc/iepl-agent", "identity and secret directory")
	set.StringVar(&cfg.RuntimeDir, "runtime-dir", "/run/iepl-agent/secrets", "ephemeral runtime secret directory")
	set.StringVar(&cfg.EnrollmentURL, "url", "", "HTTPS enrollment endpoint")
	set.StringVar(&cfg.EnrollmentTokenFile, "token-file", "", "one-time enrollment token file")
	set.DurationVar(&cfg.HeartbeatInterval, "heartbeat", 5*time.Second, "heartbeat and online snapshot interval")
	set.DurationVar(&cfg.TrafficInterval, "traffic-interval", time.Second, "traffic WAL interval")
	set.DurationVar(&cfg.ReconnectMin, "reconnect-min", time.Second, "minimum reconnect delay")
	set.DurationVar(&cfg.ReconnectMax, "reconnect-max", time.Minute, "maximum reconnect delay")
	set.Int64Var(&cfg.MaxFrameBytes, "max-frame-bytes", 1024*1024, "maximum WSS frame size")
	if err := set.Parse(args[1:]); err != nil {
		return cfg, err
	}
	cfg.StateDir = filepath.Clean(cfg.StateDir)
	cfg.ConfigDir = filepath.Clean(cfg.ConfigDir)
	cfg.RuntimeDir = filepath.Clean(cfg.RuntimeDir)
	if cfg.Command != "enroll" && cfg.Command != "run" && cfg.Command != "check" && cfg.Command != "version" {
		return cfg, errors.New("unsupported command")
	}
	if cfg.Command == "enroll" && (strings.TrimSpace(cfg.EnrollmentURL) == "" || strings.TrimSpace(cfg.EnrollmentTokenFile) == "") {
		return cfg, errors.New("enroll requires --url and --token-file")
	}
	if cfg.HeartbeatInterval < 5*time.Second || cfg.TrafficInterval < time.Second ||
		cfg.ReconnectMin <= 0 || cfg.ReconnectMax < cfg.ReconnectMin || cfg.MaxFrameBytes < 64*1024 || cfg.MaxFrameBytes > 8*1024*1024 {
		return cfg, errors.New("runtime timing or frame limits are invalid")
	}
	return cfg, nil
}

func (c Config) StateDBPath() string    { return filepath.Join(c.StateDir, "agent.db") }
func (c Config) MachineIDPath() string  { return filepath.Join(c.StateDir, "machine-id") }
func (c Config) BootIDPath() string     { return filepath.Join(c.StateDir, "boot-id") }
func (c Config) ClientKeyPath() string  { return filepath.Join(c.ConfigDir, "client.key") }
func (c Config) ClientCertPath() string { return filepath.Join(c.ConfigDir, "client.crt") }
func (c Config) CACertPath() string     { return filepath.Join(c.ConfigDir, "control-ca.crt") }
func (c Config) IdentityPath() string   { return filepath.Join(c.ConfigDir, "identity.json") }
