package logx

import (
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	FieldComponent = "component"
	FieldNodeTag   = "node_tag"
	FieldTask      = "task"
)

type Config struct {
	Level  string
	Output string
}

type Handle struct {
	closer io.Closer
}

func Setup(cfg Config) (*Handle, error) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		DisableQuote:  true,
		PadLevelText:  false,
	})
	log.SetLevel(parseLevel(cfg.Level))

	if strings.TrimSpace(cfg.Output) == "" {
		log.SetOutput(os.Stdout)
		return &Handle{}, nil
	}

	f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.SetOutput(os.Stdout)
		return &Handle{}, err
	}
	log.SetOutput(f)
	return &Handle{closer: f}, nil
}

func (h *Handle) Close() error {
	if h == nil || h.closer == nil {
		return nil
	}
	err := h.closer.Close()
	h.closer = nil
	return err
}

func Component(name string) *log.Entry {
	return log.WithField(FieldComponent, name)
}

func Node(tag string) *log.Entry {
	return Component("node").WithField(FieldNodeTag, tag)
}

func Task(name string) *log.Entry {
	return Component("task").WithField(FieldTask, name)
}

func WithNodeTag(entry *log.Entry, tag string) *log.Entry {
	if entry == nil {
		return Node(tag)
	}
	return entry.WithField(FieldNodeTag, tag)
}

func parseLevel(level string) log.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return log.DebugLevel
	case "warn", "warning":
		return log.WarnLevel
	case "error":
		return log.ErrorLevel
	case "info", "":
		return log.InfoLevel
	default:
		return log.InfoLevel
	}
}
