// Package nettune applies bounded, best-effort host TCP tuning. It never
// installs a kernel, reboots, or replaces live interface queue disciplines.
package nettune

import (
	"context"
	"fmt"
	"strings"
)

const (
	availableKey = "/proc/sys/net/ipv4/tcp_available_congestion_control"
	controlKey   = "/proc/sys/net/ipv4/tcp_congestion_control"
	qdiscKey     = "/proc/sys/net/core/default_qdisc"
	configPath   = "/etc/sysctl.d/99-zz-iepl-agent-bbr.conf"
	marker       = "# Managed by iepl-agent network tuning\n"
)

type Result struct {
	Status    string   `json:"status"`
	Algorithm string   `json:"algorithm,omitempty"`
	Previous  string   `json:"previous,omitempty"`
	Persisted bool     `json:"persisted"`
	Warnings  []string `json:"warnings,omitempty"`
}

type host interface {
	Read(string) (string, error)
	Write(string, string) error
	Load(context.Context, string) error
	Persist(string, string) error
	RemoveManaged(string) error
}

func contains(list, name string) bool {
	for _, item := range strings.Fields(list) {
		if item == name {
			return true
		}
	}
	return false
}

func apply(ctx context.Context, h host) Result {
	r := Result{Status: "skipped"}
	warn := func(err error) {
		if err != nil {
			r.Warnings = append(r.Warnings, err.Error())
		}
	}
	old, err := h.Read(controlKey)
	if err != nil {
		warn(err)
		return r
	}
	r.Previous, r.Algorithm = old, old
	available, err := h.Read(availableKey)
	if err != nil {
		warn(err)
		return r
	}
	// Preserve an explicitly selected newer implementation.
	target := ""
	if old == "bbr3" {
		target = "bbr3"
	}
	if target == "" && !contains(available, "bbr2") {
		warn(h.Load(ctx, "tcp_bbr2"))
		available, err = h.Read(availableKey)
		if err != nil {
			warn(err)
			return r
		}
	}
	if target == "" && contains(available, "bbr2") {
		target = "bbr2"
	}
	if target == "" {
		if !contains(available, "bbr") {
			warn(h.Load(ctx, "tcp_bbr"))
			available, err = h.Read(availableKey)
			if err != nil {
				warn(err)
				return r
			}
		}
		if contains(available, "bbr") {
			target = "bbr"
			r.Warnings = append(r.Warnings, "bbr2 unavailable; using kernel bbr (version not inferred from its name)")
		}
	}
	if target == "" {
		r.Status = "unsupported"
		warn(h.RemoveManaged(configPath))
		return r
	}
	if err := ctx.Err(); err != nil {
		warn(err)
		return r
	}
	if old != target {
		if err := h.Write(controlKey, target); err != nil {
			warn(err)
			return r
		}
	}
	actual, err := h.Read(controlKey)
	if err != nil || actual != target {
		warn(fmt.Errorf("verify congestion control: got %q, expected %q: %v", actual, target, err))
		if old != target {
			warn(h.Write(controlKey, old))
			rolledBack, rollbackErr := h.Read(controlKey)
			if rollbackErr != nil || rolledBack != old {
				warn(fmt.Errorf("rollback verification failed: %q: %v", rolledBack, rollbackErr))
			}
		}
		return r
	}
	r.Status, r.Algorithm = "enabled", target
	// fq is optional: BBRv2 also supports the TCP stack's internal pacing.
	// A default change affects future interfaces only; existing mq/HTB/CAKE
	// trees and application shaping are deliberately left intact.
	persist := marker + "net.ipv4.tcp_congestion_control = " + target + "\n"
	oldQ, qerr := h.Read(qdiscKey)
	if qerr == nil {
		if oldQ != "fq" {
			_ = h.Load(ctx, "sch_fq")
			qerr = h.Write(qdiscKey, "fq")
		}
		if qerr == nil {
			actualQ, readErr := h.Read(qdiscKey)
			if readErr == nil && actualQ == "fq" {
				persist += "net.core.default_qdisc = fq\n"
			} else {
				warn(fmt.Errorf("fq readback failed: %q: %v", actualQ, readErr))
				if oldQ != "fq" {
					warn(h.Write(qdiscKey, oldQ))
				}
			}
		} else {
			warn(fmt.Errorf("fq optional: %w", qerr))
		}
	} else {
		warn(fmt.Errorf("fq optional: %w", qerr))
	}
	if err := h.Persist(configPath, persist); err != nil {
		warn(fmt.Errorf("runtime-only: cannot persist BBR: %w", err))
	} else {
		r.Persisted = true
	}
	return r
}
