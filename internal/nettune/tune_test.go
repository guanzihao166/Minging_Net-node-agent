package nettune

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeHost struct {
	values       map[string]string
	modules      map[string]string
	denied       map[string]bool
	loads        []string
	badReadback  bool
	persistError bool
	body         string
	removed      bool
}

func (h *fakeHost) Read(p string) (string, error) {
	v, ok := h.values[p]
	if !ok {
		return "", os.ErrNotExist
	}
	return v, nil
}
func (h *fakeHost) Write(p, v string) error {
	if h.denied[p] {
		return os.ErrPermission
	}
	if h.badReadback && p == controlKey && v == "bbr2" {
		h.values[p] = "reno"
	} else {
		h.values[p] = v
	}
	return nil
}
func (h *fakeHost) Load(_ context.Context, m string) error {
	h.loads = append(h.loads, m)
	if v := h.modules[m]; v != "" {
		h.values[availableKey] += " " + v
		return nil
	}
	return errors.New("module unavailable")
}
func (h *fakeHost) Persist(_, body string) error {
	if h.persistError {
		return os.ErrPermission
	}
	h.body = body
	return nil
}
func (h *fakeHost) RemoveManaged(string) error { h.removed = true; return nil }
func hostFor(available, current string) *fakeHost {
	return &fakeHost{values: map[string]string{availableKey: available, controlKey: current, qdiscKey: "fq_codel"}, modules: map[string]string{}, denied: map[string]bool{}}
}

func TestCapabilitiesAndFallback(t *testing.T) {
	for _, tt := range []struct{ name, available, current, module, target, status string }{
		{"built in v2", "reno cubic bbr bbr2", "cubic", "", "bbr2", "enabled"},
		{"loadable v2", "reno cubic", "cubic", "tcp_bbr2", "bbr2", "enabled"},
		{"standard bbr fallback", "reno cubic bbr", "cubic", "", "bbr", "enabled"},
		{"loadable bbr fallback", "reno cubic", "cubic", "tcp_bbr", "bbr", "enabled"},
		{"unsupported", "reno cubic", "cubic", "", "cubic", "unsupported"},
		{"exact token match", "reno notbbr2 bbrplus", "cubic", "", "cubic", "unsupported"},
		{"preserve v3", "reno bbr2 bbr3", "bbr3", "", "bbr3", "enabled"},
		{"already v2", "reno bbr2", "bbr2", "", "bbr2", "enabled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := hostFor(tt.available, tt.current)
			if tt.module != "" {
				h.modules[tt.module] = strings.TrimPrefix(tt.module, "tcp_")
			}
			r := apply(context.Background(), h)
			if r.Status != tt.status || r.Algorithm != tt.target {
				t.Fatalf("%+v", r)
			}
			if r.Status == "enabled" && (!r.Persisted || !strings.Contains(h.body, "= "+tt.target+"\n")) {
				t.Fatalf("missing persistence: %+v %s", r, h.body)
			}
			if r.Status == "unsupported" && (!h.removed || h.body != "") {
				t.Fatal("stale managed config not removed")
			}
			if tt.target == "bbr" && !strings.Contains(strings.Join(r.Warnings, " "), "bbr2 unavailable") {
				t.Fatal("fallback not reported")
			}
			before := h.values[controlKey]
			r = apply(context.Background(), h)
			if h.values[controlKey] != before {
				t.Fatal("repeated execution changed selection")
			}
		})
	}
}

func TestFailureDoesNotDisableAgentOrLeaveBadSelection(t *testing.T) {
	for _, name := range []string{"read-only proc", "readback mismatch", "read-only etc", "missing qdisc", "qdisc permission", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			h := hostFor("cubic bbr2", "cubic")
			ctx := context.Background()
			switch name {
			case "read-only proc":
				h.denied[controlKey] = true
			case "readback mismatch":
				h.badReadback = true
			case "read-only etc":
				h.persistError = true
			case "missing qdisc":
				delete(h.values, qdiscKey)
			case "qdisc permission":
				h.denied[qdiscKey] = true
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			r := apply(ctx, h)
			if len(r.Warnings) == 0 {
				t.Fatal("failure not reported")
			}
			if name == "read-only proc" || name == "readback mismatch" || name == "cancelled" {
				if h.values[controlKey] != "cubic" || r.Status != "skipped" || h.body != "" {
					t.Fatalf("unsafe partial change: %+v", r)
				}
			} else if r.Status != "enabled" {
				t.Fatalf("optional failure rejected BBR: %+v", r)
			}
			if name == "read-only etc" && r.Persisted {
				t.Fatal("false persistence success")
			}
		})
	}
}

func TestManagedFilesAreAtomicAndDoNotOverwriteUserConfig(t *testing.T) {
	h := linuxHost{}
	path := filepath.Join(t.TempDir(), "sysctl.d", "bbr.conf")
	if err := h.Persist(path, marker+"one\n"); err != nil {
		t.Fatal(err)
	}
	if err := h.Persist(path, marker+"two\n"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != marker+"two\n" {
		t.Fatal(string(b))
	}
	if err := h.RemoveManaged(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("user config"), 0644); err != nil {
		t.Fatal(err)
	}
	if h.Persist(path, marker) == nil || h.RemoveManaged(path) == nil {
		t.Fatal("unmanaged file overwritten")
	}
	b, _ = os.ReadFile(path)
	if string(b) != "user config" {
		t.Fatal("unmanaged data changed")
	}
}
