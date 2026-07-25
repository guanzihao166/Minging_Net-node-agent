package scripts

import (
	"os"
	"strings"
	"testing"
)

func TestInstallerPreservesOpenRCPermissionsAndResetsReenrollmentState(t *testing.T) {
	raw, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, marker := range []string{
		`[ "$service_mode" = "openrc" ] && service_backup_mode=0755`,
		`service_stop || rollback_install`,
		`reenroll_state_backup="$tmp/previous-state"`,
		`for name in agent.db agent.db-shm agent.db-wal`,
		`restore_reenroll_state || true`,
		`enrollment_completed=1`,
		`iepl-agent-maintenance.service`,
		`iepl-agent-maintenance.openrc`,
		`maintenance_service_restart || rollback_install`,
		`maintenance_service_active`,
		`/var/lib/iepl-agent-maintenance`,
	} {
		if !strings.Contains(script, marker) {
			t.Errorf("installer missing reenrollment safety marker %q", marker)
		}
	}
}
