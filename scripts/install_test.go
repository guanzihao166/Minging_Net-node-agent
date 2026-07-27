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

func TestInstallerAdaptsSystemdHardeningWithoutCAPSysAdmin(t *testing.T) {
	raw, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, marker := range []string{
		`systemd_cap_sys_admin_available()`,
		`$1 == "CapBnd:"`,
		`*[2367aAbBeEfF]?????) return 0`,
		`apply_systemd_container_compat_unit()`,
		`# IEPL_SYSTEMD_CONTAINER_COMPAT=cap_sys_admin_absent`,
		`systemd restricted-container mode enabled (CAP_SYS_ADMIN is absent).`,
		`apply_systemd_container_compat_unit "$service_source"`,
		`apply_systemd_container_compat_unit "$maintenance_service_source"`,
	} {
		if !strings.Contains(script, marker) {
			t.Errorf("installer missing restricted-container marker %q", marker)
		}
	}

	start := strings.Index(script, "apply_systemd_container_compat_unit()")
	if start < 0 {
		t.Fatal("installer restricted-container unit filter is missing")
	}
	tail := script[start:]
	end := strings.Index(tail, `if [ "$service_mode" = "systemd" ]`)
	if end <= 0 {
		t.Fatal("installer restricted-container unit filter has no boundary")
	}
	filter := tail[:end]
	for _, directive := range []string{
		"PrivateTmp",
		"PrivateDevices",
		"ProtectSystem",
		"ProtectHome",
		"ProtectKernelTunables",
		"ProtectKernelModules",
		"ProtectKernelLogs",
		"ProtectControlGroups",
		"ProtectClock",
		"ProtectHostname",
		"RestrictSUIDSGID",
		"RestrictRealtime",
		"LockPersonality",
		"ReadWritePaths",
	} {
		if !strings.Contains(filter, directive) {
			t.Errorf("restricted-container unit filter keeps incompatible directive %q", directive)
		}
	}
	for _, preserved := range []string{
		"NoNewPrivileges",
		"AmbientCapabilities",
		"CapabilityBoundingSet",
		"RuntimeDirectory",
		"StateDirectory",
		"ConfigurationDirectory",
	} {
		if strings.Contains(filter, preserved) {
			t.Errorf("restricted-container unit filter removes supported directive %q", preserved)
		}
	}
}
