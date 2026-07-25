//go:build linux

package maintenance

import "syscall"

func replaceProcess(path string, arguments, environment []string) error {
	return syscall.Exec(path, arguments, environment)
}
