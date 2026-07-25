//go:build !linux

package maintenance

import "errors"

func replaceProcess(string, []string, []string) error {
	return errors.New("process replacement is supported on Linux only")
}
