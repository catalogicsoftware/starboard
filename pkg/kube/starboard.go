package kube

import (
	"fmt"
	"time"
)

var ErrOOMKilled *errOOMKilled

type errOOMKilled struct {
	container string
}

func (e *errOOMKilled) Error() string {
	return fmt.Sprintf("container %s terminated with OOMKilled", e.container)
}

func (e *errOOMKilled) Is(target error) bool {
	if _, ok := target.(*errOOMKilled); ok {
		return true
	}
	return false
}

// ScannerOpts holds configuration of the vulnerability Scanner.
// TODO Rename to CLIConfig and move it to the cmd package
type ScannerOpts struct {
	ScanJobTimeout time.Duration
	DeleteScanJob  bool
}
