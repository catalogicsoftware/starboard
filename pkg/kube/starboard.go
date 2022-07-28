package kube

import (
	"errors"
	"time"
)

var ErrOOMKilled = errors.New("OOMKilled")

// ScannerOpts holds configuration of the vulnerability Scanner.
// TODO Rename to CLIConfig and move it to the cmd package
type ScannerOpts struct {
	ScanJobTimeout time.Duration
	DeleteScanJob  bool
}
