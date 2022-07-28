package kube

import (
	"fmt"
	"time"
)

type OOMKilledErr struct {
	containerName string
}

func (e *OOMKilledErr) Error() string {
	return fmt.Sprintf(
		"container %s terminated with OOMKilled",
		e.containerName)
}

// ScannerOpts holds configuration of the vulnerability Scanner.
// TODO Rename to CLIConfig and move it to the cmd package
type ScannerOpts struct {
	ScanJobTimeout time.Duration
	DeleteScanJob  bool
}
