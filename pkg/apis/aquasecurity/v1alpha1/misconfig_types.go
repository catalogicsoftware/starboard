package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Misconfiguration struct {
	ID     string `json:"ID"`
	Status string `json:"Status"`
}

// MisconfigurationReportData is the spec for the vulnerability scan result.
//
// The spec follows the Pluggable Scanners API defined for Harbor.
// @see https://github.com/goharbor/pluggable-scanner-spec/blob/master/api/spec/scanner-adapter-openapi-v1.0.yaml
type MisconfigurationReportData struct {
	// UpdateTimestamp is a timestamp representing the server time in UTC when this report was updated.
	UpdateTimestamp metav1.Time `json:"updateTimestamp"`

	// Scanner is the scanner that generated this report.
	Scanner Scanner `json:"scanner"`

	// Registry is the registry the Artifact was pulled from.
	Registry Registry `json:"registry"`

	// Artifact is a container image scanned for Vulnerabilities.
	Artifact Artifact `json:"artifact"`

	// Summary is a summary of Vulnerability counts grouped by Severity.
	Summary VulnerabilitySummary `json:"summary"`

	// Vulnerabilities is a list of operating system (OS) or application software Vulnerability items found in the Artifact.
	Misconfigurations []Misconfiguration `json:"vulnerabilities"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterVulnerabilityReport is a specification for the ClusterVulnerabilityReport resource.
type MisconfigurationReport struct {
	metav1.TypeMeta   `json:",incline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report MisconfigurationReportData `json:"report"`
}
