package aquasecurity

type TrivyReport struct {
	Report *ScanReport
	Errors string
}

type ScanReport struct {
	Vulnerabilities   []K8SResourceVulnerability
	Misconfigurations []K8SResourceMisconfiguration
}

type K8SResourceVulnerability struct {
	Namespace string
	Kind      string
	Name      string
	Error     string                    `json:"Error,omitempty"`
	Results   []VulnerabilityScanResult `json:"Results,omitempty"`
}

type VulnerabilityScanResult struct {
	Target          string
	Class           string
	Type            string
	Vulnerabilities []Vulnerability
}

type Vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
}

type CVSS struct {
	V3Score *float64 `json:"V3Score,omitempty"`
}

type K8SResourceMisconfiguration struct {
	Namespace string
	Kind      string
	Name      string
	Error     string                       `json:"Error,omitempty"`
	Results   []MisconfigurationScanResult `json:"Results,omitempty"`
}

type MisconfigurationScanResult struct {
	Target            string
	Class             string
	Type              string
	Misconfigurations []Misconfiguration
}

type Misconfiguration struct {
	ID        string
	Status    string
	Severity  string
	Namespace string
}
