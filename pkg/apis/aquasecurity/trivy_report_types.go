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
	Results   []VulnerabilityScanResult
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
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	Severity         string `json:"Severity"`
	PrimaryURL       string `json:"PrimaryURL"`
	// References       []string         `json:"References"`
	Cvss map[string]*CVSS `json:"CVSS"`
}

type CVSS struct {
	V3Score *float64 `json:"V3Score,omitempty"`
}

type K8SResourceMisconfiguration struct {
	Namespace string
	Kind      string
	Name      string
	Results   []MisconfigurationScanResult
}

type MisconfigurationScanResult struct {
	Target            string
	Class             string
	Type              string
	Misconfigurations []Misconfiguration
}

type Misconfiguration struct {
	ID     string
	Status string
}
