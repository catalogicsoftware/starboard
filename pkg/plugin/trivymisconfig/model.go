package trivymisconfig

type ScanResult struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"`
	Type              string             `json:"Type"`
	MisconfSummary    MisconfSummary     `json:"MisconfSummary"`
	Misconfigurations []Misconfiguration `json:"Misconfigurations"`
}

type ScanReport struct {
	Namespace string       `json:"Namespace"`
	Kind      string       `json:"Kind"`
	Name      string       `json:"Name"`
	Results   []ScanResult `json:"Results"`
}

type Misconfiguration struct {
	ID     string `json:"ID"`
	Status string `json:"Status"`
	// Other fields are ommitted to avoid redundancy
}

type MisconfSummary struct {
	Successes  int64 `json:"Successes"`
	Failures   int64 `json:"Failures"`
	Exceptions int64 `json:"Exceptions"`
}

/*
"Namespace": "amds-system",
"Kind": "Deployment",
"Name": "amds-apiserver",
"Results":[]

	"Target": "Deployment/amds-apiserver",
	"Class": "config",
	"Type": "kubernetes",
	"Misconfigurations": []

		"Type": "Kubernetes Security Check",
		"ID": "KSV001",
		"Title": "Process can elevate its own privileges",
		"Description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
		"Message": "Container 'apiserver' of Deployment 'amds-apiserver' should set 'securityContext.allowPrivilegeEscalation' to false",
		"Namespace": "builtin.kubernetes.KSV001",
		"Query": "data.builtin.kubernetes.KSV001.deny",
		"Resolution": "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'.",
		"Severity": "MEDIUM",
		"PrimaryURL": "https://avd.aquasec.com/misconfig/ksv001",
		"References": [
		"https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
		"https://avd.aquasec.com/misconfig/ksv001"
		],
		"Status": "FAIL",
*/
