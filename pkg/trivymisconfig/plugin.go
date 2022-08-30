package trivymisconfig

import (
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/starboard"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Plugin defines the interface between Starboard and static vulnerability
// scanners.
type Plugin interface {

	// Init is a callback to initialize this plugin, e.g. ensure the default
	// configuration.
	Init(ctx starboard.PluginContext) error

	// GetScanJobSpec describes the pod that will be created by Starboard when
	// it schedules a Kubernetes job to scan the workload with the specified
	// descriptor.
	// The second argument maps container names to Docker registry credentials,
	// which can be passed to the scanner as environment variables with values
	// set from returned secrets.
	GetScanJobSpec(ctx starboard.PluginContext, workload client.Object) (
		corev1.PodSpec, error)

	// ParseMisconfigurationReportData is a callback to parse and convert logs of
	// the pod controlled by the scan job to v1alpha1.MisconfigurationScanResult.
	ParseMisconfigurationReportData(ctx starboard.PluginContext, logsReader io.ReadCloser) (
		v1alpha1.MisconfigurationReportData, error)
}
