package trivymisconfig

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/trivymisconfig"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Plugin the name of this plugin.
	Plugin = "TrivyMisconfig"
)

const (
	keyTrivyImageRef               = "trivy.imageRef"
	keyTrivyMode                   = "trivy.mode"
	keyTrivyCommand                = "trivy.command"
	keyTrivySeverity               = "trivy.severity"
	keyTrivyIgnoreUnfixed          = "trivy.ignoreUnfixed"
	keyTrivyTimeout                = "trivy.timeout"
	keyTrivyIgnoreFile             = "trivy.ignoreFile"
	keyTrivyInsecureRegistryPrefix = "trivy.insecureRegistry."
	keyTrivyNonSslRegistryPrefix   = "trivy.nonSslRegistry."
	keyTrivyMirrorPrefix           = "trivy.registry.mirror."
	keyTrivyHTTPProxy              = "trivy.httpProxy"
	keyTrivyHTTPSProxy             = "trivy.httpsProxy"
	keyTrivyNoProxy                = "trivy.noProxy"
	keyTrivyGitHubToken            = "trivy.githubToken"
	keyTrivySkipFiles              = "trivy.skipFiles"
	keyTrivySkipDirs               = "trivy.skipDirs"
	keyTrivyDBRepository           = "trivy.dbRepository"

	keyResourcesRequestsCPU    = "trivy.resources.requests.cpu"
	keyResourcesRequestsMemory = "trivy.resources.requests.memory"
	keyResourcesLimitsCPU      = "trivy.resources.limits.cpu"
	keyResourcesLimitsMemory   = "trivy.resources.limits.memory"
)

// Config defines configuration params for this plugin.
type Config struct {
	starboard.PluginConfig
}

// GetImageRef returns upstream Trivy container image reference.
func (c Config) GetImageRef() (string, error) {
	return c.GetRequiredData(keyTrivyImageRef)
}

// GetResourceRequirements creates ResourceRequirements from the Config.
func (c Config) GetResourceRequirements() (corev1.ResourceRequirements, error) {
	requirements := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	err := c.setResourceLimit(keyResourcesRequestsCPU, &requirements.Requests, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesRequestsMemory, &requirements.Requests, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsCPU, &requirements.Limits, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsMemory, &requirements.Limits, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	return requirements, nil
}

func (c Config) setResourceLimit(configKey string, k8sResourceList *corev1.ResourceList, k8sResourceName corev1.ResourceName) error {
	if value, found := c.Data[configKey]; found {
		quantity, err := resource.ParseQuantity(value)
		if err != nil {
			return fmt.Errorf("parsing resource definition %s: %s %w", configKey, value, err)
		}

		(*k8sResourceList)[k8sResourceName] = quantity
	}
	return nil
}

type plugin struct {
	clock          ext.Clock
	idGenerator    ext.IDGenerator
	objectResolver *kube.ObjectResolver
}

// NewPlugin constructs a new trivyConfigAudit.Plugin
//
// The plugin supports finding misconfigurations in cluster.
func NewPlugin(clock ext.Clock, idGenerator ext.IDGenerator, client client.Client) trivymisconfig.Plugin {
	return &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: &kube.ObjectResolver{Client: client},
	}
}

// Init ensures the default Config required by this plugin.
func (p *plugin) Init(ctx starboard.PluginContext) error {
	return ctx.EnsureConfig(starboard.PluginConfig{
		Data: map[string]string{
			keyTrivyImageRef:           "docker.io/aquasec/trivy:0.31.2",
			keyTrivyTimeout:            "5m0s",
			keyResourcesRequestsCPU:    "100m",
			keyResourcesRequestsMemory: "100M",
			keyResourcesLimitsCPU:      "500m",
			keyResourcesLimitsMemory:   "500M",
		},
	})
}

func (p *plugin) GetScanJobSpec(ctx starboard.PluginContext, workload client.Object) (corev1.PodSpec, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return corev1.PodSpec{}, err
	}
	return p.getPodSpecForStandaloneMode(ctx, config, workload)
}

const (
	tmpVolumeName               = "tmp"
	ignoreFileVolumeName        = "ignorefile"
	FsSharedVolumeName          = "starboard"
	SharedVolumeLocationOfTrivy = "/var/starboard/trivy"
)

// TODO: Add comments
func (p *plugin) getPodSpecForStandaloneMode(ctx starboard.PluginContext, config Config, workload client.Object) (
	corev1.PodSpec, error) {

	trivyImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, err
	}

	objectMeta, typeMeta, err := kube.GetObjectMeta(workload)
	if err != nil {
		return corev1.PodSpec{}, err
	}

	name := objectMeta.Name
	namespace := objectMeta.Namespace
	kind := typeMeta.Kind
	fmt.Println("name", name, "ns", namespace, "kind", kind)
	fmt.Println("-----------------------------------------")
	name = "amds-apiserver"
	kind = "deployment"
	namespace = "amds-system"

	var containers []corev1.Container
	resourceRequirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, err
	}

	containers = append(containers, corev1.Container{
		Name:                     "trivymisconfigscancontainer",
		Image:                    trivyImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"trivy",
		},
		Args: []string{
			"--quiet",
			"k8s",
			"--format=json",
			fmt.Sprintf("--namespace=%s", namespace),
			fmt.Sprintf("%s/%s", kind, name),
		},
		Resources: resourceRequirements,
		SecurityContext: &corev1.SecurityContext{
			Privileged:               pointer.BoolPtr(false),
			AllowPrivilegeEscalation: pointer.BoolPtr(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"all"},
			},
			ReadOnlyRootFilesystem: pointer.BoolPtr(true),
		},
	})

	return corev1.PodSpec{
		Affinity:                     starboard.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}, nil
}

func (p *plugin) ParseMisconfigurationReportData(ctx starboard.PluginContext, logsReader io.ReadCloser) (v1alpha1.MisconfigurationReportData, error) {
	var reports ScanReport
	err := json.NewDecoder(logsReader).Decode(&reports)
	if err != nil {
		return v1alpha1.MisconfigurationReportData{}, err
	}
	misconfigurations := make([]v1alpha1.Misconfiguration, 0)

	for _, report := range reports.Results {
		for _, sr := range report.Misconfigurations {
			misconfigurations = append(misconfigurations, v1alpha1.Misconfiguration{
				ID:     sr.ID,
				Status: sr.Status,
			})
		}
	}

	return v1alpha1.MisconfigurationReportData{
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:   "Trivy",
			Vendor: "Aqua Security",
		},
		Misconfigurations: misconfigurations,
	}, nil
}

func (p *plugin) newConfigFrom(ctx starboard.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{PluginConfig: pluginConfig}, nil
}
