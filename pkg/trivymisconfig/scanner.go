package trivymisconfig

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/runner"
	"github.com/aquasecurity/starboard/pkg/starboard"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Scanner is a template for running static vulnerability scanners that implement
// the Plugin interface.
type Scanner struct {
	scheme         *runtime.Scheme
	clientset      kubernetes.Interface
	plugin         Plugin
	pluginContext  starboard.PluginContext
	objectResolver *kube.ObjectResolver
	logsReader     kube.LogsReader
	config         starboard.ConfigData
	opts           kube.ScannerOpts
	secretsReader  kube.SecretsReader
}

// NewScanner constructs a new static vulnerability Scanner with the specified
// Plugin that knows how to perform the actual scanning,
// which is performed by running a Kubernetes job, and knows how to convert logs
// to instances of v1alpha1.VulnerabilityReport.
func NewScanner(
	clientset kubernetes.Interface,
	client client.Client,
	plugin Plugin,
	pluginContext starboard.PluginContext,
	config starboard.ConfigData,
	opts kube.ScannerOpts,
) *Scanner {
	return &Scanner{
		scheme:         client.Scheme(),
		clientset:      clientset,
		opts:           opts,
		plugin:         plugin,
		pluginContext:  pluginContext,
		objectResolver: &kube.ObjectResolver{Client: client},
		logsReader:     kube.NewLogsReader(clientset),
		config:         config,
		secretsReader:  kube.NewSecretsReader(client),
	}
}

// Scan creates a Kubernetes job to scan the specified workload. The pod created
// by the scan job has template contributed by the Plugin.
// It is a blocking method that watches the status of the job until it succeeds
// or fails. When succeeded it parses container logs and coverts the output
// to instances of v1alpha1.VulnerabilityReport by delegating such transformation
// logic also to the Plugin.
func (s *Scanner) Scan(ctx context.Context, workload kube.ObjectRef) ([]v1alpha1.MisconfigurationReport, error) {
	klog.V(3).Infof("Getting Pod template for workload: %v", workload)

	workloadObj, err := s.objectResolver.ObjectFromObjectRef(ctx, workload)
	if err != nil {
		return nil, fmt.Errorf("resolving object: %w", err)
	}

	// owner, err := s.objectResolver.ReportOwner(ctx, workloadObj)
	// if err != nil {
	// 	return nil, err
	// }

	scanJobTolerations, err := s.config.GetScanJobTolerations()
	if err != nil {
		return nil, fmt.Errorf("getting scan job tolerations: %w", err)
	}

	scanJobAnnotations, err := s.config.GetScanJobAnnotations()
	if err != nil {
		return nil, fmt.Errorf("getting scan job annotations: %w", err)
	}

	scanJobPodTemplateLabels, err := s.config.GetScanJobPodTemplateLabels()
	if err != nil {
		return nil, fmt.Errorf("getting scan job template labels: %w", err)
	}

	klog.V(3).Infof("Scanning with options: %+v", s.opts)

	// credentials, err := s.secretsReader.CredentialsByWorkload(ctx, owner)
	// if err != nil {
	// 	return nil, err
	// }

	job, err := NewScanJobBuilder().
		WithPlugin(s.plugin).
		WithPluginContext(s.pluginContext).
		WithTimeout(s.opts.ScanJobTimeout).
		WithObject(workloadObj).
		WithTolerations(scanJobTolerations).
		WithAnnotations(scanJobAnnotations).
		WithPodTemplateLabels(scanJobPodTemplateLabels).
		Get()

	if err != nil {
		return nil, fmt.Errorf("constructing scan job: %w", err)
	}

	err = runner.New().Run(ctx, kube.NewRunnableJob(s.scheme, s.clientset, job))
	if err != nil {
		return nil, fmt.Errorf("running scan job: %w", err)
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		klog.V(3).Infof("Deleting scan job: %s/%s", job.Namespace, job.Name)
		background := metav1.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	klog.V(3).Infof("Scan job completed: %s/%s", job.Namespace, job.Name)

	return s.getMisconfigurationReportsByScanJob(ctx, job)
}

// TODO To make this method look the same as the one used by the operator we
// should resolve the owner based on labels set on the given job instead of
// passing owner directly. The goal is for CLI and operator to create jobs
// with the same struct and set of labels to reuse code responsible for parsing
// v1alpha1.VulnerabilityReport instances.
func (s *Scanner) getMisconfigurationReportsByScanJob(ctx context.Context, job *batchv1.Job) ([]v1alpha1.MisconfigurationReport, error) {
	var reports []v1alpha1.MisconfigurationReport

	// containerImages, err := kube.GetContainerImagesFromJob(job)
	// if err != nil {
	// 	return nil, fmt.Errorf("getting container images: %w", err)
	// }

	// for containerName, containerImage := range containerImages {
	containerName := "trivymisconfigscancontainer" // TODO: Sync with plugin.go
	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", containerName, job.Namespace, job.Name)
	logsStream, err := s.logsReader.GetLogsByJobAndContainerName(ctx, job, containerName)
	if err != nil {
		return nil, err
	}
	result, err := s.plugin.ParseMisconfigurationReportData(s.pluginContext, logsStream)
	if err != nil {
		return nil, err
	}

	_ = logsStream.Close()

	report := v1alpha1.MisconfigurationReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "report-123",
			Namespace: "cloudcasa-io",
		},
		Report: result,
	}

	reports = append(reports, report)

	// }
	return reports, nil
}
