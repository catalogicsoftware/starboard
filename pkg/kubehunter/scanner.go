package kubehunter

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/runner"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/hashicorp/go-version"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"
)

const (
	kubeHunterContainerName    = "kube-hunter"
	keyResourcesRequestsCPU    = "kh.resources.requests.cpu"
	keyResourcesRequestsMemory = "kh.resources.requests.memory"
	keyResourcesLimitsCPU      = "kh.resources.limits.cpu"
	keyResourcesLimitsMemory   = "kh.resources.limits.memory"
)

type Config interface {
	GetKubeHunterImageRef() (string, error)
	GetKubeHunterQuick() (bool, error)
}

type Scanner struct {
	scheme             *runtime.Scheme
	clientset          kubernetes.Interface
	opts               kube.ScannerOpts
	logsReader         kube.LogsReader
	config             starboard.ConfigData
	namespaceName      string
	serviceAccountName string
}

func NewScanner(
	scheme *runtime.Scheme,
	clientset kubernetes.Interface,
	config starboard.ConfigData,
	opts kube.ScannerOpts,
	namespaceName string,
	serviceAccountName string,
) *Scanner {
	return &Scanner{
		scheme:             scheme,
		clientset:          clientset,
		logsReader:         kube.NewLogsReader(clientset),
		config:             config,
		opts:               opts,
		namespaceName:      namespaceName,
		serviceAccountName: serviceAccountName,
	}
}

func (s *Scanner) Scan(ctx context.Context) (v1alpha1.KubeHunterReportData, error) {
	// 1. Prepare descriptor for the Kubernetes Job which will run kube-hunter
	job, err := s.prepareKubeHunterJob()
	if err != nil {
		return v1alpha1.KubeHunterReportData{}, err
	}

	// 2. Run the prepared Job and wait for its completion or failure
	err = runner.New().Run(ctx, kube.NewRunnableJob(s.scheme, s.clientset, job))
	if err != nil {
		return v1alpha1.KubeHunterReportData{}, fmt.Errorf("running kube-hunter job: %w", err)
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		// 5. Delete the kube-hunter Job
		klog.V(3).Infof("Deleting job: %s/%s", job.Namespace, job.Name)
		background := metav1.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	// 3. Get kube-hunter JSON output from the kube-hunter Pod
	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", kubeHunterContainerName,
		job.Namespace, job.Name)
	logsStream, err := s.logsReader.GetLogsByJobAndContainerName(ctx, job, kubeHunterContainerName)
	if err != nil {
		return v1alpha1.KubeHunterReportData{}, fmt.Errorf("getting logs: %w", err)
	}
	defer func() {
		_ = logsStream.Close()
	}()

	// 4. Parse the KubeHuberOutput from the logs Reader
	return OutputFrom(s.config, logsStream)
}

func (s *Scanner) prepareKubeHunterJob() (*batchv1.Job, error) {
	imageRef, err := s.config.GetKubeHunterImageRef()
	if err != nil {
		return nil, err
	}
	kubeHunterArgs := []string{"--pod", "--report", "json", "--log", "none"}
	// Temporary fix for logging: https://github.com/aquasecurity/kube-hunter/issues/465
	quick, err := s.config.GetKubeHunterQuick()
	if err != nil {
		return nil, err
	}
	if quick {
		kubeHunterArgs = append(kubeHunterArgs, "--quick")
	}

	scanJobTolerations, err := s.config.GetScanJobTolerations()
	if err != nil {
		return nil, err
	}

	scanJobAnnotations, err := s.config.GetScanJobAnnotations()
	if err != nil {
		return nil, err
	}

	scanJobPodTemplateLabels, err := s.config.GetScanJobPodTemplateLabels()
	if err != nil {
		return nil, err
	}

	labelsSet := labels.Set{
		starboard.LabelK8SAppManagedBy: starboard.AppStarboard,
	}

	podTemplateLabelsSet := make(labels.Set)
	for key, element := range labelsSet {
		podTemplateLabelsSet[key] = element
	}
	for key, element := range scanJobPodTemplateLabels {
		podTemplateLabelsSet[key] = element
	}

	var (
		podSecurityContext       *corev1.PodSecurityContext
		containerSecurityContext *corev1.SecurityContext
	)
	ver, err := starboard.GetVersionFromImageRef(imageRef)
	if err != nil {
		return nil, err
	}
	if isAtLeast(ver, "0.4.1") || ver == "latest" {
		podSecurityContext = &corev1.PodSecurityContext{
			RunAsUser:  pointer.Int64Ptr(0),
			RunAsGroup: pointer.Int64Ptr(0),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		}
		containerSecurityContext = &corev1.SecurityContext{
			Privileged:               pointer.BoolPtr(false),
			AllowPrivilegeEscalation: pointer.BoolPtr(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"all"},
				Add:  []corev1.Capability{"NET_RAW"},
			},
			ReadOnlyRootFilesystem: pointer.BoolPtr(false),
		}
	}

	resourceRequirements, err := s.getResourceRequirements(s.config)
	if err != nil {
		return nil, err
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("scan-kubehunterreports-%s", kube.ComputeHash("cluster")),
			Namespace: s.namespaceName,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: scanJobAnnotations,
					Labels:      podTemplateLabelsSet,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: s.serviceAccountName,
					RestartPolicy:      corev1.RestartPolicyNever,
					HostPID:            true,
					Affinity:           starboard.LinuxNodeAffinity(),
					Tolerations:        scanJobTolerations,
					SecurityContext:    podSecurityContext,
					Containers: []corev1.Container{
						{
							Name:                     kubeHunterContainerName,
							Image:                    imageRef,
							ImagePullPolicy:          corev1.PullIfNotPresent,
							TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
							Args:                     kubeHunterArgs,
							SecurityContext:          containerSecurityContext,
							Resources:                resourceRequirements,
						},
					},
				},
			},
		},
	}, nil
}

func (s *Scanner) getResourceRequirements(config starboard.ConfigData) (corev1.ResourceRequirements, error) {
	requirements := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("150m"),
			corev1.ResourceMemory: resource.MustParse("128M"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("600m"),
			corev1.ResourceMemory: resource.MustParse("512M"),
		},
	}

	err := setResourceLimit(config, keyResourcesRequestsCPU, &requirements.Requests, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = setResourceLimit(config, keyResourcesRequestsMemory, &requirements.Requests, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	err = setResourceLimit(config, keyResourcesLimitsCPU, &requirements.Limits, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = setResourceLimit(config, keyResourcesLimitsMemory, &requirements.Limits, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	return requirements, nil
}

func setResourceLimit(config starboard.ConfigData, configKey string, k8sResourceList *corev1.ResourceList, k8sResourceName corev1.ResourceName) error {
	if value, found := config[configKey]; found {
		quantity, err := resource.ParseQuantity(value)
		if err != nil {
			return fmt.Errorf("parsing resource definition %s: %s %w", configKey, value, err)
		}

		(*k8sResourceList)[k8sResourceName] = quantity
	}
	return nil
}

func isAtLeast(ver string, targetVer string) bool {
	v, err := version.NewVersion(ver)
	if err != nil {
		return false
	}
	tv, err := version.NewVersion(targetVer)
	if err != nil {
		return false
	}
	return v.GreaterThanOrEqual(tv)
}
