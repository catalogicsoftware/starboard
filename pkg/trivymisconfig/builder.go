package trivymisconfig

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/starboard"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ScanJobBuilder struct {
	plugin        Plugin
	pluginContext starboard.PluginContext
	timeout       time.Duration
	object        client.Object
	// credentials       map[string]docker.Auth
	tolerations       []corev1.Toleration
	annotations       map[string]string
	podTemplateLabels labels.Set
}

func NewScanJobBuilder() *ScanJobBuilder {
	return &ScanJobBuilder{}
}

func (s *ScanJobBuilder) WithPlugin(plugin Plugin) *ScanJobBuilder {
	s.plugin = plugin
	return s
}

func (s *ScanJobBuilder) WithPluginContext(pluginContext starboard.PluginContext) *ScanJobBuilder {
	s.pluginContext = pluginContext
	return s
}

func (s *ScanJobBuilder) WithTimeout(timeout time.Duration) *ScanJobBuilder {
	s.timeout = timeout
	return s
}

func (s *ScanJobBuilder) WithObject(object client.Object) *ScanJobBuilder {
	s.object = object
	return s
}

func (s *ScanJobBuilder) WithTolerations(tolerations []corev1.Toleration) *ScanJobBuilder {
	s.tolerations = tolerations
	return s
}

func (s *ScanJobBuilder) WithAnnotations(annotations map[string]string) *ScanJobBuilder {
	s.annotations = annotations
	return s
}

func (s *ScanJobBuilder) WithPodTemplateLabels(podTemplateLabels labels.Set) *ScanJobBuilder {
	s.podTemplateLabels = podTemplateLabels
	return s
}

// func (s *ScanJobBuilder) WithCredentials(credentials map[string]docker.Auth) *ScanJobBuilder {
// 	s.credentials = credentials
// 	return s
// }

func (s *ScanJobBuilder) Get() (*batchv1.Job, error) {
	spec, err := kube.GetPodSpec(s.object)
	if err != nil {
		return nil, err
	}

	// s.object is not correct
	templateSpec, err := s.plugin.GetScanJobSpec(s.pluginContext, s.object)
	if err != nil {
		return nil, err
	}
	templateSpec.Tolerations = append(templateSpec.Tolerations, s.tolerations...)

	containerImagesAsJSON, err := kube.GetContainerImagesFromPodSpec(spec).AsJSON()
	if err != nil {
		return nil, err
	}

	podSpecHash := kube.ComputeHash(spec)

	labelsSet := map[string]string{
		starboard.LabelResourceSpecHash:           podSpecHash,
		starboard.LabelK8SAppManagedBy:            starboard.AppStarboard,
		starboard.LabelVulnerabilityReportScanner: s.pluginContext.GetName(),
	}
	podTemplateLabelsSet := make(labels.Set)
	for index, element := range labelsSet {
		podTemplateLabelsSet[index] = element
	}
	for index, element := range s.podTemplateLabels {
		podTemplateLabelsSet[index] = element
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GetScanJobName(s.object),
			Namespace: s.pluginContext.GetNamespace(),
			Labels:    labelsSet,
			Annotations: map[string]string{
				starboard.AnnotationContainerImages: containerImagesAsJSON,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(s.timeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      podTemplateLabelsSet,
					Annotations: s.annotations,
				},
				Spec: templateSpec,
			},
		},
	}

	err = kube.ObjectToObjectMeta(s.object, &job.ObjectMeta)
	if err != nil {
		return nil, err
	}

	err = kube.ObjectToObjectMeta(s.object, &job.Spec.Template.ObjectMeta)
	if err != nil {
		return nil, err
	}

	return job, nil
}

// When run scan job in workload namespace is enabled then this method will update scanjob spec with these changes
// - namespace same as workload
// - service account same as workload service account
// - ImagePullSecret same as workload imagePullSecret
func (s *ScanJobBuilder) updateScanJobForWorkloadNamespace(job *batchv1.Job, podspec corev1.PodSpec, secrets []*corev1.Secret) {
	operatorConfig := s.pluginContext.GetStarboardConfig()
	if !operatorConfig.VulnerabilityScanJobsInSameNamespace() {
		return
	}
	job.Namespace = s.object.GetNamespace()
	job.Spec.Template.Spec.ServiceAccountName = podspec.ServiceAccountName
	job.Spec.Template.Spec.ImagePullSecrets = podspec.ImagePullSecrets
	for i, _ := range secrets {
		secrets[i].Namespace = s.object.GetNamespace()
	}
}

func GetScanJobName(obj client.Object) string {
	return fmt.Sprintf("scan-misconfigreport-%s", kube.ComputeHash(kube.ObjectRef{
		Kind:      kube.Kind(obj.GetObjectKind().GroupVersionKind().Kind),
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}))
}

func RegistryCredentialsSecretName(obj client.Object) string {
	return fmt.Sprintf("%s-regcred", GetScanJobName(obj))
}

type ReportBuilder struct {
	scheme     *runtime.Scheme
	controller client.Object
	container  string
	hash       string
	data       v1alpha1.MisconfigurationReportData
	reportTTL  *time.Duration
}

func NewReportBuilder(scheme *runtime.Scheme) *ReportBuilder {
	return &ReportBuilder{
		scheme: scheme,
	}
}

func (b *ReportBuilder) Controller(controller client.Object) *ReportBuilder {
	b.controller = controller
	return b
}

func (b *ReportBuilder) Container(name string) *ReportBuilder {
	b.container = name
	return b
}

func (b *ReportBuilder) PodSpecHash(hash string) *ReportBuilder {
	b.hash = hash
	return b
}

func (b *ReportBuilder) Data(data v1alpha1.MisconfigurationReportData) *ReportBuilder {
	b.data = data
	return b
}

func (b *ReportBuilder) ReportTTL(ttl *time.Duration) *ReportBuilder {
	b.reportTTL = ttl
	return b
}

func (b *ReportBuilder) reportName() string {
	kind := b.controller.GetObjectKind().GroupVersionKind().Kind
	name := b.controller.GetName()
	reportName := fmt.Sprintf("%s-%s-%s", strings.ToLower(kind), name, b.container)
	if len(validation.IsValidLabelValue(reportName)) == 0 {
		return reportName
	}

	return fmt.Sprintf("%s-%s", strings.ToLower(kind), kube.ComputeHash(name+"-"+b.container))
}

func (b *ReportBuilder) Get() (v1alpha1.MisconfigurationReport, error) {
	labels := map[string]string{
		starboard.LabelContainerName: b.container,
	}

	if b.hash != "" {
		labels[starboard.LabelResourceSpecHash] = b.hash
	}

	report := v1alpha1.MisconfigurationReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.reportName(),
			Namespace: b.controller.GetNamespace(),
			Labels:    labels,
		},
		Report: b.data,
	}

	// if b.reportTTL != nil {
	// 	report.Annotations = map[string]string{
	// 		v1alpha1.TTLReportAnnotation: b.reportTTL.String(),
	// 	}
	// }
	// err := kube.ObjectToObjectMeta(b.controller, &report.ObjectMeta)
	// if err != nil {
	// 	return v1alpha1.MisconfigurationReport{}, err
	// }
	// err = controllerutil.SetControllerReference(b.controller, &report, b.scheme)
	// if err != nil {
	// 	return v1alpha1.MisconfigurationReport{}, fmt.Errorf("setting controller reference: %w", err)
	// }
	// // The OwnerReferencesPermissionsEnforcement admission controller protects the
	// // access to metadata.ownerReferences[x].blockOwnerDeletion of an object, so
	// // that only users with "update" permission to the finalizers subresource of the
	// // referenced owner can change it.
	// // We set metadata.ownerReferences[x].blockOwnerDeletion to false so that
	// // additional RBAC permissions are not required when the OwnerReferencesPermissionsEnforcement
	// // is enabled.
	// // See https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#ownerreferencespermissionenforcement
	// report.OwnerReferences[0].BlockOwnerDeletion = pointer.BoolPtr(false)
	return report, nil
}
