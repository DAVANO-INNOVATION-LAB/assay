package webhook

import (
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ModelRef is the model a workload intends to serve.
type ModelRef struct {
	Model       string
	Version     string
	Digest      string
	StorageURI  string
	Environment string
}

// extractModelRef pulls the model reference out of an admitted object. KServe
// InferenceServices are understood natively; every other kind opts in through
// annotations.
func extractModelRef(obj *unstructured.Unstructured) ModelRef {
	ref := ModelRef{}
	annotations := obj.GetAnnotations()

	ref.Model = annotations[AnnotationModel]
	ref.Version = annotations[AnnotationVersion]
	ref.Environment = annotations[AnnotationEnvironment]

	if obj.GetKind() == "InferenceService" {
		if uri := inferenceServiceStorageURI(obj); uri != "" {
			ref.StorageURI = uri
			ref.Digest = digestFromURI(uri)
			if ref.Model == "" {
				ref.Model, ref.Version = modelFromStorageURI(uri)
			}
		}
	}

	if ref.Environment == "" {
		ref.Environment = obj.GetLabels()[AnnotationEnvironment]
	}
	return ref
}

// inferenceServiceStorageURI reads spec.predictor.model.storageUri, falling
// back to the pre-v1beta1 spec.predictor.<framework>.storageUri layout.
func inferenceServiceStorageURI(obj *unstructured.Unstructured) string {
	if uri, found, err := unstructured.NestedString(obj.Object, "spec", "predictor", "model", "storageUri"); err == nil && found {
		return uri
	}

	predictor, found, err := unstructured.NestedMap(obj.Object, "spec", "predictor")
	if err != nil || !found {
		return ""
	}
	for _, value := range predictor {
		framework, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if uri, ok := framework["storageUri"].(string); ok && uri != "" {
			return uri
		}
	}
	return ""
}

// modelFromStorageURI derives a model name and version from a storage URI when
// the workload carries no explicit annotations. The last two path segments of
// a KServe storage URI conventionally hold the model and version.
func modelFromStorageURI(uri string) (model, version string) {
	trimmed := uri
	if idx := strings.Index(trimmed, "://"); idx >= 0 {
		trimmed = trimmed[idx+3:]
	}
	trimmed = strings.SplitN(trimmed, "@", 2)[0]
	trimmed = strings.TrimSuffix(trimmed, "/")

	parts := strings.Split(trimmed, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2], parts[len(parts)-1]
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return "", ""
}

// digestFromURI extracts a pinned digest from an OCI-style reference.
func digestFromURI(uri string) string {
	if idx := strings.LastIndex(uri, "@"); idx >= 0 {
		return uri[idx+1:]
	}
	return ""
}
