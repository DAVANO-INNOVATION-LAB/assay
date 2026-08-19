package inspector

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/assay/api/v1alpha1"
)

// Keras and TensorFlow SavedModel inspection.
//
// These formats were reported as present by the artifact summary and examined
// by nothing, which is the worst combination available: the scan named the
// format and then said nothing about it, so a reader had every reason to
// conclude it had been checked. They matter because Red Hat OpenShift AI —
// the platform this operator targets — ships Keras and TensorFlow serving
// runtimes, so a .keras or .h5 file in a model repository is loaded by
// something a cluster already runs.
//
// Three load-time execution paths are real and documented:
//
//   - A Lambda layer serialises a Python code object into the model and
//     executes it on load. Keras 3 refuses this under the default
//     safe_mode=True; Keras 2 and tf.keras legacy HDF5 loading do not, and
//     safe_mode is a keyword argument a serving runtime is free to pass as
//     False.
//   - CVE-2025-1550 (Keras 3.0.0 to before 3.8.0): "By altering the
//     config.json file within the archive, an attacker can specify arbitrary
//     Python modules and functions, along with their arguments, to be loaded
//     and executed during model loading." It bypasses safe_mode.
//   - CVE-2026-1462 (Keras before 3.13.2, CVSS 8.8): TFSMLayer
//     unconditionally loads an external TensorFlow SavedModel during
//     deserialization, from an attacker-controlled path, "even when
//     safe_mode=True".
//
// Both CVEs are against keras-team/keras. They reach OpenShift AI because it
// ships Keras, not because the CVE records name the product — the distinction
// matters when someone checks the citation.
const (
	// FindingKerasLambda is a serialized Python code object in a layer.
	FindingKerasLambda = "ASSAY-KERAS-001"
	// FindingKerasExternalModel is a layer that loads another model from a
	// path recorded in the config.
	FindingKerasExternalModel = "ASSAY-KERAS-002"
	// FindingKerasForeignModule is a layer whose implementation is imported
	// from outside the Keras and TensorFlow namespaces.
	FindingKerasForeignModule = "ASSAY-KERAS-003"
	// FindingKerasUnreadable is a Keras container that could not be examined.
	FindingKerasUnreadable = "ASSAY-KERAS-004"
	// FindingSavedModelOp is a graph operation that reads, writes or executes
	// outside the graph.
	FindingSavedModelOp = "ASSAY-TF-001"
)

// maxKerasConfigBytes bounds the config document read out of a .keras archive.
// A model config is a few hundred kilobytes; anything at this size is not one.
const maxKerasConfigBytes = 32 << 20

// hdf5Magic is the HDF5 superblock signature.
var hdf5Magic = []byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'}

// maxHDF5ScanBytes bounds the byte scan of an HDF5 file. Legacy Keras writes
// the model configuration as a JSON attribute in the root group, which lives in
// the object header near the start of the file. Reading the whole of a
// multi-gigabyte weights file to find it would be a denial of service against
// the scan pod for no additional coverage.
const maxHDF5ScanBytes = 64 << 20

// inspectKerasArchive examines a Keras v3 .keras file, which is a zip holding
// config.json, metadata.json and the weights.
//
// The archive is inspected as an archive first, so traversal entries and
// compression bombs are caught by the checks that already exist for zips, and
// then its configuration is read for the load-time execution paths above.
func inspectKerasArchive(path, rel string, limits Limits) ([]securityv1alpha1.Finding, error) {
	findings, err := inspectZip(path, rel, limits)
	if err != nil {
		// A .keras that is not a readable zip is not a footnote: the format
		// executes on load, so an unexaminable one is reported as such.
		return []securityv1alpha1.Finding{unreadable(
			FindingKerasUnreadable, "Keras model could not be examined", rel, err.Error())}, nil
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		return append(findings, unreadable(
			FindingKerasUnreadable, "Keras model could not be examined", rel, err.Error())), nil
	}
	defer zr.Close()

	for _, entry := range zr.File {
		if entry.Name != "config.json" {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return append(findings, unreadable(
				FindingKerasUnreadable, "Keras model config could not be read", rel, err.Error())), nil
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxKerasConfigBytes))
		rc.Close()
		if err != nil {
			return append(findings, unreadable(
				FindingKerasUnreadable, "Keras model config could not be read", rel, err.Error())), nil
		}
		findings = append(findings, inspectKerasConfig(data, rel+"!config.json")...)
		break
	}
	return findings, nil
}

// inspectHDF5 examines a legacy Keras .h5 file.
//
// This is a byte scan, not an HDF5 walk. Parsing HDF5 properly means a B-tree
// and heap reader, and writing one to inspect untrusted files would add more
// attack surface than it removes. The scan therefore reports what the file
// contains, not where in the file it sits — a limitation worth stating,
// because it means a match cannot be attributed to a specific layer.
func inspectHDF5(path, rel string, isKerasName bool) ([]securityv1alpha1.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxHDF5ScanBytes))
	if err != nil {
		return []securityv1alpha1.Finding{unreadable(
			FindingKerasUnreadable, "HDF5 model could not be read", rel, err.Error())}, nil
	}

	// The configuration is stored as a JSON string attribute. Locating it
	// keeps the match anchored to a Keras model rather than to any file that
	// happens to contain the word "Lambda".
	idx := bytes.Index(data, []byte(`"class_name"`))
	if idx < 0 {
		if isKerasName && !bytes.HasPrefix(data, hdf5Magic) {
			return []securityv1alpha1.Finding{finding(
				FindingKerasUnreadable, "File named as a Keras model is not HDF5", "Medium", rel,
				"the extension declares a Keras HDF5 model and the header is not HDF5; "+
					"a renamed file is how a format check is evaded")}, nil
		}
		return nil, nil
	}
	return inspectKerasConfig(data[idx:], rel), nil
}

// kerasForeignModule matches a serialized layer whose implementation comes from
// outside Keras and TensorFlow. This is the shape CVE-2025-1550 exploits.
var kerasForeignModule = regexp.MustCompile(`"module"\s*:\s*"([A-Za-z_][A-Za-z0-9_.]*)"`)

// kerasHomeModules are the namespaces a legitimate serialized layer names.
var kerasHomeModules = []string{
	"keras", "tensorflow", "tf", "builtins.keras", "keras_nlp", "keras_cv", "keras_hub",
}

// inspectKerasConfig reports the load-time execution paths a Keras model
// configuration can carry. It takes the raw bytes rather than a parsed
// document because the same checks have to run against a JSON file from a
// .keras archive and against a JSON string embedded in an HDF5 attribute.
func inspectKerasConfig(data []byte, rel string) []securityv1alpha1.Finding {
	var findings []securityv1alpha1.Finding

	if hasClassName(data, "Lambda") {
		findings = append(findings, finding(
			FindingKerasLambda, "Keras Lambda layer executes serialized Python", "Critical", rel,
			"a Lambda layer carries a marshalled Python code object that runs when the "+
				"model is loaded. Keras 3 refuses to deserialize one under the default "+
				"safe_mode=True, but Keras 2 and legacy tf.keras HDF5 loading do not, and "+
				"safe_mode is an argument a serving runtime may pass as False"))
	}

	if hasClassName(data, "TFSMLayer") {
		findings = append(findings, finding(
			FindingKerasExternalModel, "Keras TFSMLayer loads an external SavedModel", "Critical", rel,
			"TFSMLayer loads a TensorFlow SavedModel from a path recorded in this config "+
				"during deserialization. CVE-2026-1462 (Keras before 3.13.2, CVSS 8.8) is "+
				"that it does so unconditionally, from an attacker-controlled path, even "+
				"when safe_mode=True"))
	}

	seen := map[string]bool{}
	for _, m := range kerasForeignModule.FindAllSubmatch(data, -1) {
		module := string(m[1])
		if isKerasHomeModule(module) || seen[module] {
			continue
		}
		seen[module] = true
		findings = append(findings, finding(
			FindingKerasForeignModule, "Keras config imports a module outside Keras", "High", rel,
			fmt.Sprintf("a serialized object names module %q, which is neither Keras nor "+
				"TensorFlow. CVE-2025-1550 (Keras 3.0.0 to before 3.8.0) is that an altered "+
				"config.json can 'specify arbitrary Python modules and functions, along with "+
				"their arguments, to be loaded and executed during model loading', bypassing "+
				"safe_mode", module)))
	}
	return findings
}

// hasClassName looks for a serialized layer of the given class. Matching the
// key and the value together is what keeps this from firing on a tensor named
// "Lambda" or a docstring.
func hasClassName(data []byte, class string) bool {
	for _, form := range []string{
		`"class_name": "` + class + `"`,
		`"class_name":"` + class + `"`,
		`"class_name" : "` + class + `"`,
	} {
		if bytes.Contains(data, []byte(form)) {
			return true
		}
	}
	return false
}

func isKerasHomeModule(module string) bool {
	for _, home := range kerasHomeModules {
		if module == home || strings.HasPrefix(module, home+".") {
			return true
		}
	}
	return false
}

// savedModelOps are graph operations that reach outside the graph. A
// TensorFlow graph is data, but these operations make loading or running one
// equivalent to running code.
var savedModelOps = map[string]string{
	"PyFunc":             "runs an arbitrary Python callable from inside the graph",
	"PyFuncStateless":    "runs an arbitrary Python callable from inside the graph",
	"ReadFile":           "reads a file from the serving container's filesystem",
	"WriteFile":          "writes a file into the serving container's filesystem",
	"MergeV2Checkpoints": "writes checkpoint files at a path taken from the graph",
	"Save":               "writes to a path taken from the graph",
	"SaveV2":             "writes to a path taken from the graph",
	"DecodeJpeg":         "",
}

// inspectSavedModel examines a TensorFlow SavedModel protobuf.
//
// As with ONNX, the schema is large and string-matching operation names in the
// serialized graph is enough to flag a file that needs review. The operation
// names appear verbatim in the protobuf because NodeDef.op is a string field.
func inspectSavedModel(path, rel string) ([]securityv1alpha1.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return []securityv1alpha1.Finding{unreadable(
			FindingSavedModelOp, "SavedModel could not be read", rel, err.Error())}, nil
	}

	var findings []securityv1alpha1.Finding
	for op, why := range savedModelOps {
		if !bytes.Contains(data, []byte(op)) {
			continue
		}
		// Reading a file is a lower bar than running one: a legitimate
		// preprocessing graph reads its own assets. Writing and calling out
		// to Python are not things a serving graph needs to do.
		severity := "High"
		if op == "ReadFile" {
			severity = "Medium"
		}
		findings = append(findings, finding(
			FindingSavedModelOp, "TensorFlow graph operation reaches outside the graph",
			severity, rel, fmt.Sprintf("the graph contains a %s operation, which %s", op, why)))
	}
	return findings, nil
}
