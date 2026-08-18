// Package scanners defines the built-in scanner catalog: which container
// image implements each scanner, how it is invoked, and what category of
// finding it produces.
package scanners

import (
	"fmt"
	"sort"
	"strings"
)

// Category groups scanners by the kind of finding they produce. The policy
// engine gates on categories, not on individual scanner names, so operators
// can swap implementations without rewriting policy.
type Category string

const (
	CategoryMalware    Category = "malware"
	CategoryCVE        Category = "cve"
	CategorySBOM       Category = "sbom"
	CategorySecret     Category = "secret"
	CategoryLicense    Category = "license"
	CategoryModel      Category = "model"
	CategoryProvenance Category = "provenance"
)

// There is deliberately no behavioural / "AI safety" category. Prompt-injection
// resistance, jailbreak and backdoor detection are open research problems, not
// checks a scanner can make a defensible claim about. Assay's scope is the
// model *artifact*. A placeholder category here would imply a roadmap the
// README explicitly disavows, and a policy could name it and get a verdict that
// meant nothing.

// DefaultRegistry is where the Assay scanner images are published. Air-gapped
// clusters mirror these and point the operator at the mirror with
// --scanner-registry, so image references are never hardcoded to a host the
// cluster cannot reach.
const DefaultRegistry = "quay.io/davano"

// ImageTag pins the scanner image version. A security scanner must be
// reproducible: :latest would silently change what a recorded verdict means.
const ImageTag = "0.1.0"

// Definition describes one scanner in the catalog.
type Definition struct {
	// Name is the scanner's stable identifier, used in policies.
	Name string
	// Category of finding this scanner produces.
	Category Category
	// Image is the repository name within the scanner registry, without a
	// registry host or tag. Empty means the scanner is implemented by the
	// Assay runner and uses the operator image.
	Image string
	// Command overrides the image entrypoint.
	Command []string
	// Args is the default argument list. WorkspacePath and ResultsPath are
	// substituted at job build time.
	Args []string
	// OutputFile is the path the scanner writes its report to, relative to
	// the results volume.
	OutputFile string
	// ResultFormat tells the publisher how to parse OutputFile.
	ResultFormat string
	// NeedsNetwork indicates the scanner requires egress (e.g. to fetch
	// vulnerability databases). Air-gapped clusters must mirror these.
	NeedsNetwork bool
	// DefaultEnabled marks scanners that run when a policy lists no scanners.
	DefaultEnabled bool
	// Unbuilt marks a catalog entry that has no image in scanners/ yet.
	//
	// The catalog is what validates a policy's scanner list, so an entry with
	// no image passed validation and then produced a Job that could only
	// ImagePullBackOff — a scan that hangs rather than a policy that is
	// rejected. Naming one of these is now an error at the point of use.
	Unbuilt bool
}

// Placeholders substituted into scanner arguments when a Job is built.
const (
	PlaceholderWorkspace = "$(WORKSPACE)"
	PlaceholderResults   = "$(RESULTS)"
)

// Result formats the publisher understands.
const (
	FormatAssay      = "assay"
	FormatClamAV     = "clamav"
	FormatTrivyJSON  = "trivy-json"
	FormatGrypeJSON  = "grype-json"
	FormatSyftSPDX   = "syft-spdx"
	FormatTrufflehog = "trufflehog-json"
)

// catalog is the built-in scanner set.
//
// Every Assay scanner image exposes the same contract: its entrypoint takes
// exactly two positional arguments, the staged artifact directory and the
// output file. Tool-specific flags live in the image's entrypoint script
// rather than here, so the catalog never has to encode one tool's CLI, and a
// scanner can be replaced without touching the operator.
var catalog = map[string]Definition{
	"clamav": {
		Name:           "clamav",
		Category:       CategoryMalware,
		Image:          "scanner-clamav",
		Args:           []string{PlaceholderWorkspace, PlaceholderResults + "/clamav.txt"},
		OutputFile:     "clamav.txt",
		ResultFormat:   FormatClamAV,
		DefaultEnabled: true,
	},
	"yara": {
		Name:         "yara",
		Category:     CategoryMalware,
		Image:        "scanner-yara",
		Args:         []string{PlaceholderWorkspace, PlaceholderResults + "/yara.json"},
		OutputFile:   "yara.json",
		ResultFormat: FormatAssay,
		// No image is built for this yet; see scanners/.
		Unbuilt: true,
	},
	"trivy": {
		Name:         "trivy",
		Category:     CategoryCVE,
		Image:        "scanner-trivy",
		Args:         []string{PlaceholderWorkspace, PlaceholderResults + "/trivy.json"},
		OutputFile:   "trivy.json",
		ResultFormat: FormatTrivyJSON,
		// The image ships a baked vulnerability database, so a scan needs no
		// egress. Egress is only required to refresh the DB, which is done by
		// rebuilding the image.
		NeedsNetwork:   false,
		DefaultEnabled: true,
	},
	"grype": {
		Name:         "grype",
		Category:     CategoryCVE,
		Image:        "scanner-grype",
		Args:         []string{PlaceholderWorkspace, PlaceholderResults + "/grype.json"},
		OutputFile:   "grype.json",
		ResultFormat: FormatGrypeJSON,
	},
	"syft": {
		Name:           "syft",
		Category:       CategorySBOM,
		Image:          "scanner-syft",
		Args:           []string{PlaceholderWorkspace, PlaceholderResults + "/sbom.spdx.json"},
		OutputFile:     "sbom.spdx.json",
		ResultFormat:   FormatSyftSPDX,
		DefaultEnabled: true,
	},
	"trufflehog": {
		Name:           "trufflehog",
		Category:       CategorySecret,
		Image:          "scanner-trufflehog",
		Args:           []string{PlaceholderWorkspace, PlaceholderResults + "/trufflehog.json"},
		OutputFile:     "trufflehog.json",
		ResultFormat:   FormatTrufflehog,
		DefaultEnabled: true,
	},
	"model-inspector": {
		Name:           "model-inspector",
		Category:       CategoryModel,
		Image:          "", // filled in with the Assay operator image at job build time
		Command:        []string{"/assay-runner"},
		Args:           []string{"inspect", "--workspace", PlaceholderWorkspace, "--out", PlaceholderResults + "/model-inspector.json"},
		OutputFile:     "model-inspector.json",
		ResultFormat:   FormatAssay,
		DefaultEnabled: true,
	},
	"provenance": {
		Name:           "provenance",
		Category:       CategoryProvenance,
		Image:          "",
		Command:        []string{"/assay-runner"},
		Args:           []string{"verify-provenance", "--workspace", PlaceholderWorkspace, "--out", PlaceholderResults + "/provenance.json"},
		OutputFile:     "provenance.json",
		ResultFormat:   FormatAssay,
		DefaultEnabled: true,
	},
	"license": {
		Name:         "license",
		Category:     CategoryLicense,
		Image:        "scanner-license",
		Args:         []string{PlaceholderWorkspace, PlaceholderResults + "/license.json"},
		OutputFile:   "license.json",
		ResultFormat: FormatAssay,
		// No image is built for this yet; see scanners/.
		Unbuilt: true,
	},
}

// ResolveImage returns the fully qualified image for a scanner.
//
// operatorImage is used for scanners implemented by the Assay runner. registry
// is the host and namespace holding the scanner images; an empty value falls
// back to DefaultRegistry, which lets an air-gapped cluster point at a mirror
// without any change to the catalog.
func ResolveImage(def Definition, registry, operatorImage string) string {
	if UsesOperatorImage(def) {
		return operatorImage
	}
	if registry == "" {
		registry = DefaultRegistry
	}
	return fmt.Sprintf("%s/%s:%s", strings.TrimSuffix(registry, "/"), def.Image, ImageTag)
}

// Get returns the catalog definition for a scanner name.
func Get(name string) (Definition, error) {
	def, ok := catalog[name]
	if !ok {
		return Definition{}, fmt.Errorf("unknown scanner %q; known scanners: %v", name, Names())
	}
	if def.Unbuilt {
		// Failing here turns a scan that would sit in ImagePullBackOff until
		// its deadline into a policy that is rejected up front, with a reason.
		return Definition{}, fmt.Errorf(
			"scanner %q is declared in the catalog but has no image built yet; "+
				"remove it from the policy (available: %v)", name, Available())
	}
	return def, nil
}

// Available returns the scanners that actually have an image, sorted. This is
// the set a policy may name.
func Available() []string {
	names := make([]string, 0, len(catalog))
	for name, def := range catalog {
		if def.Unbuilt {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Names returns every scanner name in the catalog, sorted.
func Names() []string {
	names := make([]string, 0, len(catalog))
	for name := range catalog {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Defaults returns the scanners that run when a policy specifies none.
func Defaults() []string {
	var names []string
	for name, def := range catalog {
		if def.DefaultEnabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// UsesOperatorImage reports whether a scanner is implemented by the Assay
// runner binary rather than an external tool image.
func UsesOperatorImage(def Definition) bool { return def.Image == "" }
