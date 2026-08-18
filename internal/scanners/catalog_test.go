package scanners

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every Assay scanner image takes exactly two positional arguments: the staged
// artifact directory and the output file. The catalog and the images have to
// agree on that, and nothing at runtime would catch a mismatch — the scanner
// would just fail inside a Job and the scan would stall.
func TestExternalScannerArgsMatchTheEntrypointContract(t *testing.T) {
	for _, name := range Names() {
		def, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if UsesOperatorImage(def) {
			continue // runner-backed scanners use their own flag interface
		}

		t.Run(name, func(t *testing.T) {
			if len(def.Args) != 2 {
				t.Fatalf("args = %v, want exactly [workspace, output]", def.Args)
			}
			if def.Args[0] != PlaceholderWorkspace {
				t.Errorf("first arg = %q, want %q", def.Args[0], PlaceholderWorkspace)
			}
			wantOutput := PlaceholderResults + "/" + def.OutputFile
			if def.Args[1] != wantOutput {
				t.Errorf("second arg = %q, want %q so the publish step reads the file the scanner wrote",
					def.Args[1], wantOutput)
			}
			if len(def.Command) != 0 {
				t.Errorf("command = %v, want the image entrypoint to be used", def.Command)
			}
		})
	}
}

// A scanner whose declared output file does not match what its entrypoint
// writes would always parse as an empty, clean result — a silent false
// negative, which is the worst failure a security scanner can have.
func TestEntrypointScriptsWriteTheDeclaredOutputFile(t *testing.T) {
	for _, name := range Names() {
		def, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if UsesOperatorImage(def) {
			continue
		}

		script := filepath.Join("..", "..", "scanners", name, "entrypoint.sh")
		content, err := os.ReadFile(script)
		if err != nil {
			if os.IsNotExist(err) {
				t.Logf("%s: no entrypoint yet (scanner image not built)", name)
				continue
			}
			t.Fatalf("read %s: %v", script, err)
		}

		t.Run(name, func(t *testing.T) {
			// The script defaults its output path; that default must name the
			// same file the catalog tells the publish step to read.
			if !strings.Contains(string(content), "/results/"+def.OutputFile) {
				t.Errorf("%s never references /results/%s, which is the file the catalog expects",
					script, def.OutputFile)
			}
		})
	}
}

func TestResolveImageUsesConfiguredRegistry(t *testing.T) {
	def, err := Get("clamav")
	if err != nil {
		t.Fatal(err)
	}

	got := ResolveImage(def, "registry.internal/mirror", "assay:1.0")
	want := "registry.internal/mirror/scanner-clamav:" + ImageTag
	if got != want {
		t.Errorf("ResolveImage() = %q, want %q", got, want)
	}
}

func TestResolveImageFallsBackToDefaultRegistry(t *testing.T) {
	def, _ := Get("trivy")

	got := ResolveImage(def, "", "assay:1.0")
	want := DefaultRegistry + "/scanner-trivy:" + ImageTag
	if got != want {
		t.Errorf("ResolveImage() = %q, want %q", got, want)
	}
}

func TestResolveImageTrimsTrailingSlash(t *testing.T) {
	def, _ := Get("syft")

	if got := ResolveImage(def, "registry.internal/mirror/", "assay:1.0"); strings.Contains(got, "//") {
		t.Errorf("ResolveImage() = %q, want no doubled slash", got)
	}
}

// Runner-backed scanners ship inside the operator image, so they must never
// be resolved against the scanner registry.
func TestRunnerScannersUseTheOperatorImage(t *testing.T) {
	for _, name := range []string{"model-inspector", "provenance"} {
		def, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := ResolveImage(def, "registry.internal", "assay:1.0"); got != "assay:1.0" {
			t.Errorf("%s resolved to %q, want the operator image", name, got)
		}
	}
}

// Image references must be pinned. A :latest tag would let a recorded verdict
// silently come to mean something different on a later scan.
func TestScannerImagesArePinned(t *testing.T) {
	if ImageTag == "latest" || ImageTag == "" {
		t.Fatalf("ImageTag = %q, want a pinned version", ImageTag)
	}
	for _, name := range Names() {
		def, _ := Get(name)
		if UsesOperatorImage(def) {
			continue
		}
		if strings.Contains(def.Image, ":") {
			t.Errorf("%s: image %q should carry no tag; the tag comes from ImageTag",
				name, def.Image)
		}
	}
}

// The default set has to cover every dimension the product claims to check.
// Losing one would leave a whole class of risk silently unscanned.
func TestDefaultScannersCoverTheCoreCategories(t *testing.T) {
	covered := map[Category]bool{}
	for _, name := range Defaults() {
		def, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		covered[def.Category] = true
	}

	for _, required := range []Category{
		CategoryMalware, CategoryCVE, CategorySBOM, CategorySecret, CategoryModel,
	} {
		if !covered[required] {
			t.Errorf("no default scanner covers category %q", required)
		}
	}
}
