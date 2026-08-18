package resolver

import "testing"

// A security engineer will paste whatever the browser gave them. Every one of
// these has to land on the same repository.
func TestHuggingFaceURIForms(t *testing.T) {
	cases := []struct {
		in       string
		repo     string
		revision string
	}{
		{"hf://deepseek-ai/DeepSeek-V4-Pro-0813", "deepseek-ai/DeepSeek-V4-Pro-0813", ""},
		{"hf://openai-community/gpt2@607a30d", "openai-community/gpt2", "607a30d"},
		{"https://huggingface.co/deepseek-ai/DeepSeek-V4-Pro-0813", "deepseek-ai/DeepSeek-V4-Pro-0813", ""},
		{"https://huggingface.co/openai-community/gpt2/tree/main", "openai-community/gpt2", "main"},
		{"https://huggingface.co/openai-community/gpt2/blob/refs%2Fpr%2F1", "openai-community/gpt2", "refs%2Fpr%2F1"},
		{"huggingface.co/bert-base-uncased", "bert-base-uncased", ""},
		{"hf://bert-base-uncased", "bert-base-uncased", ""},
	}
	for _, c := range cases {
		repo, rev, err := ParseHuggingFaceURI(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if repo != c.repo || rev != c.revision {
			t.Errorf("%s -> (%q, %q), want (%q, %q)", c.in, repo, rev, c.repo, c.revision)
		}
	}
}

func TestHuggingFaceURIRejectsNonsense(t *testing.T) {
	for _, in := range []string{
		"hf://",
		"hf://owner/name/extra/segments",
		"https://huggingface.co/",
	} {
		if repo, _, err := ParseHuggingFaceURI(in); err == nil {
			t.Errorf("%q was accepted as repository %q", in, repo)
		}
	}
}

// The point of header sampling is that it applies only to formats whose risk
// is at byte zero. Getting this wrong either downloads a terabyte or, worse,
// silently skips a file that could have executed code.
func TestOnlyHeaderBearingFormatsAreSampled(t *testing.T) {
	// These declare their structure up front and cannot execute code, so the
	// header is the entire attack surface.
	sampled := []string{"model.safetensors", "weights.gguf", "arr.npy"}
	notSampled := []string{
		"pytorch_model.bin", // a pickle; the payload can be anywhere in it
		"handler.py",        // code
		"config.json",       // trust_remote_code lives here
		"archive.zip",
		"weights.pkl",
		// The inspector string-matches suspicious operators across the whole
		// ONNX protobuf, so a sampled graph would come back clean having never
		// been read past its first few bytes.
		"graph.onnx",
	}
	for _, n := range sampled {
		if !headerInspectable(n) {
			t.Errorf("%s should be header-sampled rather than skipped", n)
		}
	}
	for _, n := range notSampled {
		if headerInspectable(n) {
			t.Errorf("%s must never be header-sampled; its risk is not confined to a header", n)
		}
	}
}

// A partial fetch that reports itself as complete is the failure this whole
// design is trying to avoid.
func TestCoverageReportsItsOwnLimits(t *testing.T) {
	full := Coverage{FetchedWhole: []string{"config.json"}}
	if !full.Complete() {
		t.Error("a fetch with nothing skipped is not reported complete")
	}

	partial := Coverage{
		FetchedWhole: []string{"config.json"},
		HeaderOnly:   []string{"model.safetensors"},
		Skipped:      map[string]string{"extra.bin": "too large"},
	}
	if partial.Complete() {
		t.Error("a fetch with header-only and skipped files claims to be complete")
	}
	if got := partial.Summary(); got == "" || got == full.Summary() {
		t.Errorf("partial summary %q does not distinguish itself", got)
	}
}

func TestHuggingFaceIsRegisteredForTheHFScheme(t *testing.T) {
	r := NewRegistry()
	if !r.Supports("hf://openai-community/gpt2") {
		t.Error("hf:// URIs have no resolver")
	}
}
