package modelsource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMLflowArtifactPath(t *testing.T) {
	cases := []struct {
		src   string
		want  string
		isPxy bool
	}{
		{"mlflow-artifacts:/0/abc/artifacts/model", "0/abc/artifacts/model", true},
		{"mlflow-artifacts:///0/abc/artifacts", "0/abc/artifacts", true},
		{"mlflow-artifacts://host:5000/1/def/artifacts/m", "1/def/artifacts/m", true},
		{"s3://bucket/model", "", false},
		{"models:/name/1", "", false},
	}
	for _, c := range cases {
		got, ok := mlflowArtifactPath(c.src)
		if ok != c.isPxy || (ok && got != c.want) {
			t.Errorf("mlflowArtifactPath(%q) = (%q, %v), want (%q, %v)", c.src, got, ok, c.want, c.isPxy)
		}
	}
}

// fakeMLflow is an in-memory stand-in for the tracking server's REST surface.
type fakeMLflow struct {
	mu   sync.Mutex
	tags map[string]string // "key" -> "value" set via set-tag
}

func (f *fakeMLflow) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/2.0/mlflow/registered-models/search", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, searchModelsResponse{RegisteredModels: []mlflowRegisteredModel{{Name: "fraud-detector"}}})
	})

	mux.HandleFunc("/api/2.0/mlflow/model-versions/search", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("filter"); got != "name='fraud-detector'" {
			t.Errorf("unexpected version filter %q", got)
		}
		writeJSON(w, searchVersionsResponse{ModelVersions: []mlflowModelVersion{{
			Name: "fraud-detector", Version: "3", CurrentStage: "Production",
			Source: "mlflow-artifacts:/0/run123/artifacts/model", RunID: "run123",
		}}})
	})

	// Artifact proxy. Like the real server, the listing returns each entry's
	// path *relative to the queried directory*, and a subdirectory must be
	// followed to reach the file — so this exercises the rejoin-and-recurse
	// logic, not just a flat listing.
	mux.HandleFunc("/api/2.0/mlflow-artifacts/artifacts", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("path") {
		case "0/run123/artifacts/model":
			writeJSON(w, listArtifactsResponse{Files: []artifactFile{
				{Path: "data", IsDir: true},
				{Path: "MLmodel", IsDir: false, FileSize: 3},
			}})
		case "0/run123/artifacts/model/data":
			writeJSON(w, listArtifactsResponse{Files: []artifactFile{
				{Path: "weights.pkl", IsDir: false, FileSize: 5},
			}})
		default:
			writeJSON(w, listArtifactsResponse{})
		}
	})

	mux.HandleFunc("/api/2.0/mlflow-artifacts/artifacts/", func(w http.ResponseWriter, r *http.Request) {
		// Serve content by full path so the test proves the download URL is the
		// rejoined full path, not the listing's relative entry.
		switch r.URL.Path {
		case "/api/2.0/mlflow-artifacts/artifacts/0/run123/artifacts/model/data/weights.pkl":
			w.Write([]byte("bytes"))
		case "/api/2.0/mlflow-artifacts/artifacts/0/run123/artifacts/model/MLmodel":
			w.Write([]byte("yml"))
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	})

	mux.HandleFunc("/api/2.0/mlflow/model-versions/set-tag", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode set-tag: %v", err)
		}
		f.mu.Lock()
		f.tags[body["key"]] = body["value"]
		f.mu.Unlock()
		writeJSON(w, map[string]any{})
	})

	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestMLflowListResolveWriteBack(t *testing.T) {
	fake := &fakeMLflow{tags: map[string]string{}}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	src := NewMLflow(MLflowOptions{BaseURL: srv.URL})
	ctx := context.Background()

	// List
	versions, err := src.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("List returned %d versions, want 1", len(versions))
	}
	v := versions[0]
	if v.ModelName != "fraud-detector" || v.Version != "3" {
		t.Errorf("version identity = %s/%s, want fraud-detector/3", v.ModelName, v.Version)
	}
	if v.Labels["mlflow.run_id"] != "run123" {
		t.Errorf("run id label = %q, want run123", v.Labels["mlflow.run_id"])
	}

	// Resolve
	dest := t.TempDir()
	artifact, err := src.Resolve(ctx, v, dest)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	staged := filepath.Join(dest, "data", "weights.pkl")
	data, err := os.ReadFile(staged)
	if err != nil {
		t.Fatalf("staged file missing: %v", err)
	}
	if string(data) != "bytes" {
		t.Errorf("staged content = %q, want %q", data, "bytes")
	}
	// Both files (nested weights.pkl + top-level MLmodel) should be staged,
	// preserving the tree below the model root.
	if _, err := os.ReadFile(filepath.Join(dest, "MLmodel")); err != nil {
		t.Errorf("top-level MLmodel not staged: %v", err)
	}
	if artifact.SizeBytes != int64(len("bytes")+len("yml")) {
		t.Errorf("artifact size = %d, want %d", artifact.SizeBytes, len("bytes")+len("yml"))
	}

	// WriteBack
	err = src.WriteBack(ctx, v, Verdict{Verdict: "Quarantined", RiskScore: 60, Malware: "Clean"})
	if err != nil {
		t.Fatalf("WriteBack: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.tags[TagVerdict] != "Quarantined" {
		t.Errorf("verdict tag = %q, want Quarantined", fake.tags[TagVerdict])
	}
	if fake.tags[TagRiskScore] != "60" {
		t.Errorf("risk score tag = %q, want 60", fake.tags[TagRiskScore])
	}
	if fake.tags[TagMalware] != "Clean" {
		t.Errorf("malware tag = %q, want Clean", fake.tags[TagMalware])
	}
}
