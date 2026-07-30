// Package inspector implements Zeus's own model-format scanner. Generic
// container scanners see a model as an opaque blob; this one understands the
// serialization formats and flags the ways a model file can execute code.
package inspector

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	securityv1alpha1 "github.com/zeus-security/zeus-operator/api/v1alpha1"
)

// Report is the model inspector's output.
type Report struct {
	Findings []securityv1alpha1.Finding `json:"findings"`
	// FilesScanned is how many files the inspector examined.
	FilesScanned int `json:"filesScanned"`
	// Formats lists the model formats detected in the artifact.
	Formats []string `json:"formats,omitempty"`
}

// Limits bound the inspector's work so a hostile artifact cannot exhaust the
// scan pod.
type Limits struct {
	// MaxFiles caps how many files are examined.
	MaxFiles int
	// MaxArchiveEntries caps entries read from any single archive.
	MaxArchiveEntries int
	// MaxDecompressedBytes caps total bytes read out of any single archive.
	MaxDecompressedBytes int64
	// CompressionRatioLimit flags archives whose expansion ratio exceeds it.
	CompressionRatioLimit float64
}

// DefaultLimits are the limits used when none are supplied.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:              50000,
		MaxArchiveEntries:     10000,
		MaxDecompressedBytes:  8 << 30, // 8 GiB
		CompressionRatioLimit: 200,
	}
}

// Inspect walks the staged artifact at root and reports model-level risks.
func Inspect(root string, limits Limits) (*Report, error) {
	if limits.MaxFiles == 0 {
		limits = DefaultLimits()
	}

	report := &Report{}
	formats := map[string]bool{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// A single unreadable file must not abort the whole scan.
			report.Findings = append(report.Findings, finding(
				"ZEUS-IO-001", "Unreadable file", "Low", relPath(root, path),
				fmt.Sprintf("could not read file: %v", err)))
			return nil
		}
		if report.FilesScanned >= limits.MaxFiles {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}

		rel := relPath(root, path)

		// Symlinks are reported and never followed: a model archive that
		// links to /etc or the service account token is an exfiltration
		// attempt, not a legitimate layout.
		if info.Mode()&os.ModeSymlink != 0 {
			target, _ := os.Readlink(path)
			if isEscapingLink(root, path, target) {
				report.Findings = append(report.Findings, finding(
					"ZEUS-LINK-001", "Symlink escapes model directory", "High", rel,
					fmt.Sprintf("symlink points outside the artifact: %s", target)))
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		report.FilesScanned++

		if info.Mode().Perm()&0o111 != 0 {
			report.Findings = append(report.Findings, finding(
				"ZEUS-EXEC-001", "Executable file in model artifact", "Medium", rel,
				"model artifacts should not ship executable files"))
		}

		if format := formatOf(rel); format != "" {
			formats[format] = true
		}

		findings, err := inspectFile(path, rel, limits)
		if err != nil {
			report.Findings = append(report.Findings, finding(
				"ZEUS-IO-002", "Inspection error", "Low", rel, err.Error()))
			return nil
		}
		report.Findings = append(report.Findings, findings...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk artifact: %w", err)
	}

	for f := range formats {
		report.Formats = append(report.Formats, f)
	}
	return report, nil
}

func inspectFile(path, rel string, limits Limits) ([]securityv1alpha1.Finding, error) {
	ext := strings.ToLower(filepath.Ext(rel))

	switch ext {
	case ".pkl", ".pickle", ".joblib", ".dill":
		// The extension itself declares a pickle, so opcode evidence is
		// meaningful even without the protocol-2 magic bytes.
		return inspectPickleLike(path, rel, limits, true)
	case ".pt", ".pth", ".bin", ".ckpt":
		return inspectPickleLike(path, rel, limits, false)
	case ".npy":
		return inspectNumpy(path, rel)
	case ".zip", ".whl", ".egg", ".npz":
		return inspectZip(path, rel, limits)
	case ".tar":
		return inspectTar(path, rel, limits)
	case ".onnx":
		return inspectONNX(path, rel)
	case ".py":
		return inspectPython(path, rel)
	case ".json":
		return inspectJSONConfig(path, rel)
	case ".safetensors":
		return inspectSafetensors(path, rel)
	case ".so", ".dylib", ".dll":
		return []securityv1alpha1.Finding{finding(
			"ZEUS-NATIVE-001", "Native shared library in model artifact", "High", rel,
			"shared libraries load arbitrary native code at model load time")}, nil
	case ".sh", ".bash", ".zsh":
		return []securityv1alpha1.Finding{finding(
			"ZEUS-SHELL-001", "Shell script in model artifact", "Medium", rel,
			"shell scripts bundled with a model may execute during load or serving")}, nil
	}

	// No recognized extension: sniff the header, since attackers rename files.
	return sniffUnknown(path, rel, limits)
}

// pickleOpcodes that can cause code execution when a pickle is loaded.
var pickleOpcodes = map[byte]string{
	'c':    "GLOBAL",       // imports an arbitrary module attribute
	'\x93': "STACK_GLOBAL", // protocol 4 equivalent of GLOBAL
	'R':    "REDUCE",       // calls a callable
	'i':    "INST",         // instantiates a class
	'o':    "OBJ",          // instantiates a class
	'b':    "BUILD",        // invokes __setstate__
}

// dangerousImports are module.attr pairs that turn a pickle into RCE.
var dangerousImports = []string{
	"os.system", "os.popen", "os.execv", "os.spawn", "os.fork",
	"subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_output",
	"builtins.eval", "builtins.exec", "builtins.compile", "builtins.__import__",
	"__builtin__.eval", "__builtin__.exec",
	"posix.system", "nt.system",
	"socket.socket", "shutil.rmtree",
	"pty.spawn", "commands.getoutput",
	"importlib.import_module", "runpy._run_code",
	"torch.load", "torch.hub.load", "pickle.loads", "codecs.decode",
	"webbrowser.open", "urllib.request.urlopen", "requests.get",
}

// inspectPickleLike scans for pickle streams, which are the dominant model
// supply-chain attack: unpickling is arbitrary code execution by design.
//
// declaredPickle says the file extension itself names a pickle. Opcode-level
// evidence is only trustworthy for such files, or for files carrying the
// protocol-2 magic — a raw tensor dump will contain every pickle opcode byte
// purely by chance.
func inspectPickleLike(path, rel string, limits Limits, declaredPickle bool) ([]securityv1alpha1.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, 4)
	n, _ := io.ReadFull(f, header)
	header = header[:n]

	// A .pt/.pth from torch.save is usually a zip container holding a pickle.
	if bytes.HasPrefix(header, []byte("PK\x03\x04")) {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		findings, err := inspectZip(path, rel, limits)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding(
			"ZEUS-PICKLE-002", "Torch zip container", "Medium", rel,
			"file is a torch.save archive; loading it requires torch.load, which unpickles by default"))
		return findings, nil
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return scanPickleStream(f, rel, declaredPickle)
}

// scanPickleStream looks for executable pickle opcodes and dangerous imports.
//
// declaredPickle relaxes the format check for files whose extension already
// declares a pickle; otherwise only the protocol-2 magic counts as evidence.
func scanPickleStream(r io.Reader, rel string, declaredPickle bool) ([]securityv1alpha1.Finding, error) {
	const maxScan = 64 << 20 // 64 MiB is far past any real pickle header
	data, err := io.ReadAll(io.LimitReader(r, maxScan))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	// Pickle protocol 2+ starts with PROTO (0x80) followed by a version byte.
	// Protocol 0/1 has no magic at all, so for those the extension is the
	// only signal we can trust.
	isPickle := (data[0] == 0x80 && len(data) > 1 && data[1] <= 5) || declaredPickle

	var findings []securityv1alpha1.Finding
	seen := map[string]bool{}

	for _, imp := range dangerousImports {
		module, attr, ok := strings.Cut(imp, ".")
		if !ok {
			continue
		}
		// Pickle GLOBAL encodes the import as "module\nattr\n".
		needle := []byte(module + "\n" + attr + "\n")
		if bytes.Contains(data, needle) && !seen[imp] {
			seen[imp] = true
			findings = append(findings, finding(
				"ZEUS-PICKLE-001", "Pickle imports a dangerous callable", "Critical", rel,
				fmt.Sprintf("pickle stream references %s, which executes on load", imp)))
		}
	}

	if isPickle && len(findings) == 0 {
		var opcodes []string
		for opcode, name := range pickleOpcodes {
			if bytes.IndexByte(data, opcode) >= 0 {
				opcodes = append(opcodes, name)
			}
		}
		if len(opcodes) > 0 {
			findings = append(findings, finding(
				"ZEUS-PICKLE-003", "Pickle contains code-executing opcodes", "High", rel,
				fmt.Sprintf("stream uses opcodes that can execute code (%s); prefer safetensors", strings.Join(dedupe(opcodes), ", "))))
		} else {
			findings = append(findings, finding(
				"ZEUS-PICKLE-004", "Unsafe serialization format", "Medium", rel,
				"pickle-based weights execute arbitrary code on load; convert to safetensors"))
		}
	}

	return findings, nil
}

// inspectZip walks a zip archive looking for path traversal, zip bombs, and
// embedded pickles.
func inspectZip(path, rel string, limits Limits) ([]securityv1alpha1.Finding, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return []securityv1alpha1.Finding{finding(
			"ZEUS-ARCHIVE-001", "Malformed archive", "Medium", rel,
			fmt.Sprintf("could not open archive: %v", err))}, nil
	}
	defer zr.Close()

	var (
		findings   []securityv1alpha1.Finding
		compressed int64
		expanded   int64
		entries    int
	)

	for _, file := range zr.File {
		entries++
		if entries > limits.MaxArchiveEntries {
			findings = append(findings, finding(
				"ZEUS-ARCHIVE-002", "Archive entry limit exceeded", "High", rel,
				fmt.Sprintf("archive holds more than %d entries; possible archive bomb", limits.MaxArchiveEntries)))
			break
		}

		if isTraversalPath(file.Name) {
			findings = append(findings, finding(
				"ZEUS-ARCHIVE-003", "Archive path traversal", "Critical", rel+"!"+file.Name,
				"archive entry escapes the extraction directory (zip slip)"))
			continue
		}
		if file.Mode()&os.ModeSymlink != 0 {
			findings = append(findings, finding(
				"ZEUS-ARCHIVE-004", "Symlink inside archive", "High", rel+"!"+file.Name,
				"archive contains a symlink, which can redirect writes outside the model directory"))
			continue
		}

		compressed += int64(file.CompressedSize64)
		expanded += int64(file.UncompressedSize64)
		if expanded > limits.MaxDecompressedBytes {
			findings = append(findings, finding(
				"ZEUS-ARCHIVE-005", "Decompression limit exceeded", "High", rel,
				fmt.Sprintf("archive expands past %d bytes; possible zip bomb", limits.MaxDecompressedBytes)))
			break
		}

		// Nested pickles are the payload in most torch.save archives.
		if isPickleName(file.Name) {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			nested, err := scanPickleStream(rc, rel+"!"+file.Name, true)
			rc.Close()
			if err == nil {
				findings = append(findings, nested...)
			}
		}
	}

	if compressed > 0 && limits.CompressionRatioLimit > 0 {
		if ratio := float64(expanded) / float64(compressed); ratio > limits.CompressionRatioLimit {
			findings = append(findings, finding(
				"ZEUS-ARCHIVE-006", "Suspicious compression ratio", "High", rel,
				fmt.Sprintf("archive expands %.0fx, above the %.0fx threshold; possible zip bomb",
					ratio, limits.CompressionRatioLimit)))
		}
	}

	return findings, nil
}

func inspectTar(path, rel string, limits Limits) ([]securityv1alpha1.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	var (
		findings []securityv1alpha1.Finding
		total    int64
		entries  int
	)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			findings = append(findings, finding(
				"ZEUS-ARCHIVE-001", "Malformed archive", "Medium", rel,
				fmt.Sprintf("could not read tar entry: %v", err)))
			break
		}
		entries++
		if entries > limits.MaxArchiveEntries {
			findings = append(findings, finding(
				"ZEUS-ARCHIVE-002", "Archive entry limit exceeded", "High", rel,
				fmt.Sprintf("archive holds more than %d entries", limits.MaxArchiveEntries)))
			break
		}
		if isTraversalPath(hdr.Name) {
			findings = append(findings, finding(
				"ZEUS-ARCHIVE-003", "Archive path traversal", "Critical", rel+"!"+hdr.Name,
				"tar entry escapes the extraction directory"))
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			findings = append(findings, finding(
				"ZEUS-ARCHIVE-004", "Link inside archive", "High", rel+"!"+hdr.Name,
				fmt.Sprintf("archive contains a link to %s", hdr.Linkname)))
			continue
		}
		total += hdr.Size
		if total > limits.MaxDecompressedBytes {
			findings = append(findings, finding(
				"ZEUS-ARCHIVE-005", "Decompression limit exceeded", "High", rel,
				"tar expands past the configured limit"))
			break
		}
		if isPickleName(hdr.Name) {
			nested, err := scanPickleStream(io.LimitReader(tr, 64<<20), rel+"!"+hdr.Name, true)
			if err == nil {
				findings = append(findings, nested...)
			}
		}
	}
	return findings, nil
}

// inspectNumpy reads the .npy header. A numeric array is inert, but an
// object-dtype array ("|O") stores its elements as a pickle, so numpy has to
// unpickle it on load — the same code-execution risk as a .pkl.
func inspectNumpy(path, rel string) ([]securityv1alpha1.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	magic := make([]byte, 8)
	if _, err := io.ReadFull(f, magic); err != nil {
		return nil, nil // too short to be a .npy; nothing to say
	}
	if !bytes.HasPrefix(magic, []byte("\x93NUMPY")) {
		// Not actually a numpy array despite the extension. Sniff it instead.
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return sniffUnknown(path, rel, DefaultLimits())
	}

	// magic[6] is the major version: v1 uses a 2-byte header length, v2+ uses 4.
	headerLen := 0
	if magic[6] >= 2 {
		var length uint32
		if err := binary.Read(f, binary.LittleEndian, &length); err != nil {
			return nil, nil
		}
		headerLen = int(length)
	} else {
		var length uint16
		if err := binary.Read(f, binary.LittleEndian, &length); err != nil {
			return nil, nil
		}
		headerLen = int(length)
	}
	if headerLen <= 0 || headerLen > (1<<20) {
		return []securityv1alpha1.Finding{finding(
			"ZEUS-NPY-002", "Invalid numpy header length", "Medium", rel,
			fmt.Sprintf("declared header length %d is implausible", headerLen))}, nil
	}

	header := make([]byte, headerLen)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, nil
	}

	if bytes.Contains(header, []byte("'|O'")) || bytes.Contains(header, []byte("'O'")) {
		return []securityv1alpha1.Finding{finding(
			"ZEUS-NPY-001", "Object-dtype numpy array", "High", rel,
			"object arrays are stored as pickles, so numpy.load must unpickle them to read this file")}, nil
	}
	return nil, nil
}

// suspiciousONNXOps can read the filesystem or run arbitrary code during
// inference.
var suspiciousONNXOps = map[string]string{
	"com.microsoft.PythonOp": "runs arbitrary Python during inference",
	"PythonOp":               "runs arbitrary Python during inference",
	"ai.onnx.contrib":        "custom contrib operators execute out-of-tree code",
	"CustomOp":               "custom operator loads external native code",
	"TorchScript":            "embeds a TorchScript program",
}

func inspectONNX(path, rel string) ([]securityv1alpha1.Finding, error) {
	// The ONNX protobuf schema is large; string-matching operator domains in
	// the graph is enough to flag files that need manual review.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []securityv1alpha1.Finding
	for op, why := range suspiciousONNXOps {
		if bytes.Contains(data, []byte(op)) {
			findings = append(findings, finding(
				"ZEUS-ONNX-001", "Suspicious ONNX operator", "High", rel,
				fmt.Sprintf("graph references %s, which %s", op, why)))
		}
	}
	if bytes.Contains(data, []byte("external_data")) || bytes.Contains(data, []byte("location")) {
		if bytes.Contains(data, []byte("../")) {
			findings = append(findings, finding(
				"ZEUS-ONNX-002", "ONNX external data path traversal", "Critical", rel,
				"external tensor data reference escapes the model directory"))
		}
	}
	return findings, nil
}

var pythonDangerPatterns = []struct {
	id, title, severity string
	re                  *regexp.Regexp
	why                 string
}{
	{"ZEUS-PY-001", "Python executes a shell command", "Critical",
		regexp.MustCompile(`(?m)\b(os\.system|os\.popen|subprocess\.(Popen|run|call|check_output))\s*\(`),
		"model code shells out at import or load time"},
	{"ZEUS-PY-002", "Python dynamic code execution", "High",
		regexp.MustCompile(`(?m)\b(eval|exec|compile)\s*\(`),
		"model code evaluates code built at runtime"},
	{"ZEUS-PY-003", "Python network egress", "High",
		regexp.MustCompile(`(?m)\b(requests\.(get|post)|urllib\.request\.urlopen|socket\.socket|httpx\.(get|post))\s*\(`),
		"model code contacts the network, which can exfiltrate data or pull a second stage"},
	{"ZEUS-PY-004", "Unsafe deserialization call", "High",
		regexp.MustCompile(`(?m)\b(pickle\.loads?|torch\.load|joblib\.load|dill\.loads?|yaml\.load)\s*\(`),
		"deserialization call can execute arbitrary code"},
	{"ZEUS-PY-005", "Base64-decoded payload", "Medium",
		regexp.MustCompile(`(?m)base64\.b64decode\s*\(`),
		"encoded payloads are commonly used to hide malicious code"},
}

func inspectPython(path, rel string) ([]securityv1alpha1.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return nil, err
	}

	var findings []securityv1alpha1.Finding
	for _, pattern := range pythonDangerPatterns {
		if loc := pattern.re.FindIndex(data); loc != nil {
			findings = append(findings, finding(
				pattern.id, pattern.title, pattern.severity,
				fmt.Sprintf("%s:%d", rel, lineOf(data, loc[0])), pattern.why))
		}
	}

	// Custom CUDA/C++ extensions compile and load native code on import.
	if bytes.Contains(data, []byte("torch.utils.cpp_extension")) || bytes.Contains(data, []byte("load_inline")) {
		findings = append(findings, finding(
			"ZEUS-PY-006", "Custom native extension", "High", rel,
			"model compiles and loads a custom CUDA/C++ extension at import time"))
	}

	return findings, nil
}

// inspectJSONConfig flags Hugging Face config settings that hand execution to
// model-supplied code.
func inspectJSONConfig(path, rel string) ([]securityv1alpha1.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 4<<20 {
		return nil, nil
	}

	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, nil // not a config file we understand
	}

	var findings []securityv1alpha1.Finding
	if v, ok := cfg["trust_remote_code"]; ok {
		if enabled, _ := v.(bool); enabled {
			findings = append(findings, finding(
				"ZEUS-HF-001", "trust_remote_code is enabled", "Critical", rel,
				"the model declares trust_remote_code, so loading it executes code shipped with the weights"))
		}
	}
	if _, ok := cfg["auto_map"]; ok {
		findings = append(findings, finding(
			"ZEUS-HF-002", "Custom auto_map classes", "High", rel,
			"auto_map points transformers at model-supplied Python classes, which run on load"))
	}
	return findings, nil
}

// inspectSafetensors validates the header of the safe format. Safetensors
// cannot execute code, but a malformed header can still crash or mislead a
// loader, and the offsets should stay inside the file.
func inspectSafetensors(path, rel string) ([]securityv1alpha1.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	var headerLen uint64
	if err := binary.Read(f, binary.LittleEndian, &headerLen); err != nil {
		return []securityv1alpha1.Finding{finding(
			"ZEUS-ST-001", "Malformed safetensors header", "Medium", rel,
			"file is too short to contain a safetensors header")}, nil
	}

	if headerLen > uint64(info.Size()) || headerLen > (100<<20) {
		return []securityv1alpha1.Finding{finding(
			"ZEUS-ST-002", "Invalid safetensors header length", "High", rel,
			fmt.Sprintf("declared header length %d exceeds the file size %d", headerLen, info.Size()))}, nil
	}

	header := make([]byte, headerLen)
	if _, err := io.ReadFull(f, header); err != nil {
		return []securityv1alpha1.Finding{finding(
			"ZEUS-ST-001", "Malformed safetensors header", "Medium", rel,
			"header is truncated")}, nil
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(header, &parsed); err != nil {
		return []securityv1alpha1.Finding{finding(
			"ZEUS-ST-003", "Unparseable safetensors header", "Medium", rel,
			"header is not valid JSON")}, nil
	}
	return nil, nil
}

// sniffUnknown catches payloads hidden behind an innocuous extension.
func sniffUnknown(path, rel string, limits Limits) ([]securityv1alpha1.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	head := make([]byte, 8)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if n < 4 {
		return nil, nil
	}

	switch {
	case bytes.HasPrefix(head, []byte{0x7f, 'E', 'L', 'F'}):
		return []securityv1alpha1.Finding{finding(
			"ZEUS-BIN-001", "ELF executable in model artifact", "High", rel,
			"artifact contains a native executable")}, nil
	case bytes.HasPrefix(head, []byte{0x4d, 0x5a}):
		return []securityv1alpha1.Finding{finding(
			"ZEUS-BIN-002", "PE executable in model artifact", "High", rel,
			"artifact contains a Windows executable")}, nil
	case bytes.HasPrefix(head, []byte{0xca, 0xfe, 0xba, 0xbe}), bytes.HasPrefix(head, []byte{0xcf, 0xfa, 0xed, 0xfe}):
		return []securityv1alpha1.Finding{finding(
			"ZEUS-BIN-003", "Mach-O executable in model artifact", "High", rel,
			"artifact contains a native executable")}, nil
	case bytes.HasPrefix(head, []byte{0x80}) && n > 1 && head[1] <= 5:
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return scanPickleStream(f, rel, false)
	case bytes.HasPrefix(head, []byte("#!")):
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		line, _ := bufio.NewReader(f).ReadString('\n')
		return []securityv1alpha1.Finding{finding(
			"ZEUS-SHELL-002", "Script with interpreter directive", "Medium", rel,
			fmt.Sprintf("file begins with %q", strings.TrimSpace(line)))}, nil
	}
	return nil, nil
}

func finding(id, title, severity, location, description string) securityv1alpha1.Finding {
	return securityv1alpha1.Finding{
		ID:          id,
		Title:       title,
		Severity:    severity,
		Category:    "model",
		Location:    location,
		Description: description,
	}
}

func isPickleName(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".pkl", ".pickle", "data.pkl", ".dill", ".joblib"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return strings.HasSuffix(lower, "/data.pkl")
}

func isTraversalPath(name string) bool {
	cleaned := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(cleaned, "/") {
		return true
	}
	for _, part := range strings.Split(cleaned, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func isEscapingLink(root, linkPath, target string) bool {
	if filepath.IsAbs(target) {
		return !strings.HasPrefix(filepath.Clean(target), filepath.Clean(root)+string(filepath.Separator))
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(linkPath), target))
	return !strings.HasPrefix(resolved, filepath.Clean(root)+string(filepath.Separator))
}

func formatOf(rel string) string {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".safetensors":
		return "safetensors"
	case ".onnx":
		return "onnx"
	case ".gguf", ".ggml":
		return "gguf"
	case ".pt", ".pth", ".ckpt":
		return "pytorch"
	case ".pb":
		return "tensorflow"
	case ".h5", ".keras":
		return "keras"
	case ".pkl", ".pickle", ".joblib":
		return "pickle"
	}
	return ""
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

func lineOf(data []byte, offset int) int {
	if offset > len(data) {
		offset = len(data)
	}
	return bytes.Count(data[:offset], []byte("\n")) + 1
}

func dedupe(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
