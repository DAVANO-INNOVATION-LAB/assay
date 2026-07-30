package integration

import (
	"archive/zip"
	"bytes"
	"testing"
)

// buildRatioBomb writes a small zip whose single entry expands far beyond the
// ratio threshold. It is a real archive of highly compressible data, so the
// inspector sees a genuine compression ratio rather than a doctored header.
func buildRatioBomb(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("payload.bin")
	if err != nil {
		t.Fatal(err)
	}

	// 64 MiB of zeros compresses to a few KiB: a ratio well past the 200x
	// threshold, without needing a multi-gigabyte fixture.
	chunk := make([]byte, 1<<20)
	for range 64 {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
