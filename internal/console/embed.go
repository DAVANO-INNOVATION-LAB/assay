// Package console embeds the single-page console.
//
// Embedding rather than mounting a ConfigMap keeps the served page and the API
// it talks to in one artifact: they are versioned together, so an upgrade
// cannot leave a console calling endpoints the server no longer has.
package console

import _ "embed"

// IndexHTML is the console.
//
//go:embed index.html
var IndexHTML []byte
