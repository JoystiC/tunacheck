package assets

import _ "embed"

// GuidanceJSON contains the embedded guidance dataset.
//
//go:embed guidance.json
var GuidanceJSON []byte
