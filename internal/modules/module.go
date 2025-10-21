package modules

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/tunasec/tunacheck/assets"
)

type Module interface {
	Name() string
	Register(root *cobra.Command)
}

// Context keys and helpers
type ctxKey string

const ContextKeyStartTime ctxKey = "startTime"

// Guidance data shape
type Guidance struct {
	Headers map[string]HeaderGuidance `json:"headers"`
}

type HeaderGuidance struct {
	RecommendedValue string   `json:"recommended_value"`
	Rationale        string   `json:"rationale"`
	References       []string `json:"references"`
}

var (
	embeddedGuidance Guidance
	guidanceErr      error
)

func init() {
	if len(assets.GuidanceJSON) == 0 {
		guidanceErr = errors.New("no embedded guidance")
		return
	}
	if err := json.Unmarshal(assets.GuidanceJSON, &embeddedGuidance); err != nil {
		guidanceErr = fmt.Errorf("failed to parse embedded guidance: %w", err)
	}
}

func GuidanceAvailable() (bool, string) {
	if guidanceErr != nil {
		return false, guidanceErr.Error()
	}
	if len(embeddedGuidance.Headers) == 0 {
		return false, "no headers in guidance"
	}
	return true, ""
}

func GetGuidance() Guidance { return embeddedGuidance }

func RuntimeGoVersion() string { return runtime.Version() }

func SystemCertPoolAvailable() (bool, string) {
	if _, err := x509.SystemCertPool(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// Cache helpers
func CacheDir() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		base, _ = os.UserCacheDir()
	}
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "tunacheck")
}
