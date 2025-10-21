package headers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/tunasec/tunacheck/internal/modules"
	"github.com/tunasec/tunacheck/pkg/output"
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "security-headers" }

func (m *Module) Register(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "security-headers",
		Short: "Validate common HTTP security headers",
	}

	var target string
	var timeout time.Duration
	var followRedirects bool
	var refreshGuidance bool
	var failOnIssues bool
	var showExamples bool

	check := &cobra.Command{
		Use:   "check <url>",
		Short: "Check security headers for a URL",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if refreshGuidance {
				output.Info("Guidance is embedded at build time. To refresh during development:")
				output.Println("make guidance && make build")
				return nil
			}
			if target == "" && len(args) > 0 {
				target = args[0]
			}
			if target == "" {
				return errors.New("target URL required")
			}

			u, err := url.Parse(target)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("invalid URL: %s", target)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			hdrs, status, err := fetchHeaders(ctx, target, followRedirects)
			if err != nil {
				output.Warn("network error; attempting cache fallback")
				hdrs, status, err = readCachedHeaders(target)
				if err != nil {
					return err
				}
			} else {
				_ = writeCachedHeaders(target, hdrs, status)
			}

			res := evaluateHeaders(hdrs)
			res.Target = target
			res.Status = status
			if output.IsJSON() {
				if err := output.RenderJSON(res); err != nil {
					return err
				}
			} else if output.HasTemplate() {
				if err := output.RenderTemplate(res); err != nil {
					return err
				}
			} else {
				renderTable(res)
				if showExamples {
					renderExamples(res)
				}
			}
			// Optionally fail if issues are found
			if failOnIssues {
				var issues int
				for _, h := range res.Headers {
					if !h.Present || h.Malformed {
						issues++
					}
				}
				if issues > 0 {
					return fmt.Errorf("%d header issues found", issues)
				}
			}
			return nil
		},
	}

	check.Flags().StringVarP(&target, "target", "t", "", "Target URL")
	check.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "Request timeout")
	check.Flags().BoolVar(&followRedirects, "follow-redirects", true, "Follow redirects")
	check.Flags().BoolVar(&refreshGuidance, "refresh-guidance", false, "Print instructions to refresh embedded guidance")
	check.Flags().BoolVar(&failOnIssues, "fail-on-issues", false, "Exit non-zero if any header is missing or malformed")
	check.Flags().BoolVar(&showExamples, "examples", true, "Show Nginx/Apache examples for missing/malformed headers")

	cmd.AddCommand(check)
	root.AddCommand(cmd)
}

type headerResult struct {
	Name              string  `json:"name"`
	Present           bool    `json:"present"`
	Value             *string `json:"value"`
	RecommendedValue  *string `json:"recommended_value"`
	GuidanceReference *string `json:"guidance_reference"`
	Malformed         bool    `json:"-"`
}

type results struct {
	Target  string         `json:"target"`
	Status  int            `json:"status"`
	Headers []headerResult `json:"headers"`
}

func evaluateHeaders(h http.Header) results {
	g := modules.GetGuidance()
	names := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
		"Expect-CT",
		"Feature-Policy", // legacy alias
	}
	out := make([]headerResult, 0, len(names))
	for _, n := range names {
		val := strings.TrimSpace(h.Get(n))
		present := val != ""
		var valPtr *string
		if present {
			valPtr = &val
		}
		rec := g.Headers[n]
		var recPtr *string
		if rec.RecommendedValue != "" {
			v := rec.RecommendedValue
			recPtr = &v
		}
		var refPtr *string
		if len(rec.References) > 0 {
			v := rec.References[0]
			refPtr = &v
		}
		malformed := false
		if present {
			switch n {
			case "X-Content-Type-Options":
				malformed = !strings.EqualFold(val, "nosniff")
			case "X-Frame-Options":
				v := strings.ToUpper(val)
				malformed = v != "DENY" && v != "SAMEORIGIN"
			case "Strict-Transport-Security":
				malformed = !strings.Contains(strings.ToLower(val), "max-age=")
			}
		}
		out = append(out, headerResult{
			Name: n, Present: present, Value: valPtr, RecommendedValue: recPtr,
			GuidanceReference: refPtr, Malformed: malformed,
		})
	}
	return results{Headers: out}
}

func renderTable(res results) {
	// Styled header row
	head := color.New(color.FgCyan, color.Bold).SprintfFunc()
	nameStyle := color.New(color.FgHiWhite, color.Bold).SprintfFunc()
	green := color.New(color.FgGreen).SprintfFunc()
	yellow := color.New(color.FgYellow).SprintfFunc()
	red := color.New(color.FgHiRed).SprintfFunc()

	fmt.Fprintf(outputWriter(), "%-28s %-12s %-48s %-48s\n",
		head("Header"), head("Status"), head("Value"), head("Guidance/Suggestion"))
	for _, h := range res.Headers {
		statusText := red("missing")
		if h.Present {
			if h.Malformed {
				statusText = yellow("malformed")
			} else {
				statusText = green("present")
			}
		}
		val := ""
		if h.Value != nil {
			val = *h.Value
			if !output.IsVerbose() && len(val) > 46 {
				val = val[:43] + "..."
			}
		}
		sugg := ""
		if h.RecommendedValue != nil {
			sugg = *h.RecommendedValue
		}
		if !output.IsVerbose() && len(sugg) > 46 {
			sugg = sugg[:43] + "..."
		}
		fmt.Fprintf(outputWriter(), "%-28s %-12s %-48s %-48s\n", nameStyle(h.Name), statusText, val, sugg)
	}
}

func renderExamples(res results) {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	for _, h := range res.Headers {
		if h.Present && !h.Malformed {
			continue
		}
		name := h.Name
		rec := ""
		if h.RecommendedValue != nil {
			rec = *h.RecommendedValue
		}
		if rec == "" {
			continue
		}
		fmt.Fprintln(outputWriter())
		fmt.Fprintf(outputWriter(), "%s %s\n", cyan("Examples:"), name)
		// Nginx
		fmt.Fprintf(outputWriter(), "  nginx: add_header %s \"%s\" always;\n", name, rec)
		// Apache
		fmt.Fprintf(outputWriter(), "  apache: Header always set %s \"%s\"\n", name, rec)
	}
}

func outputWriter() io.Writer { return output.Writer() }

// HTTP fetch and caching
func fetchHeaders(ctx context.Context, target string, follow bool) (http.Header, int, error) {
	cl := &http.Client{Timeout: 0}
	if !follow {
		cl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.Header, resp.StatusCode, nil
}

type cached struct {
	Status  int         `json:"status"`
	Headers http.Header `json:"headers"`
}

func cacheFile(target string) string {
	sum := sha256.Sum256([]byte(target))
	name := hex.EncodeToString(sum[:]) + ".json"
	return filepath.Join(modules.CacheDir(), "headers", name)
}

func writeCachedHeaders(target string, h http.Header, status int) error {
	dir := filepath.Dir(cacheFile(target))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(cached{Status: status, Headers: h})
	return os.WriteFile(cacheFile(target), b, 0o644)
}

func readCachedHeaders(target string) (http.Header, int, error) {
	b, err := os.ReadFile(cacheFile(target))
	if err != nil {
		return nil, 0, err
	}
	var c cached
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, 0, err
	}
	return c.Headers, c.Status, nil
}
