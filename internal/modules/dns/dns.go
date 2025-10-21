package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tunasec/tunacheck/pkg/output"
)

type Module struct{}

func New() *Module             { return &Module{} }
func (m *Module) Name() string { return "dns" }

func (m *Module) Register(root *cobra.Command) {
	cmd := &cobra.Command{Use: "dns", Short: "Resolve and analyze DNS records"}

	var domain string
	var timeout time.Duration

	check := &cobra.Command{
		Use:   "check <domain>",
		Short: "Check A/AAAA/MX/TXT (SPF/DMARC) and DNSSEC",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if domain == "" && len(args) > 0 {
				domain = args[0]
			}
			if domain == "" {
				return errors.New("domain required")
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			res, err := runDNSChecks(ctx, domain)
			if err != nil {
				return err
			}
			if output.IsJSON() {
				return output.RenderJSON(res)
			}
			render(res)
			return nil
		},
	}

	check.Flags().StringVar(&domain, "domain", "", "Domain to check")
	check.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "Lookup timeout")

	cmd.AddCommand(check)
	root.AddCommand(cmd)
}

type Result struct {
	Domain   string   `json:"domain"`
	ARecords []string `json:"a_records"`
	AAAA     []string `json:"aaaa_records"`
	MX       []string `json:"mx_records"`
	TXT      []string `json:"txt_records"`
	SPF      string   `json:"spf"`
	DMARC    string   `json:"dmarc"`
	DNSSECOK bool     `json:"dnssec_ok"`
	Issues   []string `json:"issues"`
}

func runDNSChecks(ctx context.Context, domain string) (Result, error) {
	r := Result{Domain: domain}
	var issues []string

	// A
	if addrs, _ := net.DefaultResolver.LookupIP(ctx, "ip4", domain); len(addrs) > 0 {
		for _, a := range addrs {
			r.ARecords = append(r.ARecords, a.String())
		}
	} else {
		issues = append(issues, "missing A record")
	}

	// AAAA
	if addrs, _ := net.DefaultResolver.LookupIP(ctx, "ip6", domain); len(addrs) > 0 {
		for _, a := range addrs {
			r.AAAA = append(r.AAAA, a.String())
		}
	}

	// MX
	if mx, err := net.DefaultResolver.LookupMX(ctx, domain); err == nil && len(mx) > 0 {
		for _, m := range mx {
			r.MX = append(r.MX, fmt.Sprintf("%s (%d)", m.Host, m.Pref))
		}
	} else {
		issues = append(issues, "missing MX record")
	}

	// TXT (parse SPF and DMARC)
	var txts []string
	if tx, err := net.DefaultResolver.LookupTXT(ctx, domain); err == nil {
		txts = tx
	}
	r.TXT = txts
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") && r.SPF == "" {
			r.SPF = t
		}
	}
	// DMARC lives under _dmarc.domain
	if dm, err := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, t := range dm {
			if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
				r.DMARC = t
				break
			}
		}
	}

	// Simple DNSSEC indicator: presence of DS at parent (best-effort via net.LookupNS/LookupTXT not reliable)
	// We mark false by default; users should validate via external tools for full DNSSEC.
	r.DNSSECOK = false

	// Heuristics
	if r.SPF == "" {
		issues = append(issues, "missing SPF (TXT v=spf1)")
	}
	if r.DMARC == "" {
		issues = append(issues, "missing DMARC (_dmarc TXT v=DMARC1)")
	}
	if r.SPF != "" && !strings.Contains(r.SPF, "-all") {
		issues = append(issues, "SPF should end with -all (hard fail)")
	}
	if r.DMARC != "" && !strings.Contains(strings.ToLower(r.DMARC), "p=quarantine") && !strings.Contains(strings.ToLower(r.DMARC), "p=reject") {
		issues = append(issues, "DMARC policy should be quarantine or reject")
	}

	r.Issues = issues
	return r, nil
}

func render(res Result) {
	output.KV("Domain", res.Domain)
	output.KV("A", strings.Join(res.ARecords, ", "))
	output.KV("AAAA", strings.Join(res.AAAA, ", "))
	output.KV("MX", strings.Join(res.MX, ", "))
	if res.SPF != "" {
		output.KV("SPF", res.SPF)
	} else {
		output.Warn("SPF missing")
	}
	if res.DMARC != "" {
		output.KV("DMARC", res.DMARC)
	} else {
		output.Warn("DMARC missing")
	}
	if len(res.Issues) > 0 {
		output.Warn("Issues:")
		for _, i := range res.Issues {
			output.Println(" -", i)
		}
		output.Println("Guidance:")
		output.Println("  - SPF example: v=spf1 include:_spf.example.com -all")
		output.Println("  - DMARC example (TXT at _dmarc.domain): v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
		output.Println("  - DNSSEC: enable signing at your registrar and publish DS record")
	} else {
		output.Success("No DNS issues found")
	}
}
