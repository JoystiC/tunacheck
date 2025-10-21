package ssl

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tunasec/tunacheck/internal/modules"
	"github.com/tunasec/tunacheck/pkg/output"
)

type Module struct{}

func New() *Module             { return &Module{} }
func (m *Module) Name() string { return "ssl" }

func (m *Module) Register(root *cobra.Command) {
	cmd := &cobra.Command{Use: "ssl", Short: "Inspect TLS endpoints"}

	var host string
	var port int
	var sni string
	var timeout time.Duration
	var wantSSLLabs bool

	check := &cobra.Command{
		Use:   "check <host[:port]>",
		Short: "Perform TLS handshake and inspect the certificate chain",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" && len(args) > 0 {
				host = args[0]
			}
			if host == "" {
				return errors.New("host required")
			}
			h, p := splitHostPort(host, port)
			if sni == "" {
				sni = h
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			res, err := connectAndInspect(ctx, h, p, sni)
			if err != nil {
				return err
			}
			if wantSSLLabs {
				res.SSLLabsNote = ssllabsHeuristic(res)
			}
			if output.IsJSON() {
				if err := output.RenderJSON(res); err != nil {
					return err
				}
			} else if output.HasTemplate() {
				if err := output.RenderTemplate(res); err != nil {
					return err
				}
			} else {
				renderText(res)
			}
			// Determine exit code – non-zero on issues
			if !res.Verified {
				return fmt.Errorf("certificate chain not verified")
			}
			if res.TLSVersion != "TLS1.3" && res.TLSVersion != "TLS1.2" {
				return fmt.Errorf("old TLS version: %s", res.TLSVersion)
			}
			for _, c := range res.Certificates {
				if !c.Current {
					return fmt.Errorf("certificate not currently valid")
				}
			}
			return nil
		},
	}

	check.Flags().StringVar(&host, "host", "", "Target host[:port]")
	check.Flags().IntVar(&port, "port", 443, "Port if not provided in host")
	check.Flags().StringVar(&sni, "sni", "", "Override SNI hostname")
	check.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "Connection timeout")
	check.Flags().BoolVar(&wantSSLLabs, "ssllabs", false, "Include local SSLLabs-like heuristic note")

	cmd.AddCommand(check)
	m.registerWeak(cmd)
	root.AddCommand(cmd)
}

type TLSResult struct {
	Target       string        `json:"target"`
	TLSVersion   string        `json:"tls_version"`
	CipherSuite  string        `json:"cipher_suite"`
	OCSPStapled  bool          `json:"ocsp_stapled"`
	Verified     bool          `json:"verified"`
	VerifyError  string        `json:"verify_error,omitempty"`
	Certificates []CertDetails `json:"certificates"`
	SSLLabsNote  string        `json:"ssllabs_note,omitempty"`
}

type CertDetails struct {
	SubjectCN   string    `json:"subject_cn"`
	SANs        []string  `json:"sans"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SigAlg      string    `json:"sig_alg"`
	PubKeyAlg   string    `json:"pub_key_alg"`
	PubKeySize  int       `json:"pub_key_size"`
	Fingerprint string    `json:"fingerprint_sha256"`
	Current     bool      `json:"current"`
}

func connectAndInspect(ctx context.Context, host string, port int, sni string) (TLSResult, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := &net.Dialer{}
	var conn net.Conn
	var err error
	ch := make(chan struct{})
	go func() {
		conn, err = d.DialContext(ctx, "tcp", addr)
		close(ch)
	}()
	select {
	case <-ctx.Done():
		return TLSResult{}, ctx.Err()
	case <-ch:
	}
	if err != nil {
		return TLSResult{}, err
	}
	defer conn.Close()

	cfg := &tls.Config{ServerName: sni}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return TLSResult{}, err
	}
	state := tlsConn.ConnectionState()

	// Verify using system roots
	verified := false
	var verifyErr string
	if state.VerifiedChains != nil && len(state.VerifiedChains) > 0 {
		verified = true
	} else {
		// try manual verify
		pool, err := x509.SystemCertPool()
		if err == nil {
			opts := x509.VerifyOptions{DNSName: sni, Roots: pool, Intermediates: x509.NewCertPool()}
			for _, ic := range state.PeerCertificates[1:] {
				opts.Intermediates.AddCert(ic)
			}
			if _, err := state.PeerCertificates[0].Verify(opts); err == nil {
				verified = true
			} else {
				verifyErr = err.Error()
			}
		} else {
			verifyErr = err.Error()
		}
	}

	var certs []CertDetails
	for _, c := range state.PeerCertificates {
		certs = append(certs, certToDetails(c))
	}

	res := TLSResult{
		Target:       addr,
		TLSVersion:   tlsVersionToString(state.Version),
		CipherSuite:  cipherSuiteToString(state.CipherSuite),
		OCSPStapled:  len(state.OCSPResponse) > 0,
		Verified:     verified,
		VerifyError:  verifyErr,
		Certificates: certs,
	}
	_ = writeCachedPemChain(host, port, state.PeerCertificates)
	return res, nil
}

func certToDetails(c *x509.Certificate) CertDetails {
	fp := sha256.Sum256(c.Raw)
	size := 0
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		size = pub.N.BitLen()
	case *ecdsa.PublicKey:
		size = pub.Params().BitSize
	default:
		size = 0
	}
	return CertDetails{
		SubjectCN:   c.Subject.CommonName,
		SANs:        c.DNSNames,
		Issuer:      c.Issuer.CommonName,
		NotBefore:   c.NotBefore,
		NotAfter:    c.NotAfter,
		SigAlg:      c.SignatureAlgorithm.String(),
		PubKeyAlg:   publicKeyAlg(c.PublicKeyAlgorithm),
		PubKeySize:  size,
		Fingerprint: strings.ToUpper(hex.EncodeToString(fp[:])),
		Current:     time.Now().After(c.NotBefore) && time.Now().Before(c.NotAfter),
	}
}

func renderText(res TLSResult) {
	output.Println("TLS", res.TLSVersion, "|", res.CipherSuite, "| OCSP stapled:", res.OCSPStapled)
	if !res.Verified {
		output.Warn("Chain not verified: " + res.VerifyError)
	}
	for i, c := range res.Certificates {
		output.Println(fmt.Sprintf("Cert %d:", i))
		output.KV("  Subject", c.SubjectCN)
		if len(c.SANs) > 0 {
			output.KV("  SANs", strings.Join(c.SANs, ", "))
		}
		output.KV("  Issuer", c.Issuer)
		output.KV("  Validity", fmt.Sprintf("%s -> %s", c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339)))
		output.KV("  Signature", c.SigAlg)
		output.KV("  PublicKey", fmt.Sprintf("%s %dbit", c.PubKeyAlg, c.PubKeySize))
		output.KV("  SHA256", c.Fingerprint)
		if !c.Current {
			output.Warn("  Not currently valid")
		}
	}
	if res.SSLLabsNote != "" {
		output.Info("SSLLabs-like: " + res.SSLLabsNote)
	}
}

func splitHostPort(s string, defaultPort int) (string, int) {
	if _, _, err := net.SplitHostPort(s); err == nil {
		host, portStr, _ := net.SplitHostPort(s)
		var p int
		fmt.Sscanf(portStr, "%d", &p)
		return host, p
	}
	return s, defaultPort
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

func cipherSuiteToString(id uint16) string {
	// tls.CipherSuiteName added in 1.20 via maps; fallback friendly string
	for _, cs := range tls.CipherSuites() {
		if cs.ID == id {
			return cs.Name
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if cs.ID == id {
			return cs.Name
		}
	}
	return fmt.Sprintf("0x%x", id)
}

func publicKeyAlg(a x509.PublicKeyAlgorithm) string {
	switch a {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return a.String()
	}
}

func ssllabsHeuristic(res TLSResult) string {
	var issues []string
	// Very simple heuristics
	if res.TLSVersion != "TLS1.3" && res.TLSVersion != "TLS1.2" {
		issues = append(issues, "old TLS")
	}
	if strings.Contains(strings.ToUpper(res.CipherSuite), "RC4") {
		issues = append(issues, "RC4")
	}
	for _, c := range res.Certificates {
		if !c.Current {
			issues = append(issues, "expired cert")
			break
		}
	}
	if len(issues) == 0 {
		return "ok: modern configuration"
	}
	return "weak: " + strings.Join(issues, ", ")
}

// Cache PEM chain to disk for tests and offline inspection
func writeCachedPemChain(host string, port int, chain []*x509.Certificate) error {
	dir := filepath.Join(modules.CacheDir(), "ssl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, fmt.Sprintf("%s_%d.pem", host, port))
	var b strings.Builder
	for _, c := range chain {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
