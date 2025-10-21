package ssl

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/tunasec/tunacheck/pkg/output"
)

type weakResult struct {
	Target               string   `json:"target"`
	SupportsTLS10        bool     `json:"supports_tls10"`
	SupportsTLS11        bool     `json:"supports_tls11"`
	SupportedWeakCiphers []string `json:"supported_weak_ciphers"`
}

func (m *Module) registerWeak(parent *cobra.Command) {
	var host string
	var port int
	var sni string
	var timeout time.Duration

	weak := &cobra.Command{
		Use:   "weak-ciphers <host[:port]>",
		Short: "Probe deprecated TLS versions and weak cipher support",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" && len(args) > 0 {
				host = args[0]
			}
			if host == "" {
				return fmt.Errorf("host required")
			}
			h, p := splitHostPort(host, port)
			if sni == "" {
				sni = h
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			res, err := probeWeak(ctx, h, p, sni)
			if err != nil {
				return err
			}
			if output.IsJSON() {
				return output.RenderJSON(res)
			}
			green := color.New(color.FgGreen).SprintfFunc()
			red := color.New(color.FgHiRed).SprintfFunc()
			redBold := color.New(color.FgHiRed, color.Bold).SprintFunc()

			output.KV("Target", res.Target)
			if res.SupportsTLS10 {
				output.KV("TLS1.0", red("yes"))
			} else {
				output.KV("TLS1.0", green("no"))
			}
			if res.SupportsTLS11 {
				output.KV("TLS1.1", red("yes"))
			} else {
				output.KV("TLS1.1", green("no"))
			}
			if len(res.SupportedWeakCiphers) > 0 {
				output.Println(redBold("Weak ciphers supported:"))
				for _, c := range res.SupportedWeakCiphers {
					output.Println(red(" - ") + red(c))
				}
			} else {
				output.Success("No probed weak ciphers accepted")
			}
			return nil
		},
	}

	weak.Flags().StringVar(&host, "host", "", "Target host[:port]")
	weak.Flags().IntVar(&port, "port", 443, "Port if not provided in host")
	weak.Flags().StringVar(&sni, "sni", "", "Override SNI hostname")
	weak.Flags().DurationVar(&timeout, "timeout", 8*time.Second, "Probe timeout")

	parent.AddCommand(weak)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func probeWeak(ctx context.Context, host string, port int, sni string) (weakResult, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	res := weakResult{Target: addr}

	// Test TLS1.0 and TLS1.1 support
	res.SupportsTLS10 = tryVersion(ctx, addr, sni, tls.VersionTLS10)
	res.SupportsTLS11 = tryVersion(ctx, addr, sni, tls.VersionTLS11)

	// Probe a curated set of weak TLS1.2 cipher suites by offering each exclusively
	weakSuites := []struct {
		id   uint16
		name string
	}{
		{0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
		{0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
		{0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		{0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
		{0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
		{0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"},
		{0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"},
	}
	for _, s := range weakSuites {
		ok := tryCipher(ctx, addr, sni, s.id)
		if ok {
			res.SupportedWeakCiphers = append(res.SupportedWeakCiphers, s.name)
		}
	}
	return res, nil
}

func tryVersion(ctx context.Context, addr, sni string, ver uint16) bool {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	cfg := &tls.Config{ServerName: sni, MinVersion: ver, MaxVersion: ver}
	c := tls.Client(conn, cfg)
	err = c.HandshakeContext(ctx)
	if err != nil {
		return false
	}
	return true
}

func tryCipher(ctx context.Context, addr, sni string, cipher uint16) bool {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	cfg := &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{cipher}}
	c := tls.Client(conn, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		return false
	}
	st := c.ConnectionState()
	return st.CipherSuite == cipher
}
