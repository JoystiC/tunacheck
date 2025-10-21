package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/tunasec/tunacheck/internal/modules"
	dnsmodule "github.com/tunasec/tunacheck/internal/modules/dns"
	headers "github.com/tunasec/tunacheck/internal/modules/headers"
	ssl "github.com/tunasec/tunacheck/internal/modules/ssl"
	"github.com/tunasec/tunacheck/pkg/output"
)

var (
	flagJSON    bool
	flagVerbose bool
	flagQuiet   bool
	flagColor   bool
	flagNoColor bool
	flagFormat  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "tunacheck",
		Short: "Security checks for websites and TLS endpoints",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Configure renderer according to global flags
			output.Configure(output.Config{
				JSON:       flagJSON,
				Verbose:    flagVerbose,
				Quiet:      flagQuiet,
				ForceColor: flagColor,
				NoColor:    flagNoColor,
				Template:   flagFormat,
				Stdout:     os.Stdout,
				Stderr:     os.Stderr,
			})
			return nil
		},
	}

	rootCmd.PersistentFlags().BoolVarP(&flagJSON, "json", "j", false, "Emit JSON output")
	rootCmd.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVar(&flagQuiet, "quiet", false, "Quiet output")
	rootCmd.PersistentFlags().BoolVar(&flagColor, "color", false, "Force color output")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable color output")
	rootCmd.PersistentFlags().StringVar(&flagFormat, "format", "", "Go text/template for custom output (non-JSON)")

	// Context with sensible default timeout for commands
	ctx := context.Background()
	ctx = context.WithValue(ctx, modules.ContextKeyStartTime, time.Now())

	// Register modules
	var ms []modules.Module
	ms = append(ms, headers.New())
	ms = append(ms, ssl.New())
	ms = append(ms, dnsmodule.New())
	for _, m := range ms {
		m.Register(rootCmd)
	}

	// doctor command
	rootCmd.AddCommand(newDoctorCmd())
	rootCmd.AddCommand(newVersionCmd())

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Self-check the environment and embedded assets",
		RunE: func(cmd *cobra.Command, args []string) error {
			output.Info("Checking environment...")
			// Go version
			output.KV("GoVersion", fmt.Sprintf("%s", runtimeVersion()))
			// Guidance embedded
			if ok, why := modules.GuidanceAvailable(); ok {
				output.KV("Guidance", "embedded OK")
			} else {
				output.KV("Guidance", "missing: "+why)
			}
			// System roots
			if ok, why := modules.SystemCertPoolAvailable(); ok {
				output.KV("SystemCAPool", "available")
			} else {
				output.KV("SystemCAPool", "issue: "+why)
			}
			output.Success("Doctor finished")
			return nil
		},
	}
}

func runtimeVersion() string {
	return runtimeVersionImpl()
}
