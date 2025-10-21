package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/tunasec/tunacheck/assets"
	"github.com/tunasec/tunacheck/pkg/output"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build and runtime information",
		RunE: func(cmd *cobra.Command, args []string) error {
			output.KV("Version", version)
			output.KV("Commit", commit)
			output.KV("BuildDate", buildDate)
			output.KV("Go", runtime.Version())
			sum := sha256.Sum256(assets.GuidanceJSON)
			output.KV("GuidanceSHA256", hex.EncodeToString(sum[:8]))
			fmt.Fprintln(output.Writer())
			return nil
		},
	}
}
