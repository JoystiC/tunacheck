package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
)

type Config struct {
	JSON       bool
	Verbose    bool
	Quiet      bool
	ForceColor bool
	NoColor    bool
	Template   string
	Stdout     io.Writer
	Stderr     io.Writer
}

var cfg Config

func Configure(c Config) {
	cfg = c
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}

	// Determine color setting
	if cfg.NoColor {
		color.NoColor = true
	} else if cfg.ForceColor {
		color.NoColor = false
	} else {
		// Disable color if stdout is not a TTY
		if f, ok := cfg.Stdout.(*os.File); ok {
			color.NoColor = !isatty.IsTerminal(f.Fd()) && !isatty.IsCygwinTerminal(f.Fd())
		}
	}
}

func Println(args ...any) {
	if cfg.Quiet {
		return
	}
	fmt.Fprintln(cfg.Stdout, args...)
}

func Info(msg string) {
	if cfg.Quiet || cfg.JSON {
		return
	}
	fmt.Fprintln(cfg.Stdout, color.HiBlueString("i"), msg)
}

func Success(msg string) {
	if cfg.Quiet || cfg.JSON {
		return
	}
	fmt.Fprintln(cfg.Stdout, color.HiGreenString("✓"), msg)
}

func Warn(msg string) {
	if cfg.JSON {
		return
	}
	fmt.Fprintln(cfg.Stderr, color.YellowString("!"), msg)
}

func Error(msg string) {
	if cfg.JSON {
		return
	}
	fmt.Fprintln(cfg.Stderr, color.HiRedString("✗"), msg)
}

func KV(key, value string) {
	if cfg.Quiet || cfg.JSON {
		return
	}
	k := color.HiCyanString(key)
	fmt.Fprintf(cfg.Stdout, "%s: %s\n", k, value)
}

func RenderJSON(v any) error {
	enc := json.NewEncoder(cfg.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func RenderTemplate(data any) error {
	if cfg.Template == "" {
		return fmt.Errorf("no template provided")
	}
	t, err := template.New("out").Funcs(template.FuncMap{
		"join": strings.Join,
	}).Parse(cfg.Template)
	if err != nil {
		return err
	}
	return t.Execute(cfg.Stdout, data)
}

func IsJSON() bool    { return cfg.JSON }
func IsVerbose() bool { return cfg.Verbose }

// Writer exposes the configured stdout writer for modules to use.
func Writer() io.Writer { return cfg.Stdout }

// HasTemplate indicates if a custom template is configured.
func HasTemplate() bool { return cfg.Template != "" }
