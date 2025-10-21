## tunacheck

Security checks for websites, TLS endpoints, and DNS. Colored output by default, JSON available via `--json`.

### Install (Homebrew)

```bash
brew tap JoystiC/homebrew-tap
brew install joystic/tap/tunacheck
```

Or download from Releases and place in PATH.

### Quick start

```bash
make deps
make build
./bin/tunacheck --help
```

Examples:

```bash
./bin/tunacheck security-headers check https://example.com
./bin/tunacheck ssl check example.com:443 --sni example.com
./bin/tunacheck ssl weak-ciphers example.com:443
./bin/tunacheck dns check example.com
```

### Modules

- security-headers: validate common headers and suggest fixes using embedded guidance
- ssl: inspect TLS connection and certificate chain; optional `--ssllabs` heuristic
- ssl weak-ciphers: quick probe for deprecated TLS/ciphers
- dns: A/AAAA/MX/TXT plus SPF/DMARC checks

### Extensibility

Implement `internal/modules.Module` and call `Register(root)` to add commands.

### Build-time embedded guidance

`make guidance` runs `scripts/fetch_guidance.sh` to produce `assets/guidance.json` embedded via `go:embed`.

### Development

```bash
make deps
make test
make build
make snapshot   # local artifact build via GoReleaser
```

### Releases via Homebrew

This repo is set up with GoReleaser and a GitHub Action to publish release artifacts and a Homebrew formula to a tap repository `JoystiC/homebrew-tap`.

Steps:
- Create the tap repo `github.com/JoystiC/homebrew-tap`.
- Push a tag (e.g., `v1.0.0`).
- The workflow `.github/workflows/release.yml` will build for darwin/linux (amd64, arm64), create a GitHub release, and update the tap formula.

Install from tap:

```bash
brew tap JoystiC/homebrew-tap
brew install joystic/tap/tunacheck
```

### Checklist

- Implemented core CLI, modules, output, assets embedding, Makefile, tests.
- Stubbed: external guidance fetch transformation if source is non-JSON (instructions provided).

