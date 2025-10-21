# Changelog

## v1.0.0

- Initial stable release
- Core features:
  - security-headers: validate common headers, embedded guidance, JSON/template output, cache, examples (Nginx/Apache)
  - ssl: TLS connect, chain display, JSON, SSLLabs-like heuristic
  - ssl weak-ciphers: probe deprecated TLS versions and weak TLS 1.2 ciphers
  - dns: A/AAAA/MX/TXT, SPF/DMARC checks with guidance
  - doctor/version commands
- Build & release:
  - Makefile, guidance fetch, assets embedding
  - GoReleaser config and GitHub Actions release workflow
  - Homebrew tap publishing (JoystiC/homebrew-tap)
