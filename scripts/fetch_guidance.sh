#!/usr/bin/env sh
set -eu

# Fetch or generate security header guidance as JSON and store to assets/guidance.json
# Default source: Mozilla Web Security Guidelines (markdown). Since it's not JSON,
# we produce a curated JSON that aligns with best practices, or accept CUSTOM_URL.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ASSETS_DIR="$REPO_ROOT/assets"
OUT="$ASSETS_DIR/guidance.json"

CUSTOM_URL=${GUIDANCE_URL:-}

mkdir -p "$ASSETS_DIR"

if [ -n "$CUSTOM_URL" ]; then
  echo "Fetching guidance from $CUSTOM_URL ..." >&2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$CUSTOM_URL" -o "$OUT.tmp" || {
      echo "Failed to fetch custom guidance. Keeping existing or default." >&2
      rm -f "$OUT.tmp"
    }
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$OUT.tmp" "$CUSTOM_URL" || {
      echo "Failed to fetch custom guidance. Keeping existing or default." >&2
      rm -f "$OUT.tmp"
    }
  else
    echo "Neither curl nor wget found. Skipping fetch." >&2
  fi

  if [ -f "$OUT.tmp" ]; then
    # If fetched content isn't JSON, keep default curated file instead.
    if command -v jq >/dev/null 2>&1; then
      if jq empty "$OUT.tmp" 2>/dev/null; then
        mv "$OUT.tmp" "$OUT"
        echo "Custom JSON guidance saved to $OUT" >&2
        exit 0
      else
        echo "Fetched guidance is not valid JSON; using curated default." >&2
        rm -f "$OUT.tmp"
      fi
    else
      echo "jq not found; cannot validate JSON. Using curated default." >&2
      rm -f "$OUT.tmp"
    fi
  fi
fi

# Curated guidance JSON (fallback) – derived from public guidance like Mozilla Web Security Guidelines.
cat > "$OUT" <<'JSON'
{
  "headers": {
    "Strict-Transport-Security": {
      "recommended_value": "max-age=63072000; includeSubDomains; preload",
      "rationale": "Enforces HTTPS and enables preload for stronger transport security.",
      "references": [
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"
      ]
    },
    "Content-Security-Policy": {
      "recommended_value": "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; upgrade-insecure-requests",
      "rationale": "Restricts sources to mitigate XSS and related attacks.",
      "references": [
        "https://developer.mozilla.org/docs/Web/HTTP/CSP"
      ]
    },
    "X-Frame-Options": {
      "recommended_value": "DENY",
      "rationale": "Prevents clickjacking by disallowing framing.",
      "references": [
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"
      ]
    },
    "X-Content-Type-Options": {
      "recommended_value": "nosniff",
      "rationale": "Prevents MIME-type sniffing reducing XSS risk.",
      "references": [
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"
      ]
    },
    "Referrer-Policy": {
      "recommended_value": "no-referrer",
      "rationale": "Avoids leaking referrer information across origins.",
      "references": [
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"
      ]
    },
    "Permissions-Policy": {
      "recommended_value": "geolocation=(), microphone=(), camera=()",
      "rationale": "Disables powerful features by default.",
      "references": [
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"
      ]
    },
    "Expect-CT": {
      "recommended_value": "max-age=86400, enforce",
      "rationale": "Legacy CT enforcement header (superseded yet still informational).",
      "references": [
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Expect-CT"
      ]
    },
    "Feature-Policy": {
      "recommended_value": "geolocation 'none'; microphone 'none'; camera 'none'",
      "rationale": "Legacy alias for Permissions-Policy.",
      "references": [
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Feature-Policy"
      ]
    }
  }
}
JSON

echo "Curated guidance written to $OUT" >&2


