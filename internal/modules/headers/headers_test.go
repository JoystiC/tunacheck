package headers

import (
	"net/http"
	"testing"
)

func TestEvaluateHeaders_PresentAndMalformed(t *testing.T) {
	h := http.Header{}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "ALLOW")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	res := evaluateHeaders(h)
	found := map[string]headerResult{}
	for _, r := range res.Headers {
		found[r.Name] = r
	}
	if !found["X-Content-Type-Options"].Present || found["X-Content-Type-Options"].Malformed {
		t.Fatalf("expected X-Content-Type-Options present and well-formed")
	}
	if !found["X-Frame-Options"].Malformed {
		t.Fatalf("expected X-Frame-Options malformed when value=ALLOW")
	}
	if !found["Strict-Transport-Security"].Present || found["Strict-Transport-Security"].Malformed {
		t.Fatalf("expected HSTS present and not malformed when contains max-age")
	}
}
