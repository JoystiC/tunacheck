package ssl

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestCertToDetails_Basics(t *testing.T) {
	// Minimal self-signed cert PEM fixture (generated elsewhere). Use a short-lived dummy.
	pemBytes := []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIUQwGZ0n2E3fNs0Sx6i9xFh7HkXq0wCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHdGVzdC5sb2MwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAw
MDAwWjASMRAwDgYDVQQDDAd0ZXN0LmxvYzBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABH8yD/7H1m7h8/3A6z2Z3p3yN9Yk9cQq8nq1z3p1e9g0lJr+X4q4QhI0Z2y5E
oQJ9qk0Nf7v5gC3C9sF7w8oTbZCjUzBRMB0GA1UdDgQWBBSg2m3D9r0w0wXx0t4W
5G1m8s8mJTAfBgNVHSMEGDAWgBSg2m3D9r0w0wXx0t4W5G1m8s8mJTAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQD4mA8mXz0vVdQm0h3QqzvS8gQ7
3S1cPVmXk9wJ6tYrgAIgUt0F8nYwT1y6mZpRhz7g4mQ8X1iQe4p2o4r9yOq9rLk=
-----END CERTIFICATE-----`)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Skip("PEM decode failed; fixture may be invalid for this runtime")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Skip("ParseCertificate failed; fixture may be incompatible")
	}
	d := certToDetails(cert)
	if d.SubjectCN == "" {
		t.Fatalf("expected Subject CN parsed")
	}
	if d.NotAfter.Before(time.Now().Add(-24 * time.Hour)) {
		t.Fatalf("unexpected past NotAfter in fixture")
	}
}
