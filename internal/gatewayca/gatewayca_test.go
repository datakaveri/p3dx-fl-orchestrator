package gatewayca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := LoadOrCreate(filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.pem"), filepath.Join(dir, "records"))
	if err != nil {
		t.Fatal(err)
	}
	return ca, dir
}

func newCSR(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "gw"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func p256CSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newCSR(t, key)
}

func auth(validUntil time.Time) Authorization {
	return Authorization{ContractID: "contract-1", ProjectID: "proj-1", JobID: "job-1", SubmissionID: "sub-1",
		ValidUntil: validUntil, Parties: []Party{{ID: "kc-alice", Name: "alice"}}}
}

func TestCACreatedAndReloaded(t *testing.T) {
	ca, dir := newCA(t)
	c := ca.Certificate()
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Fatalf("CA constraints wrong: IsCA=%t BCV=%t MaxPathLen=%d Zero=%t", c.IsCA, c.BasicConstraintsValid, c.MaxPathLen, c.MaxPathLenZero)
	}
	if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("CA key usage = %v", c.KeyUsage)
	}
	if c.Subject.CommonName != "P3DX FL Gateway CA" || len(c.SubjectKeyId) == 0 {
		t.Fatalf("CA subject/SKID wrong: %v %x", c.Subject, c.SubjectKeyId)
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Fatalf("CA is not self-signed: %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil || !bytes.Equal(onDisk, ca.CAPEM()) {
		t.Fatalf("CA PEM not written: %v", err)
	}
	if st, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("CA key not written 0600: %v %v", st, err)
	}

	again, err := LoadOrCreate(filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.pem"), filepath.Join(dir, "records"))
	if err != nil {
		t.Fatal(err)
	}
	if again.Certificate().SerialNumber.Cmp(c.SerialNumber) != 0 || !bytes.Equal(again.CAPEM(), ca.CAPEM()) {
		t.Fatal("existing CA certificate was not reused")
	}
}

func TestCACertRegeneratedOnKeyChange(t *testing.T) {
	ca, dir := newCA(t)
	if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	fresh, err := LoadOrCreate(filepath.Join(dir, "ca.key"), filepath.Join(dir, "ca.pem"), filepath.Join(dir, "records"))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Certificate().SerialNumber.Cmp(ca.Certificate().SerialNumber) == 0 || !fresh.key.PublicKey.Equal(fresh.Certificate().PublicKey) {
		t.Fatal("CA certificate not regenerated for the new key")
	}
}

func TestIssue(t *testing.T) {
	ca, dir := newCA(t)
	validUntil := time.Now().Add(48 * time.Hour).UTC()
	a := auth(validUntil)
	got, err := ca.Issue(p256CSR(t), net.ParseIP("10.1.2.3"), a, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(got.CertPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CAPEM())
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "10.1.2.3", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("leaf does not verify against the CA: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("10.1.2.3")) {
		t.Fatalf("IP SANs = %v", leaf.IPAddresses)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "urn:p3dx:fl:contract:contract-1" {
		t.Fatalf("URI SANs = %v", leaf.URIs)
	}
	if !leaf.NotAfter.Equal(validUntil.Truncate(time.Second)) || !got.NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("NotAfter %v, want %v", leaf.NotAfter, validUntil.Truncate(time.Second))
	}
	if leaf.Subject.CommonName != "flotilla-gateway-proj-1" {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
	if !bytes.Equal(leaf.AuthorityKeyId, ca.Certificate().SubjectKeyId) {
		t.Fatal("leaf AuthorityKeyId does not match CA SubjectKeyId")
	}
	fp := sha256.Sum256(block.Bytes)
	if got.FingerprintSHA256 != hex.EncodeToString(fp[:]) || got.Serial != leaf.SerialNumber.Text(16) {
		t.Fatalf("fingerprint/serial mismatch: %+v", got)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "records", got.Serial+".json"))
	if err != nil {
		t.Fatalf("issued certificate not recorded: %v", err)
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Serial != got.Serial || rec.ServerIP != "10.1.2.3" || rec.ProjectID != "proj-1" || rec.ContractID != "contract-1" ||
		rec.SubmissionID != "sub-1" || rec.JobID != "job-1" || rec.FingerprintSHA256 != got.FingerprintSHA256 {
		t.Fatalf("recorded %+v", rec)
	}
}

func TestIssueRSAKeyUsage(t *testing.T) {
	ca, _ := newCA(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ca.Issue(newCSR(t, key), net.ParseIP("10.0.0.1"), auth(time.Now().Add(time.Hour)), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(got.CertPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Fatalf("RSA leaf key usage = %v", leaf.KeyUsage)
	}
}

func TestIssueRejects(t *testing.T) {
	ca, dir := newCA(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ok := auth(now.Add(time.Hour))
	for _, tc := range []struct {
		name string
		csr  string
		ip   net.IP
		a    Authorization
	}{
		{"bad csr", "not a csr", net.ParseIP("10.0.0.1"), ok},
		{"weak RSA key", newCSR(t, weak), net.ParseIP("10.0.0.1"), ok},
		{"P-384 key", newCSR(t, p384), net.ParseIP("10.0.0.1"), ok},
		{"no ip", p256CSR(t), nil, ok},
		{"expired", p256CSR(t), net.ParseIP("10.0.0.1"), auth(now.Add(-time.Minute))},
		{"no contract", p256CSR(t), net.ParseIP("10.0.0.1"), Authorization{ValidUntil: now.Add(time.Hour)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ca.Issue(tc.csr, tc.ip, tc.a, now); err == nil {
				t.Fatal("issued, want an error")
			}
		})
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "records")); len(entries) != 0 {
		t.Fatalf("rejected requests recorded certificates: %v", entries)
	}
}

func TestIssueRecordFailureWithholdsCert(t *testing.T) {
	ca, dir := newCA(t)
	// A file where the records directory should be makes the record fail.
	ca.recordsDir = filepath.Join(dir, "blocked", "records")
	if err := os.WriteFile(filepath.Join(dir, "blocked"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := ca.Issue(p256CSR(t), net.ParseIP("10.0.0.1"), auth(time.Now().Add(time.Hour)), time.Now()); err == nil || got != nil {
		t.Fatalf("got %+v, %v; want no certificate when it cannot be recorded", got, err)
	}
}
