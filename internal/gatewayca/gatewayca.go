// Package gatewayca is the orchestrator's certificate authority for Flotilla
// join gateways (moved here from gov_layer). Each FL session's gateway gets a
// TLS server certificate signed by this CA, and FL clients trust exactly this
// CA certificate.
//
// The CA has its own RSA key; gov_layer's governance key is only for contract
// signing now. The key and its self-signed certificate are generated on first
// start and persisted. If the key is ever replaced, the old certificate no
// longer matches and is regenerated.
//
// A certificate is only issued for a contract gov_layer vouches for (see
// govclient.GatewayAuthorization). It names the gateway's IP, carries the
// contract id as a URI SAN, and expires with the contract, so a client that
// trusts this CA knows the gateway it reached belongs to a live, fully signed
// FL contract. Every issued certificate is recorded under RecordsDir before
// it is handed out.
package gatewayca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	// caKeyBits is the CA key size.
	caKeyBits = 3072
	// caValidity is how long a freshly generated CA certificate lasts.
	caValidity = 5 * 365 * 24 * time.Hour
	// certBackdate covers clock skew between the orchestrator and FL clients.
	certBackdate = 5 * time.Minute
	// minCSRKeyBits is the smallest RSA key a gateway CSR may carry.
	minCSRKeyBits = 2048
)

// Party is one data provider on the contract, as parties.json lists it.
type Party struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Authorization is the contract a gateway certificate is issued for, as
// gov_layer confirmed it: final, FL, signed by every data provider, not
// expired (govclient.GatewayAuthorization).
type Authorization struct {
	ContractID   string
	ProjectID    string
	JobID        string
	SubmissionID string
	ValidUntil   time.Time
	Parties      []Party
}

// Issued is one issued gateway certificate.
type Issued struct {
	Serial            string // hex
	CertPEM           []byte
	FingerprintSHA256 string // hex SHA-256 of the certificate DER
	NotAfter          time.Time
}

// Record is one issued certificate on disk (<RecordsDir>/<serial>.json).
type Record struct {
	Serial            string    `json:"serial"`
	SubmissionID      string    `json:"submission_id"`
	ProjectID         string    `json:"project_id"`
	ContractID        string    `json:"contract_id"`
	JobID             string    `json:"job_id"`
	ServerIP          string    `json:"server_ip"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	NotAfter          time.Time `json:"not_after"`
	IssuedAt          time.Time `json:"issued_at"`
}

// CA signs gateway certificates.
type CA struct {
	key        *rsa.PrivateKey
	cert       *x509.Certificate
	certPEM    []byte
	recordsDir string
}

// LoadOrCreate loads the CA key at keyPath (PKCS#8 PEM, generated with 0600
// when missing) and its certificate at certPath (regenerated when missing,
// unparseable or issued for a different key). Issued certificates are
// recorded under recordsDir (created when needed).
func LoadOrCreate(keyPath, certPath, recordsDir string) (*CA, error) {
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	cert, certPEM, err := loadOrCreateCert(certPath, key)
	if err != nil {
		return nil, err
	}
	return &CA{key: key, cert: cert, certPEM: certPEM, recordsDir: recordsDir}, nil
}

// CAPEM is the CA certificate, PEM.
func (ca *CA) CAPEM() []byte { return ca.certPEM }

// Certificate is the CA certificate.
func (ca *CA) Certificate() *x509.Certificate { return ca.cert }

func loadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("gateway CA key %s is not valid PEM", path)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse gateway CA key %s: %w", path, err)
		}
		priv, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("gateway CA key %s is not an RSA key", path)
		}
		return priv, nil
	case errors.Is(err, fs.ErrNotExist):
		priv, err := rsa.GenerateKey(rand.Reader, caKeyBits)
		if err != nil {
			return nil, fmt.Errorf("generate gateway CA key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create gateway CA key dir: %w", err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, fmt.Errorf("write gateway CA key %s: %w", path, err)
		}
		log.Printf("[GATEWAY-CA] Generated a new CA key at %s", path)
		return priv, nil
	default:
		return nil, fmt.Errorf("read gateway CA key %s: %w", path, err)
	}
}

func loadOrCreateCert(path string, key *rsa.PrivateKey) (*x509.Certificate, []byte, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
			cert, perr := x509.ParseCertificate(block.Bytes)
			if perr == nil && key.PublicKey.Equal(cert.PublicKey) {
				return cert, pem.EncodeToMemory(block), nil
			}
		}
		log.Printf("[WARN] Gateway CA certificate %s does not match the CA key; regenerating it", path)
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, nil, fmt.Errorf("read gateway CA certificate %s: %w", path, err)
	}

	cert, certPEM, err := newCACert(key, time.Now())
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("create gateway CA certificate dir: %w", err)
	}
	if err := os.WriteFile(path, certPEM, 0o644); err != nil {
		return nil, nil, fmt.Errorf("write gateway CA certificate %s: %w", path, err)
	}
	return cert, certPEM, nil
}

// newCACert builds the self-signed CA certificate for key. It may only sign
// leaf certificates (MaxPathLen 0).
func newCACert(key *rsa.PrivateKey, now time.Time) (*x509.Certificate, []byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA serial: %w", err)
	}
	skid, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "P3DX FL Gateway CA", Organization: []string{"P3DX"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          skid,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create gateway CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// ParseCSR decodes a PEM CERTIFICATE REQUEST, checks its self-signature, and
// requires an RSA ≥2048 or ECDSA P-256 public key.
func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("CSR is not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < minCSRKeyBits {
			return nil, errors.New("RSA key must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return nil, errors.New("ECDSA key must be on P-256")
		}
	default:
		return nil, errors.New("key must be RSA or ECDSA P-256")
	}
	return csr, nil
}

// ContractURI is the URI SAN naming the contract a gateway certificate was
// issued for.
func ContractURI(contractID string) *url.URL {
	return &url.URL{Scheme: "urn", Opaque: "p3dx:fl:contract:" + contractID}
}

// Issue signs a gateway server certificate for csrPEM's key, valid at ip,
// for contract a, from now until a.ValidUntil, and records it. A
// certificate that could not be recorded is not returned.
func (ca *CA) Issue(csrPEM string, ip net.IP, a Authorization, now time.Time) (*Issued, error) {
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid CSR: %w", err)
	}
	if ip == nil {
		return nil, errors.New("server IP is not an IP address")
	}
	if a.ContractID == "" || !now.Before(a.ValidUntil) {
		return nil, errors.New("contract is missing or expired")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "flotilla-gateway-" + a.ProjectID},
		IPAddresses:           []net.IP{ip},
		URIs:                  []*url.URL{ContractURI(a.ContractID)},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		NotBefore:             now.Add(-certBackdate),
		NotAfter:              a.ValidUntil,
		AuthorityKeyId:        ca.cert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	fp := sha256.Sum256(der)
	out := &Issued{
		Serial:            serial.Text(16),
		CertPEM:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		FingerprintSHA256: hex.EncodeToString(fp[:]),
		NotAfter:          cert.NotAfter,
	}
	// Record before returning: a certificate that isn't on record is never
	// handed out.
	if err := ca.record(Record{
		Serial: out.Serial, SubmissionID: a.SubmissionID, ProjectID: a.ProjectID,
		ContractID: a.ContractID, JobID: a.JobID, ServerIP: ip.String(),
		FingerprintSHA256: out.FingerprintSHA256, NotAfter: cert.NotAfter.UTC(), IssuedAt: now.UTC(),
	}); err != nil {
		return nil, fmt.Errorf("record issued certificate: %w", err)
	}
	log.Printf("[GATEWAY-CERTS] Issued serial %s for project %s (contract %s) at %s, expires %s",
		out.Serial, a.ProjectID, a.ContractID, ip, cert.NotAfter.UTC().Format(time.RFC3339))
	return out, nil
}

func (ca *CA) record(r Record) error {
	if ca.recordsDir == "" {
		return errors.New("no records directory configured")
	}
	if err := os.MkdirAll(ca.recordsDir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(ca.recordsDir, r.Serial+".json"), b, 0o600)
}

// randomSerial returns a random positive 128-bit certificate serial number.
func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

// subjectKeyID is the RFC 5280 method-1 key identifier of pub: the SHA-1 of
// its subjectPublicKey bit string.
func subjectKeyID(pub any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:], nil
}
