// Package ca is lockhttp's local certificate authority: one per
// installation (P-256, pathlen 0, 90 days), trusted only inside lea's
// containers, and the 24-hour leaf certificates the signer issues for the
// gate's MITM.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Lifetimes.
const (
	CAValidity   = 90 * 24 * time.Hour
	LeafValidity = 24 * time.Hour
)

// File names in a CA directory.
const (
	CertFile = "ca.pem"
	KeyFile  = "ca-key.pem"
)

// CA is a loaded authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	// PEM is the certificate in PEM form.
	PEM []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
	now   func() time.Time
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// Generate creates a CA named after the installation.
func Generate(name string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "LockHTTP local CA (" + name + ")", Organization: []string{"LockHTTP"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), nil
}

// Init writes a new CA into dir (0700): ca.pem (0644) and ca-key.pem
// (0600). It refuses to overwrite an existing CA unless force.
func Init(dir, name string, force bool, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	kp := filepath.Join(dir, KeyFile)
	if _, err := os.Stat(kp); err == nil && !force {
		return fmt.Errorf("%s exists: rotate with --force", kp)
	}
	c, k, err := Generate(name, now)
	if err != nil {
		return err
	}
	tmp := kp + ".tmp"
	if err := os.WriteFile(tmp, k, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, kp); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, CertFile), c, 0o644)
}

// Load reads a CA from its PEM files.
func Load(certPath, keyPath string) (*CA, error) {
	cp, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	kp, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	return Parse(cp, kp)
}

// Parse reads a CA from PEM.
func Parse(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := ParseCert(certPEM)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("ca: no PEM key")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: key: %w", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("ca: the key does not match the certificate")
	}
	return &CA{Cert: cert, Key: key, PEM: certPEM, cache: map[string]*tls.Certificate{}, now: time.Now}, nil
}

// ParseCert reads a CA certificate from PEM.
func ParseCert(certPEM []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("ca: no PEM certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("ca: not a CA certificate")
	}
	return cert, nil
}

// Issue returns a leaf certificate (and its key) for host, cached until
// an hour before it expires.
func (c *CA) Issue(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if l, ok := c.cache[host]; ok && l.Leaf != nil && now.Before(l.Leaf.NotAfter.Add(-time.Hour)) {
		return l, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(LeafValidity)
	if notAfter.After(c.Cert.NotAfter) {
		notAfter = c.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	tc := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	c.cache[host] = tc
	return tc, nil
}
