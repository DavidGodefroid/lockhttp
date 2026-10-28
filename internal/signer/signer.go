// Package signer keeps the CA key away from the gate (decision D3): the
// signer process alone reads the key and issues leaf certificates over a
// Unix socket to the uids it allows; the gate asks it for each host it
// decrypts.
package signer

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/DavidGodefroid/lockkit/ipc"

	"github.com/DavidGodefroid/lockhttp/internal/ca"
	"github.com/DavidGodefroid/lockhttp/internal/policy"
)

type request struct {
	Host string `json:"host"`
}

type response struct {
	CertPEM string `json:"cert_pem,omitempty"`
	KeyPEM  string `json:"key_pem,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Server issues leaves to allowed peers.
type Server struct {
	CA *ca.CA
	// AllowUIDs may ask; empty allows the signer's own uid only.
	AllowUIDs []int
	// PeerUID replaces the kernel's peer check (tests).
	PeerUID func(net.Conn) (int, error)
	Log     io.Writer
}

// Listen opens the socket at path (mode 0660; the directory is the
// caller's).
func Listen(path string) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve answers on ln until it closes.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) allowed(c net.Conn) bool {
	peer := s.PeerUID
	if peer == nil {
		peer = func(c net.Conn) (int, error) {
			cred, err := ipc.PeerCred(c)
			return cred.UID, err
		}
	}
	uid, err := peer(c)
	if err != nil {
		return false
	}
	if len(s.AllowUIDs) == 0 {
		return uid == os.Getuid()
	}
	return slices.Contains(s.AllowUIDs, uid)
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	if !s.allowed(c) {
		_ = json.NewEncoder(c).Encode(response{Error: "peer not allowed"})
		return
	}
	br := bufio.NewReader(io.LimitReader(c, 64<<10))
	enc := json.NewEncoder(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Minute))
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(response{Error: "bad request"})
			return
		}
		host, err := policy.CheckHostPattern("host", req.Host, true)
		if err != nil || host[0] == '*' {
			_ = enc.Encode(response{Error: "invalid host"})
			continue
		}
		leaf, err := s.CA.Issue(host)
		if err != nil {
			_ = enc.Encode(response{Error: err.Error()})
			continue
		}
		kder, err := x509.MarshalECPrivateKey(leaf.PrivateKey.(*ecdsa.PrivateKey))
		if err != nil {
			_ = enc.Encode(response{Error: err.Error()})
			continue
		}
		if s.Log != nil {
			fmt.Fprintf(s.Log, "lockhttp signer: leaf for %s\n", host)
		}
		_ = enc.Encode(response{
			CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})),
			KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})),
		})
	}
}

// Client asks a signer for leaves and caches them; it implements the
// gate's CertSource. It checks each leaf against the CA certificate.
type Client struct {
	Path string
	// CACert is the CA certificate the leaves must chain to.
	CACert *x509.Certificate
	// Dial replaces the socket dial (tests).
	Dial func(ctx context.Context) (net.Conn, error)

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// Certificate implements gate.CertSource.
func (c *Client) Certificate(ctx context.Context, host string) (*tls.Certificate, error) {
	c.mu.Lock()
	if l, ok := c.cache[host]; ok && time.Now().Before(l.Leaf.NotAfter.Add(-time.Hour)) {
		c.mu.Unlock()
		return l, nil
	}
	c.mu.Unlock()
	dial := c.Dial
	if dial == nil {
		dial = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", c.Path)
		}
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dial(dctx)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(request{Host: host}); err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("signer: %s", resp.Error)
	}
	tc, err := tls.X509KeyPair([]byte(resp.CertPEM), []byte(resp.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	leaf, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	if c.CACert != nil {
		roots := x509.NewCertPool()
		roots.AddCert(c.CACert)
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
			return nil, fmt.Errorf("signer: leaf for %s does not chain to the CA: %w", host, err)
		}
	}
	tc.Leaf = leaf
	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[string]*tls.Certificate{}
	}
	c.cache[host] = &tc
	c.mu.Unlock()
	return &tc, nil
}
