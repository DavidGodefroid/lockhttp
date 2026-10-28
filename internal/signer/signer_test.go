package signer

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhttp/internal/ca"
)

func newCA(t *testing.T) *ca.CA {
	t.Helper()
	c, k, err := ca.Generate("t", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, err := ca.Parse(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func serve(t *testing.T, s *Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() { _ = s.Serve(ln) }()
	return path
}

func TestIssueAndVerify(t *testing.T) {
	a := newCA(t)
	path := serve(t, &Server{CA: a, PeerUID: func(net.Conn) (int, error) { return 10003, nil }, AllowUIDs: []int{10003}})
	c := &Client{Path: path, CACert: a.Cert}
	leaf, err := c.Certificate(context.Background(), "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Leaf.DNSNames[0] != "api.example.com" || time.Until(leaf.Leaf.NotAfter) > 25*time.Hour {
		t.Fatalf("leaf: %+v", leaf.Leaf)
	}
	if _, err := c.Certificate(context.Background(), "*.example.com"); err == nil {
		t.Fatal("wildcard issued")
	}
	// A leaf from another CA is refused by the client.
	other := newCA(t)
	c2 := &Client{Path: path, CACert: other.Cert}
	if _, err := c2.Certificate(context.Background(), "x.example.com"); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("foreign leaf accepted: %v", err)
	}
}

func TestPeerRefused(t *testing.T) {
	a := newCA(t)
	path := serve(t, &Server{CA: a, PeerUID: func(net.Conn) (int, error) { return 1000, nil }, AllowUIDs: []int{10003}})
	if _, err := (&Client{Path: path}).Certificate(context.Background(), "a.example.com"); err == nil {
		t.Fatal("peer not allowed got a leaf")
	}
	path = serve(t, &Server{CA: a, PeerUID: func(net.Conn) (int, error) { return 0, errors.New("no cred") }, AllowUIDs: []int{0}})
	if _, err := (&Client{Path: path}).Certificate(context.Background(), "a.example.com"); err == nil {
		t.Fatal("unknown peer got a leaf")
	}
}

func TestCAInit(t *testing.T) {
	dir := t.TempDir()
	if err := ca.Init(dir, "x", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ca.Init(dir, "x", false, time.Now()); err == nil {
		t.Fatal("overwrote a CA without --force")
	}
	a, err := ca.Load(filepath.Join(dir, ca.CertFile), filepath.Join(dir, ca.KeyFile))
	if err != nil || !a.Cert.IsCA || a.Cert.MaxPathLen != 0 || !a.Cert.MaxPathLenZero {
		t.Fatalf("ca: %v %+v", err, a)
	}
}
