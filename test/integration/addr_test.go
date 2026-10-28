//go:build integration && linux

package integration

import "net/netip"

type netipAddr = netip.Addr

// publicTestAddr is a documentation address the gate treats as public;
// the test dialer maps it to the local backend.
var publicTestAddr = netip.MustParseAddr("203.0.113.10")
