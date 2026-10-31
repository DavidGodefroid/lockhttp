package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/lockkit/ticket/devicetest"
)

// writeDevicesFile writes the devices file lock up mounts.
func writeDevicesFile(t *testing.T, devs ...ticket.Device) string {
	t.Helper()
	b, err := ticket.MarshalDevices(devs)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeHubPub(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "hub.pub")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// --devices-file, --require-device and --seal-clear are the console's:
// the last two need pinned devices, the risks must parse, and a devices
// file that does not parse stops the gate before it listens.
func TestGateDeviceFlags(t *testing.T) {
	gate := env{euid: func() int { return 1000 }}
	phone := devicetest.New("hub.example.net", "https://hub.example.net", "phone")
	good := writeDevicesFile(t, phone.Device())
	bad := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(bad, []byte("[{]"), 0o644); err != nil {
		t.Fatal(err)
	}
	none := writeDevicesFile(t)
	home := t.TempDir()
	base := []string{"gate", "--listen", "127.0.0.1:0", "--hub", "http://127.0.0.1:8443", "--hub-key-file", writeHubPub(t), "--instance", "egress", "--home", home}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--require-device", "write"}, "--require-device needs --devices-file"},
		{[]string{"--seal-clear"}, "--seal-clear needs --devices-file"},
		{[]string{"--devices-file", good, "--require-device", "writes"}, "--require-device"},
		{[]string{"--devices-file", bad}, "devices.json"},
		{[]string{"--devices-file", none, "--seal-clear"}, "pins no device"},
	} {
		code, _, errs := runEnv(t, gate, append(append([]string{}, base...), c.args...)...)
		if code != exitUsage || !strings.Contains(errs, c.want) {
			t.Errorf("%v: %d %s", c.args, code, errs)
		}
	}
	// The device flags need the hub, as the gate always does.
	if code, _, errs := runEnv(t, gate, "gate", "--listen", "127.0.0.1:0", "--devices-file", good); code != exitUsage || !strings.Contains(errs, "launched by `lox up` only") {
		t.Errorf("devices without the hub: %d %s", code, errs)
	}
	// As the other hub flags, they have their LOCKHTTP_* variables.
	t.Setenv("LOCKHTTP_SEAL_CLEAR", "1")
	if code, _, errs := runEnv(t, gate, base...); code != exitUsage || !strings.Contains(errs, "--seal-clear needs --devices-file") {
		t.Errorf("LOCKHTTP_SEAL_CLEAR: %d %s", code, errs)
	}
	t.Setenv("LOCKHTTP_SEAL_CLEAR", "")
	t.Setenv("LOCKHTTP_REQUIRE_DEVICE", "prod-write")
	if code, _, errs := runEnv(t, gate, base...); code != exitUsage || !strings.Contains(errs, "--require-device needs --devices-file") {
		t.Errorf("LOCKHTTP_REQUIRE_DEVICE: %d %s", code, errs)
	}
}

// The flags read: the pinned devices, and the risk classes that need one.
func TestHubDevicesRead(t *testing.T) {
	a := devicetest.New("hub.example.net", "https://hub.example.net", "phone")
	b := devicetest.New("hub.example.net", "https://hub.example.net", "tablet")
	devs, risks, err := hubDevices{File: writeDevicesFile(t, a.Device(), b.Device()), Require: "write, prod-write", SealClear: true}.read()
	if err != nil || len(devs) != 2 || devs[0].ID != a.Device().ID || !slices.Equal(risks, []ticket.Risk{ticket.RiskWrite, ticket.RiskProdWrite}) {
		t.Fatalf("read: %v %v %v", devs, risks, err)
	}
	if devs, risks, err := (hubDevices{}).read(); err != nil || devs != nil || risks != nil {
		t.Fatalf("no flags: %v %v %v", devs, risks, err)
	}
	// A gate with pinned devices opens its hub mode.
	h, err := openHub("http://127.0.0.1:8443", writeHubPub(t), "egress", t.TempDir(), nil, false,
		hubDevices{File: writeDevicesFile(t, a.Device()), Require: "write", SealClear: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}
