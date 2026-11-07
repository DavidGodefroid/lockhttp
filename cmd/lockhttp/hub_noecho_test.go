package main

import (
	"strings"
	"testing"
)

// With lockkit v0.8.1 a hub URL is http(s)://host[:port] only, and the
// errors of lockkit's hubclient and ticket never quote the value given:
// a token pasted in a hub flag stays out of the gate's output.
func TestHubFlagsDoNotEchoLockkitValues(t *testing.T) {
	gate := env{euid: func() int { return 1000 }}
	base := []string{"gate", "--listen", "127.0.0.1:0", "--hub-key-file", writeHubPub(t), "--instance", "egress", "--home", t.TempDir()}
	for _, hub := range []string{
		"https://user:glsa_Canary@h/path?token=glsa_Canary",
		"https://glsa_Canary@h",
		"https://h/glsa_CanarySecretToken123",
		"https://h?token=glsa_CanarySecretToken123",
		"https://h#glsa_CanarySecretToken123",
		"https://[fe80::1%25glsa_Canary]:8443",
	} {
		code, out, errs := runEnv(t, gate, append(append([]string{}, base...), "--hub", hub)...)
		if code != exitUsage || strings.Contains(out+errs, "glsa_Canary") || !strings.Contains(errs, "host") || !strings.Contains(errs, "port") {
			t.Errorf("--hub %s: %d %q %q", hub, code, out, errs)
		}
	}
	// lockkit's risk classes: the error lists them, not the value.
	code, out, errs := runEnv(t, gate, append(append([]string{}, base...), "--hub", "http://127.0.0.1:8443",
		"--devices-file", writeDevicesFile(t), "--require-device", "glsa_CanarySecretToken123")...)
	if code != exitUsage || strings.Contains(out+errs, "glsa_Canary") || !strings.Contains(errs, "prod-write") {
		t.Errorf("--require-device: %d %q %q", code, out, errs)
	}
	// hub-key hands its flags to lockkit's HubKeyCommand.
	code, out, errs = runEnv(t, env{}, "hub-key", "--home", t.TempDir(), "--instance", "glsa_CanarySecretToken123")
	if code != exitUsage || strings.Contains(out+errs, "glsa_Canary") {
		t.Errorf("hub-key --instance: %d %q %q", code, out, errs)
	}
}

// The hub client shows its URL in the canonical form the gate prints.
func TestHubClientURLIsCanonical(t *testing.T) {
	h, err := openHub("https://127.0.0.1:8443/", writeHubPub(t), "egress", t.TempDir(), nil, false, hubDevices{}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if got := h.Client.URL(); got != "https://127.0.0.1:8443" {
		t.Errorf("URL() = %q", got)
	}
}
