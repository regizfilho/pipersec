package profile

import (
	"strings"
	"testing"
)

func ready() Profile {
	p := Defaults("clinica")
	p.RemoteAddress = "vpn.example.test"
	p.XAuthUsername = "usuario.teste"
	p.XAuthPassword = "senha"
	p.PSKIdentity = "vpn.example.test"
	p.PSK = "segredo"
	return p
}
func TestRenderConnectionIncludesIKEv1XAuthFields(t *testing.T) {
	got, err := ready().RenderConnection()
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"version = 1", "aggressive = yes", "pull = yes", "xauth_id = \"usuario.teste\"", "esp_proposals = aes256-sha256-ecp384"} {
		if !strings.Contains(got, part) {
			t.Errorf("missing %q", part)
		}
	}
}
func TestRenderSecretsQuotesCredentials(t *testing.T) {
	p := ready()
	p.XAuthPassword = `a"b`
	got, err := p.RenderSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `secret = "a\"b"`) {
		t.Fatalf("unexpected secrets: %s", got)
	}
}
func TestProfileRejectsUnsafeName(t *testing.T) {
	p := ready()
	p.Name = "bad name"
	if err := p.Validate(true); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDefaultRemoteTSIsSplitTunnel(t *testing.T) {
	p := Defaults("test")
	if p.RemoteTS == "0.0.0.0/0" {
		t.Fatal("default remote_ts should not be 0.0.0.0/0 for split tunneling")
	}
}

func TestMultipleRemoteTSNetworks(t *testing.T) {
	p := ready()
	p.RemoteTS = "10.0.0.0/8, 192.168.0.0/16"
	got, err := p.RenderConnection()
	if err != nil {
		t.Fatal(err)
	}
	// strongSwan uses space-separated networks
	if !strings.Contains(got, "remote_ts = 10.0.0.0/8 192.168.0.0/16") {
		t.Errorf("multiple remote_ts not properly converted to space-separated format: %s", got)
	}
}

func TestRejectsEmptyRemoteTS(t *testing.T) {
	p := ready()
	p.RemoteTS = ""
	if err := p.Validate(true); err == nil {
		t.Fatal("expected validation error for empty remote_ts")
	}
}
