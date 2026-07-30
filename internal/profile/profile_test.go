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
