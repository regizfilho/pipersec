package strongswan

import (
	"fmt"
	"github.com/codepiper/vpnctl/internal/profile"
	"strings"
	"testing"
)

type call struct {
	name string
	args []string
}
type fakeRunner struct{ calls []call }

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name, args})
	return []byte("ok"), nil
}
func activeProfile() profile.Profile {
	p := profile.Defaults("office")
	p.RemoteAddress = "vpn.example.test"
	p.XAuthUsername = "user"
	p.XAuthPassword = "pass"
	p.PSKIdentity = "vpn.example.test"
	p.PSK = "psk"
	return p
}
func TestConnectRunsExpectedSwanctlOperations(t *testing.T) {
	r := &fakeRunner{}
	c := &Client{Runner: r, TempDir: t.TempDir()}
	if err := c.Connect(activeProfile()); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 3 {
		t.Fatalf("calls=%d", len(r.calls))
	}
	for _, x := range []string{"--load-conns", "--load-creds", "--initiate"} {
		if !strings.Contains(fmt.Sprint(r.calls), x) {
			t.Errorf("missing %s", x)
		}
	}
	if !strings.Contains(fmt.Sprint(r.calls[0]), "--load-creds") || !strings.Contains(fmt.Sprint(r.calls[1]), "--load-conns") {
		t.Fatalf("credentials must be loaded before connections: %#v", r.calls)
	}
}
