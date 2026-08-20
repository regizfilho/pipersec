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
	if strings.Contains(fmt.Sprint(args), "--load-conns") {
		return []byte("loaded connection 'office'"), nil
	}
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
	if len(r.calls) != 5 {
		t.Fatalf("calls=%d", len(r.calls))
	}
	for _, x := range []string{"--load-creds", "--load-conns", "--initiate"} {
		if !strings.Contains(fmt.Sprint(r.calls), x) {
			t.Errorf("missing %s", x)
		}
	}
	if !strings.Contains(fmt.Sprint(r.calls[0]), "--load-creds") || !strings.Contains(fmt.Sprint(r.calls[1]), "--load-conns") {
		t.Fatalf("credentials must be loaded before connections: %#v", r.calls)
	}
	if !strings.Contains(fmt.Sprint(r.calls[2]), "--initiate") || !strings.Contains(fmt.Sprint(r.calls[2]), "--ike") {
		t.Fatalf("IKE_SA must be initiated first: %#v", r.calls)
	}
	if !strings.Contains(fmt.Sprint(r.calls[3]), "--child") || !strings.Contains(fmt.Sprint(r.calls[4]), "--child") {
		t.Fatalf("every child SA must be initiated explicitly: %#v", r.calls)
	}
}

func TestConnectInitiatesEveryChildForMultipleRemoteTS(t *testing.T) {
	r := &fakeRunner{}
	c := &Client{Runner: r, TempDir: t.TempDir()}
	p := activeProfile()
	p.RemoteTS = "10.1.0.0/16,10.2.0.0/16,10.3.0.0/16"
	if err := c.Connect(p); err != nil {
		t.Fatal(err)
	}
	for _, child := range []string{"--ike office", "--child office-1", "--child office-2", "--child office-3"} {
		if !strings.Contains(fmt.Sprint(r.calls), child) {
			t.Errorf("missing %s", child)
		}
	}
}
