package store

import (
	"github.com/codepiper/vpnctl/internal/profile"
	"os"
	"path/filepath"
	"testing"
)

func testProfile(name string) profile.Profile {
	p := profile.Defaults(name)
	p.RemoteAddress = "vpn.example.test"
	p.XAuthUsername = "user"
	p.XAuthPassword = "pass"
	p.PSKIdentity = "vpn.example.test"
	p.PSK = "psk"
	return p
}
func TestEncryptedRoundTripAndNoPlaintext(t *testing.T) {
	base := t.TempDir()
	s := New(base)
	if err := s.Put(testProfile("one")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(testProfile("two")); err != nil {
		t.Fatal(err)
	}
	items, err := s.List()
	if err != nil || len(items) != 2 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
	raw, err := os.ReadFile(filepath.Join(base, "vpnctl", "profiles.enc"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || contains(string(raw), "pass") {
		t.Fatal("secrets leaked to encrypted file")
	}
	info, err := os.Stat(filepath.Join(base, "vpnctl", "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
