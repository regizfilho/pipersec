package strongswan

import "testing"

func TestParseSASRaw(t *testing.T) {
	raw := `list-sa event {corpnet {uniqueid=11 version=1 state=ESTABLISHED local-host=192.168.10.3 local-port=4500 local-id=192.168.10.3 remote-host=203.0.113.1 remote-port=4500 remote-id=203.0.113.1 initiator=yes initiator-spi=933b719078372bdd responder-spi=a3e74c0bf5730f6a nat-local=yes nat-any=yes encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 prf-alg=PRF_HMAC_SHA2_256 dh-group=ECP_384 established=791 reauth-time=42409 local-vips=[10.99.99.2] child-sas {corpnet-1-11 {name=corpnet-1 uniqueid=11 reqid=2 state=INSTALLED mode=TUNNEL protocol=ESP encap=yes spi-in=cdb3a2c5 spi-out=e1a722b0 encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 dh-group=ECP_384 bytes-in=0 packets-in=0 bytes-out=0 packets-out=0 rekey-time=38089 life-time=42409 install-time=791 local-ts=[10.99.99.2/32] remote-ts=[172.16.1.0/24]} corpnet-2-12 {name=corpnet-2 uniqueid=12 reqid=1 state=INSTALLED mode=TUNNEL protocol=ESP encap=yes spi-in=c3db4c61 spi-out=e1a722b1 encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 dh-group=ECP_384 bytes-in=0 packets-in=0 bytes-out=504 packets-out=6 use-out=715 rekey-time=38089 life-time=42409 install-time=791 local-ts=[10.99.99.2/32] remote-ts=[198.51.100.65/32]}}}}
list-sas reply {}`
	s := ParseSASRaw(raw)
	if !s.Connected {
		t.Fatalf("expected connected, got %q", s.IKEState)
	}
	if s.Vip != "10.99.99.2" {
		t.Errorf("unexpected vip %q", s.Vip)
	}
	if len(s.Children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(s.Children))
	}
	c1, c2 := s.Children[0], s.Children[1]
	if c1.Name != "corpnet-1" || c1.State != "INSTALLED" || c1.RemoteTS != "172.16.1.0/24" {
		t.Errorf("unexpected child1 %+v", c1)
	}
	if c2.Name != "corpnet-2" || c2.RemoteTS != "198.51.100.65/32" || c2.BytesOut != 504 || c2.PacketsOut != 6 {
		t.Errorf("unexpected child2 %+v", c2)
	}
}

func TestParseSASRawDisconnected(t *testing.T) {
	raw := "list-sa event {}"
	s := ParseSASRaw(raw)
	if s.Connected {
		t.Fatal("expected disconnected")
	}
	if len(s.Children) != 0 {
		t.Fatalf("expected no children, got %d", len(s.Children))
	}
}

func TestParseSASRawReal(t *testing.T) {
	raw := `list-sa event {corpnet {uniqueid=11 version=1 state=ESTABLISHED local-host=192.168.10.3 local-port=4500 local-id=192.168.10.3 remote-host=203.0.113.1 remote-port=4500 remote-id=203.0.113.1 initiator=yes initiator-spi=933b719078372bdd responder-spi=a3e74c0bf5730f6a nat-local=yes nat-any=yes encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 prf-alg=PRF_HMAC_SHA2_256 dh-group=ECP_384 established=3378 reauth-time=39822 local-vips=[10.99.99.2] child-sas {corpnet-1-11 {name=corpnet-1 uniqueid=11 reqid=2 state=INSTALLED mode=TUNNEL protocol=ESP encap=yes spi-in=cdb3a2c5 spi-out=e1a722b0 encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 dh-group=ECP_384 bytes-in=40 packets-in=1 use-in=307 bytes-out=60 packets-out=1 use-out=307 rekey-time=35502 life-time=39822 install-time=3378 local-ts=[10.99.99.2/32] remote-ts=[172.16.1.0/24]} corpnet-2-12 {name=corpnet-2 uniqueid=12 reqid=1 state=INSTALLED mode=TUNNEL protocol=ESP encap=yes spi-in=c3db4c61 spi-out=e1a722b1 encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 dh-group=ECP_384 bytes-in=22629 packets-in=82 use-in=1581 bytes-out=11931 packets-out=93 use-out=1581 rekey-time=35502 life-time=39822 install-time=3378 local-ts=[10.99.99.2/32] remote-ts=[198.51.100.65/32]}}}}
list-sas reply {}`
	s := ParseSASRaw(raw)
	if len(s.Children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(s.Children))
	}
	c1, c2 := s.Children[0], s.Children[1]
	if c1.State != "INSTALLED" || c1.BytesIn != 40 || c1.PacketsIn != 1 || c1.BytesOut != 60 || c1.PacketsOut != 1 {
		t.Errorf("child1 parse falhou: %+v", c1)
	}
	if c2.State != "INSTALLED" || c2.BytesIn != 22629 || c2.PacketsIn != 82 || c2.BytesOut != 11931 || c2.PacketsOut != 93 {
		t.Errorf("child2 parse falhou: %+v", c2)
	}
}
