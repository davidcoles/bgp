package bgp

import (
	"net/netip"
	"testing"
)

var ipv4_0, ipv4_1, ipv6_0, ipv6_1 netip.Addr

func init() {
	ipv4_0 = netip.MustParseAddr("192.168.101.0")
	ipv4_1 = netip.MustParseAddr("192.168.101.1")
	ipv6_0 = netip.MustParseAddr("fd0b:2b0b:a7b8::0")
	ipv6_1 = netip.MustParseAddr("fd0b:2b0b:a7b8::1")
}

func byteSliceEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}

	return true
}

func addrSliceEqual(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}

	return true
}

func TestASPath(t *testing.T) {

	if !byteSliceEqual(asPath(65000, false), []byte{0x40, 2, 0}) {
		t.Fatalf("AS_PATH for iBGP")
	}

	if !byteSliceEqual(asPath(65000, true), []byte{0x40, 2, 4, 2, 1, 253, 232}) {
		t.Fatalf("AS_PATH for eBGP ASN 65000")
	}

	if !byteSliceEqual(asPath(12345, true), []byte{0x40, 2, 4, 2, 1, 48, 57}) {
		t.Fatalf("AS_PATH for eBGP ASN 12345")
	}
}

func TestLocalPref(t *testing.T) {
	if !byteSliceEqual(localPref(100), []byte{0x40, 5, 4, 0, 0, 0, 100}) {
		t.Fatalf("LOCAL_PREF 100")
	}

	if !byteSliceEqual(localPref(123456789), []byte{0x40, 5, 4, 7, 91, 205, 21}) {
		t.Fatalf("LOCAL_PREF 12345678")
	}
}

func TestNLRI(t *testing.T) {

	rib := map[netip.Addr]bool{
		ipv4_0: true,
		ipv6_0: true,
		ipv4_1: false,
		ipv6_1: false,
	}

	advertise, withdrawn := sortAdvertiseWithdrawn(rib)

	if !addrSliceEqual(advertise, []netip.Addr{ipv4_0, ipv6_0}) {
		t.Fatalf("Advertised list incorrect")
	}

	if !addrSliceEqual(withdrawn, []netip.Addr{ipv4_1, ipv6_1}) {
		t.Fatalf("Withdrawn list incorrect")
	}

	ipv6 := []byte{
		128, 0xfd, 0x0b, 0x2b, 0x0b, 0xa7, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ::1 1st
		128, 0xfd, 0x0b, 0x2b, 0x0b, 0xa7, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // ::0 2nd
	}

	ipv4 := []byte{
		32, 192, 168, 101, 0,
		32, 192, 168, 101, 1,
	}

	v4, v6 := nlriByVersion([]netip.Addr{ipv4_0, ipv4_1, ipv6_1, ipv6_0}) // note IPv6 ordering

	if !byteSliceEqual(v4, ipv4) {
		t.Fatalf("IPv4 NLRI incorrect")
	}

	if !byteSliceEqual(v6, ipv6) {
		t.Fatalf("IPv6 NLRI incorrect")
	}
}

func TestUpdateMessage(t *testing.T) {

	rib := map[netip.Addr]bool{
		ipv4_0: true,
		ipv4_1: false,
		//ipv6_0: true,
		//ipv6_1: false,
	}

	// +-----------------------------------------------------+
	// |   Withdrawn Routes Length (2 octets)                |
	// +-----------------------------------------------------+
	// |   Withdrawn Routes (variable)                       |
	// +-----------------------------------------------------+
	// |   Total Path Attribute Length (2 octets)            |
	// +-----------------------------------------------------+
	// |   Path Attributes (variable)                        |
	// +-----------------------------------------------------+
	// |   Network Layer Reachability Information (variable) |
	// +-----------------------------------------------------+

	internal := []byte{
		0, 5, // withdrawn routes - 5 bytes
		32, 192, 168, 101, 1, // Withdrawn 192.168.101.0/32
		0, 21, // 21 octets of attributes
		0x40, 1, 1, 0, // ORIGIN IGP
		0x40, 2, 0, // AS_PATH for iBGP
		0x40, 3, 4, 10, 1, 2, 3, // NEXT_HOP 10.1.2.3
		0x40, 5, 4, 7, 91, 205, 21, // LOCAL_PREF 123456789
		32, 192, 168, 101, 0, // NLRI for 192.168.101.0/32
	}

	external := []byte{
		0, 5, // withdrawn routes - 5 bytes
		32, 192, 168, 101, 1, // Withdrawn 192.168.101.0/32
		0, 18, // 18 octets of attributes
		0x40, 1, 1, 0, // ORIGIN IGP
		0x40, 2, 4, 2, 1, 253, 232, // AS_PATH for eBGP, ASN 65000
		0x40, 3, 4, 10, 1, 2, 3, // NEXT_HOP 10.1.2.3
		32, 192, 168, 101, 0, // NLRI for 192.168.101.0/32
	}

	a := advert{
		ASNumber:     65000,
		NextHop:      [4]byte{10, 1, 2, 3},
		localpref:    123456789,
		PeerASNumber: 65000,
	}

	update := a.message(rib)

	if !byteSliceEqual(update, internal) {
		t.Fatalf("iBGP UPDATE message incorrect: %v", update)
	}

	a.PeerASNumber = 65001

	update = a.message(rib)

	if !byteSliceEqual(a.message(rib), external) {
		t.Fatalf("eBGP UPDATE message incorrect: %v", update)
	}
}
