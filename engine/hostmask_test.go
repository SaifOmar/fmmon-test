package engine

import "testing"

// The interface carries both an IPv4 /24 and an IPv6 /64. getHost must keep the
// IPv4 mask; taking the IPv6 one made the subnet walk index past a 4-byte IP.
func TestGetHostKeepsIPv4Mask(t *testing.T) {
	h := getHost()
	if !h.Reachable {
		t.Skip("no active interface in this environment")
	}
	if got := len(h.Mask.Mask); got != 4 {
		t.Errorf("mask is %d bytes, want 4 (IPv4): %v", got, h.Mask.Mask)
	}
	if got := len(h.IP); got != 4 {
		t.Errorf("IP is %d bytes, want 4: %v", got, h.IP)
	}
	t.Logf("host=%s ip=%v mask=%v iface=%s", h.Name, h.IP, h.Mask.Mask, h.Interface)
}

// getVendor must not panic on a short/odd MAC and must resolve the OUI file
// without a hardcoded home directory.
func TestGetVendorNoPanic(t *testing.T) {
	for _, mac := range [][]byte{nil, {}, {0xaa}, {0xaa, 0xbb, 0xcc}} {
		if got := getVendor(mac); got == "" {
			t.Errorf("getVendor(%v) returned empty", mac)
		} else {
			t.Logf("getVendor(%v) = %q", mac, got)
		}
	}
}
