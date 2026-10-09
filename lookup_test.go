package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/saif/spoofer/engine"
)

// Reproduces the production bug: the engine keys its map by hash, not by IP.
func TestLookupWorksAgainstHashKeyedMap(t *testing.T) {
	eng := engine.NewEngine()
	eng.Host = engine.Device{Interface: "enp0s31f6", IP: []byte{192, 168, 1, 19}, Reachable: true}

	const iface = "enp0s31f6"
	// Insert exactly the way engine.Start does: key = sha256(IP+MAC).
	victim := &engine.Device{
		IP:        []byte{192, 168, 1, 77},
		MAC:       []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		Interface: iface,
		Reachable: true,
	}
	eng.InsertDiscovered(victim)

	svc := &DeviceService{Engine: eng}

	// 1. Block must find the device (this is what failed for the user).
	if err := svc.SetBlocked("192.168.1.77", true); err != nil {
		t.Fatalf("SetBlocked: %v", err)
	}
	fw, _ := exec.Command("iptables", "-S", "FORWARD").Output()
	if !strings.Contains(string(fw), "192.168.1.77/32") {
		t.Errorf("no drop rule added:\n%s", fw)
	}

	// 2. Rate limit: type 512 (kb) and it must land as 4096 kbit.
	if err := svc.SetRateLimit("192.168.1.77", 512, 0); err != nil {
		t.Fatalf("SetRateLimit: %v", err)
	}
	if got := eng.DevicesSnapshot()[0].UpRateLimit; got != 4096 {
		t.Errorf("UpRateLimit = %v kbit, want 4096", got)
	}
	out, _ := exec.Command("tc", "class", "show", "dev", iface).Output()
	// tc echoes the unit back uppercased ("4096Kbit"), so match case-insensitively.
	if !strings.Contains(strings.ToLower(string(out)), "rate 4096kbit") {
		t.Errorf("tc class missing 'rate 4096kbit':\n%s", out)
	}

	// 3. Unknown IP still errors clearly.
	if err := svc.SetBlocked("10.9.9.9", true); err == nil {
		t.Error("expected error for unknown IP")
	}

	// teardown
	svc.SetBlocked("192.168.1.77", false)
	svc.SetRateLimit("192.168.1.77", 0, 0)
}
