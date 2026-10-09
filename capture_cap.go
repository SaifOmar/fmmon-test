package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// grantCapHelper is the root-owned program polkit authorises. It is the only
// privileged thing in the picture: polkit authenticates the helper, never this
// binary, because running the GUI as root cannot reach a Wayland session.
const grantCapHelper = "/usr/local/bin/fmmon-grant-cap"

// capNetRawMask is bit 13 (CAP_NET_RAW) as it appears in /proc/self/status.
const capNetRawMask = uint64(1) << 13

// captureEnvMarker stops the grant-then-re-exec step from recursing. Without it
// a failed grant would spawn the app, which would try to grant again, forever.
const captureEnvMarker = "FMMON_CAP_REQUESTED"

// hasCapNetRaw reports whether this process already holds CAP_NET_RAW in its
// effective set, read from /proc/self/status.
func hasCapNetRaw() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "CapEff:" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return false
		}
		return value&capNetRawMask != 0
	}
	return false
}

// ensureCaptureCapability makes sure the running binary can open a packet
// socket, asking polkit for it the first time and re-executing so the new
// capability is picked up. It returns an error describing what to do manually
// when the automatic route is unavailable.
func ensureCaptureCapability() error {
	if hasCapNetRaw() {
		return nil
	}
	if os.Getenv(captureEnvMarker) != "" {
		return fmt.Errorf("packet capture still not permitted after granting; check "+
			"'getcap %s' and that the filesystem supports capabilities (xattr)", os.Args[0])
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating own binary: %w", err)
	}

	log.Printf("packet capture needs CAP_NET_RAW; requesting it via polkit")
	pkexec := exec.Command("pkexec", grantCapHelper, self)
	pkexec.Stdout = os.Stderr
	pkexec.Stderr = os.Stderr
	if err := pkexec.Run(); err != nil {
		return fmt.Errorf("%w\n\nautomatic grant failed. Run this once, then start fmmon again:\n"+
			"  sudo setcap cap_net_raw=+ep %s", err, self)
	}

	// setcap changed the file behind us; the kernel applies capabilities at
	// execve, so only a fresh exec picks them up. Carry a marker so a grant that
	// silently did not take effect fails once instead of looping forever.
	env := append(os.Environ(), captureEnvMarker+"=1")
	if err := syscall.Exec(self, os.Args, env); err != nil {
		return fmt.Errorf("re-executing with new capability: %w", err)
	}
	return nil
}
