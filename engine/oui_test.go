package engine

import (
	"os"
	"testing"
)

// A real OUI must resolve, proving ouiFilePath() finds the dataset without the
// old hardcoded /home/saif path. The dataset is not beside the test binary, so
// point FMMON_OUI_FILE at it the way an install would.
func TestOuiFileResolves(t *testing.T) {
	if _, err := os.Stat("../data/ieee-oui.txt"); err != nil {
		t.Skip("no OUI dataset in the source tree")
	}
	t.Setenv("FMMON_OUI_FILE", "../data/ieee-oui.txt")

	if p := ouiFilePath(); p == "" {
		t.Fatal("ouiFilePath() found nothing")
	} else {
		t.Logf("resolved: %s", p)
	}
	// 14:89:cb is a common gateway OUI.
	if got := getVendor([]byte{0x14, 0x89, 0xcb, 0x70, 0xde, 0xf9}); got == "" || got == "Unknown" {
		t.Errorf("expected a vendor for 14:89:cb, got %q", got)
	} else {
		t.Logf("14:89:cb -> %q", got)
	}
}
