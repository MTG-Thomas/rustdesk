//go:build windows

package artifact

import (
	"os"
	"testing"
)

func TestWindowsTrustOnPinnedSignedBaseline(t *testing.T) {
	path := os.Getenv("BIFROST_QS_TEST_SIGNED_ARTIFACT")
	if path == "" {
		t.Skip("requires the pinned signed artifact supplied by Windows CI")
	}
	publisher := "4230334F8A7DD84E50D0273EF379E8B4A82F5DA5"
	if err := VerifyWindowsAuthenticode(t.Context(), path, publisher); err != nil {
		t.Fatalf("Windows rejected the pinned signed baseline: %v", err)
	}
	if err := VerifyWindowsAuthenticode(t.Context(), path, "0000000000000000000000000000000000000000"); err == nil {
		t.Fatal("Windows accepted an unexpected publisher")
	}
}
