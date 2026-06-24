package proxy

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestCertManager_RegeneratesExpiredCachedCert(t *testing.T) {
	cm, err := NewCertManager(t.TempDir(), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	// Seed the cache with a cert that has already expired.
	expired, err := GenerateLeafCert(cm.ca, cm.caParsed, cm.serverKey, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	expired.Leaf.NotAfter = time.Now().Add(-time.Hour)
	cm.certCache["example.com"] = expired

	got, err := cm.GetOrCreate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got == expired {
		t.Error("GetOrCreate returned the expired cached certificate")
	}
	if !time.Now().Before(got.Leaf.NotAfter) {
		t.Error("regenerated certificate is already expired")
	}

	// A valid cached cert must still be a cache hit (no needless regeneration).
	again, _ := cm.GetOrCreate("example.com")
	if again != got {
		t.Error("expected a cache hit to return the same valid cert")
	}
}
