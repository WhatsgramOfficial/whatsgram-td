package gen

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGeneratedLayerSourceBudget keeps future unchanged Layers cheap: profile
// cases should coalesce instead of cloning whole codecs. The thresholds leave
// deliberate headroom for real schema growth while catching accidental
// per-profile body expansion.
func TestGeneratedLayerSourceBudget(t *testing.T) {
	layerFiles, err := filepath.Glob(filepath.Join("..", "tg", "tl_layer*_gen.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(layerFiles) == 0 {
		t.Fatal("no generated multi-layer source files")
	}

	var layerBytes int64
	for _, name := range layerFiles {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		layerBytes += info.Size()
	}
	server, err := os.Stat(filepath.Join("..", "tg", "tl_server_gen.go"))
	if err != nil {
		t.Fatal(err)
	}

	const (
		maxLayerBytes       = 55 << 20
		maxLayerServerBytes = 68 << 20
	)
	if layerBytes > maxLayerBytes {
		t.Fatalf("generated layer source = %.2f MiB, budget %.2f MiB", float64(layerBytes)/(1<<20), float64(maxLayerBytes)/(1<<20))
	}
	if total := layerBytes + server.Size(); total > maxLayerServerBytes {
		t.Fatalf("generated layer+RPC source = %.2f MiB, budget %.2f MiB", float64(total)/(1<<20), float64(maxLayerServerBytes)/(1<<20))
	}
	t.Logf("generated layer source %.2f MiB; with exact RPC server %.2f MiB", float64(layerBytes)/(1<<20), float64(layerBytes+server.Size())/(1<<20))
}
