package gen

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/iamxvbaba/td/gen/semantic"
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
	set, err := semantic.LoadUniverse("../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rpc, err := generator.buildLayerRPCModel()
	if err != nil {
		t.Fatal(err)
	}
	refs, err := generator.buildLayerTypeRefModel()
	if err != nil {
		t.Fatal(err)
	}
	source, err := generator.buildLayerRPCSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}
	uniqueRPCSyntaxBytes := 0
	for _, route := range source.Routes {
		if route.EmitAdmit {
			uniqueRPCSyntaxBytes += len(route.Body)
		}
		if route.EmitProbe {
			uniqueRPCSyntaxBytes += len(route.ProbeBody)
		}
	}

	const maxLayerBytes = 55 << 20
	// Server source is budgeted by unique emitted grammar, not by a fixed cap
	// which an otherwise unchanged future Layer can accidentally cross. The
	// fixed allowance covers runtime/API scaffolding; exact route cases and
	// admission coverage cells are intentionally cheaper than a unique admit
	// body. If the template starts cloning bodies per profile again, source size
	// grows while this budget does not and the test fails.
	serverBudget := int64(2 << 20)
	serverBudget += int64(uniqueRPCSyntaxBytes) * 2
	serverBudget += int64(source.RouteCount) * 128
	serverBudget += int64(len(source.Handlers)) * 1024
	serverBudget += int64(len(source.Profiles)) * int64(len(rpc.AdmissionFields)) * 256
	if layerBytes > maxLayerBytes {
		t.Fatalf("generated layer source = %.2f MiB, budget %.2f MiB", float64(layerBytes)/(1<<20), float64(maxLayerBytes)/(1<<20))
	}
	if server.Size() > serverBudget {
		t.Fatalf("generated RPC server = %.2f MiB, syntax-scaled budget %.2f MiB (exact routes=%d unique admits=%d unique probes=%d syntax=%d bytes)",
			float64(server.Size())/(1<<20), float64(serverBudget)/(1<<20), source.RouteCount, source.UniqueAdmitCount, source.UniqueProbeCount, uniqueRPCSyntaxBytes)
	}
	t.Logf("generated layer source %.2f MiB; RPC server %.2f MiB / %.2f MiB syntax-scaled budget; total %.2f MiB",
		float64(layerBytes)/(1<<20), float64(server.Size())/(1<<20), float64(serverBudget)/(1<<20), float64(layerBytes+server.Size())/(1<<20))
}
