package semantic

import "testing"

func TestRealClientRPCOverlayIsProvenanceLockedAndCanonicalBound(t *testing.T) {
	universe, err := LoadUniverse("../../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(universe.ClientRPCOverlays), 2; got != want {
		t.Fatalf("client RPC overlay count = %d, want %d", got, want)
	}
	var overlay *ClientRPCOverlay
	for _, candidate := range universe.ClientRPCOverlays {
		if candidate.Name == "drklo_android" {
			overlay = candidate
		}
	}
	if overlay == nil {
		t.Fatal("DrKLO core overlay is absent")
	}
	if overlay.Name != "drklo_android" || overlay.Repository == "" || overlay.Commit == "" || len(overlay.Sources) != 4 {
		t.Fatalf("unexpected DrKLO provenance: %+v", overlay)
	}
	if got, want := len(overlay.Methods), 15; got != want {
		t.Fatalf("DrKLO method count = %d, want %d", got, want)
	}
	seenWire := make(map[uint32]struct{}, len(overlay.Methods))
	canonical := universe.Schemas[universe.CanonicalLayer]
	for _, method := range overlay.Methods {
		if method == nil || method.Definition == nil {
			t.Fatal("nil client RPC method")
		}
		if _, duplicate := seenWire[method.Definition.WireID]; duplicate {
			t.Fatalf("duplicate private wire ID %#08x", method.Definition.WireID)
		}
		seenWire[method.Definition.WireID] = struct{}{}
		target := canonical.ByKey[method.Target]
		if target == nil {
			t.Fatalf("private method %s targets missing canonical method %s", method.Definition.Key, method.Target)
		}
		if !method.Definition.Result.Equal(target.Result) {
			t.Fatalf("private method %s result differs from canonical target", method.Definition.Key)
		}
	}
}
