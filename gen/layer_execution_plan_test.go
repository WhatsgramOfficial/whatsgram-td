package gen

import (
	"bytes"
	"go/format"
	"strings"
	"testing"

	"github.com/iamxvbaba/td/gen/semantic"
)

func TestTLProfileSidecarGeneratedMetadata(t *testing.T) {
	set := layerRPCSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerClientSyntheticPolicy(t, set)})
	if err != nil {
		t.Fatal(err)
	}
	result := sourceSnapshot{}
	if err := generator.WriteTLProfileSource(result, "tlprofile", Template()); err != nil {
		t.Fatal(err)
	}
	source := result["tl_profile_metadata_gen.go"]
	if len(source) == 0 {
		t.Fatal("tlprofile metadata source is absent")
	}
	if _, err := format.Source(source); err != nil {
		t.Fatalf("format tlprofile metadata: %v", err)
	}
	text := string(source)
	for _, want := range []string{"type Profile int", "func ResolveProfile", "type SemanticID uint64", "func WireID", "func SemanticForWireID"} {
		if !strings.Contains(text, want) {
			t.Errorf("tlprofile metadata is missing %q", want)
		}
	}
	if strings.Contains(text, "LayerProfile") || strings.Contains(text, "LayerSemanticID") {
		t.Fatal("tlprofile metadata retained the old dense public API names")
	}
	scanner := string(result["tl_profile_scan_gen.go"])
	for _, want := range []string{"func tlScanExact", "func tlScanDynamic", "func tlScanWire", "remainingElements"} {
		if !strings.Contains(scanner, want) {
			t.Errorf("tlprofile static scanner is missing %q", want)
		}
	}
	for _, forbidden := range []string{"reflect.", "semantic.TypeRef", "map[uint32]", "LayerTypeRef"} {
		if strings.Contains(scanner, forbidden) {
			t.Errorf("tlprofile static scanner contains runtime catalog machinery %q", forbidden)
		}
	}
	routes := string(result["tl_profile_route_gen.go"])
	for _, want := range []string{"func tlLookupRoute", "func tlNewCanonical", "tlRouteDirect", "tlRouteRetag"} {
		if !strings.Contains(routes, want) {
			t.Errorf("tlprofile sparse routes are missing %q", want)
		}
	}
	if strings.Contains(routes, "map[") || strings.Contains(routes, "reflect.") {
		t.Fatal("tlprofile sparse routes contain a runtime registry or reflection")
	}
}

func TestLayerExecutionPlanDeduplicatesRoutesByBehavior(t *testing.T) {
	set := layerRPCSyntheticSchemaSet(t)
	initial, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerRPCSyntheticPolicy(t, set)})
	if err != nil {
		t.Fatal(err)
	}
	if initial.LayerConversionPlan() == nil {
		t.Fatal("initial conversion analysis is absent")
	}
	model, err := generator.buildLayerExecutionModel()
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Routes) == 0 || len(model.PreflightPlans) == 0 || len(model.ResultPlans) == 0 {
		t.Fatalf("incomplete execution model: routes=%d preflight=%d results=%d", len(model.Routes), len(model.PreflightPlans), len(model.ResultPlans))
	}
	for _, route := range model.Routes {
		if route.Mode != layerExecutionDirect && route.BodyPlan < 0 {
			t.Fatalf("non-direct route has no body plan: %+v", route)
		}
		if route.Key.Category == semantic.CategoryFunction && route.PreflightPlan < 0 {
			t.Fatalf("method route has incomplete plans: %+v", route)
		}
		if route.Key.Category == semantic.CategoryFunction && route.Mode != layerExecutionProfileOnly && route.ResultPlan < 0 {
			t.Fatalf("canonical method route has no result plan: %+v", route)
		}
	}
	if len(model.BodyPlans) >= len(model.Routes) {
		t.Fatalf("body plans were not deduplicated: plans=%d routes=%d", len(model.BodyPlans), len(model.Routes))
	}
}

func TestLayerExecutionAuditDeterministic(t *testing.T) {
	set, err := semantic.LoadUniverse("../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadLayerPolicy("../_schema/layers/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	first, err := generator.MarshalLayerExecutionAudit()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generator.MarshalLayerExecutionAudit()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("layer execution audit is not deterministic")
	}
}

func TestLayerExecutionPlanRealSchemaIsSparse(t *testing.T) {
	set, err := semantic.LoadUniverse("../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadLayerPolicy("../_schema/layers/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	model, err := generator.buildLayerExecutionModel()
	if err != nil {
		t.Fatal(err)
	}
	var direct, retag, rewrite, policyCount, profileOnly int
	for _, route := range model.Routes {
		switch route.Mode {
		case layerExecutionDirect:
			direct++
		case layerExecutionRetag:
			retag++
		case layerExecutionRewrite:
			rewrite++
		case layerExecutionPolicy:
			policyCount++
		case layerExecutionProfileOnly:
			profileOnly++
		}
	}
	t.Logf("routes=%d direct=%d retag=%d rewrite=%d policy=%d profile_only=%d body_plans=%d preflight_plans=%d result_plans=%d",
		len(model.Routes), direct, retag, rewrite, policyCount, profileOnly,
		len(model.BodyPlans), len(model.PreflightPlans), len(model.ResultPlans))
	if direct*2 <= len(model.Routes) {
		t.Fatalf("canonical-direct routes are not the majority: direct=%d routes=%d", direct, len(model.Routes))
	}
	if len(model.BodyPlans)*4 >= len(model.Routes) {
		t.Fatalf("sparse body-plan ratio regressed: plans=%d routes=%d", len(model.BodyPlans), len(model.Routes))
	}
	if len(model.BodyPlans) > 800 || len(model.PreflightPlans) > 1000 || len(model.ResultPlans) > 650 {
		t.Fatalf("sparse plan budget regressed: body=%d preflight=%d result=%d", len(model.BodyPlans), len(model.PreflightPlans), len(model.ResultPlans))
	}
}

func TestLayerScanModelRealSchemaStaysCompact(t *testing.T) {
	set, err := semantic.LoadUniverse("../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadLayerPolicy("../_schema/layers/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	model, err := generator.buildLayerScanModel()
	if err != nil {
		t.Fatal(err)
	}
	var wires int
	for _, bucket := range model.WireBuckets {
		wires += len(bucket.Wires)
	}
	t.Logf("static scanner bodies=%d wires=%d classes=%d bare=%d", len(model.Bodies), wires, len(model.Classes), len(model.Bares))
	if wires < 2000 {
		t.Fatalf("scanner wire universe is incomplete: %d", wires)
	}
	if len(model.Bodies) > 1500 {
		t.Fatalf("scanner body deduplication regressed: %d", len(model.Bodies))
	}
}

func TestLayerSparseCodecModelRealSchemaStaysCompact(t *testing.T) {
	set, err := semantic.LoadUniverse("../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadLayerPolicy("../_schema/layers/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	model, err := generator.buildLayerSparseCodecModel("tlprofile")
	if err != nil {
		t.Fatal(err)
	}
	var wires int
	for _, bucket := range model.WireBuckets {
		wires += len(bucket.Wires)
	}
	t.Logf("sparse typed codec wires=%d families=%d classes=%d result_plans=%d",
		wires, len(model.FamilyDeclarations), len(model.ClassDeclarations), len(model.SparseResultPlans))
	if wires > 1500 || len(model.FamilyDeclarations) > 4000 || len(model.ClassDeclarations) > 1000 || len(model.SparseResultPlans) > 350 {
		t.Fatalf("sparse typed codec budget regressed: wires=%d families=%d classes=%d result_plans=%d",
			wires, len(model.FamilyDeclarations), len(model.ClassDeclarations), len(model.SparseResultPlans))
	}
}
