package gen

import (
	"testing"

	"github.com/iamxvbaba/td/gen/semantic"
)

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
}
