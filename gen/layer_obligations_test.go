package gen

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/gotd/td/gen/semantic"
	"github.com/gotd/tl"
)

const obligationProfileOne = `
---types---
oldResult#10000001 = OldResult;
oldOnly#10000002 = OldOnly;
shape#10000003 flags:# renamed_old:flags.0?int required_old:long incompatible:string = Shape;
atomic#10000004 flags:# first:flags.0?int second:flags.0?int = Atomic;
---functions---
getShape#10000005 = OldResult;
// LAYER 1
`

const obligationCanonicalTwo = `
---types---
newResult#20000001 = NewResult;
newOnly#20000002 = NewOnly;
updateModern#20000003 pts:int = Update;
shape#20000004 flags:# renamed_new:flags.0?int required_new:bytes incompatible:int = Shape;
atomic#20000005 flags:# first:flags.0?int second:flags.1?int = Atomic;
---functions---
getShape#20000006 = NewResult;
// LAYER 2
`

func TestAnalyzeLayerObligationsClassifiesSyntheticChanges(t *testing.T) {
	schemaSet := obligationSchemaSet(t)
	first, err := AnalyzeLayerObligations(schemaSet, LayerObligationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := AnalyzeLayerObligations(schemaSet, LayerObligationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("obligation report is not deterministic")
	}

	kinds := make(map[LayerObligationKind]int)
	keys := make(map[LayerObligationKey]struct{})
	for _, obligation := range first.Obligations {
		kinds[obligation.Kind]++
		if obligation.Key == "" || !strings.HasPrefix(string(obligation.Key), "layer-obligation/v1/") {
			t.Fatalf("invalid stable key %q", obligation.Key)
		}
		if _, duplicate := keys[obligation.Key]; duplicate {
			t.Fatalf("duplicate obligation key %q", obligation.Key)
		}
		keys[obligation.Key] = struct{}{}
	}
	for _, kind := range []LayerObligationKind{
		LayerObligationAlias,
		LayerObligationRequired,
		LayerObligationIncompatible,
		LayerObligationResult,
		LayerObligationOldOnly,
		LayerObligationNewOnly,
		LayerObligationAtomicFlagGroup,
		LayerObligationUpdateProjection,
		LayerObligationPrivate,
	} {
		if kinds[kind] == 0 {
			t.Errorf("missing %q obligation; counts=%v", kind, kinds)
		}
	}

	alias := findObligation(t, first, LayerObligationAlias, "shape")
	if alias.Field != "renamed_new" || alias.OtherField != "renamed_old" || alias.Direction != LayerDirectionBoth {
		t.Fatalf("alias obligation = %+v", alias)
	}
	projection := findObligation(t, first, LayerObligationUpdateProjection, "updateModern")
	if projection.Direction != LayerDirectionCanonicalToProfile {
		t.Fatalf("update projection = %+v", projection)
	}
}

func TestLayerObligationPolicyMatchesExactKeyAndRejectsStale(t *testing.T) {
	schemaSet := obligationSchemaSet(t)
	report, err := AnalyzeLayerObligations(schemaSet, LayerObligationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	alias := findObligation(t, report, LayerObligationAlias, "shape")
	initialUnresolved := len(report.Unresolved())
	entry := LayerObligationPolicyEntry{Key: alias.Key, Resolution: LayerObligationResolution{
		Action: LayerResolveAlias,
		Hook:   "AliasShapeField",
	}}
	resolved, err := AnalyzeLayerObligations(schemaSet, LayerObligationPolicy{Entries: []LayerObligationPolicyEntry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(resolved.Unresolved()), initialUnresolved-1; got != want {
		t.Fatalf("unresolved = %d, want %d", got, want)
	}
	var gotResolution LayerObligationResolution
	for _, obligation := range resolved.Obligations {
		if obligation.Key == entry.Key {
			gotResolution = obligation.Resolution
		}
	}
	if gotResolution != entry.Resolution {
		t.Fatalf("resolution = %+v, want %+v", gotResolution, entry.Resolution)
	}

	_, err = AnalyzeLayerObligations(schemaSet, LayerObligationPolicy{Entries: []LayerObligationPolicyEntry{{
		Key:        "layer-obligation/v1/required/stale",
		Resolution: LayerObligationResolution{Action: LayerResolveAdapter, Hook: "RequiredField"},
	}}})
	if err == nil || !strings.Contains(err.Error(), "E_STALE_LAYER_POLICY") {
		t.Fatalf("stale policy error = %v", err)
	}

	_, err = AnalyzeLayerObligations(schemaSet, LayerObligationPolicy{Entries: []LayerObligationPolicyEntry{entry, entry}})
	if err == nil || !strings.Contains(err.Error(), "E_DUPLICATE_LAYER_POLICY") {
		t.Fatalf("duplicate policy error = %v", err)
	}

	_, err = AnalyzeLayerObligations(schemaSet, LayerObligationPolicy{Entries: []LayerObligationPolicyEntry{{
		Key: alias.Key,
		Resolution: LayerObligationResolution{
			Action: LayerResolveDrop,
			Note:   "free-form text must not resolve an alias",
		},
	}}})
	if err == nil || !strings.Contains(err.Error(), "E_INVALID_LAYER_POLICY") {
		t.Fatalf("invalid action error = %v", err)
	}

	modifiedCanonical := strings.Replace(
		obligationCanonicalTwo,
		"required_new:bytes incompatible:int = Shape;",
		"required_new:bytes incompatible:int modern:flags.2?true = Shape;",
		1,
	)
	modified := obligationSchemaSetWithCanonical(t, modifiedCanonical)
	_, err = AnalyzeLayerObligations(modified, LayerObligationPolicy{Entries: []LayerObligationPolicyEntry{entry}})
	if err == nil || !strings.Contains(err.Error(), "E_STALE_LAYER_POLICY") {
		t.Fatalf("shape-stale policy error = %v", err)
	}
}

func TestGeneratorLayerObligationsRequiresSchemaSet(t *testing.T) {
	parsed, err := tl.Parse(bytes.NewBufferString(obligationCanonicalTwo))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := NewGenerator(parsed, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.LayerObligations(LayerObligationPolicy{}); err == nil {
		t.Fatal("single-schema generator unexpectedly analyzed layer obligations")
	}
}

func TestTelegramLayerObligationReport(t *testing.T) {
	schemaSet, err := semantic.LoadUniverse("../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeLayerObligations(schemaSet, LayerObligationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[LayerObligationKind]int)
	for _, obligation := range report.Obligations {
		counts[obligation.Kind]++
	}
	if counts[LayerObligationPrivate] != 0 {
		t.Fatalf("official profiles produced private obligations: %v", counts)
	}
	t.Logf("Telegram Layers 220-227 obligations: total=%d by_kind=%v", len(report.Obligations), counts)
}

func obligationSchemaSet(t *testing.T) *SchemaSet {
	return obligationSchemaSetWithCanonical(t, obligationCanonicalTwo)
}

func obligationSchemaSetWithCanonical(t *testing.T, canonicalSource string) *SchemaSet {
	t.Helper()
	profile := parseObligationProfile(t, obligationProfileOne, semantic.SourceRef{
		Layer:      1,
		Repository: "https://example.invalid/private.git",
		Path:       "api.tl",
	})
	canonical := parseObligationProfile(t, canonicalSource, semantic.SourceRef{
		Layer:      2,
		Repository: "https://example.invalid/official.git",
		Path:       "api.tl",
	})
	schemaSet, err := NewSchemaSet(2, profile, canonical)
	if err != nil {
		t.Fatal(err)
	}
	return schemaSet
}

func parseObligationProfile(t *testing.T, source string, ref semantic.SourceRef) *SchemaProfile {
	t.Helper()
	parsed, err := tl.Parse(bytes.NewBufferString(source))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := semantic.BuildSchema(parsed, ref)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func findObligation(t *testing.T, report LayerObligationReport, kind LayerObligationKind, qname string) LayerObligation {
	t.Helper()
	for _, obligation := range report.Obligations {
		if obligation.Kind == kind && obligation.Semantic.QName == qname {
			return obligation
		}
	}
	t.Fatalf("missing %s obligation for %s", kind, qname)
	return LayerObligation{}
}
