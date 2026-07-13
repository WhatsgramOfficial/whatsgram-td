package gen

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gotd/tl"

	"github.com/gotd/td/gen/semantic"
)

func TestLayerCodecModelUniqueWireAndStaticBodies(t *testing.T) {
	set := buildLayerStaticSyntheticUniverse(t)
	generator := newLayerCodecTestGenerator(t, set)
	model, err := generator.buildLayerCodecModel("fixture")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(model.Wires), len(set.WireCodecs); got != want {
		t.Fatalf("wire codecs = %d, want %d", got, want)
	}
	if got, want := len(model.WireBuckets), 64; got != want {
		t.Fatalf("wire buckets = %d, want %d", got, want)
	}
	seen := make(map[uint32]struct{}, len(model.Wires))
	for _, wire := range model.Wires {
		if _, duplicate := seen[wire.WireID]; duplicate {
			t.Fatalf("wire %#08x was emitted more than once", wire.WireID)
		}
		seen[wire.WireID] = struct{}{}
		if !wire.ProfileOnly && (wire.CanonicalType == "" || wire.EncodeBareName == "" || wire.DecodeBareName == "") {
			t.Fatalf("incomplete canonical wire model: %+v", wire)
		}
	}
	leaf := findLayerCodecWire(t, model, 0x10000031)
	if got, want := len(leaf.Profiles), 3; got != want {
		t.Fatalf("same-CRC leaf profiles = %d, want %d", got, want)
	}
	if !strings.Contains(leaf.Profiles[0].Encode, "var wireFlags0 bin.Fields") ||
		!strings.Contains(leaf.Profiles[0].Encode, ".Has(0)") {
		t.Fatalf("target flags were not rebuilt from canonical presence:\n%s", leaf.Profiles[0].Encode)
	}
	if !strings.Contains(leaf.Profiles[0].Preflight, "value.Flags.Has(1)") ||
		!strings.Contains(leaf.Profiles[0].Preflight, "field projection rejected by policy") {
		t.Fatalf("reject-if-present field projection was not emitted as a runtime presence gate:\n%s", leaf.Profiles[0].Preflight)
	}
	canonicalLeaf := leaf.Profiles[len(leaf.Profiles)-1]
	if canonicalLeaf.Layer != 3 || canonicalLeaf.Encode != "return value.EncodeBare(b)\n" ||
		!strings.Contains(canonicalLeaf.Decode, "value.DecodeBare(b)") {
		t.Fatalf("primitive-only canonical profile did not use the bounded-safe canonical fast path: %+v", canonicalLeaf)
	}
	holder := findLayerCodecWire(t, model, 0x10000033)
	if !strings.Contains(holder.Profiles[0].Encode, "layerEncodeWire10000031BareBody") ||
		!strings.Contains(holder.Profiles[0].Decode, "layerDecodeWire10000031") {
		t.Fatalf("nested constructor did not use static target wire calls:\nencode:\n%s\ndecode:\n%s", holder.Profiles[0].Encode, holder.Profiles[0].Decode)
	}
	if !strings.Contains(holder.Profiles[0].Preflight, "layerPreflightWire10000031Bare") ||
		!strings.Contains(holder.Profiles[0].Preflight, "== 0 { return 0, nil }") ||
		!strings.Contains(holder.Profiles[0].Preflight, "return 1, nil") {
		t.Fatalf("required nested projection cardinality does not propagate through its parent:\n%s", holder.Profiles[0].Preflight)
	}
	vector := findLayerCodecWire(t, model, 0x10000035)
	if !strings.Contains(vector.Profiles[0].Encode, "layerCodecMaxVectorElements") ||
		!strings.Contains(vector.Profiles[0].Encode, "PutVectorHeader(0)") ||
		!strings.Contains(vector.Profiles[0].Encode, "IsLayerProjectionDrop") ||
		!strings.Contains(vector.Profiles[0].Encode, "Buf[layerCountOffset") ||
		!strings.Contains(vector.Profiles[0].Decode, "layerCodecDescend(profile, \"decode\"") ||
		!strings.Contains(vector.Profiles[0].Decode, "layerDecodeVectorLength(profile, nil") {
		t.Fatalf("vector codec lacks bounded static path:\nencode:\n%s\ndecode:\n%s", vector.Profiles[0].Encode, vector.Profiles[0].Decode)
	}
	decodeLength := strings.Index(vector.Profiles[0].Decode, "layerDecodeVectorLength")
	decodeMake := strings.Index(vector.Profiles[0].Decode, "make(")
	if decodeLength < 0 || decodeMake < 0 || decodeLength > decodeMake {
		t.Fatalf("vector allocation precedes shared budget admission:\n%s", vector.Profiles[0].Decode)
	}
	if model.MaxWireBytes != layerCodecMaximumWireBytes ||
		model.MaxAggregateElements != layerCodecMaximumAggregateElements ||
		model.DefaultWireBytes != layerCodecDefaultWireBytes ||
		model.DefaultDepth != layerCodecDefaultDepth ||
		model.DefaultVectorSize != layerCodecDefaultVectorSize ||
		model.DefaultAggregateElements != layerCodecDefaultAggregateElements {
		t.Fatalf("decode budget model is incomplete: %+v", model)
	}
}

func TestLayerCodecProjectionPresenceAndMalformedFlags(t *testing.T) {
	required := &layerFieldBinding{
		Semantic: &semantic.FieldShape{Name: "required"},
		Go:       &fieldDef{Name: "Required", Type: "int"},
	}
	presence, err := layerCodecProjectionPresenceExpression(required, "value.Required")
	if err != nil {
		t.Fatal(err)
	}
	if presence != "true" {
		t.Fatalf("required source-only field presence = %q, want true", presence)
	}
	for _, test := range []struct {
		name       string
		goField    fieldDef
		expression string
		want       string
	}{
		{name: "present empty slice", goField: fieldDef{Name: "Items", Type: "int", Slice: true, ConditionalField: "Flags"}, expression: "value.Items", want: "(value.Flags.Has(2) || value.Items != nil)"},
		{name: "zero constructor class", goField: fieldDef{Name: "Query", Type: "QueryClass", Interface: "QueryClass", ConditionalField: "Flags"}, expression: "value.Query", want: "(value.Flags.Has(2) || value.Query != nil)"},
		{name: "int128", goField: fieldDef{Name: "Key", Type: "bin.Int128", ConditionalField: "Flags"}, expression: "value.Key", want: "(value.Flags.Has(2) || value.Key != (bin.Int128{}))"},
		{name: "int256", goField: fieldDef{Name: "Key", Type: "bin.Int256", ConditionalField: "Flags"}, expression: "value.Key", want: "(value.Flags.Has(2) || value.Key != (bin.Int256{}))"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := &layerFieldBinding{
				Semantic: &semantic.FieldShape{Name: "conditional", Condition: &semantic.Condition{Word: "flags", Bit: 2}},
				Go:       &test.goField,
			}
			got, err := layerCodecPresenceExpression(binding, test.expression)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("presence = %q, want %q", got, test.want)
			}
		})
	}

	conditional := layerFieldBinding{
		Semantic: &semantic.FieldShape{
			Name:      "query",
			Condition: &semantic.Condition{Word: "flags", Bit: 3},
		},
		Go: &fieldDef{
			Name:             "Query",
			Type:             "bin.Object",
			Interface:        "bin.Object",
			ConditionalField: "Flags",
		},
	}
	emitter := &layerCodecEmitter{}
	check := emitter.emitMalformedConditionalChecks(&layerDefinitionBinding{
		Key:    semantic.SemanticKey{Category: semantic.CategoryType, QName: "fixture"},
		Fields: []layerFieldBinding{conditional},
	}, true)
	if !strings.Contains(check, "value.Flags.Has(3) && value.Query == nil") ||
		!strings.Contains(check, "malformed canonical value") {
		t.Fatalf("explicit flag + nil interface check was not emitted:\n%s", check)
	}
	encodeCheck := emitter.emitMalformedConditionalChecks(&layerDefinitionBinding{
		Key:    semantic.SemanticKey{Category: semantic.CategoryType, QName: "fixture"},
		Fields: []layerFieldBinding{conditional},
	}, false)
	if !strings.Contains(encodeCheck, `return &LayerCodecError{Operation: "encode"`) {
		t.Fatalf("production encode malformed check was not emitted:\n%s", encodeCheck)
	}
}

func TestLayerCodecTemplateSyntheticPackageCompiles(t *testing.T) {
	set := buildLayerStaticSyntheticUniverse(t)
	generator := newLayerCodecTestGenerator(t, set)
	model, err := generator.buildLayerCodecModel("fixture")
	if err != nil {
		t.Fatal(err)
	}

	sources := sourceSnapshot{}
	if err := generator.WriteSource(sources, "fixture", Template()); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"tl_layer_typeref_gen.go", "tl_layer_codec_runtime_gen.go", "tl_layer_codec_families_gen.go"} {
		if _, ok := sources[required]; !ok {
			t.Fatalf("WriteSource did not emit %s", required)
		}
	}
	for _, bucket := range model.WireBuckets {
		if len(bucket.Wires) == 0 {
			continue
		}
		name := fmt.Sprintf("tl_layer_codec_wire_%02d_gen.go", bucket.Index)
		if _, ok := sources[name]; !ok {
			t.Fatalf("WriteSource did not emit stable wire bucket %s", name)
		}
	}
	runLayerGeneratedPackage(t, sources)
}

func TestLayerCodecGeneratedDecodeBudgetIsSharedBeforeAllocation(t *testing.T) {
	const layerOne = `
---types---
budgetEnvelope#51000001 first:Vector<int> second:Vector<int> nested:Vector<Vector<int>> = BudgetEnvelope;
// LAYER 1
`
	layerTwo := strings.Replace(layerOne, "LAYER 1", "LAYER 2", 1)
	set := buildLayerStaticSyntheticUniverseFrom(t, 2, layerOne, layerTwo)
	generator := newLayerCodecTestGenerator(t, set)
	sources := sourceSnapshot{}
	if err := generator.WriteSource(sources, "fixture", Template()); err != nil {
		t.Fatal(err)
	}
	sources["layer_decode_budget_test.go"] = []byte(`package fixture

import (
	"errors"
	"strings"
	"testing"

	"github.com/gotd/td/bin"
)

func putBudgetIntVector(b *bin.Buffer, values ...int) {
	b.PutVectorHeader(len(values))
	for _, value := range values { b.PutInt(value) }
}

func requireBudgetCodecError(t *testing.T, err error, reason string) *LayerCodecError {
	t.Helper()
	if err == nil { t.Fatal("decode unexpectedly succeeded") }
	var typed *LayerCodecError
	if !errors.As(err, &typed) { t.Fatalf("decode error %T is not LayerCodecError: %v", err, err) }
	if reason != "" && !strings.Contains(typed.Reason, reason) { t.Fatalf("decode reason %q does not contain %q", typed.Reason, reason) }
	return typed
}

func TestGeneratedSiblingVectorsShareAggregateBudget(t *testing.T) {
	wire := &bin.Buffer{}
	wire.PutID(0x51000001)
	putBudgetIntVector(wire, 1, 2, 3)
	putBudgetIntVector(wire, 4, 5, 6)
	putBudgetIntVector(wire)
	state, err := newLayerCodecDecodeState(LayerProfile1, wire.Len(), layerCodecDecodeLimits{
		maxWireBytes: 1024, maxVectorElements: 8, maxAggregateElements: 5, maxDepth: 8,
	})
	if err != nil { t.Fatal(err) }
	input := &bin.Buffer{Buf: append([]byte(nil), wire.Buf...)}
	_, err = layerDecodeWire51000001(LayerProfile1, input, state)
	requireBudgetCodecError(t, err, "remaining aggregate element budget")
	// The second vector header is consumed, but none of its elements and no
	// later field are decoded. In particular, rejection precedes make/append.
	if input.Len() != 20 { t.Fatalf("bytes remaining after aggregate rejection = %d, want 20", input.Len()) }
}

func TestGeneratedVectorLimitsAreTypedAndPreallocationSafe(t *testing.T) {
	for _, test := range []struct {
		name string
		count int
		limits layerCodecDecodeLimits
		reason string
	}{
		{name: "configured", count: 17, limits: layerCodecDecodeLimits{maxVectorElements: 16, maxAggregateElements: 32}, reason: "configured limit"},
		{name: "hard", count: layerCodecMaxVectorElements + 1, limits: layerCodecDecodeLimits{maxVectorElements: layerCodecMaxVectorElements + 99, maxAggregateElements: layerCodecMaxAggregateElements}, reason: "hard limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := &bin.Buffer{}
			wire.PutID(0x51000001)
			wire.PutVectorHeader(test.count)
			state, err := newLayerCodecDecodeState(LayerProfile1, wire.Len(), test.limits)
			if err != nil { t.Fatal(err) }
			input := &bin.Buffer{Buf: append([]byte(nil), wire.Buf...)}
			_, err = layerDecodeWire51000001(LayerProfile1, input, state)
			requireBudgetCodecError(t, err, test.reason)
			if input.Len() != 0 { t.Fatalf("header-only rejection left %d bytes", input.Len()) }
		})
	}

	negative := &bin.Buffer{}
	negative.PutInt(-1)
	state := layerCodecState{}
	_, err := layerDecodeVectorLength(LayerProfile1, nil, negative, false, &state)
	requireBudgetCodecError(t, err, "negative vector length")

	zeroDefault := &bin.Buffer{}
	zeroDefault.PutVectorHeader(layerCodecDefaultVectorElements + 1)
	state = layerCodecState{}
	_, err = layerDecodeVectorLength(LayerProfile1, nil, zeroDefault, true, &state)
	requireBudgetCodecError(t, err, "configured limit")

	_, err = newLayerCodecDecodeState(LayerProfile1, layerCodecMaxWireBytes+1, layerCodecDecodeLimits{})
	requireBudgetCodecError(t, err, "wire byte length")
}

func TestGeneratedNestedVectorUsesConfiguredDepth(t *testing.T) {
	wire := &bin.Buffer{}
	wire.PutID(0x51000001)
	putBudgetIntVector(wire)
	putBudgetIntVector(wire)
	wire.PutVectorHeader(1)
	putBudgetIntVector(wire)
	state, err := newLayerCodecDecodeState(LayerProfile1, wire.Len(), layerCodecDecodeLimits{
		maxWireBytes: 1024, maxVectorElements: 8, maxAggregateElements: 8, maxDepth: 2,
	})
	if err != nil { t.Fatal(err) }
	input := &bin.Buffer{Buf: append([]byte(nil), wire.Buf...)}
	_, err = layerDecodeWire51000001(LayerProfile1, input, state)
	requireBudgetCodecError(t, err, "maximum decode depth")
	// The nested vector header remains unread: depth is checked before its
	// length is trusted and before a result slice can be allocated.
	if input.Len() != 8 { t.Fatalf("bytes remaining after depth rejection = %d, want 8", input.Len()) }
}
`)
	runLayerGeneratedPackage(t, sources)
}

func TestLayerCodecHistoricalTypeClassAndObjectRoundTrip(t *testing.T) {
	set := buildLayerCodecHistoricalTypeUniverse(t)
	initial, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	policy := LayerObligationPolicy{}
	for _, obligation := range initial.LayerConversionPlan().Report.Unresolved() {
		resolution := LayerObligationResolution{Action: LayerResolveReject}
		if obligation.Kind == LayerObligationOldOnly && obligation.Semantic.QName == "oldChoice" {
			resolution = LayerObligationResolution{
				Action: LayerResolveAdapter,
				Hook:   "layerHistoricalChoice",
				Target: "type:newChoice",
			}
		}
		policy.Entries = append(policy.Entries, LayerObligationPolicyEntry{Key: obligation.Key, Resolution: resolution})
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	model, err := generator.buildLayerCodecModel("fixture")
	if err != nil {
		t.Fatal(err)
	}
	historical := findLayerCodecWire(t, model, 0x41000001)
	if historical.ProfileOnly || historical.CanonicalType != "NewChoice" {
		t.Fatalf("historical constructor did not become a typed wire: %+v", historical)
	}
	if len(historical.Profiles) != 1 ||
		!strings.Contains(historical.Profiles[0].Encode, "layerHistoricalChoiceEncode") ||
		!strings.Contains(historical.Profiles[0].Decode, "layerHistoricalChoiceDecode") {
		t.Fatalf("historical constructor lacks bidirectional typed hooks: %+v", historical.Profiles)
	}
	joinedFamilies := strings.Join(model.FamilyDeclarations, "\n")
	if !strings.Contains(joinedFamilies, "b.PutID(0x41000001)") ||
		!strings.Contains(joinedFamilies, "layerDecodeWire41000001") && !strings.Contains(strings.Join(model.ClassDeclarations, "\n"), "layerDecodeWire41000001") {
		t.Fatalf("canonical target was not redirected to the historical wire")
	}
	if !strings.Contains(joinedFamilies, "case LayerProfile1, LayerProfile2:") {
		t.Fatalf("identical family profile actions were not coalesced")
	}
	joinedClasses := strings.Join(model.ClassDeclarations, "\n")
	if !strings.Contains(joinedClasses, "case *NewChoice:") || !strings.Contains(joinedClasses, "layerDecodeWire41000001") {
		t.Fatalf("historical constructor was not installed in the canonical class dispatcher:\n%s", joinedClasses)
	}
	if !strings.Contains(joinedClasses, "case LayerProfile1, LayerProfile2:") {
		t.Fatalf("identical class constructor sets were not coalesced")
	}

	sources := sourceSnapshot{}
	if err := generator.WriteSource(sources, "fixture", Template()); err != nil {
		t.Fatal(err)
	}
	sources["layer_historical_type_test.go"] = []byte(`package fixture

import (
	"testing"

	"github.com/gotd/td/bin"
)

var historicalChoiceEncodeCalls int
var historicalChoiceDecodeCalls int

func layerHistoricalChoiceEncode(_ LayerProfile, value *NewChoice) (int, error) {
	historicalChoiceEncodeCalls++
	return value.Value, nil
}

func layerHistoricalChoiceDecode(_ LayerProfile, value int) (*NewChoice, error) {
	historicalChoiceDecodeCalls++
	return &NewChoice{Value: value}, nil
}

func TestGeneratedHistoricalTypeClassAndObjectRoundTrip(t *testing.T) {
	holder := &Holder{
		Choice: &NewChoice{Value: 7},
	}
	historicalChoiceEncodeCalls = 0
	historicalChoiceDecodeCalls = 0
	b := &bin.Buffer{}
	if err := EncodeLayer(LayerProfile1, LayerConstructorHolderType(), holder, b); err != nil { t.Fatal(err) }
	if historicalChoiceEncodeCalls != 1 { t.Fatalf("nested historical encode hooks = %d, want 1", historicalChoiceEncodeCalls) }
	decoded, err := DecodeLayer(LayerProfile1, LayerConstructorHolderType(), &bin.Buffer{Buf: append([]byte(nil), b.Buf...)})
	if err != nil { t.Fatal(err) }
	choice, ok := decoded.Choice.(*NewChoice)
	if !ok || choice.Value != 7 { t.Fatalf("class field roundtrip = %#v", decoded.Choice) }
	if historicalChoiceDecodeCalls != 1 { t.Fatalf("nested historical decode hooks = %d, want 1", historicalChoiceDecodeCalls) }

	historicalChoiceEncodeCalls = 0
	historicalChoiceDecodeCalls = 0
	b.Reset()
	if err := EncodeLayer(LayerProfile1, LayerObjectType(), bin.Object(&NewChoice{Value: 11}), b); err != nil { t.Fatal(err) }
	dynamic, err := DecodeLayer(LayerProfile1, LayerObjectType(), &bin.Buffer{Buf: append([]byte(nil), b.Buf...)})
	if err != nil { t.Fatal(err) }
	dynamicChoice, ok := dynamic.(*NewChoice)
	if !ok || dynamicChoice.Value != 11 { t.Fatalf("dynamic Object roundtrip = %#v", dynamic) }
	if historicalChoiceEncodeCalls != 1 || historicalChoiceDecodeCalls != 1 {
		t.Fatalf("dynamic historical hook calls encode=%d decode=%d, want 1/1", historicalChoiceEncodeCalls, historicalChoiceDecodeCalls)
	}
}
`)
	runLayerGeneratedPackage(t, sources)
}

func TestLayerCodecHistoricalTypeRejectPolicyFailsGeneration(t *testing.T) {
	set := buildLayerCodecHistoricalTypeUniverse(t)
	initial, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	policy := LayerObligationPolicy{}
	for _, obligation := range initial.LayerConversionPlan().Report.Unresolved() {
		policy.Entries = append(policy.Entries, LayerObligationPolicyEntry{
			Key:        obligation.Key,
			Resolution: LayerObligationResolution{Action: LayerResolveReject},
		})
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	_, err = generator.buildLayerCodecModel("fixture")
	if err == nil || !strings.Contains(err.Error(), "E_PROFILE_ONLY_TYPE_POLICY") {
		t.Fatalf("historical type reject policy error = %v, want E_PROFILE_ONLY_TYPE_POLICY", err)
	}
}

func TestLayerCodecHistoricalSingularTypeUsesSharedMetadataAndTypeRefs(t *testing.T) {
	set := buildLayerCodecHistoricalSingularUniverse(t)
	initial, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	policy := LayerObligationPolicy{}
	for _, obligation := range initial.LayerConversionPlan().Report.Unresolved() {
		resolution := LayerObligationResolution{Action: LayerResolveReject}
		switch {
		case obligation.Kind == LayerObligationOldOnly && obligation.Semantic.QName == "oldRecord":
			resolution = LayerObligationResolution{Action: LayerResolveAdapter, Hook: "layerHistoricalRecord", Target: "type:newRecord"}
		case obligation.Kind == LayerObligationResult && obligation.Semantic.QName == "getRecord":
			resolution = LayerObligationResolution{Action: LayerResolveAdapter, Hook: "layerHistoricalExactResult"}
		case obligation.Kind == LayerObligationRequired:
			resolution.Action = LayerResolveDefault
		case obligation.Kind == LayerObligationDiscard || obligation.Kind == LayerObligationUpdateProjection:
			resolution.Action = LayerResolveDrop
		case obligation.Kind == LayerObligationFieldProjection:
			resolution.Action = LayerResolveRejectIfPresent
		case obligation.Kind == LayerObligationPrivate:
			resolution.Action = LayerResolveAllow
		}
		policy.Entries = append(policy.Entries, LayerObligationPolicyEntry{Key: obligation.Key, Resolution: resolution})
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}

	wires, err := generator.buildLayerWireModel()
	if err != nil {
		t.Fatal(err)
	}
	for _, layer := range []int{1, 2} {
		mapped := wires.historicalTarget(layer, semantic.SemanticKey{Category: semantic.CategoryType, QName: "newRecord"})
		if mapped == nil || mapped.WireID != 0x42000001 || mapped.Target == nil || mapped.Target.Structure.Name != "NewRecord" {
			t.Fatalf("layer %d shared historical target = %+v", layer, mapped)
		}
	}

	codec, err := generator.buildLayerCodecModel("fixture")
	if err != nil {
		t.Fatal(err)
	}
	historical := findLayerCodecWire(t, codec, 0x42000001)
	if len(historical.Profiles) != 2 || len(historical.ProfileGroups) != 1 ||
		!reflect.DeepEqual(historical.ProfileGroups[0].Layers, []int{1, 2}) {
		t.Fatalf("historical wire profile grouping = %+v", historical.ProfileGroups)
	}
	if !strings.Contains(historical.ProfileGroups[0].Encode, "layerHistoricalRecordEncode") ||
		!strings.Contains(historical.ProfileGroups[0].Decode, "layerHistoricalRecordDecode") {
		t.Fatalf("historical grouped body lost typed hooks: %+v", historical.ProfileGroups[0])
	}

	metadata, err := generator.buildLayerMetadata()
	if err != nil {
		t.Fatal(err)
	}
	newRecordConstant := layerSemanticConstant(semantic.SemanticKey{Category: semantic.CategoryType, QName: "newRecord"})
	for _, layer := range []int{1, 2} {
		var found bool
		for _, override := range metadata.Overrides {
			if override.Layer != layer {
				continue
			}
			for _, entry := range override.Entries {
				if entry.Constant == newRecordConstant && entry.Present && entry.WireID == 0x42000001 {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("layer %d metadata did not map newRecord to historical wire", layer)
		}
	}

	refs, err := generator.buildLayerTypeRefModel()
	if err != nil {
		t.Fatal(err)
	}
	canonicalBare := findLayerTypeRefNode(t, refs, func(node *layerTypeRefNode) bool {
		return node.IsExactBare() && node.QName == "newRecord" && node.Bare && !node.Percent
	})
	for _, layer := range []int{1, 2} {
		profile := nodeProfile(canonicalBare, layer)
		if profile == nil || !profile.Available || !profile.Callable || profile.WireID != 0x42000001 {
			t.Fatalf("layer %d canonical bare historical profile = %+v", layer, profile)
		}
	}
	singular := findLayerTypeRefNode(t, refs, func(node *layerTypeRefNode) bool {
		return node.IsConcrete() && node.QName == "Record"
	})
	if singular.GoType != "NewRecord" || !singular.Runnable || !nodeProfile(singular, 1).Callable {
		t.Fatalf("historical singular boxed TypeRef = %+v", singular)
	}
	rpc := findLayerRPCTypePlan(t, refs, semantic.SemanticKey{Category: semantic.CategoryFunction, QName: "getRecord"})
	oldResult := rpc.profile(1)
	if oldResult == nil || oldResult.CanonicalResult < 0 || oldResult.WireResult < 0 {
		t.Fatalf("historical exact RPC result plan = %+v", oldResult)
	}
	wireResult := &refs.Nodes[oldResult.WireResult]
	if wireResult.QName != "oldRecord" || wireResult.GoType != "NewRecord" || !wireResult.Runnable || !nodeProfile(wireResult, 1).Callable {
		t.Fatalf("historical exact wire result TypeRef = %+v", wireResult)
	}

	sources := sourceSnapshot{}
	if err := generator.WriteSource(sources, "fixture", Template()); err != nil {
		t.Fatal(err)
	}
	sources["layer_historical_singular_test.go"] = []byte(`package fixture

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gotd/td/bin"
)

var historicalRecordFail bool
var historicalRecordPartial bool

func layerHistoricalRecordEncode(_ LayerProfile, value *NewRecord) (bool, bool, int, bool, []byte, []int, error) {
	if historicalRecordFail { return false, false, 0, false, nil, nil, errors.New("historical adapter failure") }
	shared := value.Count != 0 || value.Proof != nil
	proofPresent := shared
	if historicalRecordPartial { proofPresent = false }
	return value.Enabled, shared, value.Count, proofPresent, append([]byte(nil), value.Proof...), append([]int(nil), value.Items...), nil
}

func layerHistoricalRecordDecode(_ LayerProfile, enabled bool, countPresent bool, count int, proofPresent bool, proof []byte, items []int) (*NewRecord, error) {
	if countPresent != proofPresent { return nil, errors.New("partial shared historical flag") }
	return &NewRecord{Enabled: enabled, Count: count, Proof: append([]byte(nil), proof...), Items: append([]int(nil), items...)}, nil
}

func layerHistoricalExactResult(_ LayerProfile, value *NewRecord) (*NewRecord, error) { return value, nil }

func TestGeneratedHistoricalSingularBareBoxedVectorAndRollback(t *testing.T) {
	value := &NewRecord{Enabled: true, Count: 7, Proof: []byte{1, 2}, Items: []int{3, 4}}
	for _, profile := range []LayerProfile{LayerProfile1, LayerProfile2} {
		wireID, ok := LayerWireID(profile, LayerSemanticTypeNewRecord)
		if !ok || wireID != 0x42000001 { t.Fatalf("profile %d newRecord wire = %#x/%t", profile, wireID, ok) }

		var direct bin.Buffer
		if err := EncodeLayer(profile, LayerConstructorNewRecordType(), value, &direct); err != nil { t.Fatal(err) }
		if id, err := direct.PeekID(); err != nil || id != 0x42000001 { t.Fatalf("direct historical ID = %#x err=%v", id, err) }
		decoded, err := DecodeLayer(profile, LayerConstructorNewRecordType(), &bin.Buffer{Buf: direct.Copy()})
		if err != nil { t.Fatal(err) }
		if decoded.Count != value.Count || !bytes.Equal(decoded.Proof, value.Proof) || len(decoded.Items) != 2 { t.Fatalf("direct roundtrip = %#v", decoded) }

		var boxed bin.Buffer
		if err := EncodeLayer(profile, LayerClassRecordType(), *value, &boxed); err != nil { t.Fatal(err) }
		boxedDecoded, err := DecodeLayer(profile, LayerClassRecordType(), &bin.Buffer{Buf: boxed.Copy()})
		if err != nil || boxedDecoded.Count != value.Count { t.Fatalf("boxed roundtrip = %#v err=%v", boxedDecoded, err) }

		batch := &RecordBatch{Records: []NewRecord{*value, {Count: 9, Proof: []byte{5}, Items: []int{6}}}}
		var vector bin.Buffer
		if err := EncodeLayer(profile, LayerConstructorRecordBatchType(), batch, &vector); err != nil { t.Fatal(err) }
		batchDecoded, err := DecodeLayer(profile, LayerConstructorRecordBatchType(), &bin.Buffer{Buf: vector.Copy()})
		if err != nil || len(batchDecoded.Records) != 2 || batchDecoded.Records[1].Count != 9 { t.Fatalf("vector roundtrip = %#v err=%v", batchDecoded, err) }
	}

	prefix := []byte{0xaa, 0xbb}
	failed := &bin.Buffer{Buf: append([]byte(nil), prefix...)}
	historicalRecordFail = true
	if err := EncodeLayer(LayerProfile1, LayerConstructorNewRecordType(), value, failed); err == nil { t.Fatal("historical hook failure was ignored") }
	historicalRecordFail = false
	if !bytes.Equal(failed.Buf, prefix) { t.Fatalf("hook failure left bytes: %x", failed.Buf) }

	partial := &bin.Buffer{Buf: append([]byte(nil), prefix...)}
	historicalRecordPartial = true
	if err := EncodeLayer(LayerProfile1, LayerConstructorNewRecordType(), value, partial); err == nil { t.Fatal("partial shared flag was accepted") }
	historicalRecordPartial = false
	if !bytes.Equal(partial.Buf, prefix) { t.Fatalf("partial shared flag left bytes: %x", partial.Buf) }
}
`)
	runLayerGeneratedPackage(t, sources)
}

func buildLayerCodecHistoricalSingularUniverse(t *testing.T) *SchemaSet {
	t.Helper()
	const historical = `
---types---
oldRecord#42000001 flags:# enabled:flags.0?true count:flags.1?int proof:flags.1?bytes items:Vector<int> = Record;
recordBatch#42000003 records:Vector<Record> = RecordBatch;
---functions---
getRecord#42000004 = %%oldRecord;
// LAYER %d
`
	const canonical = `
---types---
newRecord#42000002 enabled:Bool count:int proof:bytes items:Vector<int> = Record;
recordBatch#42000003 records:Vector<Record> = RecordBatch;
---functions---
getRecord#42000004 = %newRecord;
// LAYER 3
`
	sources := []string{fmt.Sprintf(historical, 1), fmt.Sprintf(historical, 2), canonical}
	profiles := make([]*semantic.SchemaModel, 0, len(sources))
	for _, source := range sources {
		parsed, err := tl.Parse(bytes.NewBufferString(source))
		if err != nil {
			t.Fatal(err)
		}
		profile, err := semantic.BuildSchema(parsed, semantic.SourceRef{Layer: parsed.Layer})
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, profile)
	}
	set, err := NewSchemaSet(3, profiles...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func buildLayerCodecHistoricalTypeUniverse(t *testing.T) *SchemaSet {
	t.Helper()
	const layerOne = `
---types---
oldChoice#41000001 value:int = Choice;
otherChoice#41000003 value:int = Choice;
holder#41000010 choice:Choice = Holder;
stableA#41000020 = Stable;
stableB#41000021 = Stable;
// LAYER 1
`
	const layerTwo = `
---types---
newChoice#41000002 value:int = Choice;
otherChoice#41000003 value:int = Choice;
holder#41000010 choice:Choice = Holder;
stableA#41000020 = Stable;
stableB#41000021 = Stable;
// LAYER 2
`
	profiles := make([]*semantic.SchemaModel, 0, 2)
	for _, source := range []string{layerOne, layerTwo} {
		parsed, err := tl.Parse(bytes.NewBufferString(source))
		if err != nil {
			t.Fatal(err)
		}
		profile, err := semantic.BuildSchema(parsed, semantic.SourceRef{Layer: parsed.Layer})
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, profile)
	}
	set, err := NewSchemaSet(2, profiles...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func runLayerGeneratedPackage(t *testing.T, sources sourceSnapshot) {
	t.Helper()

	dir := t.TempDir()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	goMod := fmt.Sprintf("module fixture\n\ngo 1.25\n\nrequire github.com/gotd/td v0.0.0\nreplace github.com/gotd/td => %s\n", filepath.ToSlash(root))
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, source := range sources {
		formatted, err := format.Source(source)
		if err != nil {
			t.Fatalf("format %s: %v\n%s", name, err, source)
		}
		if err := os.WriteFile(filepath.Join(dir, name), formatted, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("go", "test", "-mod=mod", "./...")
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("compile generated synthetic package: %v\n%s", err, output)
	}
}

func TestLayerCodecEncodeAdapterOnceAndRollback(t *testing.T) {
	const profileOne = `
---types---
thing#30000001 value:string = Thing;
payloadKeep#30000021 value:int = Payload;
payloadOther#30000024 value:int = Payload;
updateKeep#30000011 value:int = Update;
batch#30000013 updates:Vector<Update> = Batch;
grouped#30000022 flags:# items:flags.0?Vector<int> proof:flags.0?bytes payload:flags.1?Payload marker:flags.1?int = Grouped;
optionalBatch#30000023 flags:# marker:flags.0?int update:flags.0?Update = OptionalBatch;
legacy#30000030 flags:# value:int = Legacy;
textBlob#30000040 text:string data:bytes = TextBlob;
// LAYER 1
`
	const profileTwo = `
---types---
thing#30000002 value:int = Thing;
payloadKeep#30000021 value:int = Payload;
payloadOther#30000024 value:int = Payload;
updateKeep#30000011 value:int = Update;
updateGone#30000012 value:int = Update;
batch#30000013 updates:Vector<Update> = Batch;
grouped#30000022 flags:# items:flags.0?Vector<int> proof:flags.0?bytes payload:flags.1?Payload marker:flags.1?int = Grouped;
optionalBatch#30000023 flags:# marker:flags.0?int update:flags.0?Update = OptionalBatch;
legacy#30000031 flags:# value:int payload:flags.0?Payload = Legacy;
textBlob#30000040 text:string data:bytes = TextBlob;
// LAYER 2
`
	profiles := make([]*semantic.SchemaModel, 0, 2)
	for _, source := range []string{profileOne, profileTwo} {
		parsed, err := tl.Parse(bytes.NewBufferString(source))
		if err != nil {
			t.Fatal(err)
		}
		profile, err := semantic.BuildSchema(parsed, semantic.SourceRef{Layer: parsed.Layer})
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, profile)
	}
	set, err := NewSchemaSet(2, profiles...)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	policy := LayerObligationPolicy{}
	for _, obligation := range initial.LayerConversionPlan().Report.Unresolved() {
		resolution := LayerObligationResolution{Action: LayerResolveReject}
		switch obligation.Kind {
		case LayerObligationIncompatible:
			resolution = LayerObligationResolution{Action: LayerResolveAdapter, Hook: "layerCountedValue"}
		case LayerObligationUpdateProjection:
			resolution = LayerObligationResolution{Action: LayerResolveDrop}
		case LayerObligationFieldProjection:
			resolution = LayerObligationResolution{Action: LayerResolveDrop}
		}
		policy.Entries = append(policy.Entries, LayerObligationPolicyEntry{Key: obligation.Key, Resolution: resolution})
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	sources := sourceSnapshot{}
	if err := generator.WriteSource(sources, "fixture", Template()); err != nil {
		t.Fatal(err)
	}
	sources["layer_adapter_once_test.go"] = []byte(`package fixture

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gotd/td/bin"
)

var (
	layerCountedValueCalls int
	layerCountedValueFail bool
)

func layerCountedValueEncode(_ LayerProfile, _ *Thing, _ int) (string, error) {
	layerCountedValueCalls++
	if layerCountedValueFail { return "", errors.New("adapter failure") }
	return "adapted", nil
}

func layerCountedValueDecode(_ LayerProfile, _ *Thing, _ bool, _ string) (int, error) {
	return 7, nil
}

func TestGeneratedAdapterOnceAndRollback(t *testing.T) {
	value := &Thing{Value: 7}
	buffer := &bin.Buffer{Buf: []byte{0xaa}}
	layerCountedValueCalls = 0
	layerCountedValueFail = false
	if err := EncodeLayer(LayerProfile1, LayerConstructorThingType(), value, buffer); err != nil { t.Fatal(err) }
	if layerCountedValueCalls != 1 { t.Fatalf("successful adapter calls = %d, want 1", layerCountedValueCalls) }
	if len(buffer.Buf) <= 1 || buffer.Buf[0] != 0xaa { t.Fatalf("successful encoding corrupted prefix: %x", buffer.Buf) }

	before := append([]byte(nil), buffer.Buf...)
	layerCountedValueCalls = 0
	layerCountedValueFail = true
	if err := EncodeLayer(LayerProfile1, LayerConstructorThingType(), value, buffer); err == nil { t.Fatal("adapter failure was ignored") }
	if layerCountedValueCalls != 1 { t.Fatalf("failing adapter calls = %d, want 1", layerCountedValueCalls) }
	if !bytes.Equal(buffer.Buf, before) { t.Fatalf("failed encoding left partial bytes: got %x want %x", buffer.Buf, before) }

	layerCountedValueFail = false
	vectorBuffer := &bin.Buffer{}
	batch := &Batch{Updates: []UpdateClass{
		&UpdateKeep{Value: 1},
		&UpdateGone{Value: 2},
		&UpdateKeep{Value: 3},
	}}
	if err := EncodeLayer(LayerProfile1, LayerConstructorBatchType(), batch, vectorBuffer); err != nil { t.Fatal(err) }
	decoded, err := DecodeLayer(LayerProfile1, LayerConstructorBatchType(), &bin.Buffer{Buf: append([]byte(nil), vectorBuffer.Buf...)})
	if err != nil { t.Fatal(err) }
	if len(decoded.Updates) != 2 { t.Fatalf("decoded projected updates = %d, want 2", len(decoded.Updates)) }
	if decoded.Updates[0].(*UpdateKeep).Value != 1 || decoded.Updates[1].(*UpdateKeep).Value != 3 {
		t.Fatalf("projected vector kept wrong elements: %#v", decoded.Updates)
	}

	allocationBuffer := &bin.Buffer{}
	adapterAllocs := testing.AllocsPerRun(200, func() {
		allocationBuffer.Reset()
		if err := EncodeLayer(LayerProfile1, LayerConstructorThingType(), value, allocationBuffer); err != nil { panic(err) }
	})
	if adapterAllocs > 4 { t.Fatalf("primitive adapted encode allocations/run = %.2f, want <= 4", adapterAllocs) }
	vectorAllocs := testing.AllocsPerRun(200, func() {
		allocationBuffer.Reset()
		if err := EncodeLayer(LayerProfile1, LayerConstructorBatchType(), batch, allocationBuffer); err != nil { panic(err) }
	})
	if vectorAllocs > 8 { t.Fatalf("required vector projection encode allocations/run = %.2f, want <= 8", vectorAllocs) }
	keepBatch := &Batch{Updates: []UpdateClass{&UpdateKeep{Value: 1}, &UpdateKeep{Value: 3}}}
	keepVectorAllocs := testing.AllocsPerRun(200, func() {
		allocationBuffer.Reset()
		if err := EncodeLayer(LayerProfile1, LayerConstructorBatchType(), keepBatch, allocationBuffer); err != nil { panic(err) }
	})
	if keepVectorAllocs > 4 { t.Fatalf("required all-kept vector encode allocations/run = %.2f, want <= 4", keepVectorAllocs) }

	presentEmpty := &Grouped{Items: make([]int, 0)}
	groupBuffer := &bin.Buffer{}
	if err := EncodeLayer(LayerProfile1, LayerConstructorGroupedType(), presentEmpty, groupBuffer); err != nil { t.Fatal(err) }
	groupDecoded, err := DecodeLayer(LayerProfile1, LayerConstructorGroupedType(), &bin.Buffer{Buf: append([]byte(nil), groupBuffer.Buf...)})
	if err != nil { t.Fatal(err) }
	if !groupDecoded.Flags.Has(0) || len(groupDecoded.Items) != 0 { t.Fatalf("present-empty shared flag group was lost: %#v", groupDecoded) }

	groupBuffer.Reset()
	if err := EncodeLayer(LayerProfile1, LayerConstructorGroupedType(), &Grouped{Marker: 1}, groupBuffer); err == nil {
		t.Fatal("shared flag group accepted a nil class member")
	}
	if len(groupBuffer.Buf) != 0 { t.Fatalf("failed shared group encoding left bytes: %x", groupBuffer.Buf) }

	partial := &OptionalBatch{Marker: 1, Update: &UpdateGone{Value: 2}}
	if err := EncodeLayer(LayerProfile1, LayerConstructorOptionalBatchType(), partial, groupBuffer); err == nil {
		t.Fatal("shared flag group accepted a partial Layer projection")
	}
	if len(groupBuffer.Buf) != 0 { t.Fatalf("partial projection left bytes: %x", groupBuffer.Buf) }

	allDropped := &OptionalBatch{Update: &UpdateGone{Value: 2}}
	if err := EncodeLayer(LayerProfile1, LayerConstructorOptionalBatchType(), allDropped, groupBuffer); err != nil { t.Fatal(err) }
	droppedDecoded, err := DecodeLayer(LayerProfile1, LayerConstructorOptionalBatchType(), &bin.Buffer{Buf: append([]byte(nil), groupBuffer.Buf...)})
	if err != nil { t.Fatal(err) }
	if droppedDecoded.Flags.Has(0) || droppedDecoded.Update != nil { t.Fatalf("fully dropped optional group survived: %#v", droppedDecoded) }

	malformedBuffer := &bin.Buffer{Buf: []byte{0xbb}}
	malformed := &Legacy{Flags: 1, Value: 9, Payload: nil}
	if err := EncodeLayer(LayerProfile1, LayerConstructorLegacyType(), malformed, malformedBuffer); err == nil {
		t.Fatal("low-layer field projection hid an explicit flag with nil interface")
	}
	if !bytes.Equal(malformedBuffer.Buf, []byte{0xbb}) {
		t.Fatalf("malformed projection did not roll back: %x", malformedBuffer.Buf)
	}

	oversizedBuffer := &bin.Buffer{Buf: []byte{0xcc}}
	oversized := &TextBlob{Text: strings.Repeat("x", 1<<24)}
	if err := EncodeLayer(LayerProfile1, LayerConstructorTextBlobType(), oversized, oversizedBuffer); err == nil {
		t.Fatal("generated codec accepted a TL string beyond the 24-bit header")
	}
	if !bytes.Equal(oversizedBuffer.Buf, []byte{0xcc}) {
		t.Fatalf("oversized TL string did not roll back: %x", oversizedBuffer.Buf)
	}
}
`)
	runLayerGeneratedPackage(t, sources)
}

func TestLayerCodecModelTelegram220Through227Completeness(t *testing.T) {
	set, err := semantic.LoadUniverse("../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	policy := layerTestPolicy(t, set)
	initial, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var replacement *LayerObligation
	for index := range initial.LayerConversionPlan().Report.Obligations {
		obligation := &initial.LayerConversionPlan().Report.Obligations[index]
		if obligation.Kind != LayerObligationFieldReplacement {
			continue
		}
		replacement = obligation
		for policyIndex := range policy.Entries {
			if policy.Entries[policyIndex].Key == obligation.Key {
				policy.Entries[policyIndex].Resolution = LayerObligationResolution{
					Action: LayerResolveAdapter,
					Hook:   "layerTestFieldReplacement",
				}
			}
		}
	}
	if replacement == nil {
		t.Fatal("real schema set has no field-replacement obligation")
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	model, err := generator.buildLayerCodecModel("tg")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(model.Wires), len(set.WireCodecs); got != want {
		t.Fatalf("real unique wire codecs = %d, want %d", got, want)
	}
	profileBodies := 0
	profileGroups := 0
	profileOnly := 0
	for _, wire := range model.Wires {
		profileBodies += len(wire.Profiles)
		profileGroups += len(wire.ProfileGroups)
		if wire.ProfileOnly {
			profileOnly++
			if len(wire.RejectProfiles) == 0 {
				t.Fatalf("profile-only wire %#08x has no explicit admission rejection", wire.WireID)
			}
		}
	}
	if profileBodies == 0 || profileOnly == 0 {
		t.Fatalf("real codec coverage profiles=%d profile_only=%d", profileBodies, profileOnly)
	}
	if profileGroups <= 0 || profileGroups >= profileBodies {
		t.Fatalf("profile body coalescing ineffective: groups=%d bodies=%d", profileGroups, profileBodies)
	}
	var replacementPreflight, replacementEncode, replacementDecode bool
	for _, wire := range model.Wires {
		for _, profile := range wire.Profiles {
			if profile.Layer != replacement.Layer {
				continue
			}
			replacementPreflight = replacementPreflight || strings.Contains(profile.Preflight, "layerTestFieldReplacementEncode")
			replacementEncode = replacementEncode || strings.Contains(profile.Encode, "layerTestFieldReplacementEncode")
			replacementDecode = replacementDecode || strings.Contains(profile.Decode, "layerTestFieldReplacementDecode")
		}
	}
	if !replacementPreflight || !replacementEncode || !replacementDecode {
		t.Fatalf("field replacement was not lowered to preflighted bidirectional typed adapters: preflight=%t encode=%t decode=%t", replacementPreflight, replacementEncode, replacementDecode)
	}
	invokeWithLayer := findLayerCodecWire(t, model, 0xda9b0d0d)
	for _, profile := range invokeWithLayer.Profiles {
		if !strings.Contains(profile.Preflight, "ResolveLayerProfile(value.Layer)") ||
			!strings.Contains(profile.Preflight, "state.generic[0].preflight") ||
			!strings.Contains(profile.Encode, "state.generic[0].encode") ||
			!strings.Contains(profile.Decode, "state.generic[0].decode") {
			t.Fatalf("invokeWithLayer layer %d lost nested exact-profile/generic binding:\npreflight:\n%s\nencode:\n%s\ndecode:\n%s", profile.Layer, profile.Preflight, profile.Encode, profile.Decode)
		}
	}
	for index, bucket := range model.WireBuckets {
		for _, wire := range bucket.Wires {
			if int(wire.WireID%64) != index {
				t.Fatalf("wire %#08x is in unstable bucket %d", wire.WireID, index)
			}
		}
	}
	t.Logf("Telegram 220-227 codec model: wires=%d exact_profile_bodies=%d coalesced_groups=%d profile_only=%d hooks=%d declarations=%d", len(model.Wires), profileBodies, profileGroups, profileOnly, len(model.Hooks), len(model.Declarations))
}

func newLayerCodecTestGenerator(t *testing.T, set *SchemaSet) *Generator {
	t.Helper()
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerTestPolicy(t, set)})
	if err != nil {
		t.Fatal(err)
	}
	return generator
}

func findLayerCodecWire(t *testing.T, model *layerCodecModel, id uint32) *layerCodecWire {
	t.Helper()
	for index := range model.Wires {
		if model.Wires[index].WireID == id {
			return &model.Wires[index]
		}
	}
	t.Fatalf("wire %#08x is absent", id)
	return nil
}
