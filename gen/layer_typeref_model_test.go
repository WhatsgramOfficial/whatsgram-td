package gen

import (
	"bytes"
	"fmt"
	"go/format"
	"sort"
	"strings"
	"testing"

	"github.com/gotd/td/gen/semantic"
)

func TestLayerTypeRefModelBuildsStaticDAGAndScopedWrapperSlots(t *testing.T) {
	set := layerValueSyntheticSchemaSet(t)
	generator := newLayerValueSyntheticGenerator(t, set)
	model, err := generator.buildLayerTypeRefModel()
	if err != nil {
		t.Fatal(err)
	}
	if model.CanonicalLayer != 2 || len(model.Profiles) != 2 || len(model.Nodes) == 0 {
		t.Fatalf("TypeRef model header = %+v", model)
	}
	if model.MaxGenericSlots != 1 || model.BindingCapacity != 1 {
		t.Fatalf("generic capacity = max:%d capacity:%d", model.MaxGenericSlots, model.BindingCapacity)
	}
	if model.MaxDepth != layerCodecMaximumDepth || model.MaxVectorSize != layerCodecMaximumVectorSize {
		t.Fatalf("codec limits = depth:%d vector:%d", model.MaxDepth, model.MaxVectorSize)
	}
	for index := range model.Nodes {
		node := &model.Nodes[index]
		if node.Index != index || node.RefName != fmt.Sprintf("layerTypeRef%dMetadata", index) ||
			node.EncodeName != fmt.Sprintf("layerEncodeTypeRef%d", index) ||
			node.DecodeName != fmt.Sprintf("layerDecodeTypeRef%d", index) {
			t.Fatalf("node %d static names = %+v", index, node)
		}
		if index > 0 && model.Nodes[index-1].Key >= node.Key {
			t.Fatalf("TypeRef DAG is not deterministically sorted at %d", index)
		}
		if len(node.Profiles) != len(model.Profiles) {
			t.Fatalf("node %d profile count = %d, want %d", index, len(node.Profiles), len(model.Profiles))
		}
	}

	primitive := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsPrimitive() && node.QName == "int"
	})
	if primitive.GoType != "int" || primitive.PrimitivePut != "PutInt" || !primitive.Runnable {
		t.Fatalf("primitive node = %+v", primitive)
	}
	object := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool { return node.IsObject() })
	if object.GoType != "bin.Object" || !object.Runnable || object.KindConstant != "LayerTypeObject" {
		t.Fatalf("Object node = %+v", object)
	}
	percent := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsExactBare() && node.QName == "bareItem" && node.Percent
	})
	bare := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsExactBare() && node.QName == "bareItem" && node.Bare && !node.Percent
	})
	if percent.Index == bare.Index || percent.SemanticConstant != bare.SemanticConstant || !percent.Runnable || !bare.Runnable {
		t.Fatalf("bare/percent descriptors collapsed or incomplete: percent=%+v bare=%+v", percent, bare)
	}
	legacy := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsExactBare() && node.QName == "legacy" && node.Bare && !node.Percent
	})
	if !legacy.EmitCodec || !legacy.Runnable || legacy.GoType != "ModernLegacy" ||
		nodeProfile(legacy, 1) == nil || !nodeProfile(legacy, 1).Available || !nodeProfile(legacy, 1).Callable {
		t.Fatalf("historical constructor lost its canonical target descriptor: %+v", legacy)
	}
	leaf := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsClass() && node.QName == "Leaf"
	})
	if leaf.GoType != "LeafClass" || leaf.ClassCodecSuffix != "Leaf" || !leaf.Runnable {
		t.Fatalf("abstract class node = %+v", leaf)
	}
	nested := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsVector() && node.Ref.String() == "Vector<vector<%bareItem>>"
	})
	if nested.Element < 0 || model.Nodes[nested.Element].Element < 0 || nested.GoType != "[][]BareItem" || !nested.Runnable {
		t.Fatalf("nested vector node = %+v", nested)
	}

	generic := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool { return node.IsGeneric() })
	if generic.GenericName != "X" || generic.GenericSlot != 0 || generic.GenericOwner != "function:wrap<X>" ||
		!generic.RequiresBinding || generic.Runnable || !generic.EmitCodec || generic.KindConstant != "LayerTypeGeneric" {
		t.Fatalf("scoped generic node = %+v", generic)
	}
	wrap := findLayerRPCTypePlan(t, model, semantic.SemanticKey{Category: semantic.CategoryFunction, QName: "wrap"})
	for _, layer := range model.Profiles {
		profile := wrap.profile(layer)
		if profile == nil || !profile.Available || !profile.Unwrap || profile.ResultSourceField != 0 ||
			len(profile.GenericSlots) != 1 || len(profile.GenericUses) != 1 || len(profile.ResultSlots) != 1 {
			t.Fatalf("layer %d wrapper metadata = %+v", layer, profile)
		}
		if profile.GenericUses[0].Slot != 0 || !profile.GenericUses[0].Direct || !profile.GenericUses[0].ReplacesResult ||
			profile.WireResult != generic.Index || profile.CanonicalResult != generic.Index {
			t.Fatalf("layer %d wrapper replacement = %+v", layer, profile)
		}
		if model.Nodes[profile.WireResult].IsObject() {
			t.Fatalf("layer %d generic result was degraded to Object", layer)
		}
	}
	objectAccessor := findLayerTypeAccessor(t, model, "LayerObjectType")
	if objectAccessor.Kind != "object" || objectAccessor.Node != object.Index || objectAccessor.DescriptorName != object.DescriptorName {
		t.Fatalf("Object accessor = %+v", objectAccessor)
	}
	constructorAccessor := findLayerTypeAccessor(t, model, "LayerConstructorBareItemType")
	if !constructorAccessor.IsConstructor() || constructorAccessor.GoType != "*BareItem" || constructorAccessor.SemanticConstant == "" {
		t.Fatalf("constructor accessor = %+v", constructorAccessor)
	}
	if accessor := findLayerTypeAccessor(t, model, "LayerClassLeafType"); accessor.Node != leaf.Index || accessor.GoType != "LeafClass" {
		t.Fatalf("class accessor = %+v", accessor)
	}
	for index := 1; index < len(model.Accessors); index++ {
		if model.Accessors[index-1].Name >= model.Accessors[index].Name {
			t.Fatalf("accessors are not uniquely sorted at %d", index)
		}
	}
	secondGenerator := newLayerValueSyntheticGenerator(t, set)
	second, err := secondGenerator.buildLayerTypeRefModel()
	if err != nil {
		t.Fatal(err)
	}
	if firstFingerprint, secondFingerprint := layerTypeRefModelFingerprint(model), layerTypeRefModelFingerprint(second); firstFingerprint != secondFingerprint {
		t.Fatalf("TypeRef model is not deterministic:\nfirst=%s\nsecond=%s", firstFingerprint, secondFingerprint)
	}
}

func TestLayerTypeRefModelRetainsCanonicalAndWireRPCResults(t *testing.T) {
	set := buildLayerStaticSyntheticUniverse(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	model, err := generator.buildLayerTypeRefModel()
	if err != nil {
		t.Fatal(err)
	}
	rpc := findLayerRPCTypePlan(t, model, functionStaticKey("getHolder"))
	old := rpc.profile(1)
	if old == nil || !old.ResultChanged || old.CanonicalResult < 0 || old.WireResult < 0 ||
		model.Nodes[old.CanonicalResult].QName != "Holder" || model.Nodes[old.WireResult].QName != "Leaf" ||
		len(old.ResultObligations) != 2 {
		t.Fatalf("changed RPC result plan = %+v", old)
	}
	canonical := rpc.profile(3)
	if canonical == nil || canonical.ResultChanged || canonical.CanonicalResult != canonical.WireResult ||
		model.Nodes[canonical.WireResult].QName != "Holder" {
		t.Fatalf("canonical RPC result plan = %+v", canonical)
	}
}

func TestLayerTypeRefWireEquivalenceIsConservative(t *testing.T) {
	set := layerValueSyntheticSchemaSet(t)
	generator := newLayerValueSyntheticGenerator(t, set)
	model, err := generator.buildLayerTypeRefModel()
	if err != nil {
		t.Fatal(err)
	}
	assertEquivalent := func(node *layerTypeRefNode, layer int, want bool) {
		t.Helper()
		profile := nodeProfile(node, layer)
		if profile == nil || profile.WireEquivalent != want {
			t.Fatalf("node %s layer %d wire-equivalent = %v, want %v", node.Ref.String(), layer, profile != nil && profile.WireEquivalent, want)
		}
		if node.WireEquivalentName == "" {
			t.Fatalf("node %s has no static equivalence predicate", node.Ref.String())
		}
	}

	primitive := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsPrimitive() && node.QName == "int"
	})
	directBare := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsExactBare() && node.QName == "bareItem" && node.Bare && !node.Percent
	})
	directVector := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsVector() && node.Ref.String() == "Vector<vector<%bareItem>>"
	})
	shrunkClass := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsClass() && node.QName == "Leaf"
	})
	dynamic := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool { return node.IsObject() })
	historical := findLayerTypeRefNode(t, model, func(node *layerTypeRefNode) bool {
		return node.IsExactBare() && node.QName == "legacy" && node.Bare && !node.Percent
	})

	for _, node := range model.Nodes {
		assertEquivalent(&node, model.CanonicalLayer, true)
	}
	assertEquivalent(primitive, 1, true)
	assertEquivalent(directBare, 1, true)
	assertEquivalent(directVector, 1, true)
	assertEquivalent(shrunkClass, 1, false)
	assertEquivalent(dynamic, 1, false)
	assertEquivalent(historical, 1, false)

	if len(model.WireEquivalentGroups) == 0 || len(model.WireEquivalentGroups) >= len(model.Nodes) {
		t.Fatalf("equivalence predicate groups = %d for %d nodes; predicates were not deduplicated", len(model.WireEquivalentGroups), len(model.Nodes))
	}
}

func TestLayerTypeRefAccessorRejectsGeneratedNameCollision(t *testing.T) {
	set := layerValueSyntheticSchemaSet(t)
	generator := newLayerValueSyntheticGenerator(t, set)
	model, err := generator.buildLayerTypeRefModel()
	if err != nil {
		t.Fatal(err)
	}
	wires, err := generator.buildLayerWireModel()
	if err != nil {
		t.Fatal(err)
	}
	generator.structs = append(generator.structs, structDef{Name: "LayerObjectType", RawName: "collision"})
	if _, err := generator.buildLayerTypeAccessors(model, wires); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("accessor collision error = %v", err)
	}
}

func TestLayerTypeRefTemplateUsesDirectFunctionsAndNoRuntimeCatalog(t *testing.T) {
	set := layerValueSyntheticSchemaSet(t)
	generator := newLayerValueSyntheticGenerator(t, set)
	model, err := generator.buildLayerTypeRefModel()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	data := map[string]any{"Package": "fixture", "LayerTypeRefs": model}
	if err := Template().ExecuteTemplate(&output, "layer_typeref", data); err != nil {
		t.Fatal(err)
	}
	formatted, err := format.Source(output.Bytes())
	if err != nil {
		t.Fatalf("format generated TypeRef descriptors: %v\n%s", err, output.String())
	}
	source := string(formatted)
	if strings.Contains(source, "reflect.") || strings.Contains(source, "map[") {
		t.Fatal("generated TypeRef descriptors contain reflection or a runtime schema map")
	}
	checks := []string{
		"preflight: layerPreflightTypeRef",
		"layerEncodeTypeRef",
		"layerDecodeTypeRef",
		"decodeBudget *layerCodecDecodeBudget",
		"layerCodecDescend(profile, \"decode\", state)",
		"layerDecodeVectorLength(profile, &layerTypeRef",
		"layerEncodeDynamicObject",
		"genericBound",
		"type layerBoundType struct",
		"binding.encode(profile, value, b, state)",
		"layerCodecMaxDepth",
		"func LayerObjectType() LayerType[bin.Object]",
		"func LayerConstructorBareItemType() LayerType[*BareItem]",
		"layerPreflightConstructorBareItem",
		"decodeState:",
		"wireEquivalent:",
		"func layerWireEquivalentProfiles",
	}
	for _, want := range checks {
		if !strings.Contains(source, want) {
			t.Errorf("generated TypeRef source is missing %q", want)
		}
	}
	if strings.Contains(source, "binding.encode(profile, value, b)") {
		t.Fatal("generic binding lost the outer layer codec state")
	}
	if strings.Contains(source, "length, err := b.VectorHeader()") || strings.Contains(source, "length, err := b.Int()") {
		t.Fatal("TypeRef vector decode bypasses the shared vector budget helper")
	}
	for _, node := range model.Nodes {
		hasPublicDescriptor := strings.Contains(source, "var "+node.DescriptorName+" = LayerType[")
		if node.Public && !hasPublicDescriptor {
			t.Fatalf("public node %d has no static descriptor", node.Index)
		}
		if !node.Public && hasPublicDescriptor {
			t.Fatalf("internal node %d emitted an unused public descriptor", node.Index)
		}
		if node.RequiresBinding && hasPublicDescriptor {
			t.Fatalf("generic-dependent node %d was exposed as an unbound descriptor", node.Index)
		}
		if node.Runnable && !strings.Contains(source, "var "+node.BoundDescriptorName+" = layerBoundType{") {
			t.Fatalf("runnable node %d has no bound static descriptor", node.Index)
		}
	}
}

func TestLayerTypeRefModelTelegram225Through228Completeness(t *testing.T) {
	set, err := semantic.LoadUniverse("../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	model, err := generator.buildLayerTypeRefModel()
	if err != nil {
		t.Fatal(err)
	}
	if model.MaxGenericSlots != 1 || model.BindingCapacity != 1 {
		t.Fatalf("real generic capacity = max:%d capacity:%d", model.MaxGenericSlots, model.BindingCapacity)
	}

	functionFamilies := 0
	for _, key := range set.SortedKeys() {
		if key.Category == semantic.CategoryFunction {
			functionFamilies++
		}
	}
	if len(model.RPCs) != functionFamilies {
		t.Fatalf("RPC TypeRef plans = %d, want %d", len(model.RPCs), functionFamilies)
	}
	canonicalTypes := 0
	for _, definition := range set.Schemas[set.CanonicalLayer].Definitions {
		if definition.Key.Category == semantic.CategoryType {
			canonicalTypes++
		}
	}
	if got, want := len(model.Accessors), 1+canonicalTypes+len(set.Schemas[set.CanonicalLayer].ConstructorsByClass); got != want {
		t.Fatalf("exported immutable TypeRef accessors = %d, want %d", got, want)
	}
	resultChanges := 0
	wrapperProfiles := 0
	for rpcIndex := range model.RPCs {
		rpc := &model.RPCs[rpcIndex]
		if len(rpc.Profiles) != len(model.Profiles) {
			t.Fatalf("RPC %s profile count = %d, want %d", rpc.Key, len(rpc.Profiles), len(model.Profiles))
		}
		for _, profile := range rpc.Profiles {
			if profile.ResultChanged {
				resultChanges++
			}
			if profile.Unwrap {
				wrapperProfiles++
				if profile.ResultSourceField < 0 || len(profile.ResultSlots) != 1 {
					t.Fatalf("RPC %s layer %d incomplete wrapper metadata: %+v", rpc.Key, profile.Layer, profile)
				}
			}
			if profile.Available && profile.WireResult < 0 {
				t.Fatalf("RPC %s layer %d has no complete wire result TypeRef", rpc.Key, profile.Layer)
			}
			if profile.Conversion.Canonical != nil && profile.CanonicalResult < 0 {
				t.Fatalf("RPC %s layer %d has no canonical result TypeRef", rpc.Key, profile.Layer)
			}
		}
	}
	if resultChanges != 4 {
		t.Fatalf("result-changing RPC profiles = %d, want 4", resultChanges)
	}
	if wrapperProfiles == 0 {
		t.Fatal("real schemas produced no generic wrapper replacement metadata")
	}

	rootCount := 0
	for _, layer := range set.Layers() {
		schema := set.Schemas[layer]
		definitions := append([]*semantic.Definition(nil), schema.Definitions...)
		sort.Slice(definitions, func(i, j int) bool { return definitions[i].Key.String() < definitions[j].Key.String() })
		for _, definition := range definitions {
			scope := makeLayerTypeRefScope(definition)
			for fieldIndex := range definition.Fields {
				field := &definition.Fields[fieldIndex]
				if field.Kind != semantic.FieldValue {
					continue
				}
				assertLayerTypeRefRoot(t, model, &field.Type, scope)
				rootCount++
			}
			assertLayerTypeRefRoot(t, model, &definition.Result, scope)
			rootCount++
		}
	}

	nonRunnableGeneric := 0
	profileOnlyExact := 0
	for index := range model.Nodes {
		node := &model.Nodes[index]
		if node.IsClass() && node.AcceptPointer {
			t.Fatalf("singular canonical node %d incorrectly depends on an abstract class codec", index)
		}
		if node.RequiresBinding {
			nonRunnableGeneric++
			if node.Runnable {
				t.Fatalf("generic-dependent node %d is independently runnable", index)
			}
		}
		if node.IsExactBare() && !node.EmitCodec {
			profileOnlyExact++
		}
	}
	if nonRunnableGeneric == 0 {
		t.Fatalf("real TypeRef gates generic=%d profile_only_exact=%d", nonRunnableGeneric, profileOnlyExact)
	}
	t.Logf(
		"Telegram Layers 225-228 TypeRef model: nodes=%d roots_checked=%d RPCs=%d result_changes=%d wrapper_profiles=%d generic_nodes=%d profile_only_exact=%d",
		len(model.Nodes), rootCount, len(model.RPCs), resultChanges, wrapperProfiles, nonRunnableGeneric, profileOnlyExact,
	)
}

func findLayerTypeRefNode(t *testing.T, model *layerTypeRefModel, match func(*layerTypeRefNode) bool) *layerTypeRefNode {
	t.Helper()
	var found *layerTypeRefNode
	for index := range model.Nodes {
		node := &model.Nodes[index]
		if !match(node) {
			continue
		}
		if found != nil {
			t.Fatalf("multiple TypeRef nodes matched: %d and %d", found.Index, node.Index)
		}
		found = node
	}
	if found == nil {
		t.Fatal("TypeRef node was not found")
	}
	return found
}

func findLayerRPCTypePlan(t *testing.T, model *layerTypeRefModel, key semantic.SemanticKey) *layerRPCTypePlan {
	t.Helper()
	for index := range model.RPCs {
		if model.RPCs[index].Key == key {
			return &model.RPCs[index]
		}
	}
	t.Fatalf("RPC TypeRef plan %s was not found", key)
	return nil
}

func findLayerTypeAccessor(t *testing.T, model *layerTypeRefModel, name string) *layerTypeAccessorPlan {
	t.Helper()
	for index := range model.Accessors {
		if model.Accessors[index].Name == name {
			return &model.Accessors[index]
		}
	}
	t.Fatalf("TypeRef accessor %q was not found", name)
	return nil
}

func assertLayerTypeRefRoot(t *testing.T, model *layerTypeRefModel, ref *semantic.TypeRef, scope layerTypeRefScope) {
	t.Helper()
	var keyFor func(*semantic.TypeRef) string
	keyFor = func(current *semantic.TypeRef) string {
		elementKey := ""
		if current.Arg != nil {
			elementKey = keyFor(current.Arg)
		}
		owner := ""
		slot := -1
		if current.Kind == semantic.TypeGenericRef {
			owner = scope.owner
			slot = scope.slots[current.QName]
		}
		return layerTypeRefStructuralKey(*current, elementKey, owner, slot)
	}
	want := keyFor(ref)
	for index := range model.Nodes {
		if model.Nodes[index].Key == want {
			return
		}
	}
	t.Fatalf("TypeRef root %s (%q) is absent", ref.String(), want)
}

func layerTypeRefModelFingerprint(model *layerTypeRefModel) string {
	var result strings.Builder
	fmt.Fprintf(&result, "c=%d/p=%v/d=%d/v=%d/b=%d\n", model.CanonicalLayer, model.Profiles, model.MaxDepth, model.MaxVectorSize, model.BindingCapacity)
	for _, node := range model.Nodes {
		fmt.Fprintf(&result, "n=%d/%s/%s/%s/%d/%t/%t/%s/%s/%s\n", node.Index, node.Key, node.Strategy, node.GoType, node.Element, node.EmitCodec, node.Runnable, node.EncodeName, node.DecodeName, node.WireEquivalentName)
		for _, profile := range node.Profiles {
			fmt.Fprintf(&result, "np=%d/%t/%t/%s/%08x/%t\n", profile.Layer, profile.Available, profile.Callable, profile.Action, profile.WireID, profile.WireEquivalent)
		}
	}
	for _, group := range model.WireEquivalentGroups {
		fmt.Fprintf(&result, "we=%s/%v\n", group.Name, group.ProfileConstants)
	}
	for _, rpc := range model.RPCs {
		fmt.Fprintf(&result, "r=%s/%s\n", rpc.Key, rpc.SemanticConstant)
		for _, profile := range rpc.Profiles {
			fmt.Fprintf(&result, "rp=%d/%t/%08x/%d/%d/%t/%v/%d/%d\n", profile.Layer, profile.Available, profile.WireID, profile.CanonicalResult, profile.WireResult, profile.Unwrap, profile.ResultSlots, profile.ResultSourceField, profile.NestedProfileSourceField)
			for _, use := range profile.GenericUses {
				fmt.Fprintf(&result, "gu=%d/%d/%s/%s/%t/%t\n", use.Slot, use.FieldOrdinal, use.FieldName, use.Path, use.Direct, use.ReplacesResult)
			}
		}
	}
	for _, accessor := range model.Accessors {
		fmt.Fprintf(&result, "a=%s/%s/%d/%s/%s\n", accessor.Name, accessor.Kind, accessor.Node, accessor.GoType, accessor.DescriptorName)
	}
	return result.String()
}
