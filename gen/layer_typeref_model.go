package gen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/iamxvbaba/td/gen/semantic"
)

// layerTypeRefStrategy is the generated, static implementation selected for
// one interned TypeRef. It is deliberately an emitter decision: generated
// code never walks semantic.TypeRef values at runtime.
type layerTypeRefStrategy uint8

const (
	layerTypeRefPrimitive layerTypeRefStrategy = iota
	layerTypeRefExactBare
	layerTypeRefConcrete
	layerTypeRefClass
	layerTypeRefVector
	layerTypeRefGeneric
	layerTypeRefObject
)

func (s layerTypeRefStrategy) String() string {
	switch s {
	case layerTypeRefPrimitive:
		return "primitive"
	case layerTypeRefExactBare:
		return "exact-bare"
	case layerTypeRefConcrete:
		return "boxed-concrete"
	case layerTypeRefClass:
		return "boxed-class"
	case layerTypeRefVector:
		return "vector"
	case layerTypeRefGeneric:
		return "generic-slot"
	case layerTypeRefObject:
		return "dynamic-object"
	default:
		return fmt.Sprintf("layerTypeRefStrategy(%d)", s)
	}
}

// layerTypeRefModel is the complete generation-time descriptor graph. Nodes
// are structurally interned and linked as a DAG by deterministic integer index. RPCs
// retain both the canonical result and the exact wire-profile result; this is
// what lets request admission freeze a complete result descriptor rather than
// consulting mutable session Layer state later.
type layerTypeRefModel struct {
	CanonicalLayer       int
	Profiles             []int
	Nodes                []layerTypeRefNode
	WireEquivalentGroups []layerTypeRefWireEquivalentGroup
	RPCs                 []layerRPCTypePlan
	Accessors            []layerTypeAccessorPlan
	MaxGenericSlots      int
	BindingCapacity      int
	MaxDepth             int
	MaxVectorSize        int
}

// layerTypeRefNode is one immutable generated TypeRef descriptor. Ref is kept
// only in the generator model. The generated package gets scalar metadata and
// direct function pointers named by EncodeName and DecodeName.
type layerTypeRefNode struct {
	Index        int
	Key          string
	Ref          semantic.TypeRef
	Strategy     layerTypeRefStrategy
	KindConstant string
	QName        string
	Bare         bool
	Percent      bool

	Element               int
	ElementRefName        string
	ElementGoType         string
	ElementPreflightState string
	ElementEncodeState    string
	ElementDecodeState    string

	GenericOwner string
	GenericName  string
	GenericSlot  int

	RequiresBinding bool
	EmitCodec       bool
	Runnable        bool
	Public          bool
	AcceptPointer   bool
	GoType          string

	RefName               string
	DescriptorName        string
	AnyDescriptorName     string
	BoundDescriptorName   string
	EncodeName            string
	DecodeName            string
	PreflightName         string
	PreflightAnyName      string
	EncodeAnyStateName    string
	DecodeAnyStateName    string
	PreflightAnyStateName string
	PreflightStateName    string
	EncodeStateName       string
	DecodeStateName       string
	WireEquivalentName    string

	SemanticConstant string
	ClassCodecSuffix string
	PrimitivePut     string
	PrimitiveRead    string
	BoxedVector      bool

	Profiles      []layerTypeRefProfilePlan
	ProfileGroups []layerTypeRefProfilePlan
}

func (n layerTypeRefNode) IsPrimitive() bool { return n.Strategy == layerTypeRefPrimitive }
func (n layerTypeRefNode) IsExactBare() bool { return n.Strategy == layerTypeRefExactBare }
func (n layerTypeRefNode) IsConcrete() bool  { return n.Strategy == layerTypeRefConcrete }
func (n layerTypeRefNode) IsClass() bool     { return n.Strategy == layerTypeRefClass }
func (n layerTypeRefNode) IsVector() bool    { return n.Strategy == layerTypeRefVector }
func (n layerTypeRefNode) IsGeneric() bool   { return n.Strategy == layerTypeRefGeneric }
func (n layerTypeRefNode) IsObject() bool    { return n.Strategy == layerTypeRefObject }

// layerTypeRefProfilePlan explicitly covers every generated profile. Missing
// types and profile-only constructors have Callable=false, so source emission
// produces a typed hard failure instead of a canonical-byte fallback.
type layerTypeRefProfilePlan struct {
	Layer              int
	ProfileConstant    string
	ProfileConstants   []string
	Available          bool
	Callable           bool
	Action             layerWireActionKind
	WireID             uint32
	WirePreflightName  string
	WireEncodeName     string
	WireEncodeBodyName string
	WireDecodeName     string
	Value              *layerValuePlan
	Reason             string
	WireEquivalent     bool
}

// layerTypeRefWireEquivalentGroup deduplicates the generated profile
// predicates used by public LayerType descriptors. The predicate is static
// source, not a runtime schema/catalog lookup.
type layerTypeRefWireEquivalentGroup struct {
	Name             string
	ProfileConstants []string
}

// layerRPCTypePlan is one semantic method family. Its profile entries are
// complete, including explicit absent/unavailable methods.
type layerRPCTypePlan struct {
	Key              semantic.SemanticKey
	Name             string
	SemanticConstant string
	Canonical        *layerDefinitionBinding
	Profiles         []layerRPCTypeProfilePlan
}

func (p *layerRPCTypePlan) profile(layer int) *layerRPCTypeProfilePlan {
	if p == nil {
		return nil
	}
	for i := range p.Profiles {
		if p.Profiles[i].Layer == layer {
			return &p.Profiles[i]
		}
	}
	return nil
}

// layerRPCTypeProfilePlan retains the full canonical and target result roots.
// Generic wrapper information is scoped to this exact method profile: a !X
// is a slot, never an alias for Object.
type layerRPCTypeProfilePlan struct {
	Layer             int
	ProfileConstant   string
	Available         bool
	WireID            uint32
	Conversion        *LayerFamilyConversion
	CanonicalResult   int
	WireResult        int
	ResultChanged     bool
	ResultObligations []LayerObligation

	GenericSlots []layerGenericSlotPlan
	GenericUses  []layerGenericUsePlan
	ResultSlots  []int

	// Unwrap is true when a direct generic query field supplies the direct
	// generic result. ResultSourceField is the exact field ordinal whose
	// nested LayerCall replaces the wrapper's result descriptor.
	Unwrap                   bool
	ResultSourceField        int
	NestedProfileSourceField int
}

type layerGenericSlotPlan struct {
	Index int
	Name  string
}

type layerGenericUsePlan struct {
	Slot           int
	FieldOrdinal   int
	FieldName      string
	Node           int
	Path           string
	Direct         bool
	ReplacesResult bool
}

// layerTypeAccessorPlan is the small exported surface of the descriptor DAG.
// Accessors return LayerType values, never pointers to mutable descriptor
// variables. Constructors use their own boxed wrapper around the interned bare
// node, while classes and Object reuse their ordinary root descriptor.
type layerTypeAccessorPlan struct {
	Name                   string
	Kind                   string
	Node                   int
	GoType                 string
	DescriptorName         string
	RefName                string
	EncodeName             string
	DecodeName             string
	DecodeStateName        string
	PreflightName          string
	NodePreflightStateName string
	NodeEncodeStateName    string
	NodeDecodeStateName    string
	SemanticConstant       string
	QName                  string
	Profiles               []layerTypeRefProfilePlan
	WireEquivalentName     string
}

func (a layerTypeAccessorPlan) IsConstructor() bool { return a.Kind == "constructor" }

type layerTypeRefScope struct {
	owner string
	slots map[string]int
}

type layerTypeRefDraft struct {
	key          string
	ref          semantic.TypeRef
	elementKey   string
	genericOwner string
	genericName  string
	genericSlot  int
}

type layerTypeRefCollector struct {
	drafts map[string]*layerTypeRefDraft
}

// buildLayerTypeRefModel compiles every schema TypeRef, every constructor
// class, every exact bare constructor, and every RPC result through the one
// cached LayerConversionPlan and layerValueCompiler.
func (g *Generator) buildLayerTypeRefModel() (*layerTypeRefModel, error) {
	if g == nil || g.schemaSet == nil {
		return nil, fmt.Errorf("gen: layer TypeRef model requires a schema-set generator")
	}
	wires, err := g.buildLayerWireModel()
	if err != nil {
		return nil, err
	}
	compiler, err := g.newLayerValueCompilerForWire(wires)
	if err != nil {
		return nil, err
	}

	collector := &layerTypeRefCollector{drafts: make(map[string]*layerTypeRefDraft)}
	keys := g.schemaSet.SortedKeys()
	for _, layer := range g.schemaSet.Layers() {
		schema := g.schemaSet.Schemas[layer]
		for _, key := range keys {
			definition := schema.ByKey[key]
			if definition == nil {
				continue
			}
			scope := makeLayerTypeRefScope(definition)
			for fieldIndex := range definition.Fields {
				field := &definition.Fields[fieldIndex]
				if field.Kind != semantic.FieldValue {
					continue
				}
				if _, err := collector.add(&field.Type, scope); err != nil {
					return nil, fmt.Errorf("gen: collect layer %d %s field %q TypeRef: %w", layer, key, field.Name, err)
				}
			}
			if _, err := collector.add(&definition.Result, scope); err != nil {
				return nil, fmt.Errorf("gen: collect layer %d %s result TypeRef: %w", layer, key, err)
			}
			if key.Category == semantic.CategoryType {
				bare := semantic.TypeRef{Kind: semantic.TypeNamed, QName: key.QName, Bare: true}
				if _, err := collector.add(&bare, layerTypeRefScope{}); err != nil {
					return nil, fmt.Errorf("gen: collect layer %d %s exact bare TypeRef: %w", layer, key, err)
				}
			}
		}
		classNames := make([]string, 0, len(schema.ConstructorsByClass))
		for className := range schema.ConstructorsByClass {
			classNames = append(classNames, className)
		}
		sort.Strings(classNames)
		for _, className := range classNames {
			classRef := semantic.TypeRef{Kind: semantic.TypeNamed, QName: className}
			if _, err := collector.add(&classRef, layerTypeRefScope{}); err != nil {
				return nil, fmt.Errorf("gen: collect layer %d class %q TypeRef: %w", layer, className, err)
			}
		}
	}
	// Object is a first-class dynamic descriptor even if a particular schema
	// spells every dynamic wrapper as !X.
	object := semantic.TypeRef{Kind: semantic.TypePrimitive, QName: "Object"}
	if _, err := collector.add(&object, layerTypeRefScope{}); err != nil {
		return nil, err
	}

	model, nodeByKey, err := g.finishLayerTypeRefNodes(collector, compiler, wires)
	if err != nil {
		return nil, err
	}
	model.RPCs, err = g.buildLayerRPCTypePlans(collector, nodeByKey)
	if err != nil {
		return nil, err
	}
	for _, rpc := range model.RPCs {
		for _, profile := range rpc.Profiles {
			if count := len(profile.GenericSlots); count > model.MaxGenericSlots {
				model.MaxGenericSlots = count
			}
		}
	}
	model.BindingCapacity = model.MaxGenericSlots
	if model.BindingCapacity < 1 {
		model.BindingCapacity = 1
	}
	model.MaxDepth = layerCodecMaximumDepth
	model.MaxVectorSize = layerCodecMaximumVectorSize
	model.Accessors, err = g.buildLayerTypeAccessors(model, wires)
	if err != nil {
		return nil, err
	}
	for _, accessor := range model.Accessors {
		if accessor.IsConstructor() {
			continue
		}
		if accessor.Node < 0 || accessor.Node >= len(model.Nodes) {
			return nil, fmt.Errorf("gen: public LayerType accessor %q has invalid node %d", accessor.Name, accessor.Node)
		}
		model.Nodes[accessor.Node].Public = true
	}
	return model, nil
}

func makeLayerTypeRefScope(definition *semantic.Definition) layerTypeRefScope {
	if definition == nil || len(definition.GenericParams) == 0 {
		return layerTypeRefScope{}
	}
	slots := make(map[string]int, len(definition.GenericParams))
	for index, name := range definition.GenericParams {
		slots[name] = index
	}
	return layerTypeRefScope{
		owner: definition.Key.String() + "<" + strings.Join(definition.GenericParams, ",") + ">",
		slots: slots,
	}
}

func (c *layerTypeRefCollector) add(ref *semantic.TypeRef, scope layerTypeRefScope) (string, error) {
	if ref == nil {
		return "", fmt.Errorf("nil TypeRef")
	}
	elementKey := ""
	if ref.Arg != nil {
		var err error
		elementKey, err = c.add(ref.Arg, scope)
		if err != nil {
			return "", err
		}
	}
	genericOwner := ""
	genericName := ""
	genericSlot := -1
	if ref.Kind == semantic.TypeGenericRef {
		var ok bool
		genericSlot, ok = scope.slots[ref.QName]
		if !ok || scope.owner == "" {
			return "", fmt.Errorf("generic reference %q has no scoped binding slot", ref.QName)
		}
		genericOwner = scope.owner
		genericName = ref.QName
	}
	key := layerTypeRefStructuralKey(*ref, elementKey, genericOwner, genericSlot)
	if previous := c.drafts[key]; previous != nil {
		if !previous.ref.Equal(*ref) || previous.elementKey != elementKey || previous.genericOwner != genericOwner || previous.genericSlot != genericSlot {
			return "", fmt.Errorf("TypeRef structural key collision for %q", key)
		}
		return key, nil
	}
	c.drafts[key] = &layerTypeRefDraft{
		key:          key,
		ref:          cloneLayerTypeRef(*ref),
		elementKey:   elementKey,
		genericOwner: genericOwner,
		genericName:  genericName,
		genericSlot:  genericSlot,
	}
	return key, nil
}

func layerTypeRefStructuralKey(ref semantic.TypeRef, elementKey, owner string, slot int) string {
	return fmt.Sprintf(
		"typeref/v1/k=%d/q=%q/b=%t/p=%t/e=%q/o=%q/s=%d",
		ref.Kind, ref.QName, ref.Bare, ref.Percent, elementKey, owner, slot,
	)
}

func cloneLayerTypeRef(ref semantic.TypeRef) semantic.TypeRef {
	result := ref
	if ref.Arg != nil {
		arg := cloneLayerTypeRef(*ref.Arg)
		result.Arg = &arg
	}
	return result
}

func (g *Generator) finishLayerTypeRefNodes(
	collector *layerTypeRefCollector,
	compiler *layerValueCompiler,
	wires *layerWireModel,
) (*layerTypeRefModel, map[string]int, error) {
	keys := make([]string, 0, len(collector.drafts))
	for key := range collector.drafts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	indices := make(map[string]int, len(keys))
	for index, key := range keys {
		indices[key] = index
	}
	model := &layerTypeRefModel{
		CanonicalLayer: g.schemaSet.CanonicalLayer,
		Profiles:       g.schemaSet.Layers(),
		Nodes:          make([]layerTypeRefNode, len(keys)),
	}
	for index, key := range keys {
		draft := collector.drafts[key]
		node := layerTypeRefNode{
			Index:                 index,
			Key:                   key,
			Ref:                   cloneLayerTypeRef(draft.ref),
			QName:                 draft.ref.QName,
			Bare:                  draft.ref.Bare,
			Percent:               draft.ref.Percent,
			Element:               -1,
			GenericOwner:          draft.genericOwner,
			GenericName:           draft.genericName,
			GenericSlot:           draft.genericSlot,
			RefName:               fmt.Sprintf("layerTypeRef%dMetadata", index),
			DescriptorName:        fmt.Sprintf("layerTypeRef%dDescriptor", index),
			AnyDescriptorName:     fmt.Sprintf("layerTypeRef%dAnyDescriptor", index),
			BoundDescriptorName:   fmt.Sprintf("layerTypeRef%dBoundDescriptor", index),
			EncodeName:            fmt.Sprintf("layerEncodeTypeRef%d", index),
			DecodeName:            fmt.Sprintf("layerDecodeTypeRef%d", index),
			PreflightName:         fmt.Sprintf("layerPreflightTypeRef%d", index),
			PreflightAnyName:      fmt.Sprintf("layerPreflightTypeRef%dAny", index),
			EncodeAnyStateName:    fmt.Sprintf("layerEncodeTypeRef%dAnyState", index),
			DecodeAnyStateName:    fmt.Sprintf("layerDecodeTypeRef%dAnyState", index),
			PreflightAnyStateName: fmt.Sprintf("layerPreflightTypeRef%dAnyState", index),
			PreflightStateName:    fmt.Sprintf("layerPreflightTypeRef%dState", index),
			EncodeStateName:       fmt.Sprintf("layerEncodeTypeRef%dState", index),
			DecodeStateName:       fmt.Sprintf("layerDecodeTypeRef%dState", index),
			Profiles:              make([]layerTypeRefProfilePlan, 0, len(model.Profiles)),
		}
		if draft.elementKey != "" {
			element, ok := indices[draft.elementKey]
			if !ok {
				return nil, nil, fmt.Errorf("gen: TypeRef %q references missing element %q", key, draft.elementKey)
			}
			node.Element = element
		}
		for _, layer := range model.Profiles {
			profile := layerTypeRefProfilePlan{
				Layer:           layer,
				ProfileConstant: fmt.Sprintf("LayerProfile%d", layer),
				Action:          layerWireAbsent,
			}
			if !layerTypeRefAvailable(g.schemaSet.Schemas[layer], wires, layer, &draft.ref) {
				profile.Reason = "TypeRef is unavailable in the exact profile"
				node.Profiles = append(node.Profiles, profile)
				continue
			}
			value, err := compiler.Compile(layer, &draft.ref)
			if err != nil {
				return nil, nil, fmt.Errorf("gen: compile profile %d TypeRef %s: %w", layer, draft.ref.String(), err)
			}
			profile.Available = true
			profile.Value = value
			if len(value.Constructors) == 1 {
				constructor := value.Constructors[0]
				conversion := constructor.Conversion
				family := wires.family(conversion.Key)
				if family == nil {
					return nil, nil, fmt.Errorf("gen: profile %d TypeRef %s constructor %s has no wire family", layer, draft.ref.String(), conversion.Key)
				}
				action := family.profile(layer)
				if action == nil {
					return nil, nil, fmt.Errorf("gen: profile %d TypeRef %s constructor %s has no wire action", layer, draft.ref.String(), conversion.Key)
				}
				profile.Action = action.Kind
				if conversion.Profile != nil {
					profile.WireID = conversion.Profile.Definition.WireID
					profile.WirePreflightName = fmt.Sprintf("layerPreflightWire%08xBare", profile.WireID)
					profile.WireEncodeName = fmt.Sprintf("layerEncodeWire%08xBare", profile.WireID)
					profile.WireEncodeBodyName = fmt.Sprintf("layerEncodeWire%08xBareBody", profile.WireID)
					profile.WireDecodeName = fmt.Sprintf("layerDecodeWire%08xBare", profile.WireID)
				}
				profile.Callable = layerTypeRefConstructorCallable(wires, layer, constructor, action)
				if !profile.Callable {
					profile.Reason = fmt.Sprintf("wire constructor %#08x has %s action or no canonical representation", profile.WireID, action.Kind)
				}
			}
			node.Profiles = append(node.Profiles, profile)
		}
		node.ProfileGroups = groupLayerTypeRefProfiles(node.Profiles)
		model.Nodes[index] = node
	}

	// Strategy and Go types depend on profile aggregation and child nodes, so
	// they are resolved after every deterministic index exists.
	goTypeState := make([]uint8, len(model.Nodes))
	for index := range model.Nodes {
		if err := g.finishLayerTypeRefNode(model, index, wires, goTypeState); err != nil {
			return nil, nil, err
		}
	}
	if err := finishLayerTypeRefWireEquivalence(model, wires); err != nil {
		return nil, nil, err
	}
	return model, indices, nil
}

// finishLayerTypeRefWireEquivalence proves, at generation time, when a
// canonical frozen byte snapshot is already the exact target-profile wire
// representation. It deliberately recognizes only closed, statically proven
// cases. Retags, rewrites, policy hooks, dynamic Object and generic bindings
// remain on the ordinary decode/adapt/encode path.
func finishLayerTypeRefWireEquivalence(model *layerTypeRefModel, wires *layerWireModel) error {
	if model == nil || wires == nil {
		return fmt.Errorf("gen: layer TypeRef wire equivalence requires TypeRef and wire models")
	}
	states := make([][]uint8, len(model.Nodes))
	for index := range states {
		states[index] = make([]uint8, len(model.Profiles))
	}
	var visit func(int, int) (bool, error)
	visit = func(nodeIndex, profileIndex int) (bool, error) {
		if nodeIndex < 0 || nodeIndex >= len(model.Nodes) || profileIndex < 0 || profileIndex >= len(model.Profiles) {
			return false, fmt.Errorf("gen: invalid TypeRef wire equivalence index node=%d profile=%d", nodeIndex, profileIndex)
		}
		node := &model.Nodes[nodeIndex]
		profile := &node.Profiles[profileIndex]
		switch states[nodeIndex][profileIndex] {
		case 2:
			return profile.WireEquivalent, nil
		case 1:
			return false, fmt.Errorf("gen: cyclic TypeRef wire equivalence at node %d profile %d", nodeIndex, profile.Layer)
		}
		states[nodeIndex][profileIndex] = 1
		equivalent := profile.Layer == model.CanonicalLayer
		if !equivalent {
			switch node.Strategy {
			case layerTypeRefPrimitive:
				equivalent = profile.Available
			case layerTypeRefExactBare, layerTypeRefConcrete:
				equivalent = profile.Available && profile.Callable && profile.Action == layerWireDirect
			case layerTypeRefClass:
				equivalent = layerTypeRefClassWireEquivalent(wires, node.QName, model.CanonicalLayer, profile.Layer)
			case layerTypeRefVector:
				var err error
				equivalent, err = visit(node.Element, profileIndex)
				if err != nil {
					return false, err
				}
			case layerTypeRefGeneric, layerTypeRefObject:
				// The runtime binding/dynamic constructor determines the wire
				// shape, so the complete descriptor cannot prove equivalence.
				equivalent = false
			default:
				return false, fmt.Errorf("gen: unsupported TypeRef strategy %s for wire equivalence", node.Strategy)
			}
		}
		profile.WireEquivalent = equivalent
		states[nodeIndex][profileIndex] = 2
		return equivalent, nil
	}
	for nodeIndex := range model.Nodes {
		for profileIndex := range model.Profiles {
			if _, err := visit(nodeIndex, profileIndex); err != nil {
				return err
			}
		}
	}

	groups := make(map[string]int)
	for nodeIndex := range model.Nodes {
		node := &model.Nodes[nodeIndex]
		constants := make([]string, 0, len(node.Profiles))
		layers := make([]string, 0, len(node.Profiles))
		for _, profile := range node.Profiles {
			if !profile.WireEquivalent {
				continue
			}
			constants = append(constants, profile.ProfileConstant)
			layers = append(layers, fmt.Sprint(profile.Layer))
		}
		key := strings.Join(layers, ",")
		groupIndex, ok := groups[key]
		if !ok {
			groupIndex = len(model.WireEquivalentGroups)
			groups[key] = groupIndex
			model.WireEquivalentGroups = append(model.WireEquivalentGroups, layerTypeRefWireEquivalentGroup{
				Name:             fmt.Sprintf("layerWireEquivalentProfiles%d", groupIndex),
				ProfileConstants: constants,
			})
		}
		node.WireEquivalentName = model.WireEquivalentGroups[groupIndex].Name
	}
	return nil
}

func layerTypeRefClassWireEquivalent(wires *layerWireModel, qname string, canonicalLayer, profileLayer int) bool {
	class := wires.class(qname)
	if class == nil {
		return false
	}
	var canonical, profile *layerClassProfilePlan
	for index := range class.Profiles {
		candidate := &class.Profiles[index]
		switch candidate.Layer {
		case canonicalLayer:
			canonical = candidate
		case profileLayer:
			profile = candidate
		}
	}
	if canonical == nil || profile == nil || len(canonical.Constructors) == 0 ||
		len(profile.Constructors) != len(canonical.Constructors) {
		return false
	}
	for _, canonicalConstructor := range canonical.Constructors {
		if canonicalConstructor.Kind != layerWireDirect {
			return false
		}
		matched := false
		for _, profileConstructor := range profile.Constructors {
			if profileConstructor.Key != canonicalConstructor.Key {
				continue
			}
			if profileConstructor.Kind != layerWireDirect || profileConstructor.WireID != canonicalConstructor.WireID {
				return false
			}
			matched = true
			break
		}
		if !matched {
			return false
		}
	}
	return true
}

func groupLayerTypeRefProfiles(profiles []layerTypeRefProfilePlan) []layerTypeRefProfilePlan {
	groups := make([]layerTypeRefProfilePlan, 0, len(profiles))
	for _, profile := range profiles {
		match := -1
		for index := range groups {
			group := &groups[index]
			if group.Callable == profile.Callable && group.WireID == profile.WireID &&
				group.WirePreflightName == profile.WirePreflightName && group.WireEncodeBodyName == profile.WireEncodeBodyName &&
				group.WireDecodeName == profile.WireDecodeName && group.Reason == profile.Reason {
				match = index
				break
			}
		}
		if match >= 0 {
			groups[match].ProfileConstants = append(groups[match].ProfileConstants, profile.ProfileConstant)
			continue
		}
		profile.ProfileConstants = []string{profile.ProfileConstant}
		groups = append(groups, profile)
	}
	return groups
}

func layerTypeRefConstructorCallable(wires *layerWireModel, layer int, constructor layerValueConstructor, action *layerFamilyProfileAction) bool {
	if wires == nil || constructor.Canonical == nil || action == nil || constructor.Conversion == nil || constructor.Conversion.Profile == nil {
		return false
	}
	switch action.Kind {
	case layerWireDirect, layerWireRetag, layerWireRewrite, layerWirePolicy:
		return true
	case layerWireProfileOnly:
		historical := wires.historicalWire(layer, constructor.Conversion.Profile.Definition.WireID)
		return historical != nil && historical.Target != nil && historical.Target.Key == constructor.Canonical.Key
	default:
		return false
	}
}

func (g *Generator) finishLayerTypeRefNode(model *layerTypeRefModel, index int, wires *layerWireModel, state []uint8) error {
	if state[index] == 2 {
		return nil
	}
	if state[index] == 1 {
		return fmt.Errorf("gen: cyclic TypeRef DAG at node %d", index)
	}
	state[index] = 1
	node := &model.Nodes[index]
	if node.Element >= 0 {
		if err := g.finishLayerTypeRefNode(model, node.Element, wires, state); err != nil {
			return err
		}
		element := &model.Nodes[node.Element]
		node.ElementRefName = element.RefName
		node.ElementGoType = element.GoType
		node.ElementPreflightState = element.PreflightStateName
		node.ElementEncodeState = element.EncodeStateName
		node.ElementDecodeState = element.DecodeStateName
	}

	canonical := nodeProfile(node, model.CanonicalLayer)
	switch node.Ref.Kind {
	case semantic.TypePrimitive:
		if node.Ref.QName == "Object" {
			node.Strategy = layerTypeRefObject
			node.KindConstant = "LayerTypeObject"
			node.GoType = "bin.Object"
			node.EmitCodec = true
			break
		}
		node.Strategy = layerTypeRefPrimitive
		node.KindConstant = "LayerTypePrimitive"
		goType, put, read, err := layerPrimitiveCodec(node.Ref.QName)
		if err != nil {
			return err
		}
		node.GoType, node.PrimitivePut, node.PrimitiveRead = goType, put, read
		node.EmitCodec = true

	case semantic.TypeGenericRef:
		node.Strategy = layerTypeRefGeneric
		node.KindConstant = "LayerTypeGeneric"
		node.GoType = "any"
		node.RequiresBinding = true
		node.EmitCodec = true

	case semantic.TypeVector:
		node.Strategy = layerTypeRefVector
		node.KindConstant = "LayerTypeVector"
		node.BoxedVector = node.Ref.QName == "Vector" && !node.Ref.Bare && !node.Ref.Percent
		if node.Element < 0 {
			return fmt.Errorf("gen: vector TypeRef node %d has no element", index)
		}
		element := &model.Nodes[node.Element]
		node.RequiresBinding = element.RequiresBinding
		if element.EmitCodec {
			node.GoType = "[]" + element.GoType
			node.EmitCodec = true
		}

	case semantic.TypeNamed:
		node.KindConstant = "LayerTypeSemantic"
		if node.Ref.Bare || node.Ref.Percent {
			node.Strategy = layerTypeRefExactBare
			key := semantic.SemanticKey{Category: semantic.CategoryType, QName: node.Ref.QName}
			node.SemanticConstant = layerSemanticConstant(key)
			if canonical != nil && canonical.Available && canonical.Value != nil && len(canonical.Value.Constructors) == 1 {
				binding := canonical.Value.Constructors[0].Canonical
				if binding != nil {
					node.GoType = binding.Structure.Name
					node.EmitCodec = true
					node.AcceptPointer = true
				}
			}
			if !node.EmitCodec {
				// Wire-result TypeRefs may retain the deleted constructor name.
				// Their unique shared mapping still gives the node one canonical
				// Go representation, so RPC result adaptation can bind it.
				if binding := wires.historicalSourceTarget(key); binding != nil && binding.Structure != nil {
					node.GoType = binding.Structure.Name
					node.EmitCodec = true
					node.AcceptPointer = true
				}
			}
			break
		}
		class := wires.class(node.Ref.QName)
		if class == nil {
			return fmt.Errorf("gen: boxed TypeRef node %d class %q has no wire class plan", index, node.Ref.QName)
		}
		node.ClassCodecSuffix = layerTypeRefClassSuffix(node.Ref.QName)
		if class.Canonical != nil {
			node.GoType = class.Canonical.Backend.Name
			node.EmitCodec = true
			node.AcceptPointer = class.Canonical.Backend.Singular
		}
		concrete := class.Canonical != nil && class.Canonical.Backend.Singular
		if concrete {
			node.Strategy = layerTypeRefConcrete
			if len(class.Canonical.Constructors) != 1 {
				return fmt.Errorf("gen: singular canonical class %q has %d constructors", node.Ref.QName, len(class.Canonical.Constructors))
			}
			canonicalKey := class.Canonical.Constructors[0].Key
			for profileIndex := range node.Profiles {
				profile := &node.Profiles[profileIndex]
				profile.Callable = false
				profile.Reason = "canonical singular constructor is unavailable in exact class profile"
				if profile.Value == nil {
					continue
				}
				for _, constructor := range profile.Value.Constructors {
					if constructor.Conversion == nil || constructor.Canonical == nil || constructor.Canonical.Key != canonicalKey {
						continue
					}
					family := wires.family(constructor.Conversion.Key)
					if family == nil {
						return fmt.Errorf("gen: singular canonical class %q constructor %s has no wire family", node.Ref.QName, constructor.Conversion.Key)
					}
					action := family.profile(profile.Layer)
					if action == nil || constructor.Conversion.Profile == nil {
						continue
					}
					profile.Action = action.Kind
					profile.WireID = constructor.Conversion.Profile.Definition.WireID
					profile.WirePreflightName = fmt.Sprintf("layerPreflightWire%08xBare", profile.WireID)
					profile.WireEncodeName = fmt.Sprintf("layerEncodeWire%08xBare", profile.WireID)
					profile.WireEncodeBodyName = fmt.Sprintf("layerEncodeWire%08xBareBody", profile.WireID)
					profile.WireDecodeName = fmt.Sprintf("layerDecodeWire%08xBare", profile.WireID)
					profile.Callable = layerTypeRefConstructorCallable(wires, profile.Layer, constructor, action)
					if profile.Callable {
						profile.Reason = ""
					} else {
						profile.Reason = fmt.Sprintf("wire constructor %#08x has %s action or no canonical representation", profile.WireID, action.Kind)
					}
					break
				}
			}
		} else {
			node.Strategy = layerTypeRefClass
		}

	default:
		return fmt.Errorf("gen: unsupported TypeRef kind %d at node %d", node.Ref.Kind, index)
	}
	node.Runnable = node.EmitCodec && !node.RequiresBinding
	state[index] = 2
	return nil
}

func layerPrimitiveCodec(qname string) (goType, put, read string, err error) {
	switch qname {
	case "int", "Int":
		return "int", "PutInt", "Int", nil
	case "int32":
		return "int32", "PutInt32", "Int32", nil
	case "int53":
		return "int64", "PutInt53", "Int53", nil
	case "long", "int64", "Long":
		return "int64", "PutLong", "Long", nil
	case "int128":
		return "bin.Int128", "PutInt128", "Int128", nil
	case "int256":
		return "bin.Int256", "PutInt256", "Int256", nil
	case "double", "Double":
		return "float64", "PutDouble", "Double", nil
	case "string", "String":
		return "string", "PutString", "String", nil
	case "bytes", "Bytes":
		return "[]byte", "PutBytes", "Bytes", nil
	case "bool", "Bool", "true", "false", "True":
		return "bool", "PutBool", "Bool", nil
	default:
		return "", "", "", fmt.Errorf("gen: unsupported primitive TypeRef %q", qname)
	}
}

func layerTypeRefClassSuffix(qname string) string {
	parts := strings.Split(qname, ".")
	return namespacedName(parts[len(parts)-1], parts[:len(parts)-1])
}

func nodeProfile(node *layerTypeRefNode, layer int) *layerTypeRefProfilePlan {
	if node == nil {
		return nil
	}
	for i := range node.Profiles {
		if node.Profiles[i].Layer == layer {
			return &node.Profiles[i]
		}
	}
	return nil
}

func layerTypeRefAvailable(schema *semantic.SchemaModel, wires *layerWireModel, layer int, ref *semantic.TypeRef) bool {
	if schema == nil || ref == nil {
		return false
	}
	switch ref.Kind {
	case semantic.TypePrimitive, semantic.TypeGenericRef:
		return true
	case semantic.TypeVector:
		return ref.Arg != nil && layerTypeRefAvailable(schema, wires, layer, ref.Arg)
	case semantic.TypeNamed:
		if ref.Bare || ref.Percent {
			key := semantic.SemanticKey{Category: semantic.CategoryType, QName: ref.QName}
			return schema.ByKey[key] != nil || wires.historicalTarget(layer, key) != nil
		}
		return len(schema.ConstructorsByClass[ref.QName]) != 0
	default:
		return false
	}
}

func (g *Generator) buildLayerRPCTypePlans(collector *layerTypeRefCollector, nodeByKey map[string]int) ([]layerRPCTypePlan, error) {
	bindings, err := g.buildLayerBindings()
	if err != nil {
		return nil, fmt.Errorf("gen: RPC TypeRef canonical bindings: %w", err)
	}
	result := make([]layerRPCTypePlan, 0)
	canonicalLayer := g.schemaSet.CanonicalLayer
	for _, key := range g.schemaSet.SortedKeys() {
		if key.Category != semantic.CategoryFunction {
			continue
		}
		family := g.schemaSet.Families[key]
		plan := layerRPCTypePlan{
			Key:              key,
			Name:             layerTypeRefClassSuffix(key.QName),
			SemanticConstant: layerSemanticConstant(key),
		}
		if canonical := family.ProfilesByLayer[canonicalLayer]; canonical != nil {
			plan.Canonical = bindings.definition(key)
		}
		for _, layer := range g.schemaSet.Layers() {
			conversion := g.LayerConversionPlan().Profile(layer).Family(key)
			if conversion == nil {
				return nil, fmt.Errorf("gen: RPC TypeRef profile %d misses conversion for %s", layer, key)
			}
			profile := layerRPCTypeProfilePlan{
				Layer:                    layer,
				ProfileConstant:          fmt.Sprintf("LayerProfile%d", layer),
				Conversion:               conversion,
				CanonicalResult:          -1,
				WireResult:               -1,
				ResultChanged:            conversion.ResultChanged,
				ResultObligations:        conversion.ResultObligations(),
				ResultSourceField:        -1,
				NestedProfileSourceField: -1,
			}
			if conversion.Canonical != nil {
				definition := conversion.Canonical.Definition
				scope := makeLayerTypeRefScope(definition)
				rootKey, err := collector.add(&definition.Result, scope)
				if err != nil {
					return nil, err
				}
				var ok bool
				profile.CanonicalResult, ok = nodeByKey[rootKey]
				if !ok {
					return nil, fmt.Errorf("gen: RPC TypeRef profile %d %s canonical result node %q was not finalized", layer, key, rootKey)
				}
			}
			if conversion.Profile != nil {
				profile.Available = true
				definition := conversion.Profile.Definition
				profile.WireID = definition.WireID
				scope := makeLayerTypeRefScope(definition)
				rootKey, err := collector.add(&definition.Result, scope)
				if err != nil {
					return nil, err
				}
				var ok bool
				profile.WireResult, ok = nodeByKey[rootKey]
				if !ok {
					return nil, fmt.Errorf("gen: RPC TypeRef profile %d %s result node %q was not finalized", layer, key, rootKey)
				}
				profile.GenericSlots = makeLayerGenericSlots(definition)
				profile.ResultSlots = layerTypeRefSlots(&definition.Result, scope)
				for fieldIndex := range definition.Fields {
					field := &definition.Fields[fieldIndex]
					if field.Kind != semantic.FieldValue {
						continue
					}
					fieldKey, err := collector.add(&field.Type, scope)
					if err != nil {
						return nil, err
					}
					fieldNode, ok := nodeByKey[fieldKey]
					if !ok {
						return nil, fmt.Errorf("gen: RPC TypeRef profile %d %s field %q node was not finalized", layer, key, field.Name)
					}
					uses := collectLayerGenericUses(&field.Type, scope, field.Ordinal, field.Name, fieldNode)
					profile.GenericUses = append(profile.GenericUses, uses...)
					if key.QName == "invokeWithLayer" && field.Name == "layer" && field.Type.Kind == semantic.TypePrimitive {
						profile.NestedProfileSourceField = field.Ordinal
					}
				}
				profile.finishWrapperMetadata()
			}
			plan.Profiles = append(plan.Profiles, profile)
		}
		result = append(result, plan)
	}
	return result, nil
}

func makeLayerGenericSlots(definition *semantic.Definition) []layerGenericSlotPlan {
	result := make([]layerGenericSlotPlan, 0, len(definition.GenericParams))
	for index, name := range definition.GenericParams {
		result = append(result, layerGenericSlotPlan{Index: index, Name: name})
	}
	return result
}

func layerTypeRefSlots(ref *semantic.TypeRef, scope layerTypeRefScope) []int {
	set := make(map[int]struct{})
	var visit func(*semantic.TypeRef)
	visit = func(current *semantic.TypeRef) {
		if current == nil {
			return
		}
		if current.Kind == semantic.TypeGenericRef {
			if slot, ok := scope.slots[current.QName]; ok {
				set[slot] = struct{}{}
			}
		}
		visit(current.Arg)
	}
	visit(ref)
	result := make([]int, 0, len(set))
	for slot := range set {
		result = append(result, slot)
	}
	sort.Ints(result)
	return result
}

func collectLayerGenericUses(ref *semantic.TypeRef, scope layerTypeRefScope, ordinal int, fieldName string, node int) []layerGenericUsePlan {
	result := make([]layerGenericUsePlan, 0)
	var visit func(*semantic.TypeRef, string)
	visit = func(current *semantic.TypeRef, path string) {
		if current == nil {
			return
		}
		if current.Kind == semantic.TypeGenericRef {
			slot, ok := scope.slots[current.QName]
			if ok {
				result = append(result, layerGenericUsePlan{
					Slot:         slot,
					FieldOrdinal: ordinal,
					FieldName:    fieldName,
					Node:         node,
					Path:         path,
					Direct:       path == "",
				})
			}
		}
		if current.Arg != nil {
			next := "element"
			if path != "" {
				next = path + ".element"
			}
			visit(current.Arg, next)
		}
	}
	visit(ref, "")
	return result
}

func (p *layerRPCTypeProfilePlan) finishWrapperMetadata() {
	if p == nil || len(p.ResultSlots) != 1 {
		return
	}
	resultSlot := p.ResultSlots[0]
	source := -1
	for index := range p.GenericUses {
		use := &p.GenericUses[index]
		if use.Slot != resultSlot {
			continue
		}
		use.ReplacesResult = true
		if use.Direct {
			if source == -1 {
				source = use.FieldOrdinal
			} else if source != use.FieldOrdinal {
				source = -2
			}
		}
	}
	if source >= 0 {
		p.Unwrap = true
		p.ResultSourceField = source
	}
}

func (g *Generator) buildLayerTypeAccessors(model *layerTypeRefModel, wires *layerWireModel) ([]layerTypeAccessorPlan, error) {
	if model == nil || wires == nil {
		return nil, fmt.Errorf("gen: layer TypeRef accessors require TypeRef and wire models")
	}
	used := make(map[string]string)
	for index := range g.structs {
		used[g.structs[index].Name] = "canonical-type:" + g.structs[index].RawName
	}
	for index := range g.interfaces {
		used[g.interfaces[index].Name] = "canonical-class:" + g.interfaces[index].RawType
	}
	for _, name := range []string{"EncodeLayer", "DecodeLayer", "ResolveLayerProfile", "LayerWireID", "LayerSemanticName"} {
		used[name] = "generated-layer-api"
	}
	add := func(result *[]layerTypeAccessorPlan, accessor layerTypeAccessorPlan) error {
		if accessor.Name == "" || accessor.GoType == "" || accessor.DescriptorName == "" {
			return fmt.Errorf("gen: incomplete layer TypeRef accessor for %s %q", accessor.Kind, accessor.QName)
		}
		identity := accessor.Kind + ":" + accessor.QName
		if previous, duplicate := used[accessor.Name]; duplicate {
			return fmt.Errorf("gen: layer TypeRef accessor %q collides for %s and %s", accessor.Name, previous, identity)
		}
		used[accessor.Name] = identity
		*result = append(*result, accessor)
		return nil
	}

	result := make([]layerTypeAccessorPlan, 0, len(wires.Classes)+len(g.schemaSet.Schemas[g.schemaSet.CanonicalLayer].Definitions)+1)
	for index := range model.Nodes {
		node := &model.Nodes[index]
		if !node.IsObject() {
			continue
		}
		if !node.Runnable {
			return nil, fmt.Errorf("gen: dynamic Object TypeRef node is not runnable")
		}
		if err := add(&result, layerTypeAccessorPlan{
			Name:               "LayerObjectType",
			Kind:               "object",
			Node:               node.Index,
			GoType:             node.GoType,
			DescriptorName:     node.DescriptorName,
			WireEquivalentName: node.WireEquivalentName,
			QName:              node.QName,
		}); err != nil {
			return nil, err
		}
	}

	for classIndex := range wires.Classes {
		class := &wires.Classes[classIndex]
		if class.Canonical == nil {
			continue
		}
		node := findLayerTypeRefClassNode(model, class.QName)
		if node == nil || !node.Runnable {
			return nil, fmt.Errorf("gen: canonical class %q has no runnable TypeRef descriptor", class.QName)
		}
		if err := add(&result, layerTypeAccessorPlan{
			Name:               "LayerClass" + layerTypeRefClassSuffix(class.QName) + "Type",
			Kind:               "class",
			Node:               node.Index,
			GoType:             node.GoType,
			DescriptorName:     node.DescriptorName,
			WireEquivalentName: node.WireEquivalentName,
			QName:              class.QName,
		}); err != nil {
			return nil, err
		}
	}

	canonical := g.schemaSet.Schemas[g.schemaSet.CanonicalLayer]
	definitions := append([]*semantic.Definition(nil), canonical.Definitions...)
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].Key.String() < definitions[j].Key.String() })
	for _, definition := range definitions {
		if definition.Key.Category != semantic.CategoryType {
			continue
		}
		ref := semantic.TypeRef{Kind: semantic.TypeNamed, QName: definition.Key.QName, Bare: true}
		key := layerTypeRefStructuralKey(ref, "", "", -1)
		index, ok := layerTypeRefNodeIndex(model, key)
		if !ok {
			return nil, fmt.Errorf("gen: canonical constructor %s has no exact TypeRef node", definition.Key)
		}
		node := &model.Nodes[index]
		if !node.Runnable || !node.AcceptPointer {
			return nil, fmt.Errorf("gen: canonical constructor %s exact TypeRef is not runnable", definition.Key)
		}
		name := node.GoType
		accessor := layerTypeAccessorPlan{
			Name:                   "LayerConstructor" + name + "Type",
			Kind:                   "constructor",
			Node:                   node.Index,
			GoType:                 "*" + name,
			DescriptorName:         "layerConstructor" + name + "Descriptor",
			RefName:                "layerConstructor" + name + "Metadata",
			EncodeName:             "layerEncodeConstructor" + name,
			DecodeName:             "layerDecodeConstructor" + name,
			DecodeStateName:        fmt.Sprintf("layerDecodeConstructorState%08x", definition.WireID),
			PreflightName:          "layerPreflightConstructor" + name,
			NodePreflightStateName: node.PreflightStateName,
			NodeEncodeStateName:    node.EncodeStateName,
			NodeDecodeStateName:    node.DecodeStateName,
			SemanticConstant:       layerSemanticConstant(definition.Key),
			QName:                  definition.Key.QName,
			Profiles:               append([]layerTypeRefProfilePlan(nil), node.Profiles...),
			WireEquivalentName:     node.WireEquivalentName,
		}
		if err := add(&result, accessor); err != nil {
			return nil, err
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func findLayerTypeRefClassNode(model *layerTypeRefModel, qname string) *layerTypeRefNode {
	for index := range model.Nodes {
		node := &model.Nodes[index]
		if node.Ref.Kind == semantic.TypeNamed && !node.Bare && !node.Percent && node.QName == qname {
			return node
		}
	}
	return nil
}

func layerTypeRefNodeIndex(model *layerTypeRefModel, key string) (int, bool) {
	for index := range model.Nodes {
		if model.Nodes[index].Key == key {
			return index, true
		}
	}
	return 0, false
}
