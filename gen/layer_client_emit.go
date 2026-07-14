package gen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gotd/td/gen/semantic"
)

// layerClientSourceModel is the generated, statically routed client facade.
// It accepts canonical request structs, selects one exact profile method ID,
// and decodes the complete method result TypeRef back to the canonical Go
// representation. Runtime code does not interpret schema metadata.
type layerClientSourceModel struct {
	Profiles   []int
	Methods    []layerClientSourceMethod
	Encoders   []string
	Adapters   []string
	HookChecks []layerRPCSourceHookCheck
}

type layerClientResultKind uint8

const (
	layerClientResultValue layerClientResultKind = iota
	layerClientResultPointer
	layerClientResultPointerValue
	layerClientResultBool
	layerClientResultErrorOnly
)

type layerClientSourceMethod struct {
	Method       *layerRPCMethodPlan
	Structure    *structDef
	Name         string
	ResultType   string
	ResultGoType string
	ResultKind   layerClientResultKind
	PrepareBody  string
}

func (m layerClientSourceMethod) ErrorOnly() bool {
	return m.ResultKind == layerClientResultErrorOnly
}

func (m layerClientSourceMethod) PointerResult() bool {
	return m.ResultKind == layerClientResultPointer
}

func (m layerClientSourceMethod) PointerValueResult() bool {
	return m.ResultKind == layerClientResultPointerValue
}

func (m layerClientSourceMethod) BoolResult() bool {
	return m.ResultKind == layerClientResultBool
}

type layerClientSourceEmitter struct {
	rpc         *layerRPCModel
	refs        *layerTypeRefModel
	rpcRefByKey map[semantic.SemanticKey]*layerRPCTypePlan
	hookByName  map[string]string
	encoders    map[string]struct{}
	adapters    map[string]struct{}
	model       *layerClientSourceModel
}

func (g *Generator) buildLayerClientSourceModel(rpc *layerRPCModel, refs *layerTypeRefModel) (*layerClientSourceModel, error) {
	if g == nil || g.schemaSet == nil {
		return nil, fmt.Errorf("gen: layer client source requires a schema-set generator")
	}
	if rpc == nil || refs == nil {
		return nil, fmt.Errorf("gen: layer client source requires RPC and TypeRef models")
	}
	if rpc.CanonicalLayer != refs.CanonicalLayer || rpc.CanonicalLayer != g.schemaSet.CanonicalLayer ||
		!equalLayerRPCSourceProfiles(rpc.Profiles, refs.Profiles) || !equalLayerRPCSourceProfiles(rpc.Profiles, g.schemaSet.Layers()) {
		return nil, fmt.Errorf("gen: layer client source models do not share one exact profile universe")
	}
	emitter := &layerClientSourceEmitter{
		rpc:         rpc,
		refs:        refs,
		rpcRefByKey: make(map[semantic.SemanticKey]*layerRPCTypePlan, len(refs.RPCs)),
		hookByName:  make(map[string]string),
		encoders:    make(map[string]struct{}),
		adapters:    make(map[string]struct{}),
		model: &layerClientSourceModel{
			Profiles: append([]int(nil), rpc.Profiles...),
		},
	}
	for index := range refs.RPCs {
		plan := &refs.RPCs[index]
		if previous := emitter.rpcRefByKey[plan.Key]; previous != nil {
			return nil, fmt.Errorf("gen: layer client repeats RPC TypeRef plan %s", plan.Key)
		}
		emitter.rpcRefByKey[plan.Key] = plan
	}
	if len(emitter.rpcRefByKey) != len(rpc.Methods) {
		return nil, fmt.Errorf("gen: layer client method/TypeRef count mismatch: RPC=%d TypeRef=%d", len(rpc.Methods), len(emitter.rpcRefByKey))
	}
	requestTypes := make(map[string]semantic.SemanticKey)
	handlerCount := 0
	for methodIndex := range rpc.Methods {
		method := &rpc.Methods[methodIndex]
		if !method.Handler {
			continue
		}
		handlerCount++
		source, err := emitter.buildMethod(method)
		if err != nil {
			return nil, fmt.Errorf("gen: layer client facade %s: %w", method.Key, err)
		}
		if previous, ok := requestTypes[source.Structure.Name]; ok {
			return nil, fmt.Errorf("gen: E_LAYER_CLIENT_REQUEST_AMBIGUOUS: canonical request %s routes both %s and %s", source.Structure.Name, previous, method.Key)
		}
		requestTypes[source.Structure.Name] = method.Key
		emitter.model.Methods = append(emitter.model.Methods, source)
	}
	if len(emitter.model.Methods) != handlerCount || len(requestTypes) != handlerCount {
		return nil, fmt.Errorf("gen: E_LAYER_CLIENT_REQUEST_SWITCH_INCOMPLETE: ordinary methods=%d generated cases=%d unique requests=%d", handlerCount, len(emitter.model.Methods), len(requestTypes))
	}
	sort.Slice(emitter.model.Methods, func(i, j int) bool {
		return emitter.model.Methods[i].Method.Key.String() < emitter.model.Methods[j].Method.Key.String()
	})
	sort.Strings(emitter.model.Encoders)
	sort.Strings(emitter.model.Adapters)
	sort.Slice(emitter.model.HookChecks, func(i, j int) bool {
		return emitter.model.HookChecks[i].Name < emitter.model.HookChecks[j].Name
	})
	return emitter.model, nil
}

func (e *layerClientSourceEmitter) buildMethod(method *layerRPCMethodPlan) (layerClientSourceMethod, error) {
	if method == nil || !method.Handler || method.Canonical == nil || method.Canonical.Structure == nil || method.Canonical.Definition == nil {
		return layerClientSourceMethod{}, fmt.Errorf("E_LAYER_CLIENT_CANONICAL_REQUEST_ABSENT: ordinary method has no canonical request binding")
	}
	refMethod := e.rpcRefByKey[method.Key]
	if refMethod == nil {
		return layerClientSourceMethod{}, fmt.Errorf("E_LAYER_CLIENT_RESULT_TYPEREF_ABSENT: method has no TypeRef plan")
	}
	canonicalProfile := refMethod.profile(e.rpc.CanonicalLayer)
	if canonicalProfile == nil || !canonicalProfile.Available || canonicalProfile.CanonicalResult < 0 || canonicalProfile.CanonicalResult >= len(e.refs.Nodes) {
		return layerClientSourceMethod{}, fmt.Errorf("E_LAYER_CLIENT_RESULT_TYPEREF_ABSENT: method has no canonical result TypeRef")
	}
	canonicalResult := &e.refs.Nodes[canonicalProfile.CanonicalResult]
	if canonicalResult.RequiresBinding || !canonicalResult.Runnable || canonicalResult.GoType == "" || canonicalResult.BoundDescriptorName == "" {
		return layerClientSourceMethod{}, fmt.Errorf("E_LAYER_CLIENT_RESULT_UNSUPPORTED: canonical result %s is not a standalone runnable TypeRef", canonicalResult.Ref.String())
	}
	if !canonicalResult.Ref.Equal(method.Canonical.Definition.Result) {
		return layerClientSourceMethod{}, fmt.Errorf("E_LAYER_CLIENT_RESULT_TYPEREF_STALE: canonical result disagrees with method definition")
	}

	structure := method.Canonical.Structure
	name := structure.Method
	if name == "" {
		parts := strings.Split(method.Key.QName, ".")
		name = namespacedName(parts[len(parts)-1], parts[:len(parts)-1])
		if structure.Name != name+"Request" {
			return layerClientSourceMethod{}, fmt.Errorf("E_LAYER_CLIENT_NAME_MISMATCH: request %q does not match facade %q", structure.Name, name)
		}
	}
	source := layerClientSourceMethod{
		Method:       method,
		Structure:    structure,
		Name:         name,
		ResultGoType: canonicalResult.GoType,
	}
	switch {
	case canonicalResult.IsConcrete() && canonicalResult.Ref.QName == "Ok":
		source.ResultKind = layerClientResultErrorOnly
	case canonicalResult.IsPrimitive(), canonicalResult.IsObject(), canonicalResult.IsClass(), canonicalResult.IsVector():
		source.ResultType = canonicalResult.GoType
	case canonicalResult.IsConcrete():
		source.ResultKind = layerClientResultPointer
		source.ResultType = "*" + canonicalResult.GoType
	case canonicalResult.IsExactBare():
		source.ResultKind = layerClientResultPointerValue
		source.ResultType = canonicalResult.GoType
	default:
		return layerClientSourceMethod{}, fmt.Errorf("E_LAYER_CLIENT_RESULT_UNSUPPORTED: canonical result %s strategy %s has no facade", canonicalResult.Ref.String(), canonicalResult.Strategy)
	}
	if canonicalResult.IsClass() && canonicalResult.Ref.QName == "Bool" {
		source.ResultKind = layerClientResultBool
		source.ResultType = "bool"
	}
	if !source.ErrorOnly() && source.ResultType == "" {
		return layerClientSourceMethod{}, fmt.Errorf("E_LAYER_CLIENT_RESULT_UNSUPPORTED: canonical result %s produced no return type", canonicalResult.Ref.String())
	}

	var prepare strings.Builder
	prepare.WriteString("switch profile {\n")
	for _, layer := range e.rpc.Profiles {
		profile := method.profile(layer)
		refProfile := refMethod.profile(layer)
		fmt.Fprintf(&prepare, "case LayerProfile%d:\n", layer)
		if reason := e.unavailableReason(method, profile, refProfile); reason != "" {
			fmt.Fprintf(&prepare, "\treturn LayerOutboundCall{}, &LayerCodecError{Operation: \"prepare RPC client call\", Profile: profile, Semantic: %s, Reason: %q}\n", method.Constant, reason)
			continue
		}
		canonicalNode := &e.refs.Nodes[refProfile.CanonicalResult]
		wireNode := &e.refs.Nodes[refProfile.WireResult]
		if canonicalNode.Index != canonicalResult.Index || canonicalNode.RefName != canonicalResult.RefName || !canonicalNode.Ref.Equal(canonicalResult.Ref) {
			return layerClientSourceMethod{}, fmt.Errorf("profile %d canonical result TypeRef is stale", layer)
		}
		if wireNode.RequiresBinding || !wireNode.Runnable || wireNode.GoType == "" || wireNode.BoundDescriptorName == "" {
			return layerClientSourceMethod{}, fmt.Errorf("profile %d wire result %s is not a standalone runnable TypeRef", layer, wireNode.Ref.String())
		}
		encoder := e.addRequestEncoder(method, profile)
		adapter := ""
		var err error
		switch profile.Result.ClientAction {
		case layerRPCDirect:
			if !canonicalNode.Ref.Equal(wireNode.Ref) {
				return layerClientSourceMethod{}, fmt.Errorf("profile %d direct client result has unequal TypeRefs", layer)
			}
		case layerRPCAdapter:
			adapter, err = e.addResultAdapter(method, profile, canonicalNode, wireNode)
			if err != nil {
				return layerClientSourceMethod{}, fmt.Errorf("profile %d client result adapter: %w", layer, err)
			}
		default:
			return layerClientSourceMethod{}, fmt.Errorf("profile %d unexpectedly passed availability with result action %s", layer, profile.Result.ClientAction)
		}
		fmt.Fprintf(&prepare, "\treturn LayerOutboundCall{call: layerClientCall{profile: profile, method: %s, wireID: 0x%08x, canonicalResult: &%s, wireResult: &%s, request: request, encodeRequest: %s, decodeResult: %s", method.Constant, profile.WireID, canonicalNode.RefName, wireNode.RefName, encoder, wireNode.BoundDescriptorName)
		if adapter != "" {
			fmt.Fprintf(&prepare, ", adaptResult: %s", adapter)
		}
		prepare.WriteString("}}, nil\n")
	}
	prepare.WriteString("default:\n")
	fmt.Fprintf(&prepare, "\treturn LayerOutboundCall{}, &LayerCodecError{Operation: \"prepare RPC client call\", Profile: profile, Semantic: %s, Reason: \"unsupported exact profile\"}\n", method.Constant)
	prepare.WriteString("}\n")
	source.PrepareBody = prepare.String()
	return source, nil
}

func (e *layerClientSourceEmitter) unavailableReason(method *layerRPCMethodPlan, profile *layerRPCMethodProfile, refProfile *layerRPCTypeProfilePlan) string {
	if profile == nil || refProfile == nil {
		return "method has no generated exact-profile plan"
	}
	if profile.Definition == nil || !refProfile.Available {
		return "method is unavailable in exact profile"
	}
	if profile.Wrapper != nil {
		return "transparent RPC wrappers are not callable as terminal layer-client methods"
	}
	if profile.WireID == 0 || profile.WireID != profile.Definition.WireID || profile.WireID != refProfile.WireID {
		return "method wire identity is stale"
	}
	if profile.ClientRequest == layerRPCReject || profile.ClientRequest == layerRPCUnavailable {
		return "canonical request cannot be encoded for exact profile"
	}
	if profile.Result.ClientAction == layerRPCReject || profile.Result.ClientAction == layerRPCUnavailable {
		return "wire result cannot be decoded to the canonical result without loss"
	}
	if refProfile.CanonicalResult < 0 || refProfile.CanonicalResult >= len(e.refs.Nodes) ||
		refProfile.WireResult < 0 || refProfile.WireResult >= len(e.refs.Nodes) {
		return "method has incomplete result TypeRef descriptors"
	}
	if method.Canonical == nil || method.Canonical.Structure == nil {
		return "method has no canonical request structure"
	}
	return ""
}

func (e *layerClientSourceEmitter) addRequestEncoder(method *layerRPCMethodPlan, profile *layerRPCMethodProfile) string {
	name := fmt.Sprintf("layerClientEncode%s_%08x", method.Canonical.Structure.Name, profile.WireID)
	if _, exists := e.encoders[name]; exists {
		return name
	}
	e.encoders[name] = struct{}{}
	var source strings.Builder
	fmt.Fprintf(&source, "func %s(profile LayerProfile, value any, b *bin.Buffer, state *layerCodecState) error {\n", name)
	fmt.Fprintf(&source, "\trequest, ok := value.(*%s)\n", method.Canonical.Structure.Name)
	fmt.Fprintf(&source, "\tif !ok || request == nil { return &LayerCodecError{Operation: \"encode RPC client request\", Profile: profile, Semantic: %s, WireID: 0x%08x, Reason: fmt.Sprintf(\"canonical request has type %%T, want *%s\", value)} }\n", method.Constant, profile.WireID, method.Canonical.Structure.Name)
	fmt.Fprintf(&source, "\treturn layerEncodeWire%08x(profile, request, b, state)\n", profile.WireID)
	source.WriteString("}\n")
	e.model.Encoders = append(e.model.Encoders, source.String())
	return name
}

func (e *layerClientSourceEmitter) addResultAdapter(method *layerRPCMethodPlan, profile *layerRPCMethodProfile, canonical, wire *layerTypeRefNode) (string, error) {
	hook := strings.TrimSpace(profile.Result.ClientAdapter)
	if hook == "" {
		return "", fmt.Errorf("profile-to-canonical result adapter has no policy hook")
	}
	wireType := layerRPCResultHookType(wire)
	canonicalType := layerRPCResultHookType(canonical)
	signature := fmt.Sprintf("func(LayerProfile, %s) (%s, error)", wireType, canonicalType)
	if previous, exists := e.hookByName[hook]; exists {
		if previous != signature {
			return "", fmt.Errorf("layer client policy hook %q has incompatible signatures %q and %q", hook, previous, signature)
		}
	} else {
		e.hookByName[hook] = signature
		e.model.HookChecks = append(e.model.HookChecks, layerRPCSourceHookCheck{Name: hook, Signature: signature})
	}

	name := fmt.Sprintf("layerClientAdaptRPCResult%d_%08x", profile.Layer, profile.WireID)
	if _, exists := e.adapters[name]; exists {
		return name, nil
	}
	e.adapters[name] = struct{}{}
	var source strings.Builder
	fmt.Fprintf(&source, "func %s(profile LayerProfile, value any) (any, error) {\n", name)
	if wire.AcceptPointer {
		fmt.Fprintf(&source, "\tvar typed *%s\n", wire.GoType)
		fmt.Fprintf(&source, "\tswitch candidate := value.(type) { case %s: copy := candidate; typed = &copy; case *%s: typed = candidate; default: return nil, fmt.Errorf(\"RPC client result adapter %s expected %s, got %%T\", value) }\n", wire.GoType, wire.GoType, hook, wireType)
		fmt.Fprintf(&source, "\tif typed == nil { return nil, fmt.Errorf(\"RPC client result adapter %s received nil %s\") }\n", hook, wireType)
	} else {
		fmt.Fprintf(&source, "\ttyped, ok := value.(%s)\n", wire.GoType)
		fmt.Fprintf(&source, "\tif !ok { return nil, fmt.Errorf(\"RPC client result adapter %s expected %s, got %%T\", value) }\n", hook, wireType)
	}
	fmt.Fprintf(&source, "\tadapted, err := %s(profile, typed)\n", hook)
	fmt.Fprintf(&source, "\tif err != nil { return nil, fmt.Errorf(\"RPC client result adapter %s: %%w\", err) }\n", hook)
	source.WriteString("\treturn adapted, nil\n}\n")
	e.model.Adapters = append(e.model.Adapters, source.String())
	return name, nil
}
