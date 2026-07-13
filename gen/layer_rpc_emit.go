package gen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gotd/td/gen/semantic"
)

// layerRPCSourceModel is the source-only projection of layerRPCModel and
// layerTypeRefModel. It contains Go identifiers and already-expanded route
// bodies; generated code never interprets either model at runtime.
type layerRPCSourceModel struct {
	LayerRPC     *layerRPCModel
	Profiles     []layerRPCSourceProfile
	Routes       []layerRPCSourceRoute
	Handlers     []layerRPCSourceHandler
	Adapters     []string
	HookChecks   []layerRPCSourceHookCheck
	Unprofiled   *layerRPCUnprofiledSource
	MaxDepth     int
	RouteCount   int
	WrapperCount int
}

// layerRPCSourceHandler is the complete canonical ServerDispatcher facade for
// one ordinary semantic method. ResultType and CanonicalResultEncoder are
// lowered from the canonical result TypeRef; legacy structDef result metadata
// is used only to preserve established box/vector Go shapes where they exist.
type layerRPCSourceHandler struct {
	Method                 *layerRPCMethodPlan
	Structure              *structDef
	Name                   string
	ResultType             string
	ErrorOnly              bool
	CanonicalResultEncoder string
}

type layerRPCSourceProfile struct {
	Layer           int
	ProfileConstant string
	Routes          []layerRPCSourceRouteRef
}

type layerRPCSourceRouteRef struct {
	WireID uint32
	Admit  string
}

type layerRPCSourceRoute struct {
	Layer   int
	WireID  uint32
	Admit   string
	Body    string
	Wrapper bool
}

type layerRPCSourceHookCheck struct {
	Name      string
	Signature string
}

type layerRPCUnprofiledSource struct {
	WireID uint32
	Method string
	Body   string
}

type layerRPCSourceEmitter struct {
	rpc          *layerRPCModel
	refs         *layerTypeRefModel
	nodeByKey    map[string]*layerTypeRefNode
	rpcRefByKey  map[semantic.SemanticKey]*layerRPCTypePlan
	hookByName   map[string]string
	adapterNames map[string]struct{}
	model        *layerRPCSourceModel
}

// buildLayerRPCSourceModel lowers every exact (profile, method wire ID) route
// into a static admission function. The two input models must describe the
// same cached SchemaSet conversion plan; mismatches fail generation instead
// of creating a runtime fallback.
func (g *Generator) buildLayerRPCSourceModel(rpc *layerRPCModel, refs *layerTypeRefModel) (*layerRPCSourceModel, error) {
	if g == nil || g.schemaSet == nil {
		return nil, fmt.Errorf("gen: layer RPC source requires a schema-set generator")
	}
	if rpc == nil || refs == nil {
		return nil, fmt.Errorf("gen: layer RPC source requires RPC and TypeRef models")
	}
	if rpc.CanonicalLayer != refs.CanonicalLayer || rpc.CanonicalLayer != g.schemaSet.CanonicalLayer ||
		!equalLayerRPCSourceProfiles(rpc.Profiles, refs.Profiles) || !equalLayerRPCSourceProfiles(rpc.Profiles, g.schemaSet.Layers()) {
		return nil, fmt.Errorf("gen: layer RPC source models do not share one exact profile universe")
	}
	if refs.MaxDepth <= 0 || refs.BindingCapacity <= 0 {
		return nil, fmt.Errorf("gen: layer RPC source has invalid TypeRef limits depth=%d bindings=%d", refs.MaxDepth, refs.BindingCapacity)
	}

	emitter := &layerRPCSourceEmitter{
		rpc:          rpc,
		refs:         refs,
		nodeByKey:    make(map[string]*layerTypeRefNode, len(refs.Nodes)),
		rpcRefByKey:  make(map[semantic.SemanticKey]*layerRPCTypePlan, len(refs.RPCs)),
		hookByName:   make(map[string]string),
		adapterNames: make(map[string]struct{}),
		model: &layerRPCSourceModel{
			LayerRPC: rpc,
			MaxDepth: refs.MaxDepth,
		},
	}
	for index := range refs.Nodes {
		node := &refs.Nodes[index]
		if previous := emitter.nodeByKey[node.Key]; previous != nil {
			return nil, fmt.Errorf("gen: layer RPC source repeats TypeRef node key %q", node.Key)
		}
		emitter.nodeByKey[node.Key] = node
	}
	for index := range refs.RPCs {
		plan := &refs.RPCs[index]
		if previous := emitter.rpcRefByKey[plan.Key]; previous != nil {
			return nil, fmt.Errorf("gen: layer RPC source repeats RPC TypeRef plan %s", plan.Key)
		}
		emitter.rpcRefByKey[plan.Key] = plan
	}
	if len(emitter.rpcRefByKey) != len(rpc.Methods) {
		return nil, fmt.Errorf("gen: layer RPC source method/TypeRef plan count mismatch: RPC=%d TypeRef=%d", len(rpc.Methods), len(emitter.rpcRefByKey))
	}
	if err := emitter.build(); err != nil {
		return nil, err
	}
	return emitter.model, nil
}

func equalLayerRPCSourceProfiles(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (e *layerRPCSourceEmitter) build() error {
	profiles := make(map[int]*layerRPCSourceProfile, len(e.rpc.Profiles))
	e.model.Profiles = make([]layerRPCSourceProfile, len(e.rpc.Profiles))
	for index, layer := range e.rpc.Profiles {
		e.model.Profiles[index] = layerRPCSourceProfile{
			Layer:           layer,
			ProfileConstant: fmt.Sprintf("LayerProfile%d", layer),
		}
		profiles[layer] = &e.model.Profiles[index]
	}
	for methodIndex := range e.rpc.Methods {
		method := &e.rpc.Methods[methodIndex]
		if !method.Handler {
			continue
		}
		handler, err := e.buildHandler(method)
		if err != nil {
			return fmt.Errorf("gen: layer RPC handler facade %s: %w", method.Key, err)
		}
		e.model.Handlers = append(e.model.Handlers, handler)
	}

	for routeIndex := range e.rpc.Routes {
		route := &e.rpc.Routes[routeIndex]
		profile := profiles[route.Layer]
		if profile == nil {
			return fmt.Errorf("gen: layer RPC route profile %d is outside the TypeRef universe", route.Layer)
		}
		out, err := e.buildRoute(route)
		if err != nil {
			return fmt.Errorf("gen: layer RPC source profile %d wire %#08x %s: %w", route.Layer, route.WireID, route.Method.Key, err)
		}
		e.model.Routes = append(e.model.Routes, out)
		profile.Routes = append(profile.Routes, layerRPCSourceRouteRef{WireID: out.WireID, Admit: out.Admit})
		if out.Wrapper {
			e.model.WrapperCount++
		}
	}
	e.model.RouteCount = len(e.model.Routes)
	for index := range e.model.Profiles {
		sort.Slice(e.model.Profiles[index].Routes, func(i, j int) bool {
			return e.model.Profiles[index].Routes[i].WireID < e.model.Profiles[index].Routes[j].WireID
		})
	}
	sort.Slice(e.model.HookChecks, func(i, j int) bool { return e.model.HookChecks[i].Name < e.model.HookChecks[j].Name })
	sort.Strings(e.model.Adapters)
	unprofiled, err := e.buildUnprofiled()
	if err != nil {
		return err
	}
	e.model.Unprofiled = unprofiled
	return nil
}

func (e *layerRPCSourceEmitter) buildHandler(method *layerRPCMethodPlan) (layerRPCSourceHandler, error) {
	if method == nil || !method.Handler || method.Canonical == nil || method.Canonical.Structure == nil || method.Canonical.Definition == nil {
		return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_CANONICAL_REQUEST_ABSENT: ordinary handler has no canonical request binding")
	}
	refMethod := e.rpcRefByKey[method.Key]
	if refMethod == nil {
		return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_TYPEREF_ABSENT: canonical RPC TypeRef plan is absent")
	}
	refProfile := refMethod.profile(e.rpc.CanonicalLayer)
	if refProfile == nil || !refProfile.Available || refProfile.CanonicalResult < 0 || refProfile.CanonicalResult >= len(e.refs.Nodes) {
		return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_TYPEREF_ABSENT: canonical result TypeRef is absent")
	}
	result := &e.refs.Nodes[refProfile.CanonicalResult]
	canonicalProfile := method.profile(e.rpc.CanonicalLayer)
	if canonicalProfile == nil || canonicalProfile.Definition == nil || canonicalProfile.Wrapper != nil || canonicalProfile.Result.CanonicalRef == nil ||
		!result.Ref.Equal(*canonicalProfile.Result.CanonicalRef) || !result.Ref.Equal(method.Canonical.Definition.Result) {
		return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_TYPEREF_STALE: canonical result TypeRef disagrees with the semantic method")
	}
	if result.RequiresBinding || !result.Runnable || result.GoType == "" {
		return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_UNSUPPORTED: canonical result %s is not a standalone runnable TypeRef", result.Ref.String())
	}

	structure := method.Canonical.Structure
	name := structure.Method
	if name == "" {
		parts := strings.Split(method.Key.QName, ".")
		name = namespacedName(parts[len(parts)-1], parts[:len(parts)-1])
		if structure.Name != name+"Request" {
			return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_NAME_MISMATCH: canonical request %q does not match derived facade %q", structure.Name, name)
		}
	}
	handler := layerRPCSourceHandler{
		Method:    method,
		Structure: structure,
		Name:      name,
	}

	// Ok is the established error-only facade even though the complete result
	// TypeRef is the concrete Ok constructor.
	if result.IsConcrete() && result.Ref.QName == "Ok" && structure.Result == "" {
		handler.ErrorOnly = true
		handler.CanonicalResultEncoder = "layerRPCDirectCanonicalResult"
		return handler, nil
	}
	typeRefEncoder := func() (string, error) {
		if result.BoundDescriptorName == "" {
			return "", fmt.Errorf("E_RPC_HANDLER_RESULT_UNSUPPORTED: canonical result %s has no static bound descriptor", result.Ref.String())
		}
		return fmt.Sprintf(`func(value any) (bin.Encoder, error) {
		return &layerRPCCanonicalTypeRefResult{typ: %s, value: value}, nil
	}`, result.BoundDescriptorName), nil
	}

	switch {
	case result.IsPrimitive():
		handler.ResultType = result.GoType
		// Bool already had a public ServerDispatcher facade before schema-set
		// generation. Keep its historical *BoolBox Handle shape, while every
		// previously unsupported primitive uses its exact TypeRef descriptor.
		if result.PrimitivePut == "PutBool" && structure.Result == "BoolClass" && !structure.ResultSingular && !structure.ResultVector {
			handler.CanonicalResultEncoder = fmt.Sprintf(`func(value any) (bin.Encoder, error) {
			response, ok := value.(bool)
			if !ok { return nil, fmt.Errorf("tg: canonical %s result has type %%T, want bool", value) }
			if response { return &BoolBox{Bool: &BoolTrue{}}, nil }
			return &BoolBox{Bool: &BoolFalse{}}, nil
		}`, structure.RawName)
		} else {
			var err error
			handler.CanonicalResultEncoder, err = typeRefEncoder()
			if err != nil {
				return layerRPCSourceHandler{}, err
			}
		}

	case result.IsObject():
		if result.GoType != "bin.Object" {
			return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_UNSUPPORTED: Object result has Go type %q", result.GoType)
		}
		handler.ResultType = result.GoType
		var err error
		handler.CanonicalResultEncoder, err = typeRefEncoder()
		if err != nil {
			return layerRPCSourceHandler{}, err
		}

	case result.IsConcrete():
		if !result.AcceptPointer || structure.Result != result.GoType || !structure.ResultSingular || structure.ResultVector {
			return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_BACKEND_MISMATCH: concrete result %s has legacy backend result=%q singular=%v vector=%v", result.Ref.String(), structure.Result, structure.ResultSingular, structure.ResultVector)
		}
		handler.ResultType = "*" + result.GoType
		handler.CanonicalResultEncoder = "layerRPCDirectCanonicalResult"

	case result.IsClass() && result.Ref.QName == "Bool":
		if structure.Result != "BoolClass" || structure.ResultSingular || structure.ResultVector {
			return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_BACKEND_MISMATCH: Bool result has legacy backend result=%q singular=%v vector=%v", structure.Result, structure.ResultSingular, structure.ResultVector)
		}
		handler.ResultType = "bool"
		handler.CanonicalResultEncoder = fmt.Sprintf(`func(value any) (bin.Encoder, error) {
			response, ok := value.(bool)
			if !ok { return nil, fmt.Errorf("tg: canonical %s result has type %%T, want bool", value) }
			if response { return &BoolBox{Bool: &BoolTrue{}}, nil }
			return &BoolBox{Bool: &BoolFalse{}}, nil
		}`, structure.RawName)

	case result.IsClass():
		if structure.Result != result.GoType || structure.ResultSingular || structure.ResultVector || structure.ResultFunc == "" || structure.ResultBaseName == "" {
			return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_BACKEND_MISMATCH: class result %s has incomplete legacy box metadata", result.Ref.String())
		}
		handler.ResultType = result.GoType
		handler.CanonicalResultEncoder = fmt.Sprintf(`func(value any) (bin.Encoder, error) {
		if value == nil { return &%sBox{}, nil }
		response, ok := value.(%s)
		if !ok { return nil, fmt.Errorf("tg: canonical %s result has type %%T, want %s", value) }
		return &%sBox{%s: response}, nil
	}`, structure.ResultFunc, result.GoType, structure.RawName, result.GoType, structure.ResultFunc, structure.ResultBaseName)

	case result.IsVector() && result.BoxedVector:
		if !structure.ResultSingular || !structure.ResultVector || structure.Result == "" {
			return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_BACKEND_MISMATCH: boxed vector result %s has no established vector backend", result.Ref.String())
		}
		handler.ResultType = result.GoType
		handler.CanonicalResultEncoder = fmt.Sprintf(`func(value any) (bin.Encoder, error) {
		response, ok := value.(%s)
		if !ok { return nil, fmt.Errorf("tg: canonical %s result has type %%T, want %s", value) }
		return &%s{Elems: response}, nil
	}`, result.GoType, structure.RawName, result.GoType, structure.Result)

	case result.IsExactBare() || result.IsVector():
		handler.ResultType = result.GoType
		var err error
		handler.CanonicalResultEncoder, err = typeRefEncoder()
		if err != nil {
			return layerRPCSourceHandler{}, err
		}

	default:
		return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_UNSUPPORTED: canonical result %s strategy %s has no static ServerDispatcher facade", result.Ref.String(), result.Strategy)
	}
	if handler.ResultType == "" || handler.CanonicalResultEncoder == "" {
		return layerRPCSourceHandler{}, fmt.Errorf("E_RPC_HANDLER_RESULT_UNSUPPORTED: canonical result %s produced an incomplete facade", result.Ref.String())
	}
	return handler, nil
}

// buildUnprofiled emits the only legal pre-profile admission path. It accepts
// invokeWithLayer only when every generated schema proves an identical outer
// wire ID and body shape. The selected layer is decoded directly from the
// invariant primitive field; no canonical profile is guessed.
func (e *layerRPCSourceEmitter) buildUnprofiled() (*layerRPCUnprofiledSource, error) {
	key := semantic.SemanticKey{Category: semantic.CategoryFunction, QName: "invokeWithLayer"}
	method := e.rpc.method(key)
	if method == nil || method.Canonical == nil || method.Handler {
		return nil, fmt.Errorf("gen: E_UNPROFILED_INVOKE_WITH_LAYER_ABSENT: transparent %s is required", key)
	}
	var (
		wireID uint32
		shape  semantic.ShapeDigest
	)
	for index, layer := range e.rpc.Profiles {
		profile := method.profile(layer)
		if profile == nil || profile.Definition == nil || profile.Wrapper == nil ||
			profile.Request == layerRPCReject || profile.Request == layerRPCUnavailable {
			return nil, fmt.Errorf("gen: E_UNPROFILED_INVOKE_WITH_LAYER_UNAVAILABLE: layer %d has no admitted wrapper", layer)
		}
		definition := profile.Definition
		if index == 0 {
			wireID = definition.WireID
			shape = definition.BodyShape
		} else if definition.WireID != wireID || definition.BodyShape != shape {
			return nil, fmt.Errorf("gen: E_UNPROFILED_INVOKE_WITH_LAYER_DRIFT: layer %d wire/body differs from the generated invariant", layer)
		}
		wrapper := profile.Wrapper
		if wrapper.NestedProfile != layerRPCProfileFromField || wrapper.ProfileField < 0 ||
			wrapper.QueryFieldOrdinal < 0 || wrapper.ProfileField >= wrapper.QueryFieldOrdinal {
			return nil, fmt.Errorf("gen: E_UNPROFILED_INVOKE_WITH_LAYER_SHAPE: layer %d wrapper metadata is not exact", layer)
		}
		if len(definition.Fields) != 2 {
			return nil, fmt.Errorf("gen: E_UNPROFILED_INVOKE_WITH_LAYER_SHAPE: layer %d has %d fields, want invariant layer+query", layer, len(definition.Fields))
		}
		layerField := &definition.Fields[0]
		queryField := &definition.Fields[1]
		if layerField.Ordinal != wrapper.ProfileField || layerField.Kind != semantic.FieldValue || layerField.Condition != nil ||
			layerField.Type.Kind != semantic.TypePrimitive || layerField.Type.QName != "int" {
			return nil, fmt.Errorf("gen: E_UNPROFILED_INVOKE_WITH_LAYER_SHAPE: layer %d selector is not an unconditional int", layer)
		}
		if queryField.Ordinal != wrapper.QueryFieldOrdinal || queryField.Kind != semantic.FieldValue || queryField.Condition != nil ||
			queryField.Type.Kind != semantic.TypeGenericRef || wrapper.QuerySlot == nil || queryField.Type.QName != wrapper.QuerySlot.Name {
			return nil, fmt.Errorf("gen: E_UNPROFILED_INVOKE_WITH_LAYER_SHAPE: layer %d query is not the direct generic result slot", layer)
		}
	}
	var body strings.Builder
	fmt.Fprintf(&body, "if err := probe.ConsumeID(0x%08x); err != nil { return LayerProfile(0), fmt.Errorf(\"consume unprofiled invokeWithLayer probe: %%w\", err) }\n", wireID)
	body.WriteString("selectedLayer, err := probe.Int()\n")
	body.WriteString("if err != nil { return LayerProfile(0), fmt.Errorf(\"decode unprofiled invokeWithLayer layer probe: %w\", err) }\n")
	body.WriteString("selectedProfile, ok := ResolveLayerProfile(selectedLayer)\n")
	fmt.Fprintf(&body, "if !ok { return LayerProfile(0), &LayerCodecError{Operation: \"probe unprofiled RPC wrapper\", Semantic: %s, WireID: 0x%08x, Reason: fmt.Sprintf(\"invokeWithLayer selected unsupported exact profile %%d\", selectedLayer)} }\n", method.Constant, wireID)
	body.WriteString("return selectedProfile, nil\n")
	return &layerRPCUnprofiledSource{WireID: wireID, Method: method.Constant, Body: body.String()}, nil
}

func (e *layerRPCSourceEmitter) buildRoute(route *layerRPCRoutePlan) (layerRPCSourceRoute, error) {
	if route == nil || route.Method == nil || route.Profile == nil || route.Profile.Definition == nil {
		return layerRPCSourceRoute{}, fmt.Errorf("incomplete route model")
	}
	if route.Profile.Layer != route.Layer || route.Profile.WireID != route.WireID || route.Profile.Definition.WireID != route.WireID {
		return layerRPCSourceRoute{}, fmt.Errorf("route identity is stale")
	}
	refMethod := e.rpcRefByKey[route.Method.Key]
	if refMethod == nil {
		return layerRPCSourceRoute{}, fmt.Errorf("RPC TypeRef plan is absent")
	}
	refProfile := refMethod.profile(route.Layer)
	if refProfile == nil || !refProfile.Available || refProfile.WireID != route.WireID {
		return layerRPCSourceRoute{}, fmt.Errorf("exact RPC TypeRef profile is absent or stale")
	}
	if refProfile.Conversion != route.Profile.Conversion {
		return layerRPCSourceRoute{}, fmt.Errorf("RPC and TypeRef source models do not share one conversion plan")
	}
	name := fmt.Sprintf("layerAdmitRPC%d_%08x", route.Layer, route.WireID)
	out := layerRPCSourceRoute{
		Layer:   route.Layer,
		WireID:  route.WireID,
		Admit:   name,
		Wrapper: route.Profile.Wrapper != nil,
	}

	if route.Profile.Request == layerRPCUnavailable {
		return layerRPCSourceRoute{}, fmt.Errorf("available route has unavailable request action")
	}
	if route.Profile.Availability == LayerAvailabilityProfileOnly {
		if route.Profile.Request == layerRPCAdapter {
			body, err := e.buildOldOnlyRoute(route, refProfile)
			if err != nil {
				return layerRPCSourceRoute{}, err
			}
			out.Body = body
			return out, nil
		}
		out.Body = layerRPCRejectRouteBody(route, "request", "historical-only RPC has no canonical semantic target")
		return out, nil
	}
	if route.Profile.Request == layerRPCReject {
		out.Body = layerRPCRejectRouteBody(route, "request", "request conversion is rejected by exact layer policy")
		return out, nil
	}
	if route.Profile.RequestHook != "" {
		return layerRPCSourceRoute{}, fmt.Errorf("canonical request unexpectedly requires whole-request hook %q", route.Profile.RequestHook)
	}
	if route.Profile.Result.Action == layerRPCReject || route.Profile.Result.Action == layerRPCUnavailable {
		out.Body = layerRPCRejectRouteBody(route, "result", "RPC result conversion is rejected by exact layer policy")
		return out, nil
	}
	if route.Profile.Wrapper != nil {
		body, err := e.buildWrapperRoute(route, refProfile)
		if err != nil {
			return layerRPCSourceRoute{}, err
		}
		out.Body = body
		return out, nil
	}
	if !route.Method.Handler || route.Method.Canonical == nil {
		return layerRPCSourceRoute{}, fmt.Errorf("ordinary exact route has no canonical semantic handler")
	}
	body, err := e.buildOrdinaryRoute(route, refProfile)
	if err != nil {
		return layerRPCSourceRoute{}, err
	}
	out.Body = body
	return out, nil
}

func layerRPCRejectRouteBody(route *layerRPCRoutePlan, boundary, reason string) string {
	return fmt.Sprintf(
		"return layerDecodedRPCRequest{}, &LayerCodecError{Operation: %q, Profile: profile, Semantic: %s, WireID: 0x%08x, Reason: %q}\n",
		"admit RPC "+boundary, route.Method.Constant, route.WireID, reason,
	)
}

// buildOldOnlyRoute admits a historical method only when policy names both a
// strongly typed hook and an existing canonical semantic handler. Historical
// request fields are decoded statically; no fake canonical struct or dynamic
// schema object is introduced.
func (e *layerRPCSourceEmitter) buildOldOnlyRoute(route *layerRPCRoutePlan, refProfile *layerRPCTypeProfilePlan) (string, error) {
	resolution, err := layerRPCOldOnlyResolution(route.Profile)
	if err != nil {
		return "", err
	}
	targetKey, err := parseLayerPolicySemanticTarget(resolution.Target)
	if err != nil {
		return "", fmt.Errorf("E_OLD_ONLY_RPC_TARGET_INVALID: %w", err)
	}
	if targetKey.Category != semantic.CategoryFunction {
		return "", fmt.Errorf("E_OLD_ONLY_RPC_TARGET_NOT_METHOD: target %s is not a function", targetKey)
	}
	target := e.rpc.method(targetKey)
	if target == nil || target.Canonical == nil || !target.Handler {
		return "", fmt.Errorf("E_OLD_ONLY_RPC_TARGET_NOT_FOUND: target %s has no single canonical semantic handler", targetKey)
	}
	targetProfile := target.profile(route.Layer)
	if targetProfile == nil || targetProfile.Result.CanonicalRef == nil {
		return "", fmt.Errorf("E_OLD_ONLY_RPC_TARGET_RESULT_ABSENT: target %s has no canonical result in source profile %d", targetKey, route.Layer)
	}
	targetRefMethod := e.rpcRefByKey[targetKey]
	if targetRefMethod == nil {
		return "", fmt.Errorf("E_OLD_ONLY_RPC_TARGET_TYPEREF_ABSENT: target %s has no TypeRef plan", targetKey)
	}
	targetRefProfile := targetRefMethod.profile(route.Layer)
	if targetRefProfile == nil || targetRefProfile.CanonicalResult < 0 || targetRefProfile.CanonicalResult >= len(e.refs.Nodes) {
		return "", fmt.Errorf("E_OLD_ONLY_RPC_TARGET_TYPEREF_ABSENT: target %s has no canonical result TypeRef", targetKey)
	}
	if refProfile.WireResult < 0 || refProfile.WireResult >= len(e.refs.Nodes) {
		return "", fmt.Errorf("historical method has no complete wire result TypeRef")
	}
	canonicalResult := &e.refs.Nodes[targetRefProfile.CanonicalResult]
	wireResult := &e.refs.Nodes[refProfile.WireResult]
	if !canonicalResult.Ref.Equal(*targetProfile.Result.CanonicalRef) || route.Profile.Result.WireRef == nil ||
		!wireResult.Ref.Equal(*route.Profile.Result.WireRef) {
		return "", fmt.Errorf("old-only target/result TypeRef models disagree")
	}
	if canonicalResult.RequiresBinding || wireResult.RequiresBinding || !canonicalResult.Runnable || !wireResult.Runnable {
		return "", fmt.Errorf("old-only target result requires an unsupported generic or profile-only codec")
	}
	resultAdapter := ""
	if canonicalResult.Index != wireResult.Index || !canonicalResult.Ref.Equal(wireResult.Ref) {
		resultAdapter, err = e.addResultAdapter(route, resolution.Hook+"Result", canonicalResult, wireResult)
		if err != nil {
			return "", fmt.Errorf("old-only result adapter: %w", err)
		}
	}

	definition := route.Profile.Definition
	flags := make(map[string]int)
	for fieldIndex := range definition.Fields {
		field := &definition.Fields[fieldIndex]
		if field.Kind == semantic.FieldFlagsWord {
			flags[field.Name] = field.Ordinal
		}
	}
	arguments := []string{"profile"}
	types := []string{"LayerProfile"}
	var decode strings.Builder
	fmt.Fprintf(&decode, "if err := preflight.run(profile, %s, 0x%08x, b); err != nil { return layerDecodedRPCRequest{}, err }\n", target.Constant, route.WireID)
	fmt.Fprintf(&decode, "if err := b.ConsumeID(0x%08x); err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"consume historical RPC method 0x%08x: %%w\", err) }\n", route.WireID, route.WireID)
	for fieldIndex := range definition.Fields {
		field := &definition.Fields[fieldIndex]
		if field.Kind == semantic.FieldFlagsWord {
			fmt.Fprintf(&decode, "var rpcFlags%d bin.Fields\n", field.Ordinal)
			fmt.Fprintf(&decode, "if err := rpcFlags%d.Decode(b); err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"decode historical RPC flags %s: %%w\", err) }\n", field.Ordinal, field.Name)
			continue
		}
		local := fmt.Sprintf("historicalField%d", field.Ordinal)
		if field.Condition != nil && field.Condition.PresenceOnly {
			flagsOrdinal, ok := flags[field.Condition.Word]
			if !ok {
				return "", fmt.Errorf("historical field %q references missing flags word %q", field.Name, field.Condition.Word)
			}
			fmt.Fprintf(&decode, "%s := rpcFlags%d.Has(%d)\n", local, flagsOrdinal, field.Condition.Bit)
			arguments = append(arguments, local)
			types = append(types, "bool")
			continue
		}
		node, err := e.nodeForField(definition, field)
		if err != nil {
			return "", fmt.Errorf("historical field %q: %w", field.Name, err)
		}
		if node.RequiresBinding || !node.EmitCodec || node.DecodeStateName == "" || node.GoType == "" {
			return "", fmt.Errorf("historical field %q has no standalone static TypeRef decoder", field.Name)
		}
		if field.Condition == nil {
			fmt.Fprintf(&decode, "%s, err := %s(profile, b, state)\n", local, node.DecodeStateName)
			fmt.Fprintf(&decode, "if err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"decode historical RPC field %s: %%w\", err) }\n", field.Name)
			arguments = append(arguments, local)
			types = append(types, node.GoType)
			continue
		}
		flagsOrdinal, ok := flags[field.Condition.Word]
		if !ok {
			return "", fmt.Errorf("historical field %q references missing flags word %q", field.Name, field.Condition.Word)
		}
		present := local + "Present"
		fmt.Fprintf(&decode, "%s := rpcFlags%d.Has(%d)\n", present, flagsOrdinal, field.Condition.Bit)
		fmt.Fprintf(&decode, "var %s %s\n", local, node.GoType)
		fmt.Fprintf(&decode, "if %s { decoded, err := %s(profile, b, state); if err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"decode historical RPC field %s: %%w\", err) }; %s = decoded }\n", present, node.DecodeStateName, field.Name, local)
		arguments = append(arguments, present, local)
		types = append(types, "bool", node.GoType)
	}

	requestType := "*" + target.Canonical.Structure.Name
	hookSignature := fmt.Sprintf("func(%s) (%s, error)", strings.Join(types, ", "), requestType)
	if err := e.addHookCheck(resolution.Hook, hookSignature); err != nil {
		return "", err
	}
	fmt.Fprintf(&decode, "request, err := %s(%s)\n", resolution.Hook, strings.Join(arguments, ", "))
	decode.WriteString("if err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"adapt historical RPC request: %w\", err) }\n")
	fmt.Fprintf(&decode, "if request == nil { return layerDecodedRPCRequest{}, &LayerCodecError{Operation: \"adapt historical RPC request\", Profile: profile, Semantic: %s, WireID: 0x%08x, Reason: \"policy hook returned nil canonical request\"} }\n", target.Constant, route.WireID)
	fmt.Fprintf(&decode, "semanticIdentity, err := layerSemanticIdentity%s(request)\n", target.Canonical.Structure.Name)
	decode.WriteString("if err != nil { return layerDecodedRPCRequest{}, err }\n")
	decode.WriteString("call := LayerCall{\n")
	decode.WriteString("\tprofile: profile,\n")
	decode.WriteString("\tmethod: " + target.Constant + ",\n")
	fmt.Fprintf(&decode, "\twireID: 0x%08x,\n", route.WireID)
	decode.WriteString("\tcanonicalResult: &" + canonicalResult.RefName + ",\n")
	decode.WriteString("\twireResult: &" + wireResult.RefName + ",\n")
	decode.WriteString("\tcanonical: " + canonicalResult.BoundDescriptorName + ",\n")
	decode.WriteString("\tresult: " + wireResult.BoundDescriptorName + ",\n")
	if resultAdapter != "" {
		decode.WriteString("\tadaptResult: " + resultAdapter + ",\n")
	}
	decode.WriteString("}\n")
	decode.WriteString("return layerDecodedRPCRequest{request: request, call: call, semanticIdentity: semanticIdentity}, nil\n")
	return decode.String(), nil
}

func layerRPCOldOnlyResolution(profile *layerRPCMethodProfile) (LayerObligationResolution, error) {
	if profile == nil {
		return LayerObligationResolution{}, fmt.Errorf("nil old-only RPC profile")
	}
	var found *LayerObligationResolution
	for index := range profile.RequestObligations {
		obligation := &profile.RequestObligations[index]
		if obligation.Kind != LayerObligationOldOnly {
			continue
		}
		if found != nil {
			return LayerObligationResolution{}, fmt.Errorf("old-only RPC has multiple policy resolutions")
		}
		resolution := obligation.Resolution
		found = &resolution
	}
	if found == nil || (found.Action != LayerResolveAlias && found.Action != LayerResolveAdapter) ||
		strings.TrimSpace(found.Hook) == "" || found.Hook != profile.RequestHook {
		return LayerObligationResolution{}, fmt.Errorf("old-only RPC has no exact alias/adapter resolution")
	}
	return *found, nil
}

func (e *layerRPCSourceEmitter) buildOrdinaryRoute(route *layerRPCRoutePlan, refProfile *layerRPCTypeProfilePlan) (string, error) {
	canonicalResult, wireResult, err := e.resultNodes(route, refProfile)
	if err != nil {
		return "", err
	}
	if canonicalResult.RequiresBinding || wireResult.RequiresBinding || !canonicalResult.Runnable || !wireResult.Runnable {
		return "", fmt.Errorf("ordinary RPC result TypeRef requires an unsupported generic binding")
	}
	adapter := ""
	switch route.Profile.Result.Action {
	case layerRPCDirect:
		if !route.Profile.Result.CanonicalRef.Equal(*route.Profile.Result.WireRef) {
			return "", fmt.Errorf("direct result action has different canonical and wire TypeRefs")
		}
	case layerRPCAdapter:
		adapter, err = e.addResultAdapter(route, route.Profile.Result.Adapter, canonicalResult, wireResult)
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unsupported admitted result action %s", route.Profile.Result.Action)
	}

	var body strings.Builder
	fmt.Fprintf(&body, "if err := preflight.run(profile, %s, 0x%08x, b); err != nil { return layerDecodedRPCRequest{}, err }\n", route.Method.Constant, route.WireID)
	fmt.Fprintf(&body, "if err := b.ConsumeID(0x%08x); err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"consume RPC method 0x%08x: %%w\", err) }\n", route.WireID, route.WireID)
	fmt.Fprintf(&body, "request, err := layerDecodeWire%08xBare(profile, b, state)\n", route.WireID)
	body.WriteString("if err != nil { return layerDecodedRPCRequest{}, err }\n")
	body.WriteString("if request == nil { return layerDecodedRPCRequest{}, &LayerCodecError{Operation: \"admit RPC request\", Profile: profile, Semantic: ")
	body.WriteString(route.Method.Constant)
	fmt.Fprintf(&body, ", WireID: 0x%08x, Reason: \"wire decoder returned nil canonical request\"} }\n", route.WireID)
	fmt.Fprintf(&body, "semanticIdentity, err := layerSemanticIdentity%s(request)\n", route.Method.Canonical.Structure.Name)
	body.WriteString("if err != nil { return layerDecodedRPCRequest{}, err }\n")
	body.WriteString("call := LayerCall{\n")
	body.WriteString("\tprofile: profile,\n")
	body.WriteString("\tmethod: " + route.Method.Constant + ",\n")
	fmt.Fprintf(&body, "\twireID: 0x%08x,\n", route.WireID)
	body.WriteString("\tcanonicalResult: &" + canonicalResult.RefName + ",\n")
	body.WriteString("\twireResult: &" + wireResult.RefName + ",\n")
	body.WriteString("\tcanonical: " + canonicalResult.BoundDescriptorName + ",\n")
	body.WriteString("\tresult: " + wireResult.BoundDescriptorName + ",\n")
	if adapter != "" {
		body.WriteString("\tadaptResult: " + adapter + ",\n")
	}
	body.WriteString("}\n")
	body.WriteString("return layerDecodedRPCRequest{request: request, call: call, semanticIdentity: semanticIdentity}, nil\n")
	return body.String(), nil
}

func (e *layerRPCSourceEmitter) resultNodes(route *layerRPCRoutePlan, profile *layerRPCTypeProfilePlan) (*layerTypeRefNode, *layerTypeRefNode, error) {
	if profile.CanonicalResult < 0 || profile.CanonicalResult >= len(e.refs.Nodes) || profile.WireResult < 0 || profile.WireResult >= len(e.refs.Nodes) {
		return nil, nil, fmt.Errorf("RPC result TypeRef indices are incomplete")
	}
	canonical := &e.refs.Nodes[profile.CanonicalResult]
	wire := &e.refs.Nodes[profile.WireResult]
	if route.Profile.Result.CanonicalRef == nil || route.Profile.Result.WireRef == nil ||
		!canonical.Ref.Equal(*route.Profile.Result.CanonicalRef) || !wire.Ref.Equal(*route.Profile.Result.WireRef) {
		return nil, nil, fmt.Errorf("RPC result TypeRef models disagree")
	}
	return canonical, wire, nil
}

func (e *layerRPCSourceEmitter) addResultAdapter(route *layerRPCRoutePlan, hook string, canonical, wire *layerTypeRefNode) (string, error) {
	hook = strings.TrimSpace(hook)
	if hook == "" {
		return "", fmt.Errorf("result adapter action has no policy hook")
	}
	canonicalType := layerRPCResultHookType(canonical)
	wireType := layerRPCResultHookType(wire)
	signature := fmt.Sprintf("func(LayerProfile, %s) (%s, error)", canonicalType, wireType)
	if err := e.addHookCheck(hook, signature); err != nil {
		return "", err
	}

	name := fmt.Sprintf("layerAdaptRPCResult%d_%08x", route.Layer, route.WireID)
	if _, duplicate := e.adapterNames[name]; duplicate {
		return "", fmt.Errorf("duplicate result adapter name %q", name)
	}
	e.adapterNames[name] = struct{}{}
	var source strings.Builder
	fmt.Fprintf(&source, "func %s(profile LayerProfile, value any) (any, error) {\n", name)
	if canonical.AcceptPointer {
		fmt.Fprintf(&source, "\tvar typed *%s\n", canonical.GoType)
		fmt.Fprintf(&source, "\tswitch candidate := value.(type) {\n\tcase %s:\n\t\tcopy := candidate\n\t\ttyped = &copy\n\tcase *%s:\n\t\ttyped = candidate\n\tdefault:\n", canonical.GoType, canonical.GoType)
		fmt.Fprintf(&source, "\t\treturn nil, fmt.Errorf(\"RPC result adapter %s expected %s, got %%T\", value)\n\t}\n", hook, canonicalType)
		fmt.Fprintf(&source, "\tif typed == nil { return nil, fmt.Errorf(\"RPC result adapter %s received nil %s\") }\n", hook, canonicalType)
	} else {
		fmt.Fprintf(&source, "\ttyped, ok := value.(%s)\n", canonical.GoType)
		fmt.Fprintf(&source, "\tif !ok { return nil, fmt.Errorf(\"RPC result adapter %s expected %s, got %%T\", value) }\n", hook, canonicalType)
	}
	fmt.Fprintf(&source, "\tadapted, err := %s(profile, typed)\n", hook)
	fmt.Fprintf(&source, "\tif err != nil { return nil, fmt.Errorf(\"RPC result adapter %s: %%w\", err) }\n", hook)
	source.WriteString("\treturn adapted, nil\n}\n")
	e.model.Adapters = append(e.model.Adapters, source.String())
	return name, nil
}

func (e *layerRPCSourceEmitter) addHookCheck(name, signature string) error {
	name = strings.TrimSpace(name)
	if name == "" || signature == "" {
		return fmt.Errorf("layer RPC policy hook has an empty name or signature")
	}
	if previous, exists := e.hookByName[name]; exists {
		if previous != signature {
			return fmt.Errorf("layer RPC policy hook %q has incompatible signatures %q and %q", name, previous, signature)
		}
		return nil
	}
	e.hookByName[name] = signature
	e.model.HookChecks = append(e.model.HookChecks, layerRPCSourceHookCheck{Name: name, Signature: signature})
	return nil
}

func layerRPCResultHookType(node *layerTypeRefNode) string {
	if node != nil && node.AcceptPointer {
		return "*" + node.GoType
	}
	if node == nil {
		return ""
	}
	return node.GoType
}

func (e *layerRPCSourceEmitter) buildWrapperRoute(route *layerRPCRoutePlan, refProfile *layerRPCTypeProfilePlan) (string, error) {
	wrapper := route.Profile.Wrapper
	if wrapper == nil {
		return "", fmt.Errorf("nil wrapper plan")
	}
	if route.Profile.Result.Action != layerRPCDirect || route.Profile.Result.CanonicalRef == nil ||
		route.Profile.Result.WireRef == nil || !route.Profile.Result.CanonicalRef.Equal(*route.Profile.Result.WireRef) {
		return "", fmt.Errorf("transparent wrapper requires an identical direct generic result")
	}
	if route.Method.Handler {
		return "", fmt.Errorf("exact wrapper route would bypass a canonical semantic handler")
	}
	if !refProfile.Unwrap || refProfile.ResultSourceField != wrapper.QueryFieldOrdinal {
		return "", fmt.Errorf("RPC and TypeRef wrapper plans disagree about query field")
	}
	if len(refProfile.GenericSlots) != len(wrapper.Slots) {
		return "", fmt.Errorf("RPC and TypeRef wrapper plans disagree about generic slot count")
	}
	for index := range wrapper.Slots {
		if refProfile.GenericSlots[index].Index != wrapper.Slots[index].Ordinal ||
			refProfile.GenericSlots[index].Name != wrapper.Slots[index].Name {
			return "", fmt.Errorf("RPC and TypeRef wrapper plans disagree about generic slot %d", index)
		}
	}
	wantProfileField := -1
	switch wrapper.NestedProfile {
	case layerRPCInheritProfile:
	case layerRPCProfileFromField:
		wantProfileField = wrapper.ProfileField
	default:
		return "", fmt.Errorf("wrapper has unsupported nested profile mode %s", wrapper.NestedProfile)
	}
	if refProfile.NestedProfileSourceField != wantProfileField {
		return "", fmt.Errorf("RPC and TypeRef wrapper plans disagree about nested profile source")
	}
	if wrapper.QuerySlot == nil || wrapper.ResultSlot == nil || *wrapper.QuerySlot != *wrapper.ResultSlot {
		return "", fmt.Errorf("wrapper query/result generic slots are not identical")
	}
	if wrapper.QuerySlot.Ordinal < 0 || wrapper.QuerySlot.Ordinal >= e.refs.BindingCapacity {
		return "", fmt.Errorf("wrapper generic slot %d exceeds TypeRef binding capacity %d", wrapper.QuerySlot.Ordinal, e.refs.BindingCapacity)
	}
	canonicalProfile := route.Method.profile(e.rpc.CanonicalLayer)
	if canonicalProfile == nil || canonicalProfile.Definition == nil || canonicalProfile.Wrapper == nil || route.Method.Canonical == nil {
		return "", fmt.Errorf("wrapper has no canonical semantic profile")
	}
	canonicalWrapper := canonicalProfile.Wrapper
	if canonicalWrapper.QuerySlot == nil || canonicalWrapper.ResultSlot == nil ||
		canonicalWrapper.QuerySlot.Ordinal != wrapper.QuerySlot.Ordinal || canonicalWrapper.ResultSlot.Ordinal != wrapper.ResultSlot.Ordinal {
		return "", fmt.Errorf("wrapper query/result generic slot changed across profiles")
	}
	if canonicalWrapper.NestedProfile != wrapper.NestedProfile {
		return "", fmt.Errorf("wrapper nested-profile semantics changed across profiles")
	}
	if route.Profile.Conversion == nil || len(route.Profile.Conversion.Fields) != len(route.Profile.Definition.Fields) {
		return "", fmt.Errorf("wrapper field conversion mapping is absent or stale")
	}
	for _, obligation := range route.Profile.RequestObligations {
		if obligation.Kind == LayerObligationAtomicFlagGroup &&
			layerCodecDirectionMatches(obligation.Direction, LayerDirectionProfileToCanonical) &&
			(obligation.Resolution.Action == LayerResolveAdapter || obligation.Resolution.Action == LayerResolveAlias || obligation.Resolution.Action == LayerResolveProject) {
			return "", fmt.Errorf("E_WRAPPER_ATOMIC_METADATA_ADAPTER_UNSUPPORTED: policy hook %q spans multiple metadata fields", obligation.Resolution.Hook)
		}
	}

	definition := route.Profile.Definition
	canonicalDefinition := canonicalProfile.Definition
	queryIndex := -1
	for index := range definition.Fields {
		if definition.Fields[index].Ordinal == wrapper.QueryFieldOrdinal {
			queryIndex = index
			break
		}
	}
	if queryIndex < 0 {
		return "", fmt.Errorf("wrapper query field ordinal %d is absent", wrapper.QueryFieldOrdinal)
	}
	query := &definition.Fields[queryIndex]
	if query.Kind != semantic.FieldValue || query.Condition != nil || query.Type.Kind != semantic.TypeGenericRef || query.Type.QName != wrapper.QuerySlot.Name {
		return "", fmt.Errorf("wrapper query field %q is not an unconditional direct generic reference", query.Name)
	}
	queryMapping := route.Profile.Conversion.Fields[queryIndex]
	if queryMapping.CanonicalOrdinal < 0 || queryMapping.CanonicalOrdinal >= len(canonicalDefinition.Fields) ||
		canonicalDefinition.Fields[queryMapping.CanonicalOrdinal].Ordinal != canonicalWrapper.QueryFieldOrdinal {
		return "", fmt.Errorf("wrapper query field does not map to the canonical generic query")
	}
	canonicalQuery := &canonicalDefinition.Fields[queryMapping.CanonicalOrdinal]
	if policy, err := layerRPCWrapperFieldPolicy(route.Profile.Conversion, query.Name, canonicalQuery.Name); err != nil {
		return "", err
	} else if policy != nil {
		return "", fmt.Errorf("E_WRAPPER_QUERY_POLICY_UNSUPPORTED: query policy hook %q cannot transform the recursively admitted request", policy.Resolution.Hook)
	}

	flags := make(map[string]int)
	for index := range definition.Fields {
		field := &definition.Fields[index]
		if field.Kind == semantic.FieldFlagsWord {
			flags[field.Name] = field.Ordinal
		}
	}

	type wrapperFieldSource struct {
		expression string
	}
	frameFields := make([]wrapperFieldSource, 0, len(definition.Fields)-1)
	var body strings.Builder
	fmt.Fprintf(&body, "if err := b.ConsumeID(0x%08x); err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"consume RPC wrapper 0x%08x: %%w\", err) }\n", route.WireID, route.WireID)
	body.WriteString("nestedProfile := profile\n")
	querySeen := false
	bound := false
	mappedCanonical := map[int]bool{queryMapping.CanonicalOrdinal: true}
	calledMetadataHooks := make(map[string]struct{})
	for fieldIndex := range definition.Fields {
		field := &definition.Fields[fieldIndex]
		if field.Kind == semantic.FieldFlagsWord {
			fmt.Fprintf(&body, "var rpcFlags%d bin.Fields\n", field.Ordinal)
			fmt.Fprintf(&body, "if err := rpcFlags%d.Decode(b); err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"decode RPC wrapper flags %s: %%w\", err) }\n", field.Ordinal, field.Name)
			frameFields = append(frameFields, wrapperFieldSource{expression: fmt.Sprintf("layerRPCWrapperField{name: %q, present: true, direct: true, value: rpcFlags%d}", field.Name, field.Ordinal)})
			continue
		}
		if field.Ordinal == wrapper.QueryFieldOrdinal {
			body.WriteString("admitted, err := decodeLayerRPCRequestState(nestedProfile, b, state, preflight, depth+1)\n")
			body.WriteString("if err != nil { return layerDecodedRPCRequest{}, err }\n")
			fmt.Fprintf(&body, "bindingSnapshot, err := state.bind(%d, admitted.call.result)\n", wrapper.QuerySlot.Ordinal)
			body.WriteString("if err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"bind RPC wrapper result: %w\", err) }\n")
			body.WriteString("defer state.restore(bindingSnapshot)\n")
			querySeen = true
			bound = true
			continue
		}
		mapping := route.Profile.Conversion.Fields[fieldIndex]
		if mapping.ProfileOrdinal != fieldIndex || mapping.ProfileName != field.Name {
			return "", fmt.Errorf("wrapper field %q has a stale conversion mapping", field.Name)
		}
		var canonicalField *semantic.FieldShape
		if mapping.CanonicalOrdinal >= 0 {
			if mapping.CanonicalOrdinal >= len(canonicalDefinition.Fields) {
				return "", fmt.Errorf("wrapper field %q maps outside the canonical definition", field.Name)
			}
			canonicalField = &canonicalDefinition.Fields[mapping.CanonicalOrdinal]
			if canonicalField.Kind != semantic.FieldValue || canonicalField.Name != mapping.CanonicalName {
				return "", fmt.Errorf("wrapper field %q has an invalid canonical mapping", field.Name)
			}
			mappedCanonical[mapping.CanonicalOrdinal] = true
		}
		node, err := e.nodeForField(definition, field)
		if err != nil {
			return "", fmt.Errorf("field %q: %w", field.Name, err)
		}
		if node.RequiresBinding && !bound {
			return "", fmt.Errorf("generic field %q precedes the wrapper query binding", field.Name)
		}
		if !node.EmitCodec || node.DecodeStateName == "" {
			return "", fmt.Errorf("field %q has no static TypeRef decoder", field.Name)
		}
		condition := "true"
		presenceOnly := field.Condition != nil && field.Condition.PresenceOnly
		if field.Condition != nil {
			ordinal, ok := flags[field.Condition.Word]
			if !ok {
				return "", fmt.Errorf("field %q references missing flags word %q", field.Name, field.Condition.Word)
			}
			condition = fmt.Sprintf("rpcFlags%d.Has(%d)", ordinal, field.Condition.Bit)
		}
		local := fmt.Sprintf("rpcWrapperField%d", field.Ordinal)
		present := condition
		if presenceOnly {
			fmt.Fprintf(&body, "%s := %s\n", local, condition)
		} else {
			decode := fmt.Sprintf("%s(profile, b, state)", node.DecodeStateName)
			if field.Condition != nil {
				present = local + "Present"
				fmt.Fprintf(&body, "%s := %s\n", present, condition)
				fmt.Fprintf(&body, "var %s %s\n", local, node.GoType)
				fmt.Fprintf(&body, "if %s { decoded, err := %s; if err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"decode RPC wrapper field %s: %%w\", err) }; %s = decoded }\n", present, decode, field.Name, local)
			} else {
				fmt.Fprintf(&body, "%s, err := %s\n", local, decode)
				fmt.Fprintf(&body, "if err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"decode RPC wrapper field %s: %%w\", err) }\n", field.Name)
			}
		}
		if field.Ordinal == wrapper.ProfileField {
			if node.GoType != "int" || field.Condition != nil {
				return "", fmt.Errorf("nested profile source field %q is not an unconditional int", field.Name)
			}
			if canonicalField == nil || canonicalField.Ordinal != canonicalWrapper.ProfileField || !canonicalField.Type.Equal(field.Type) {
				return "", fmt.Errorf("nested profile source field %q does not map identically to canonical", field.Name)
			}
			if policy, err := layerRPCWrapperFieldPolicy(route.Profile.Conversion, field.Name, canonicalField.Name); err != nil {
				return "", err
			} else if policy != nil {
				return "", fmt.Errorf("nested profile source field %q cannot use policy hook %q", field.Name, policy.Resolution.Hook)
			}
			fmt.Fprintf(&body, "selectedProfile%d, ok := ResolveLayerProfile(%s)\n", field.Ordinal, local)
			fmt.Fprintf(&body, "if !ok { return layerDecodedRPCRequest{}, &LayerCodecError{Operation: \"admit RPC wrapper\", Profile: profile, Semantic: %s, WireID: 0x%08x, Reason: fmt.Sprintf(\"invokeWithLayer selected unsupported exact profile %%d\", %s)} }\n", route.Method.Constant, route.WireID, local)
			fmt.Fprintf(&body, "if selectedProfile%d != profile { return layerDecodedRPCRequest{}, &LayerCodecError{Operation: \"admit RPC wrapper\", Profile: profile, Semantic: %s, WireID: 0x%08x, Reason: fmt.Sprintf(\"invokeWithLayer selected profile %%d, want frozen admission profile %%d\", selectedProfile%d, profile)} }\n", field.Ordinal, route.Method.Constant, route.WireID, field.Ordinal)
			fmt.Fprintf(&body, "nestedProfile = selectedProfile%d\n", field.Ordinal)
		}
		if canonicalField == nil {
			if !layerCodecDroppedField(route.Profile.Conversion, field.Name) {
				return "", fmt.Errorf("E_WRAPPER_METADATA_TARGET_ABSENT: field %q has no canonical target for its policy", field.Name)
			}
			continue
		}
		canonicalNode, err := e.nodeForField(canonicalDefinition, canonicalField)
		if err != nil {
			return "", fmt.Errorf("canonical wrapper field %q: %w", canonicalField.Name, err)
		}
		if canonicalNode.RequiresBinding {
			return "", fmt.Errorf("E_WRAPPER_CANONICAL_METADATA_GENERIC_UNSUPPORTED: field %q requires a generic binding", canonicalField.Name)
		}
		if !canonicalNode.EmitCodec || canonicalNode.BoundDescriptorName == "" {
			return "", fmt.Errorf("canonical wrapper field %q has no static bound TypeRef descriptor", canonicalField.Name)
		}
		wireType := node.GoType
		canonicalType := canonicalNode.GoType
		if presenceOnly {
			wireType = "bool"
		}
		if canonicalField.Condition != nil && canonicalField.Condition.PresenceOnly {
			canonicalType = "bool"
		}
		normalizedValue, normalizedPresent, err := e.emitWrapperMetadataNormalization(&body, route, field, canonicalField, wireType, canonicalType, local, present, calledMetadataHooks)
		if err != nil {
			return "", err
		}
		if canonicalField.Condition != nil && canonicalField.Condition.PresenceOnly {
			frameFields = append(frameFields, wrapperFieldSource{expression: fmt.Sprintf("layerRPCWrapperField{name: %q, present: %s, direct: true, value: %s}", canonicalField.Name, normalizedPresent, normalizedValue)})
			continue
		}
		frozen := fmt.Sprintf("rpcWrapperFrozenField%d", field.Ordinal)
		fmt.Fprintf(&body, "%s, err := layerFreezeRPCWrapperField(LayerProfileCanonical, %q, %s, %s, %s, state)\n", frozen, canonicalField.Name, normalizedPresent, canonicalNode.BoundDescriptorName, normalizedValue)
		fmt.Fprintf(&body, "if err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"freeze canonical RPC wrapper field %s: %%w\", err) }\n", canonicalField.Name)
		frameFields = append(frameFields, wrapperFieldSource{expression: frozen})
	}
	for canonicalIndex := range canonicalDefinition.Fields {
		canonicalField := &canonicalDefinition.Fields[canonicalIndex]
		if canonicalField.Kind != semantic.FieldValue || canonicalField.Ordinal == canonicalWrapper.QueryFieldOrdinal || mappedCanonical[canonicalIndex] {
			continue
		}
		if canonicalField.Condition != nil {
			frameFields = append(frameFields, wrapperFieldSource{expression: fmt.Sprintf("layerRPCWrapperField{name: %q, present: false}", canonicalField.Name)})
			continue
		}
		return "", fmt.Errorf("E_WRAPPER_REQUIRED_METADATA_SOURCE_ABSENT: canonical field %q has no profile source", canonicalField.Name)
	}
	if !querySeen {
		return "", fmt.Errorf("wrapper query was not emitted")
	}
	body.WriteString("wrapperFrame := LayerRPCWrapper{\n")
	body.WriteString("\tprofile: profile,\n")
	body.WriteString("\tsemantic: " + route.Method.Constant + ",\n")
	fmt.Fprintf(&body, "\twireID: 0x%08x,\n", route.WireID)
	if len(frameFields) != 0 {
		body.WriteString("\tfields: []layerRPCWrapperField{\n")
		for _, field := range frameFields {
			fmt.Fprintf(&body, "\t\t%s,\n", field.expression)
		}
		body.WriteString("\t},\n")
	}
	body.WriteString("}\n")
	body.WriteString("admitted.wrappers = append(admitted.wrappers, wrapperFrame)\n")
	body.WriteString("return admitted, nil\n")
	return body.String(), nil
}

func layerRPCWrapperFieldPolicy(conversion *LayerFamilyConversion, profileField, canonicalField string) (*LayerObligation, error) {
	if conversion == nil {
		return nil, fmt.Errorf("nil wrapper conversion")
	}
	var found *LayerObligation
	for index := range conversion.Obligations {
		obligation := &conversion.Obligations[index]
		if !layerCodecDirectionMatches(obligation.Direction, LayerDirectionProfileToCanonical) || obligation.Kind == LayerObligationAtomicFlagGroup {
			continue
		}
		switch obligation.Resolution.Action {
		case LayerResolveAdapter, LayerResolveAlias, LayerResolveProject:
		default:
			continue
		}
		matches := obligation.Field == profileField && (obligation.OtherField == "" || obligation.OtherField == canonicalField)
		if obligation.Kind == LayerObligationAlias || obligation.Kind == LayerObligationFieldReplacement {
			matches = obligation.OtherField == profileField && obligation.Field == canonicalField
		}
		if !matches {
			continue
		}
		if strings.TrimSpace(obligation.Resolution.Hook) == "" {
			return nil, fmt.Errorf("wrapper metadata field %q policy has no hook", profileField)
		}
		if found != nil && (found.Resolution.Hook != obligation.Resolution.Hook || found.Resolution.Action != obligation.Resolution.Action) {
			return nil, fmt.Errorf("wrapper metadata field %q has conflicting policy hooks %q and %q", profileField, found.Resolution.Hook, obligation.Resolution.Hook)
		}
		found = obligation
	}
	return found, nil
}

func (e *layerRPCSourceEmitter) emitWrapperMetadataNormalization(
	body *strings.Builder,
	route *layerRPCRoutePlan,
	profileField, canonicalField *semantic.FieldShape,
	wireType, canonicalType, wireValue, wirePresent string,
	called map[string]struct{},
) (value, present string, err error) {
	if body == nil || route == nil || route.Profile == nil || route.Profile.Conversion == nil || profileField == nil || canonicalField == nil {
		return "", "", fmt.Errorf("incomplete wrapper metadata normalization")
	}
	policy, err := layerRPCWrapperFieldPolicy(route.Profile.Conversion, profileField.Name, canonicalField.Name)
	if err != nil {
		return "", "", err
	}
	profilePresenceOnly := profileField.Condition != nil && profileField.Condition.PresenceOnly
	canonicalPresenceOnly := canonicalField.Condition != nil && canonicalField.Condition.PresenceOnly
	if policy == nil {
		if wireType != canonicalType || profilePresenceOnly != canonicalPresenceOnly {
			return "", "", fmt.Errorf("E_WRAPPER_METADATA_POLICY_REQUIRED: field %q (%s) cannot map directly to %q (%s)", profileField.Name, wireType, canonicalField.Name, canonicalType)
		}
		present = wirePresent
		if canonicalField.Condition == nil && profileField.Condition != nil {
			if !layerCodecDefaultedField(route.Profile.Conversion, canonicalField.Name, LayerDirectionProfileToCanonical) {
				return "", "", fmt.Errorf("E_WRAPPER_REQUIRED_METADATA_POLICY_REQUIRED: optional field %q maps to required canonical field %q", profileField.Name, canonicalField.Name)
			}
			present = "true"
		}
		return wireValue, present, nil
	}
	hook := strings.TrimSpace(policy.Resolution.Hook) + "RPCMetadataDecode"
	if _, duplicate := called[hook]; duplicate {
		return "", "", fmt.Errorf("E_WRAPPER_METADATA_HOOK_REUSED: hook %q would be called more than once in one admission", hook)
	}
	called[hook] = struct{}{}
	signature := fmt.Sprintf("func(LayerProfile, bool, %s) (%s, bool, error)", wireType, canonicalType)
	if err := e.addHookCheck(hook, signature); err != nil {
		return "", "", err
	}
	value = fmt.Sprintf("rpcWrapperCanonicalField%d", profileField.Ordinal)
	present = value + "Present"
	fmt.Fprintf(body, "%s, %s, err := %s(profile, %s, %s)\n", value, present, hook, wirePresent, wireValue)
	fmt.Fprintf(body, "if err != nil { return layerDecodedRPCRequest{}, fmt.Errorf(\"adapt RPC wrapper metadata field %s to %s: %%w\", err) }\n", profileField.Name, canonicalField.Name)
	if canonicalField.Condition == nil {
		fmt.Fprintf(body, "if !%s { return layerDecodedRPCRequest{}, &LayerCodecError{Operation: \"adapt RPC wrapper metadata\", Profile: profile, Semantic: %s, WireID: 0x%08x, Reason: %q} }\n", present, route.Method.Constant, route.WireID, "policy hook returned absent required canonical field "+canonicalField.Name)
	}
	return value, present, nil
}

func (e *layerRPCSourceEmitter) nodeForField(definition *semantic.Definition, field *semantic.FieldShape) (*layerTypeRefNode, error) {
	if definition == nil || field == nil || field.Kind != semantic.FieldValue {
		return nil, fmt.Errorf("invalid value field")
	}
	collector := &layerTypeRefCollector{drafts: make(map[string]*layerTypeRefDraft)}
	key, err := collector.add(&field.Type, makeLayerTypeRefScope(definition))
	if err != nil {
		return nil, err
	}
	node := e.nodeByKey[key]
	if node == nil || !node.Ref.Equal(field.Type) {
		return nil, fmt.Errorf("TypeRef node %q is absent or stale", key)
	}
	return node, nil
}
