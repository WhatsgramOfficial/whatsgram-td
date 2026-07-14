package gen

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gotd/tl"

	"github.com/iamxvbaba/td/gen/semantic"
)

func TestLayerRPCSourceModelStaticAdmissionAndFrozenResult(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	policy := layerRPCSourceSyntheticPolicy(t, set)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
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
	model, err := generator.buildLayerRPCSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}
	if model.LayerRPC != rpc || model.RouteCount != len(rpc.Routes) || len(model.Routes) != len(rpc.Routes) {
		t.Fatalf("RPC source route coverage = model:%d routes:%d want:%d", model.RouteCount, len(model.Routes), len(rpc.Routes))
	}
	if model.ProbeAttemptLimit != len(model.Profiles)+refs.MaxDepth || model.ProbeWorkMultiplier != len(model.Profiles) {
		t.Fatalf("speculative probe bounds = attempts:%d multiplier:%d, want %d/%d", model.ProbeAttemptLimit, model.ProbeWorkMultiplier, len(model.Profiles)+refs.MaxDepth, len(model.Profiles))
	}
	if model.UniqueAdmitCount <= 0 || model.UniqueAdmitCount >= model.RouteCount {
		t.Fatalf("RPC admit body coalescing = unique:%d exact:%d", model.UniqueAdmitCount, model.RouteCount)
	}
	confirmOne := findLayerRPCSourceRoute(t, model, 1, 0x21000030)
	confirmTwo := findLayerRPCSourceRoute(t, model, 2, 0x21000030)
	if confirmOne.Admit != confirmTwo.Admit || confirmOne.EmitAdmit == confirmTwo.EmitAdmit {
		t.Fatalf("identical future-stable route did not share one admit helper: one=%+v two=%+v", confirmOne, confirmTwo)
	}
	if model.Unprofiled == nil {
		t.Fatal("unprofiled admission model is absent")
	}
	if invariant := findLayerRPCUnprofiledInvariant(model, 0x21000030); invariant == nil || invariant.Method != "LayerSemanticMethodConfirm" {
		t.Fatalf("invariant Bool bootstrap route = %+v", invariant)
	}
	for _, rejected := range []uint32{0x21000020, 0x21000021} {
		if invariant := findLayerRPCUnprofiledInvariant(model, rejected); invariant != nil {
			t.Fatalf("cross-layer request/result drift %#08x was classified invariant: %+v", rejected, invariant)
		}
	}
	for _, layer := range []int{1, 2} {
		confirm := findLayerRPCSourceRoute(t, model, layer, 0x21000030)
		if !strings.Contains(confirm.Body, "wireInvariant: true") {
			t.Fatalf("invariant Bool route layer %d lacks wire proof metadata:\n%s", layer, confirm.Body)
		}
	}
	if echo := findLayerRPCSourceRoute(t, model, 2, 0x21000020); strings.Contains(echo.Body, "wireInvariant: true") {
		t.Fatalf("request-drift route was marked wire invariant:\n%s", echo.Body)
	}
	if join := findLayerRPCSourceRoute(t, model, 2, 0x21000021); strings.Contains(join.Body, "wireInvariant: true") {
		t.Fatalf("result-drift route was marked wire invariant:\n%s", join.Body)
	}
	if model.WrapperCount != 12 {
		t.Fatalf("wrapper route count = %d, want six wrappers in two profiles", model.WrapperCount)
	}
	if len(model.DefaultWrappers) != 7 {
		t.Fatalf("default wrapper fallback count = %d, want seven distinct wrapper CRCs", len(model.DefaultWrappers))
	}
	futureFallback := false
	for _, fallback := range model.DefaultWrappers {
		if fallback.WireID == 0x42000002 {
			futureFallback = len(fallback.Candidates) == 1 && fallback.Candidates[0].WireProfile == 2 &&
				fallback.Candidates[0].ProfileConstant == "LayerProfile2" && fallback.Candidates[0].Probe != ""
		}
	}
	if !futureFallback {
		t.Fatalf("Layer 2 future wrapper fallback = %+v", model.DefaultWrappers)
	}
	profileFallback := false
	invariantFallback := false
	for _, fallback := range model.DefaultWrappers {
		if fallback.WireID == 0x43000001 {
			profileFallback = len(fallback.Candidates) == 2 && fallback.Candidates[0].WireProfile == 1 &&
				fallback.Candidates[0].ProbeCandidate && fallback.Candidates[1].WireProfile == 2 && fallback.Candidates[1].ProbeCandidate
		}
		if fallback.WireID == 0xcb9f372d {
			probeCandidates := 0
			for _, candidate := range fallback.Candidates {
				if candidate.ProbeCandidate {
					probeCandidates++
				}
			}
			invariantFallback = len(fallback.Candidates) == 2 && probeCandidates == 1
		}
	}
	if !profileFallback {
		t.Fatalf("same-CRC profile-specific prefix probes = %+v", model.DefaultWrappers)
	}
	if !invariantFallback {
		t.Fatalf("invariant same-CRC candidates were not collapsed = %+v", model.DefaultWrappers)
	}
	for _, profile := range model.Profiles {
		found := false
		for _, route := range profile.Routes {
			if route.WireID == 0x43000001 {
				found = route.ProbeDefault
			}
		}
		if !found {
			t.Fatalf("profile %d same-CRC drift route omitted default prefix probing", profile.Layer)
		}
	}
	for name, resultType := range map[string]string{
		"GetInt":    "int",
		"GetLong":   "int64",
		"GetDouble": "float64",
		"GetString": "string",
		"GetBytes":  "[]byte",
		"GetObject": "bin.Object",
	} {
		handler := findLayerRPCSourceHandler(t, model, name)
		if handler.ResultType != resultType || handler.ErrorOnly ||
			!strings.Contains(handler.CanonicalResultEncoder, "layerRPCCanonicalTypeRefResult") {
			t.Errorf("%s handler facade = type:%q errorOnly:%v encoder:%q", name, handler.ResultType, handler.ErrorOnly, handler.CanonicalResultEncoder)
		}
	}
	if len(model.HookChecks) != 1 || model.HookChecks[0].Name != "adaptOldJoinResult" ||
		model.HookChecks[0].Signature != "func(LayerProfile, *NewJoin) (*OldJoin, error)" {
		t.Fatalf("typed result hook contracts = %+v", model.HookChecks)
	}

	join := findLayerRPCSourceRoute(t, model, 1, 0x21000011)
	for _, want := range []string{
		"layerDecodeWire21000011Bare(profile, b, state)",
		"canonicalResult: &",
		"wireResult: &",
		"canonical: layerTypeRef",
		"result: layerTypeRef",
		"adaptResult: layerAdaptRPCResult1_21000011",
	} {
		if !strings.Contains(join.Body, want) {
			t.Errorf("layer 1 join admission is missing %q\n%s", want, join.Body)
		}
	}
	if strings.Contains(join.Body, "map[") || strings.Contains(join.Body, "reflect.") {
		t.Fatal("ordinary admission contains a runtime schema map or reflection")
	}

	withLayer := findLayerRPCSourceRoute(t, model, 2, 0xda9b0d0d)
	if !withLayer.Wrapper {
		t.Fatal("invokeWithLayer route was not emitted as a transparent wrapper")
	}
	for _, want := range []string{
		"ResolveLayerProfile(rpcWrapperField",
		"preflight.selectExplicitProfile(inheritedProfile, selectedProfile",
		"decodeLayerRPCRequestState(nestedProfile, b, state, preflight, depth+1)",
		"state.bind(0, admitted.call.result)",
		"defer state.restore(bindingSnapshot)",
		"layerFreezeRPCWrapperField(LayerProfileCanonical, \"layer\"",
		"rpcUnknownTerminal.withOuterWrapper(profile, LayerSemanticMethodInvokeWithLayer, 0xda9b0d0d)",
		"admitted.wrappers = append(admitted.wrappers, wrapperFrame)",
	} {
		if !strings.Contains(withLayer.Body, want) {
			t.Errorf("invokeWithLayer admission is missing %q\n%s", want, withLayer.Body)
		}
	}
	futureWrapper := findLayerRPCSourceRoute(t, model, 2, 0x42000002)
	if !futureWrapper.Wrapper || !strings.Contains(futureWrapper.Body, "nestedProfile := inheritedProfile") {
		t.Fatalf("future wrapper does not separate wire and inherited profiles:\n%s", futureWrapper.Body)
	}

	legacy := findLayerRPCSourceRoute(t, model, 1, 0x21000012)
	if strings.Contains(legacy.Body, "ConsumeID") || !strings.Contains(legacy.Body, "historical-only RPC has no canonical semantic target") {
		t.Fatalf("historical-only rejection consumed input or invented a canonical request:\n%s", legacy.Body)
	}
}

func TestLayerRPCSourceUnsupportedHandlerResultFailsClosed(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerRPCSourceSyntheticPolicy(t, set)})
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
	var resultIndex = -1
	for index := range refs.RPCs {
		plan := &refs.RPCs[index]
		if plan.Key.Category != semantic.CategoryFunction || plan.Key.QName != "getInt" {
			continue
		}
		profile := plan.profile(set.CanonicalLayer)
		if profile != nil {
			resultIndex = profile.CanonicalResult
		}
		break
	}
	if resultIndex < 0 || resultIndex >= len(refs.Nodes) {
		t.Fatalf("getInt canonical result node = %d", resultIndex)
	}
	// Model an ordinary result that needs a generic binding unavailable at an
	// ordinary handler boundary. Source generation must stop instead of
	// inventing Object or canonical-byte fallback semantics.
	refs.Nodes[resultIndex].RequiresBinding = true
	_, err = generator.buildLayerRPCSourceModel(rpc, refs)
	if err == nil || !strings.Contains(err.Error(), "E_RPC_HANDLER_RESULT_UNSUPPORTED") {
		t.Fatalf("unsupported ordinary result error = %v", err)
	}
}

func TestLayerRPCSourceRejectsResultBeforeConsumingBody(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
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
	model, err := generator.buildLayerRPCSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}
	join := findLayerRPCSourceRoute(t, model, 1, 0x21000011)
	if strings.Contains(join.Body, "ConsumeID") || strings.Contains(join.Body, "layerDecodeWire") {
		t.Fatalf("rejected result consumed request bytes:\n%s", join.Body)
	}
	if !strings.Contains(join.Body, "admit RPC result") {
		t.Fatalf("rejected result has no exact boundary error:\n%s", join.Body)
	}
}

func TestLayerRPCSourceOldOnlyAdapterRequiresCanonicalTarget(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerRPCSourceAliasPolicy(t, set, "function:missing")})
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
	_, err = generator.buildLayerRPCSourceModel(rpc, refs)
	if err == nil || !strings.Contains(err.Error(), "E_OLD_ONLY_RPC_TARGET_NOT_FOUND") {
		t.Fatalf("old-only adapter without a canonical semantic target error = %v", err)
	}
}

func TestLayerRPCSourceOldOnlyAliasRoutesTypedCanonicalRequest(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerRPCSourceAliasPolicy(t, set, "function:modern")})
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
	model, err := generator.buildLayerRPCSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}
	legacy := findLayerRPCSourceRoute(t, model, 1, 0x21000012)
	for _, want := range []string{
		"preflight.run(profile, LayerSemanticMethodModern, 0x21000012, b)",
		"historicalField0, err := layerDecodeTypeRef",
		"request, err := adaptLegacyRequest(profile, historicalField0)",
		"method: LayerSemanticMethodModern",
		"canonicalResult: &",
		"wireResult: &",
	} {
		if !strings.Contains(legacy.Body, want) {
			t.Errorf("old-only alias admission is missing %q\n%s", want, legacy.Body)
		}
	}
	found := false
	for _, hook := range model.HookChecks {
		if hook.Name == "adaptLegacyRequest" {
			found = true
			if hook.Signature != "func(LayerProfile, int) (*ModernRequest, error)" {
				t.Fatalf("old-only request hook signature = %q", hook.Signature)
			}
		}
	}
	if !found {
		t.Fatalf("old-only request hook contract is absent: %+v", model.HookChecks)
	}
}

func TestLayerRPCSourceOldOnlyAliasFreezesCompanionResultAdapter(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerRPCSourceAliasPolicy(t, set, "function:join")})
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
	model, err := generator.buildLayerRPCSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}
	legacy := findLayerRPCSourceRoute(t, model, 1, 0x21000012)
	if !strings.Contains(legacy.Body, "method: LayerSemanticMethodJoin") ||
		!strings.Contains(legacy.Body, "adaptResult: layerAdaptRPCResult1_21000012") {
		t.Fatalf("old-only differing result was not frozen with the target handler and companion adapter:\n%s", legacy.Body)
	}
	want := map[string]string{
		"adaptLegacyRequest":       "func(LayerProfile, int) (*JoinRequest, error)",
		"adaptLegacyRequestResult": "func(LayerProfile, *NewJoin) (*Pong, error)",
	}
	for _, hook := range model.HookChecks {
		if signature, ok := want[hook.Name]; ok {
			if hook.Signature != signature {
				t.Fatalf("hook %s signature=%q, want %q", hook.Name, hook.Signature, signature)
			}
			delete(want, hook.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("old-only companion hook contracts are missing: %+v", want)
	}
}

func TestLayerRPCServerSourceIsSyntacticallyCompilable(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerRPCSourceSyntheticPolicy(t, set)})
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
	sourceModel, err := generator.buildLayerRPCSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}
	data := struct {
		Package        string
		LayerRPCSource *layerRPCSourceModel
	}{Package: "layerfixture", LayerRPCSource: sourceModel}
	var rendered bytes.Buffer
	if err := Template().ExecuteTemplate(&rendered, "layer_server", data); err != nil {
		t.Fatal(err)
	}
	formatted, err := format.Source(rendered.Bytes())
	if err != nil {
		t.Fatalf("format generated layer RPC server: %v\n%s", err, rendered.String())
	}
	text := string(formatted)
	for _, want := range []string{
		"switch profile",
		"switch id",
		"func decodeDefaultLayerRPCWrapper(",
		"layerProbeRPC2_42000002(LayerProfile2",
		"decodeLayerRPCRequestState(selected, b, state, preflight, depth)",
		"allowDefaultWrapperFallback(profile)",
		"func layerAdmitRPC1_21000011",
		"var _ func(LayerProfile, *NewJoin) (*OldJoin, error) = adaptOldJoinResult",
		"r.prepared.Call().EncodeResult(r.value, b)",
		"sha256.Sum256(wireRequest)",
		"func (s *ServerDispatcher) AdmitLayer(",
		"func (s *ServerDispatcher) AdmitDefaultLayer(",
		"func (s *ServerDispatcher) AdmitUnprofiled(",
		"return newLayerRPCUnknownTerminalError(profile, wireID, wireSize)",
		"func (s *ServerDispatcher) DispatchAdmitted(ctx context.Context, admitted LayerRequest) (LayerRPCResult, error)",
		"func (s *ServerDispatcher) HasLayerRPCHandler(semantic LayerSemanticID) bool",
		"func (s *ServerDispatcher) HandleUnprofiled(",
		"type LayerRPCWrapperConsumer func(context.Context, LayerRequest, LayerRPCNext) error",
		"func (s *ServerDispatcher) OnLayerRPCWrappers(",
		"atomic.CompareAndSwapUint32(&lease.consumed, 0, 1)",
		"type LayerRPCResult interface",
		"Prepare() (LayerPreparedResult, error)",
		"return r.prepared.Call().prepareResult(r.value)",
		"wrapper consumer returned before next completed",
		"func layerSemanticIdentityEchoRequest(",
		"semanticIdentity: semanticIdentity",
		"func (s *ServerDispatcher) OnJoin(",
		"func (s *ServerDispatcher) OnGetInt(f func(ctx context.Context) (int, error))",
		"func (s *ServerDispatcher) OnGetLong(f func(ctx context.Context) (int64, error))",
		"func (s *ServerDispatcher) OnGetDouble(f func(ctx context.Context) (float64, error))",
		"func (s *ServerDispatcher) OnGetString(f func(ctx context.Context) (string, error))",
		"func (s *ServerDispatcher) OnGetBytes(f func(ctx context.Context) ([]byte, error))",
		"func (s *ServerDispatcher) OnGetObject(f func(ctx context.Context) (bin.Object, error))",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("generated layer RPC server is missing %q", want)
		}
	}
	if strings.Contains(text, "map[uint32]") || strings.Contains(text, "reflect.") {
		t.Fatal("generated exact RPC routing contains a runtime wire map or reflection")
	}
}

func TestLayerRPCSourceTelegram225Through228Completeness(t *testing.T) {
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
	model, err := generator.buildLayerRPCSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}
	if model.RouteCount != len(rpc.Routes) || len(model.Profiles) != len(set.Schemas) {
		t.Fatalf("real RPC source coverage routes=%d/%d profiles=%d/%d", model.RouteCount, len(rpc.Routes), len(model.Profiles), len(set.Schemas))
	}
	wantWrappers := 0
	for routeIndex := range rpc.Routes {
		if rpc.Routes[routeIndex].Profile.Wrapper != nil {
			wantWrappers++
		}
	}
	if model.WrapperCount != wantWrappers || wantWrappers == 0 {
		t.Fatalf("real wrapper route coverage = %d, want %d", model.WrapperCount, wantWrappers)
	}
	authBind := findLayerRPCUnprofiledInvariant(model, 0xcdd42a05)
	if authBind == nil || authBind.Method != "LayerSemanticMethodAuthBindTempAuthKey" {
		t.Fatalf("auth.bindTempAuthKey is not a generated invariant bootstrap RPC: %+v", authBind)
	}
	for profileIndex := range model.Profiles {
		profile := &model.Profiles[profileIndex]
		want := 0
		for routeIndex := range rpc.Routes {
			if rpc.Routes[routeIndex].Layer == profile.Layer {
				want++
			}
		}
		if len(profile.Routes) != want {
			t.Fatalf("layer %d static switch routes=%d, want=%d", profile.Layer, len(profile.Routes), want)
		}
	}
	var rendered bytes.Buffer
	if err := Template().ExecuteTemplate(&rendered, "layer_server", struct {
		Package        string
		LayerRPCSource *layerRPCSourceModel
	}{Package: "tg", LayerRPCSource: model}); err != nil {
		t.Fatal(err)
	}
	if _, err := format.Source(rendered.Bytes()); err != nil {
		t.Fatalf("format Telegram Layers 225-228 generated RPC server: %v\n%s", err, rendered.String())
	}
	uniqueBodyBytes := 0
	for _, route := range model.Routes {
		if route.EmitAdmit {
			uniqueBodyBytes += len(route.Body)
		}
		if route.EmitProbe {
			uniqueBodyBytes += len(route.ProbeBody)
		}
	}
	t.Logf("Telegram Layers 225-228 RPC source: exact_routes=%d unique_admits=%d wrapper_routes=%d unique_probes=%d handlers=%d admission_fields=%d",
		model.RouteCount, model.UniqueAdmitCount, model.WrapperCount, model.UniqueProbeCount, len(model.Handlers), len(model.LayerRPC.AdmissionFields))
	t.Logf("Telegram Layers 225-228 unique RPC body syntax=%d bytes", uniqueBodyBytes)
}

func TestLayerRPCSourceUnchangedFutureProfileReusesAdmitBodies(t *testing.T) {
	profile, canonical := layerRPCSourceSyntheticSources()
	future := strings.Replace(canonical, "// LAYER 2", "// LAYER 3", 1)
	profiles := make([]*semantic.SchemaModel, 0, 3)
	for _, source := range []string{profile, canonical, future} {
		parsed, err := tl.Parse(bytes.NewBufferString(source))
		if err != nil {
			t.Fatal(err)
		}
		schema, err := semantic.BuildSchema(parsed, semantic.SourceRef{Layer: parsed.Layer, Repository: "https://example.invalid/official.git", Path: "api.tl"})
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, schema)
	}
	set, err := NewSchemaSet(3, profiles...)
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerRPCSourceSyntheticPolicy(t, set)})
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
	model, err := generator.buildLayerRPCSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}
	for _, wireID := range []uint32{0x21000030, 0xcb9f372d, 0xda9b0d0d} {
		previous := findLayerRPCSourceRoute(t, model, 2, wireID)
		added := findLayerRPCSourceRoute(t, model, 3, wireID)
		if previous.Admit != added.Admit || added.EmitAdmit {
			t.Fatalf("unchanged future route %#08x cloned admit helper: previous=%s added=%s emit=%v", wireID, previous.Admit, added.Admit, added.EmitAdmit)
		}
		if previous.Probe != "" && (previous.Probe != added.Probe || added.EmitProbe) {
			t.Fatalf("unchanged future wrapper %#08x cloned probe helper: previous=%s added=%s emit=%v", wireID, previous.Probe, added.Probe, added.EmitProbe)
		}
	}
	render := func() []byte {
		var output bytes.Buffer
		if err := Template().ExecuteTemplate(&output, "layer_server", struct {
			Package        string
			LayerRPCSource *layerRPCSourceModel
		}{Package: "tg", LayerRPCSource: model}); err != nil {
			t.Fatal(err)
		}
		formatted, err := format.Source(output.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return formatted
	}
	first, second := render(), render()
	if !bytes.Equal(first, second) {
		t.Fatal("coalesced future-profile server source is nondeterministic")
	}
}

func TestSchemaSetWriteSourceSelectsStaticLayerServer(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{
		LayerPolicy: layerTestPolicy(t, set),
		GenerateFlags: GenerateFlags{
			Server: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	files := sourceSnapshot{}
	if err := generator.WriteSource(files, "layerfixture", Template()); err != nil {
		t.Fatal(err)
	}
	server := files["tl_server_gen.go"]
	if len(server) == 0 {
		t.Fatal("schema-set Server generation omitted tl_server_gen.go")
	}
	if _, err := format.Source(server); err != nil {
		t.Fatalf("format integrated layer server: %v\n%s", err, server)
	}
	text := string(server)
	for _, want := range []string{
		"func decodeLayerRPCRequestState(",
		"func layerAdmitRPC1_21000011(",
		"handlers map[LayerSemanticID]layerRPCRegisteredHandler",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("integrated schema-set server is missing %q", want)
		}
	}
	if strings.Contains(text, "handlers map[uint32]func") || strings.Contains(text, "s.handlers[JoinRequestTypeID]") {
		t.Fatal("schema-set Server generation fell back to the legacy canonical-ID dispatcher")
	}
	codecAPI := string(files["tl_layer_codec_api_gen.go"])
	if strings.Contains(codecAPI, "func (r LayerRequest) Request()") {
		t.Fatal("generated LayerRequest exposes its mutable canonical request")
	}
	for _, want := range []string{
		"lease *layerRPCRequestLease",
		"func (w LayerRPCWrapper) Value(name string) (value any, present bool, ok bool, err error)",
		"type LayerPreparedValue[T any] struct",
		"func PrepareFrozenLayer[T any](",
		"type LayerPreparedResult struct",
		"func (c LayerCall) PrepareFrozenResult(",
		"type LayerSemanticRequestIdentity struct",
		"func (p LayerPreparedCall) SemanticIdentity() LayerSemanticRequestIdentity",
		"func (r LayerRequest) ProfileEvidence() (LayerProfile, bool)",
		"func (r LayerRequest) EffectiveProfile() (LayerProfile, bool)",
		"var ErrLayerProfileRequired = errors.New(\"layer profile required\")",
		"var ErrLayerProfileAmbiguous = errors.New(\"ambiguous layer profile evidence\")",
		"type LayerRPCUnknownTerminalWrapper struct",
		"func (e *LayerRPCUnknownTerminalError) WrapperCount() int",
		"func (e *LayerRPCUnknownTerminalError) Wrapper(index int) (LayerRPCUnknownTerminalWrapper, bool)",
	} {
		if !strings.Contains(codecAPI, want) {
			t.Errorf("integrated layer codec API is missing %q", want)
		}
	}
}

func TestLayerRPCSyntheticGeneratedPackageCompiles(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{
		LayerPolicy: layerTestPolicy(t, set),
		GenerateFlags: GenerateFlags{
			Client: true,
			Server: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sources := sourceSnapshot{}
	if err := generator.WriteSource(sources, "layerfixture", Template()); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	goMod := fmt.Sprintf("module layerfixture\n\ngo 1.25\n\nrequire github.com/iamxvbaba/td v0.0.0\nreplace github.com/iamxvbaba/td => %s\n", filepath.ToSlash(root))
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
	runtimeTest := []byte(`package layerfixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iamxvbaba/td/bin"
)

type layerRPCContextKey struct{}

func wrappedEchoWire() []byte {
	var encoded bin.Buffer
	encoded.PutID(0xda9b0d0d)
	encoded.PutInt(1)
	encoded.PutID(0x365275f2)
	encoded.PutVectorHeader(2)
	encoded.PutLong(11)
	encoded.PutLong(22)
	encoded.PutID(0x31000002)
	encoded.PutID(0x31000001)
	encoded.PutInt(5)
	encoded.PutInt(10)
	encoded.PutID(0xcb9f372d)
	encoded.PutLong(99)
	encoded.PutID(0x21000010)
	encoded.PutString("historical")
	encoded.PutInt(42)
	return encoded.Copy()
}

func bulkWire(wireID uint32, first, second []int) []byte {
	var encoded bin.Buffer
	encoded.PutID(wireID)
	encoded.PutVectorHeader(len(first))
	for _, value := range first { encoded.PutInt(value) }
	encoded.PutVectorHeader(len(second))
	for _, value := range second { encoded.PutInt(value) }
	return encoded.Copy()
}

func canonicalRequest(wireID uint32, values ...int) *bin.Buffer {
	var encoded bin.Buffer
	encoded.PutID(wireID)
	for _, value := range values { encoded.PutInt(value) }
	return &encoded
}

func TestGeneratedUnknownTerminalEvidenceRequiresDecodedWrapper(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	for _, profile := range []LayerProfile{LayerProfile1, LayerProfile2} {
		wrapped := bin.Buffer{}
		wrapped.PutID(0xda9b0d0d)
		wrapped.PutInt(int(profile))
		wrapped.PutID(0xfeedbeef)
		before := wrapped.Copy()
		_, err := dispatcher.AdmitLayer(profile, &wrapped)
		if !errors.Is(err, ErrLayerUnknownRPCMethod) {
			t.Fatalf("profile %d wrapped unknown classification = %v", profile, err)
		}
		var terminal *LayerRPCUnknownTerminalError
		if !errors.As(err, &terminal) {
			t.Fatalf("profile %d wrapped unknown type = %T, want *LayerRPCUnknownTerminalError", profile, err)
		}
		if terminal.Profile != profile || terminal.WireID != 0xfeedbeef || terminal.WireSize != 4 {
			t.Fatalf("profile %d wrapped unknown evidence = %+v", profile, terminal)
		}
		wrapper, ok := terminal.Wrapper(0)
		if terminal.WrapperCount() != 1 || !ok || wrapper.Profile() != profile ||
			wrapper.Semantic() != LayerSemanticMethodInvokeWithLayer || wrapper.WireID() != 0xda9b0d0d {
			t.Fatalf("profile %d wrapped unknown chain = count:%d wrapper:%v/%+v", profile, terminal.WrapperCount(), ok, wrapper)
		}
		if _, ok := terminal.Wrapper(1); ok { t.Fatalf("profile %d exposed wrapper outside chain", profile) }
		if !bytes.Equal(wrapped.Raw(), before) { t.Fatalf("profile %d wrapped unknown consumed caller input", profile) }
	}

	other := bin.Buffer{}
	other.PutID(0xcb9f372d)
	other.PutLong(99)
	other.PutID(0xda9b0d0d)
	other.PutInt(2)
	other.PutID(0xfeedbeef)
	_, err := dispatcher.AdmitLayer(LayerProfile2, &other)
	var otherTerminal *LayerRPCUnknownTerminalError
	if !errors.As(err, &otherTerminal) || otherTerminal.WrapperCount() != 2 {
		t.Fatalf("distinct wrapper chain = %#v / %v", otherTerminal, err)
	}
	outer, outerOK := otherTerminal.Wrapper(0)
	inner, innerOK := otherTerminal.Wrapper(1)
	if !outerOK || !innerOK || outer.Semantic() != LayerSemanticMethodInvokeAfterMsg || outer.WireID() != 0xcb9f372d ||
		inner.Semantic() != LayerSemanticMethodInvokeWithLayer || inner.WireID() != 0xda9b0d0d {
		t.Fatalf("distinct wrapper identities = outer:%v/%+v inner:%v/%+v", outerOK, outer, innerOK, inner)
	}

	trailing := bin.Buffer{}
	trailing.PutID(0xda9b0d0d)
	trailing.PutInt(2)
	trailing.PutID(0xfeedbeef)
	trailing.PutInt(7)
	_, err = dispatcher.AdmitLayer(LayerProfile2, &trailing)
	var terminal *LayerRPCUnknownTerminalError
	if !errors.As(err, &terminal) || terminal.WireSize != 8 {
		t.Fatalf("wrapped unknown trailing evidence = %#v / %v, want 8 bytes", terminal, err)
	}

	naked := canonicalRequest(0xfeedbeef)
	_, err = dispatcher.AdmitLayer(LayerProfile2, naked)
	terminal = nil
	if !errors.Is(err, ErrLayerUnknownRPCMethod) || errors.As(err, &terminal) {
		t.Fatalf("naked unknown was classified as decoded wrapper terminal: %#v / %v", terminal, err)
	}

	malformed := canonicalRequest(0xda9b0d0d, 2)
	_, err = dispatcher.AdmitLayer(LayerProfile2, malformed)
	terminal = nil
	if err == nil || errors.As(err, &terminal) {
		t.Fatalf("malformed wrapper was classified as decoded terminal: %#v / %v", terminal, err)
	}

	malformedOther := canonicalRequest(0xcb9f372d, 1)
	_, err = dispatcher.AdmitLayer(LayerProfile2, malformedOther)
	terminal = nil
	if err == nil || errors.As(err, &terminal) {
		t.Fatalf("malformed non-selector wrapper was classified as decoded terminal: %#v / %v", terminal, err)
	}
}

func TestGeneratedCanonicalHandleCompatibility(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	var nilDispatcher *ServerDispatcher
	if nilDispatcher.HasLayerRPCHandler(LayerSemanticMethodGetInt) {
		t.Fatal("nil dispatcher reported a registered RPC handler")
	}
	if dispatcher.HasLayerRPCHandler(LayerSemanticMethodGetInt) {
		t.Fatal("unregistered primitive RPC handler was reported as present")
	}
	thingCalls := 0
	failBytes := false
	dispatcher.OnEcho(func(context.Context, int) (*Pong, error) {
		return &Pong{Value: 7}, nil
	})
	dispatcher.OnConfirm(func(context.Context) (bool, error) { return true, nil })
	dispatcher.OnGetThing(func(context.Context) (ThingClass, error) {
		thingCalls++
		if thingCalls == 2 { return nil, nil }
		return &ThingOne{Value: 8}, nil
	})
	dispatcher.OnListIDs(func(context.Context) ([]int, error) {
		return []int{9, 10}, nil
	})
	dispatcher.OnGetInt(func(context.Context) (int, error) { return -7, nil })
	dispatcher.OnGetLong(func(context.Context) (int64, error) { return (int64(1) << 40) + 3, nil })
	dispatcher.OnGetDouble(func(context.Context) (float64, error) { return 1.5, nil })
	dispatcher.OnGetString(func(context.Context) (string, error) { return "layered", nil })
	dispatcher.OnGetBytes(func(context.Context) ([]byte, error) {
		if failBytes { return nil, context.Canceled }
		return []byte{1, 2, 3, 4, 5}, nil
	})
	dispatcher.OnGetObject(func(context.Context) (bin.Object, error) {
		return &Pong{Value: 12}, nil
	})
	if !dispatcher.HasLayerRPCHandler(LayerSemanticMethodGetInt) {
		t.Fatal("registered primitive RPC handler was not reported as present")
	}

	direct, err := dispatcher.Handle(context.Background(), canonicalRequest(0x21000020, 1))
	if err != nil { t.Fatal(err) }
	if value, ok := direct.(*Pong); !ok || value.Value != 7 {
		t.Fatalf("canonical direct result = %#v", direct)
	}

	boolean, err := dispatcher.Handle(context.Background(), canonicalRequest(0x21000030))
	if err != nil { t.Fatal(err) }
	if boxed, ok := boolean.(*BoolBox); !ok {
		t.Fatalf("canonical Bool result = %T", boolean)
	} else if _, ok := boxed.Bool.(*BoolTrue); !ok {
		t.Fatalf("canonical Bool payload = %T", boxed.Bool)
	}

	class, err := dispatcher.Handle(context.Background(), canonicalRequest(0x21000031))
	if err != nil { t.Fatal(err) }
	if boxed, ok := class.(*ThingBox); !ok {
		t.Fatalf("canonical class result = %T", class)
	} else if value, ok := boxed.Thing.(*ThingOne); !ok || value.Value != 8 {
		t.Fatalf("canonical class payload = %#v", boxed.Thing)
	}
	nilClass, err := dispatcher.Handle(context.Background(), canonicalRequest(0x21000031))
	if err != nil { t.Fatal(err) }
	if boxed, ok := nilClass.(*ThingBox); !ok || boxed.Thing != nil {
		t.Fatalf("canonical nil class result = %#v", nilClass)
	}

	vector, err := dispatcher.Handle(context.Background(), canonicalRequest(0x21000032))
	if err != nil { t.Fatal(err) }
	if boxed, ok := vector.(*IntVector); !ok || len(boxed.Elems) != 2 || boxed.Elems[0] != 9 || boxed.Elems[1] != 10 {
		t.Fatalf("canonical vector result = %#v", vector)
	}

	primitiveCases := []struct {
		name string
		wireID uint32
		want func(*bin.Buffer)
	}{
		{name: "int", wireID: 0x21000043, want: func(b *bin.Buffer) { b.PutInt(-7) }},
		{name: "long", wireID: 0x21000044, want: func(b *bin.Buffer) { b.PutLong((int64(1) << 40) + 3) }},
		{name: "double", wireID: 0x21000045, want: func(b *bin.Buffer) { b.PutDouble(1.5) }},
		{name: "string", wireID: 0x21000046, want: func(b *bin.Buffer) { b.PutString("layered") }},
		{name: "bytes", wireID: 0x21000047, want: func(b *bin.Buffer) { b.PutBytes([]byte{1, 2, 3, 4, 5}) }},
		{name: "Object", wireID: 0x21000048, want: func(b *bin.Buffer) {
			b.PutID(0x21000001)
			b.PutInt(12)
		}},
	}
	for _, test := range primitiveCases {
		t.Run(test.name, func(t *testing.T) {
			result, err := dispatcher.Handle(context.Background(), canonicalRequest(test.wireID))
			if err != nil { t.Fatal(err) }
			var got bin.Buffer
			if err := result.Encode(&got); err != nil { t.Fatal(err) }
			var want bin.Buffer
			test.want(&want)
			if !bytes.Equal(got.Raw(), want.Raw()) {
				t.Fatalf("canonical %s bytes = %x, want %x", test.name, got.Raw(), want.Raw())
			}
		})
	}

	profileResult, err := dispatcher.HandleLayer(LayerProfile1, context.Background(), canonicalRequest(0x21000033))
	if err != nil { t.Fatal(err) }
	if _, ok := profileResult.(LayerRPCResult); !ok {
		t.Fatalf("exact-profile primitive result = %T, want LayerRPCResult", profileResult)
	}
	var profileBytes bin.Buffer
	if err := profileResult.Encode(&profileBytes); err != nil { t.Fatal(err) }
	var wantProfileBytes bin.Buffer
	wantProfileBytes.PutInt(-7)
	if !bytes.Equal(profileBytes.Raw(), wantProfileBytes.Raw()) {
		t.Fatalf("profile primitive bytes = %x, want %x", profileBytes.Raw(), wantProfileBytes.Raw())
	}

	failBytes = true
	if _, err := dispatcher.Handle(context.Background(), canonicalRequest(0x21000047)); err != context.Canceled {
		t.Fatalf("primitive handler error = %v, want context.Canceled", err)
	}
}

func admitWrappedEcho(t *testing.T, dispatcher *ServerDispatcher, wire []byte) LayerRequest {
	t.Helper()
	requestBody := bin.Buffer{Buf: append([]byte(nil), wire...)}
	admitted, err := dispatcher.AdmitUnprofiled(&requestBody)
	if err != nil {
		t.Fatal(err)
	}
	if requestBody.Len() != 0 {
		t.Fatalf("admission left %d request bytes", requestBody.Len())
	}
	return admitted
}

func TestGeneratedUnprofiledInvariantBootstrap(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	dispatcher.OnConfirm(func(context.Context) (bool, error) { return true, nil })

	bare := canonicalRequest(0x21000030)
	admitted, err := dispatcher.AdmitUnprofiled(bare)
	if err != nil { t.Fatal(err) }
	if bare.Len() != 0 { t.Fatalf("invariant admission left %d bytes", bare.Len()) }
	if evidence, ok := admitted.ProfileEvidence(); ok || evidence != LayerProfile(0) {
		t.Fatalf("invariant admission fabricated profile evidence: %d/%v", evidence, ok)
	}
	if effective, ok := admitted.EffectiveProfile(); ok || effective != LayerProfile(0) {
		t.Fatalf("invariant admission fabricated an effective profile: %d/%v", effective, ok)
	}
	if admitted.Call().Profile() != LayerProfileCanonical {
		t.Fatalf("invariant internal codec profile = %d, want canonical", admitted.Call().Profile())
	}
	if !admitted.Call().WireInvariant() {
		t.Fatal("invariant admission lost generated request/result wire proof")
	}
	result, err := dispatcher.DispatchAdmitted(context.Background(), admitted)
	if err != nil { t.Fatal(err) }
	if !result.WireInvariant() {
		t.Fatal("invariant RPC result lost generated wire proof")
	}
	var encoded bin.Buffer
	if err := result.Encode(&encoded); err != nil { t.Fatal(err) }
	var want bin.Buffer
	want.PutID(0x997275b5)
	if !bytes.Equal(encoded.Raw(), want.Raw()) {
		t.Fatalf("invariant Bool result = %x, want %x", encoded.Raw(), want.Raw())
	}

	requestDrift := canonicalRequest(0x21000020, 7)
	if _, err := dispatcher.AdmitUnprofiled(requestDrift); err == nil {
		t.Fatal("unprofiled admission accepted a cross-layer request-ID/body change")
	}
	resultDrift := canonicalRequest(0x21000021, 7)
	if _, err := dispatcher.AdmitUnprofiled(resultDrift); err == nil {
		t.Fatal("unprofiled admission accepted a cross-layer result TypeRef change")
	}

	var wrapped bin.Buffer
	wrapped.PutID(0xda9b0d0d)
	wrapped.PutInt(1)
	wrapped.PutID(0x21000030)
	wrappedAdmission, err := dispatcher.AdmitUnprofiled(&wrapped)
	if err != nil { t.Fatal(err) }
	if evidence, ok := wrappedAdmission.ProfileEvidence(); !ok || evidence != LayerProfile1 {
		t.Fatalf("invokeWithLayer profile evidence = %d/%v, want 1/true", evidence, ok)
	}
	if effective, ok := wrappedAdmission.EffectiveProfile(); !ok || effective != LayerProfile1 {
		t.Fatalf("invokeWithLayer effective profile = %d/%v, want 1/true", effective, ok)
	}
	if wrappedAdmission.Call().Profile() != LayerProfile1 {
		t.Fatalf("invokeWithLayer call profile = %d, want 1", wrappedAdmission.Call().Profile())
	}
}

func TestGeneratedDefaultLayerAdmission(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)

	naked := canonicalRequest(0x21000020, 7)
	admitted, err := dispatcher.AdmitDefaultLayer(LayerProfile2, naked)
	if err != nil { t.Fatal(err) }
	if naked.Len() != 0 { t.Fatalf("default naked admission left %d bytes", naked.Len()) }
	if effective, ok := admitted.EffectiveProfile(); !ok || effective != LayerProfile2 {
		t.Fatalf("default naked effective profile = %d/%v, want 2/true", effective, ok)
	}
	if evidence, ok := admitted.ProfileEvidence(); ok || evidence != LayerProfile(0) {
		t.Fatalf("inherited default masqueraded as explicit evidence: %d/%v", evidence, ok)
	}
	if admitted.Call().Profile() != LayerProfile2 {
		t.Fatalf("default naked call profile = %d, want 2", admitted.Call().Profile())
	}

	// Layer 1 does not know the Layer 2 CRC of this transparent envelope. A
	// naked nested query supplies no profile evidence, so default admission
	// fails closed without consuming the caller buffer.
	var futureNaked bin.Buffer
	futureNaked.PutID(0x42000002)
	futureNaked.PutID(0x21000010)
	futureNaked.PutString("historical")
	futureNaked.PutInt(42)
	futureNakedBefore := futureNaked.Copy()
	futureNakedStrict := bin.Buffer{Buf: futureNaked.Copy()}
	futureNakedStrictBefore := futureNakedStrict.Copy()
	if _, err := dispatcher.AdmitDefaultLayer(LayerProfile1, &futureNaked); !errors.Is(err, ErrLayerProfileRequired) {
		t.Fatalf("future naked wrapper error = %v, want ErrLayerProfileRequired", err)
	}
	if !bytes.Equal(futureNaked.Raw(), futureNakedBefore) {
		t.Fatal("future naked wrapper probe mutated caller input")
	}
	if _, err := dispatcher.AdmitLayer(LayerProfile1, &futureNakedStrict); !errors.Is(err, ErrLayerUnknownRPCMethod) {
		t.Fatalf("strict Layer 1 future wrapper error = %v, want ErrLayerUnknownRPCMethod", err)
	}
	if !bytes.Equal(futureNakedStrict.Raw(), futureNakedStrictBefore) {
		t.Fatal("strict future-wrapper rejection mutated caller input")
	}

	// The same future envelope can expose invokeWithLayer. Prefix probing uses
	// private copies, then exact Layer 2 admission re-decodes the complete bytes
	// and reproduces that explicit evidence before accepting the request.
	var futureSelected bin.Buffer
	futureSelected.PutID(0x42000002)
	futureSelected.PutID(0xda9b0d0d)
	futureSelected.PutInt(2)
	futureSelected.PutID(0x21000020)
	futureSelected.PutInt(7)
	futureAdmission, err := dispatcher.AdmitDefaultLayer(LayerProfile1, &futureSelected)
	if err != nil { t.Fatal(err) }
	if futureSelected.Len() != 0 || futureAdmission.Call().Profile() != LayerProfile2 || futureAdmission.WrapperCount() != 2 {
		t.Fatalf("future selected admission = remaining:%d profile:%d wrappers:%d", futureSelected.Len(), futureAdmission.Call().Profile(), futureAdmission.WrapperCount())
	}
	if evidence, ok := futureAdmission.ProfileEvidence(); !ok || evidence != LayerProfile2 {
		t.Fatalf("future selected evidence = %d/%v, want 2/true", evidence, ok)
	}
	outer, _ := futureAdmission.Wrapper(0)
	selector, selectorOK := futureAdmission.Wrapper(1)
	if outer.Profile() != LayerProfile2 || outer.WireID() != 0x42000002 ||
		!selectorOK || selector.Profile() != LayerProfile2 || selector.WireID() != 0xda9b0d0d {
		t.Fatalf("future wrapper profiles = outer:%d/%#08x selector:%d/%#08x/%v",
			outer.Profile(), outer.WireID(), selector.Profile(), selector.WireID(), selectorOK)
	}

	// This wrapper keeps one CRC and direct BodyShape across profiles, while
	// its metadata class uses profile-specific constructor IDs. The inherited
	// Layer 1 prefix fails on Layer 2 metadata, the Layer 2 candidate uniquely
	// reaches invokeWithLayer(2), and only then does exact replay consume bytes.
	var driftSelected bin.Buffer
	driftSelected.PutID(0x43000001)
	driftSelected.PutVectorHeader(3)
	driftSelected.PutInt(1)
	driftSelected.PutInt(2)
	driftSelected.PutInt(3)
	driftSelected.PutID(0x44000002)
	driftSelected.PutInt(9)
	driftSelected.PutID(0xda9b0d0d)
	driftSelected.PutInt(2)
	driftSelected.PutID(0x21000020)
	driftSelected.PutInt(7)
	driftStrict := bin.Buffer{Buf: driftSelected.Copy()}
	driftStrictBefore := driftStrict.Copy()
	driftAdmission, err := dispatcher.AdmitDefaultLayerWithLimits(LayerProfile1, &driftSelected, LayerDecodeLimits{MaxVectorElements: 3, MaxAggregateElements: 3})
	if err != nil { t.Fatal(err) }
	if driftSelected.Len() != 0 || driftAdmission.Call().Profile() != LayerProfile2 || driftAdmission.WrapperCount() != 2 {
		t.Fatalf("same-CRC drift admission = remaining:%d profile:%d wrappers:%d", driftSelected.Len(), driftAdmission.Call().Profile(), driftAdmission.WrapperCount())
	}
	if evidence, ok := driftAdmission.ProfileEvidence(); !ok || evidence != LayerProfile2 {
		t.Fatalf("same-CRC drift evidence = %d/%v, want 2/true", evidence, ok)
	}
	if _, err := dispatcher.AdmitLayer(LayerProfile1, &driftStrict); err == nil {
		t.Fatal("strict Layer 1 admission accepted Layer 2 metadata layout")
	}
	if !bytes.Equal(driftStrict.Raw(), driftStrictBefore) {
		t.Fatal("strict same-CRC layout rejection mutated caller input")
	}

	// The inherited profile really owns this same-CRC layout, and its nested
	// query is a naked terminal. Prefix probing supplies no explicit selector;
	// the current exact switch must therefore perform one authoritative replay
	// under the inherited default instead of rejecting the valid request.
	inheritedDispatcher := NewServerDispatcher(nil)
	inheritedPreflightCalls := 0
	inheritedDispatcher.OnLayerRPCAdmissionPreflight(func(view LayerRPCAdmissionView) error {
		inheritedPreflightCalls++
		if view.Profile() != LayerProfile1 || view.Semantic() != LayerSemanticMethodEcho { t.Fatalf("inherited terminal view = profile:%d semantic:%d", view.Profile(), view.Semantic()) }
		return nil
	})
	var inheritedNaked bin.Buffer
	inheritedNaked.PutID(0x43000001)
	inheritedNaked.PutVectorHeader(3)
	inheritedNaked.PutInt(1); inheritedNaked.PutInt(2); inheritedNaked.PutInt(3)
	inheritedNaked.PutID(0x44000001); inheritedNaked.PutInt(8)
	inheritedNaked.PutID(0x21000010); inheritedNaked.PutString("historical"); inheritedNaked.PutInt(42)
	inheritedAdmission, err := inheritedDispatcher.AdmitDefaultLayerWithLimits(LayerProfile1, &inheritedNaked, LayerDecodeLimits{MaxVectorElements: 3, MaxAggregateElements: 3})
	if err != nil { t.Fatal(err) }
	if inheritedNaked.Len() != 0 || inheritedAdmission.Call().Profile() != LayerProfile1 || inheritedAdmission.WrapperCount() != 1 || inheritedPreflightCalls != 1 {
		t.Fatalf("inherited same-CRC naked admission = remaining:%d profile:%d wrappers:%d preflight:%d", inheritedNaked.Len(), inheritedAdmission.Call().Profile(), inheritedAdmission.WrapperCount(), inheritedPreflightCalls)
	}
	if evidence, ok := inheritedAdmission.ProfileEvidence(); ok || evidence != LayerProfile(0) {
		t.Fatalf("inherited naked wrapper invented explicit evidence: %d/%v", evidence, ok)
	}

	var unsupportedSelector bin.Buffer
	unsupportedSelector.PutID(0x43000001)
	unsupportedSelector.PutVectorHeader(3)
	unsupportedSelector.PutInt(1); unsupportedSelector.PutInt(2); unsupportedSelector.PutInt(3)
	unsupportedSelector.PutID(0x44000001); unsupportedSelector.PutInt(8)
	unsupportedSelector.PutID(0xda9b0d0d); unsupportedSelector.PutInt(999)
	unsupportedSelector.PutID(0x21000010); unsupportedSelector.PutString("historical"); unsupportedSelector.PutInt(42)
	unsupportedBefore := unsupportedSelector.Copy()
	if _, err := inheritedDispatcher.AdmitDefaultLayerWithLimits(LayerProfile1, &unsupportedSelector, LayerDecodeLimits{MaxVectorElements: 3, MaxAggregateElements: 3}); !errors.Is(err, errLayerRPCProbeUnsupportedProfile) {
		t.Fatalf("unsupported selector fallback error = %v", err)
	}
	if !bytes.Equal(unsupportedSelector.Raw(), unsupportedBefore) { t.Fatal("unsupported selector fallback mutated caller input") }
	// Reverse which profile-specific layout is valid. Candidate order stays
	// deterministic, so this covers both wrong-before-right and right-before-
	// wrong without allowing either failed candidate to consume the other's
	// semantic aggregate budget.
	var reverseDrift bin.Buffer
	reverseDrift.PutID(0x43000001)
	reverseDrift.PutVectorHeader(3)
	reverseDrift.PutInt(1)
	reverseDrift.PutInt(2)
	reverseDrift.PutInt(3)
	reverseDrift.PutID(0x44000001)
	reverseDrift.PutInt(8)
	reverseDrift.PutID(0xda9b0d0d)
	reverseDrift.PutInt(1)
	reverseDrift.PutID(0x21000010)
	reverseDrift.PutString("historical")
	reverseDrift.PutInt(42)
	reverseAdmission, err := dispatcher.AdmitDefaultLayerWithLimits(LayerProfile2, &reverseDrift, LayerDecodeLimits{MaxVectorElements: 3, MaxAggregateElements: 3})
	if err != nil { t.Fatal(err) }
	if reverseDrift.Len() != 0 || reverseAdmission.Call().Profile() != LayerProfile1 || reverseAdmission.WrapperCount() != 2 {
		t.Fatalf("reverse same-CRC drift admission = remaining:%d profile:%d wrappers:%d", reverseDrift.Len(), reverseAdmission.Call().Profile(), reverseAdmission.WrapperCount())
	}

	// A long chain of wrappers whose generated prefix is identical in every
	// profile must remain one linear probe path, not profiles^depth branches.
	var invariantChain bin.Buffer
	invariantChain.PutID(0x42000002)
	const invariantDepth = 12
	for index := 0; index < invariantDepth; index++ {
		invariantChain.PutID(0xcb9f372d)
		invariantChain.PutLong(int64(index + 1))
	}
	invariantChain.PutID(0xda9b0d0d)
	invariantChain.PutInt(2)
	invariantChain.PutID(0x21000020)
	invariantChain.PutInt(7)
	invariantAdmission, err := dispatcher.AdmitDefaultLayer(LayerProfile1, &invariantChain)
	if err != nil { t.Fatal(err) }
	if invariantChain.Len() != 0 || invariantAdmission.Call().Profile() != LayerProfile2 ||
		invariantAdmission.WrapperCount() != invariantDepth+2 {
		t.Fatalf("linear invariant wrapper chain = remaining:%d profile:%d wrappers:%d", invariantChain.Len(), invariantAdmission.Call().Profile(), invariantAdmission.WrapperCount())
	}

	var futureUnknown bin.Buffer
	futureUnknown.PutID(0x42000002)
	futureUnknown.PutID(0xfeedbeef)
	futureUnknownBefore := futureUnknown.Copy()
	if _, err := dispatcher.AdmitDefaultLayer(LayerProfile1, &futureUnknown); !errors.Is(err, ErrLayerUnknownRPCMethod) {
		t.Fatalf("future wrapper unknown terminal = %v, want ErrLayerUnknownRPCMethod", err)
	}
	if !bytes.Equal(futureUnknown.Raw(), futureUnknownBefore) {
		t.Fatal("unknown nested terminal probe mutated caller input")
	}

	// An inherited transparent wrapper is decoded under the caller default,
	// while an inner invokeWithLayer overrides only its nested query.
	var wrapped bin.Buffer
	wrapped.PutID(0xcb9f372d)
	wrapped.PutLong(99)
	wrapped.PutID(0xda9b0d0d)
	wrapped.PutInt(1)
	wrapped.PutID(0x21000010)
	wrapped.PutString("historical")
	wrapped.PutInt(42)
	strict := bin.Buffer{Buf: wrapped.Copy()}
	strictBefore := strict.Copy()
	admitted, err = dispatcher.AdmitDefaultLayer(LayerProfile2, &wrapped)
	if err != nil { t.Fatal(err) }
	if wrapped.Len() != 0 { t.Fatalf("default wrapped admission left %d bytes", wrapped.Len()) }
	if effective, ok := admitted.EffectiveProfile(); !ok || effective != LayerProfile1 {
		t.Fatalf("explicit override effective profile = %d/%v, want 1/true", effective, ok)
	}
	if evidence, ok := admitted.ProfileEvidence(); !ok || evidence != LayerProfile1 {
		t.Fatalf("explicit override evidence = %d/%v, want 1/true", evidence, ok)
	}
	if admitted.Call().Profile() != LayerProfile1 || admitted.WrapperCount() != 2 {
		t.Fatalf("explicit override call = profile:%d wrappers:%d", admitted.Call().Profile(), admitted.WrapperCount())
	}
	if _, err := dispatcher.AdmitLayer(LayerProfile2, &strict); err == nil {
		t.Fatal("strict frozen admission accepted a conflicting invokeWithLayer")
	}
	if !bytes.Equal(strict.Raw(), strictBefore) {
		t.Fatal("strict conflict mutated caller input")
	}

	var conflict bin.Buffer
	conflict.PutID(0xda9b0d0d)
	conflict.PutInt(1)
	conflict.PutID(0xda9b0d0d)
	conflict.PutInt(2)
	conflict.PutID(0x21000020)
	conflict.PutInt(7)
	conflictBefore := conflict.Copy()
	if _, err := dispatcher.AdmitDefaultLayer(LayerProfile2, &conflict); err == nil || !strings.Contains(err.Error(), "conflicts with explicit profile") {
		t.Fatalf("conflicting explicit selectors error = %v", err)
	}
	if !bytes.Equal(conflict.Raw(), conflictBefore) { t.Fatal("explicit selector conflict mutated caller input") }

	var repeated bin.Buffer
	repeated.PutID(0xda9b0d0d)
	repeated.PutInt(1)
	repeated.PutID(0xda9b0d0d)
	repeated.PutInt(1)
	repeated.PutID(0x21000010)
	repeated.PutString("historical")
	repeated.PutInt(42)
	repeatedAdmission, err := dispatcher.AdmitDefaultLayer(LayerProfile2, &repeated)
	if err != nil { t.Fatal(err) }
	if effective, ok := repeatedAdmission.EffectiveProfile(); !ok || effective != LayerProfile1 {
		t.Fatalf("repeated matching selector effective profile = %d/%v, want 1/true", effective, ok)
	}

	// Duplicate wire-layout candidates which expose the same selector collapse
	// to one result; conflicting evidence is explicitly classified ambiguous.
	var same layerRPCProfileProbeAccumulator
	if err := same.add(0x42000002, LayerProfile2, true, nil); err != nil { t.Fatal(err) }
	if err := same.add(0x42000002, LayerProfile2, true, nil); err != nil { t.Fatal(err) }
	if selected, found, err := same.result(0x42000002); err != nil || !found || selected != LayerProfile2 {
		t.Fatalf("same-profile probe collapse = %d/%v/%v", selected, found, err)
	}
	var ambiguous layerRPCProfileProbeAccumulator
	if err := ambiguous.add(0x42000002, LayerProfile1, true, nil); err != nil { t.Fatal(err) }
	if err := ambiguous.add(0x42000002, LayerProfile2, true, nil); !errors.Is(err, ErrLayerProfileAmbiguous) {
		t.Fatalf("conflicting probe evidence = %v, want ErrLayerProfileAmbiguous", err)
	}
	// An ambiguity discovered by a recursively probed inner wrapper remains
	// fatal even if another outer-layout candidate already found evidence.
	var nestedInner layerRPCProfileProbeAccumulator
	if err := nestedInner.add(0x43000001, LayerProfile1, true, nil); err != nil { t.Fatal(err) }
	nestedErr := nestedInner.add(0x43000001, LayerProfile2, true, nil)
	var nestedOuter layerRPCProfileProbeAccumulator
	if err := nestedOuter.add(0x42000002, LayerProfile1, true, nil); err != nil { t.Fatal(err) }
	var ambiguityCaller bin.Buffer
	ambiguityCaller.PutID(0x42000002)
	ambiguityBefore := ambiguityCaller.Copy()
	if err := nestedOuter.add(0x42000002, LayerProfile(0), false, nestedErr); !errors.Is(err, ErrLayerProfileAmbiguous) {
		t.Fatalf("outer accumulator swallowed nested ambiguity: %v", err)
	}
	if !bytes.Equal(ambiguityCaller.Raw(), ambiguityBefore) { t.Fatal("nested ambiguity handling mutated caller input") }
}

func TestGeneratedUnprofiledClassification(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	known := canonicalRequest(0x21000020, 7)
	knownBefore := known.Copy()
	if _, err := dispatcher.AdmitUnprofiled(known); !errors.Is(err, ErrLayerProfileRequired) {
		t.Fatalf("known unprofiled RPC error = %v, want ErrLayerProfileRequired", err)
	}
	if !bytes.Equal(known.Raw(), knownBefore) { t.Fatal("profile-required admission mutated caller input") }

	unknown := canonicalRequest(0xfeedbeef)
	if _, err := dispatcher.AdmitUnprofiled(unknown); !errors.Is(err, ErrLayerUnknownRPCMethod) {
		t.Fatalf("unknown unprofiled constructor error = %v, want ErrLayerUnknownRPCMethod", err)
	}

	malformed := canonicalRequest(0xda9b0d0d)
	if _, err := dispatcher.AdmitUnprofiled(malformed); err == nil || errors.Is(err, ErrLayerProfileRequired) || errors.Is(err, ErrLayerUnknownRPCMethod) {
		t.Fatalf("malformed invokeWithLayer classification = %v", err)
	}
}

func TestGeneratedInvariantIdentitySurvivesLaterProfileFreeze(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)

	unprofiledBody := canonicalRequest(0x21000030)
	unprofiled, err := dispatcher.AdmitUnprofiled(unprofiledBody)
	if err != nil { t.Fatal(err) }
	profiledBody := canonicalRequest(0x21000030)
	profiled, err := dispatcher.AdmitLayer(LayerProfile1, profiledBody)
	if err != nil { t.Fatal(err) }
	if evidence, ok := profiled.ProfileEvidence(); !ok || evidence != LayerProfile1 {
		t.Fatalf("frozen-profile admission evidence = %d/%v, want 1/true", evidence, ok)
	}
	if unprofiled.Call().Profile() == profiled.Call().Profile() {
		t.Fatal("test did not exercise distinct actual codec profiles")
	}
	if !unprofiled.Call().WireInvariant() || !profiled.Call().WireInvariant() {
		t.Fatal("invariant route proof was not emitted for both profiles")
	}
	if unprofiled.Call().Identity() != profiled.Call().Identity() {
		t.Fatalf("invariant call identity changed after profile freeze: %#v != %#v", unprofiled.Call().Identity(), profiled.Call().Identity())
	}
	if unprofiled.Prepared().Identity() != profiled.Prepared().Identity() {
		t.Fatalf("invariant prepared identity changed after profile freeze: %#v != %#v", unprofiled.Prepared().Identity(), profiled.Prepared().Identity())
	}
	prepared, err := unprofiled.Call().prepareResult(true)
	if err != nil { t.Fatal(err) }
	var replayed bin.Buffer
	if err := prepared.Encode(profiled.Call(), &replayed); err != nil {
		t.Fatalf("reuse invariant cached result under later frozen profile: %v", err)
	}
	var want bin.Buffer
	want.PutID(0x997275b5)
	if !bytes.Equal(replayed.Raw(), want.Raw()) {
		t.Fatalf("replayed invariant result = %x, want %x", replayed.Raw(), want.Raw())
	}

	drift := canonicalRequest(0x21000020, 7)
	driftAdmission, err := dispatcher.AdmitLayer(LayerProfile2, drift)
	if err != nil { t.Fatal(err) }
	if driftAdmission.Call().WireInvariant() {
		t.Fatal("request-drift method exposed a false wire-invariant proof")
	}
}

func TestGeneratedLayerRPCAdmissionRuntime(t *testing.T) {
	var order []string
	var handlerResult *Pong
	dispatcher := NewServerDispatcher(nil)
	dispatcher.OnEcho(func(ctx context.Context, value int) (*Pong, error) {
		order = append(order, "handler")
		if ctx.Value(layerRPCContextKey{}) != "wrapped" {
			t.Fatal("wrapper consumer did not replace the handler context")
		}
		if value != 42 {
			t.Fatalf("canonical handler value = %d, want 42", value)
		}
		handlerResult = &Pong{Value: value + 1}
		return handlerResult, nil
	})

	wire := wrappedEchoWire()
	admitted := admitWrappedEcho(t, dispatcher, wire)
	admittedCopy := admitted
	if admitted.Call().Profile() != LayerProfile1 {
		t.Fatalf("admitted profile = %d, want 1", admitted.Call().Profile())
	}
	semanticIdentity := admitted.Prepared().SemanticIdentity()
	if semanticIdentity.Method() != admitted.Call().Method() || semanticIdentity.CanonicalSize() == 0 {
		t.Fatalf("semantic request identity = method:%d size:%d digest:%x", semanticIdentity.Method(), semanticIdentity.CanonicalSize(), semanticIdentity.CanonicalDigest())
	}
	var nakedBody bin.Buffer
	nakedBody.PutID(0x21000010)
	nakedBody.PutString("historical")
	nakedBody.PutInt(42)
	nakedAdmission, err := dispatcher.AdmitLayer(LayerProfile1, &nakedBody)
	if err != nil {
		t.Fatal(err)
	}
	if nakedAdmission.Prepared().SemanticIdentity() != semanticIdentity {
		t.Fatal("naked and invokeWithLayer-wrapped requests lost semantic identity equality")
	}
	if nakedAdmission.Prepared().Identity() == admitted.Prepared().Identity() {
		t.Fatal("exact wire identity ignored outer wrappers")
	}
	identityBeforeMutation := nakedAdmission.Prepared().SemanticIdentity()
	nakedAdmission.lease.request.(*EchoRequest).Value = 999
	if nakedAdmission.Prepared().SemanticIdentity() != identityBeforeMutation {
		t.Fatal("semantic identity changed after canonical request source mutation")
	}
	var differentArgumentBody bin.Buffer
	differentArgumentBody.PutID(0x21000010)
	differentArgumentBody.PutString("historical")
	differentArgumentBody.PutInt(43)
	differentArgument, err := dispatcher.AdmitLayer(LayerProfile1, &differentArgumentBody)
	if err != nil {
		t.Fatal(err)
	}
	if differentArgument.Prepared().SemanticIdentity() == semanticIdentity {
		t.Fatal("different canonical request arguments shared a semantic identity")
	}
	var differentMethodBody bin.Buffer
	differentMethodBody.PutID(0x21000022)
	differentMethodBody.PutInt(42)
	differentMethod, err := dispatcher.AdmitLayer(LayerProfile2, &differentMethodBody)
	if err != nil {
		t.Fatal(err)
	}
	if differentMethod.Prepared().SemanticIdentity() == semanticIdentity {
		t.Fatal("different semantic methods shared a request identity")
	}
	if admitted.WrapperCount() != 4 {
		t.Fatalf("wrapper count = %d, want 4", admitted.WrapperCount())
	}
	outer, ok := admitted.Wrapper(0)
	if !ok {
		t.Fatal("outer wrapper is absent")
	}
	_, outerName, ok := LayerSemanticName(outer.Semantic())
	if !ok || outerName != "invokeWithLayer" || outer.Profile() != LayerProfile1 || outer.WireID() != 0xda9b0d0d {
		t.Fatalf("outer wrapper = profile:%d name:%q wire:%#08x", outer.Profile(), outerName, outer.WireID())
	}
	layerValue, present, ok, err := outer.Value("layer")
	if err != nil || !ok || !present || layerValue != 1 {
		t.Fatalf("outer layer metadata = (%#v, %v, %v, %v)", layerValue, present, ok, err)
	}
	afterMsgs, ok := admitted.Wrapper(1)
	if !ok {
		t.Fatal("invokeAfterMsgs wrapper is absent")
	}
	_, afterMsgsName, ok := LayerSemanticName(afterMsgs.Semantic())
	if !ok || afterMsgsName != "invokeAfterMsgs" {
		t.Fatalf("invokeAfterMsgs wrapper semantic = %q", afterMsgsName)
	}
	messageIDsValue, present, ok, err := afterMsgs.Value("msg_ids")
	if err != nil || !ok || !present {
		t.Fatalf("msg_ids metadata = (%#v, %v, %v, %v)", messageIDsValue, present, ok, err)
	}
	messageIDs, ok := messageIDsValue.([]int64)
	if !ok || len(messageIDs) != 2 || messageIDs[0] != 11 || messageIDs[1] != 22 {
		t.Fatalf("msg_ids value = %#v", messageIDsValue)
	}
	messageIDs[0] = 999
	messageIDsAgain, _, _, err := afterMsgs.Value("msg_ids")
	if err != nil || messageIDsAgain.([]int64)[0] != 11 {
		t.Fatalf("msg_ids getter exposed its internal slice: %#v, %v", messageIDsAgain, err)
	}
	rangeWrapper, ok := admitted.Wrapper(2)
	if !ok {
		t.Fatal("invokeWithMessagesRange wrapper is absent")
	}
	rangeValue, present, ok, err := rangeWrapper.Value("range")
	if err != nil || !ok || !present {
		t.Fatalf("range metadata = (%#v, %v, %v, %v)", rangeValue, present, ok, err)
	}
	messageRange, ok := rangeValue.(*MessageRange)
	if !ok || messageRange.MinID != 5 || messageRange.MaxID != 10 {
		t.Fatalf("range value = %#v", rangeValue)
	}
	messageRange.MinID = 999
	rangeAgain, _, _, err := rangeWrapper.Value("range")
	if err != nil || rangeAgain.(*MessageRange).MinID != 5 {
		t.Fatalf("range getter exposed its internal object: %#v, %v", rangeAgain, err)
	}
	inner, ok := admitted.Wrapper(3)
	if !ok {
		t.Fatal("invokeAfterMsg wrapper is absent")
	}
	messageID, present, ok, err := inner.Value("msg_id")
	if err != nil || !ok || !present || messageID != int64(99) {
		t.Fatalf("inner msg_id metadata = (%#v, %v, %v, %v)", messageID, present, ok, err)
	}

	prepared := admitted.Prepared()
	if prepared.WireSize() != len(wire) || prepared.WireDigest() != sha256.Sum256(wire) {
		t.Fatalf("prepared wire identity = size:%d digest:%x", prepared.WireSize(), prepared.WireDigest())
	}
	if _, err := dispatcher.DispatchAdmitted(context.Background(), admitted); err == nil {
		t.Fatal("non-layer wrappers were dispatched without a consumer")
	}
	if len(order) != 0 {
		t.Fatalf("handler ran before wrapper consumption: %v", order)
	}
	dispatcher.OnLayerRPCWrappers(func(ctx context.Context, request LayerRequest, next LayerRPCNext) error {
		order = append(order, "before")
		if request.WrapperCount() != 4 {
			t.Fatalf("consumer wrapper count = %d", request.WrapperCount())
		}
		err := next(context.WithValue(ctx, layerRPCContextKey{}, "wrapped"))
		order = append(order, "after")
		return err
	})
	result, err := dispatcher.DispatchAdmitted(context.Background(), admitted)
	if err != nil {
		t.Fatal(err)
	}
	var _ LayerRPCResult = result
	if result.Prepared().Identity() != prepared.Identity() {
		t.Fatalf("result carrier = %#v", result)
	}
	if strings.Join(order, ",") != "before,handler,after" {
		t.Fatalf("wrapper middleware order = %v", order)
	}
	if _, err := dispatcher.DispatchAdmitted(context.Background(), admittedCopy); err == nil {
		t.Fatal("a copied admission token dispatched more than once")
	}
	preparedResult, err := result.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	if preparedResult.Identity() != admitted.Call().Identity() {
		t.Fatal("prepared result lost its full call identity")
	}
	var preparedFirst, preparedSecond bin.Buffer
	if err := preparedResult.Encode(admitted.Call(), &preparedFirst); err != nil {
		t.Fatal(err)
	}
	handlerResult.Value = 999
	if err := preparedResult.Encode(admitted.Call(), &preparedSecond); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preparedFirst.Raw(), preparedSecond.Raw()) {
		t.Fatalf("prepared result changed after source mutation: %x != %x", preparedFirst.Raw(), preparedSecond.Raw())
	}
	handlerResult.Value = 43
	var otherBody bin.Buffer
	otherBody.PutID(0x21000020)
	otherBody.PutInt(42)
	otherAdmission, err := dispatcher.AdmitLayer(LayerProfile2, &otherBody)
	if err != nil {
		t.Fatal(err)
	}
	mismatchTarget := bin.Buffer{Buf: []byte{0xaa, 0xbb}}
	mismatchBefore := mismatchTarget.Copy()
	if err := preparedResult.Encode(otherAdmission.Call(), &mismatchTarget); err == nil {
		t.Fatal("prepared result accepted a different call identity")
	}
	if !bytes.Equal(mismatchTarget.Raw(), mismatchBefore) {
		t.Fatalf("prepared result identity failure polluted target: %x", mismatchTarget.Raw())
	}
	mismatchSlice := []byte{0xbc}
	mismatchAppended, err := preparedResult.Append(otherAdmission.Call(), mismatchSlice)
	if err == nil || !bytes.Equal(mismatchAppended, mismatchSlice) {
		t.Fatalf("prepared result append mismatch = %x, %v", mismatchAppended, err)
	}
	appendedResult, err := preparedResult.Append(admitted.Call(), []byte{0xcc})
	if err != nil || !bytes.Equal(appendedResult[1:], preparedFirst.Raw()) {
		t.Fatalf("append prepared result = %x, %v", appendedResult, err)
	}
	frozen, err := result.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	if frozen.CanonicalSize() == 0 {
		t.Fatal("frozen result has an empty canonical snapshot")
	}
	preparedFrozenResult, err := admitted.Call().PrepareFrozenResult(frozen)
	if err != nil {
		t.Fatal(err)
	}
	var direct, replay, preparedReplay bin.Buffer
	if err := result.Encode(&direct); err != nil {
		t.Fatal(err)
	}
	if err := admitted.Call().EncodeFrozenResult(frozen, &replay); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(direct.Raw(), replay.Raw()) {
		t.Fatalf("frozen replay = %x, direct = %x", replay.Raw(), direct.Raw())
	}
	if err := preparedFrozenResult.Encode(admitted.Call(), &preparedReplay); err != nil || !bytes.Equal(direct.Raw(), preparedReplay.Raw()) {
		t.Fatalf("prepared frozen replay = %x, direct = %x, err = %v", preparedReplay.Raw(), direct.Raw(), err)
	}

	zeroNext := NewServerDispatcher(nil)
	zeroNext.OnEcho(func(context.Context, int) (*Pong, error) { return &Pong{}, nil })
	zeroNext.OnLayerRPCWrappers(func(context.Context, LayerRequest, LayerRPCNext) error { return nil })
	if _, err := zeroNext.DispatchAdmitted(context.Background(), admitWrappedEcho(t, zeroNext, wire)); err == nil {
		t.Fatal("wrapper consumer skipped next without a hard error")
	}
	doubleNext := NewServerDispatcher(nil)
	doubleNext.OnEcho(func(context.Context, int) (*Pong, error) { return &Pong{}, nil })
	doubleNext.OnLayerRPCWrappers(func(ctx context.Context, _ LayerRequest, next LayerRPCNext) error {
		_ = next(ctx)
		_ = next(ctx)
		return nil
	})
	if _, err := doubleNext.DispatchAdmitted(context.Background(), admitWrappedEcho(t, doubleNext, wire)); err == nil {
		t.Fatal("wrapper consumer called next twice without a hard error")
	}
	asyncNext := NewServerDispatcher(nil)
	asyncEntered := make(chan struct{})
	asyncRelease := make(chan struct{})
	consumerReturning := make(chan struct{})
	asyncNext.OnEcho(func(context.Context, int) (*Pong, error) {
		close(asyncEntered)
		<-asyncRelease
		return &Pong{}, nil
	})
	asyncNext.OnLayerRPCWrappers(func(ctx context.Context, _ LayerRequest, next LayerRPCNext) error {
		go func() { _ = next(ctx) }()
		<-asyncEntered
		close(consumerReturning)
		return nil
	})
	asyncDispatch := make(chan error, 1)
	asyncAdmission := admitWrappedEcho(t, asyncNext, wire)
	go func() {
		_, err := asyncNext.DispatchAdmitted(context.Background(), asyncAdmission)
		asyncDispatch <- err
	}()
	<-consumerReturning
	// Let DispatchAdmitted observe the consumer return while next remains in
	// the handler, then release it so the post-invoke escape check runs.
	time.Sleep(20 * time.Millisecond)
	close(asyncRelease)
	if err := <-asyncDispatch; err == nil {
		t.Fatal("wrapper consumer let an asynchronous next escape")
	}
	layerOnly := NewServerDispatcher(nil)
	layerOnly.OnEcho(func(context.Context, int) (*Pong, error) { return &Pong{}, nil })
	var layerOnlyBody bin.Buffer
	layerOnlyBody.PutID(0xda9b0d0d)
	layerOnlyBody.PutInt(1)
	layerOnlyBody.PutID(0x21000010)
	layerOnlyBody.PutString("historical")
	layerOnlyBody.PutInt(42)
	if _, err := layerOnly.DispatchAdmitted(context.Background(), admitWrappedEcho(t, layerOnly, layerOnlyBody.Copy())); err != nil {
		t.Fatalf("invokeWithLayer alone unexpectedly required a wrapper consumer: %v", err)
	}
	concurrent := NewServerDispatcher(nil)
	var handlerCalls atomic.Int32
	concurrent.OnEcho(func(context.Context, int) (*Pong, error) {
		handlerCalls.Add(1)
		return &Pong{}, nil
	})
	var exactBody bin.Buffer
	exactBody.PutID(0x21000020)
	exactBody.PutInt(7)
	exactAdmission, err := concurrent.AdmitLayer(LayerProfile2, &exactBody)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var dispatches sync.WaitGroup
	for i := 0; i < 2; i++ {
		dispatches.Add(1)
		go func(token LayerRequest) {
			defer dispatches.Done()
			_, err := concurrent.DispatchAdmitted(context.Background(), token)
			results <- err
		}(exactAdmission)
	}
	dispatches.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 || handlerCalls.Load() != 1 {
		t.Fatalf("concurrent admission dispatches = successes:%d handler_calls:%d", successes, handlerCalls.Load())
	}
	pongType := LayerConstructorPongType()
	sourcePong := &Pong{Value: 77}
	frozenValue, err := FreezeLayer(pongType, sourcePong)
	if err != nil {
		t.Fatal(err)
	}
	preparedValue, err := PrepareFrozenLayer(LayerProfile1, frozenValue)
	if err != nil {
		t.Fatal(err)
	}
	sourcePong.Value = 999
	var preparedValueFirst, preparedValueSecond, expectedValue bin.Buffer
	if err := preparedValue.Encode(LayerProfile1, pongType, &preparedValueFirst); err != nil {
		t.Fatal(err)
	}
	if err := preparedValue.Encode(LayerProfile1, pongType, &preparedValueSecond); err != nil {
		t.Fatal(err)
	}
	if err := EncodeLayer(LayerProfile1, pongType, &Pong{Value: 77}, &expectedValue); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preparedValueFirst.Raw(), preparedValueSecond.Raw()) || !bytes.Equal(preparedValueFirst.Raw(), expectedValue.Raw()) {
		t.Fatalf("prepared value was not a defensive repeatable snapshot: %x %x %x", preparedValueFirst.Raw(), preparedValueSecond.Raw(), expectedValue.Raw())
	}
	wrongValueTarget := bin.Buffer{Buf: []byte{0xdd}}
	wrongValueBefore := wrongValueTarget.Copy()
	if err := preparedValue.Encode(LayerProfile2, pongType, &wrongValueTarget); err == nil {
		t.Fatal("prepared value accepted a different exact profile")
	}
	if !bytes.Equal(wrongValueTarget.Raw(), wrongValueBefore) {
		t.Fatalf("prepared value profile failure polluted target: %x", wrongValueTarget.Raw())
	}
	wrongValueSlice := []byte{0xde}
	wrongValueAppended, err := preparedValue.Append(LayerProfile2, pongType, wrongValueSlice)
	if err == nil || !bytes.Equal(wrongValueAppended, wrongValueSlice) {
		t.Fatalf("prepared value append mismatch = %x, %v", wrongValueAppended, err)
	}
	wrongPongType := pongType
	wrongPongType.ref = LayerConstructorMessageRangeType().ref
	if err := preparedValue.Encode(LayerProfile1, wrongPongType, &wrongValueTarget); err == nil {
		t.Fatal("prepared value accepted a different TypeRef identity")
	}
	appendedValue, err := preparedValue.Append(LayerProfile1, pongType, []byte{0xee})
	if err != nil || !bytes.Equal(appendedValue[1:], preparedValueFirst.Raw()) {
		t.Fatalf("append prepared value = %x, %v", appendedValue, err)
	}

	zeroType := LayerType[struct{}]{
		ref: &LayerTypeRef{kind: LayerTypePrimitive, qname: "test.zero"},
		preflight: func(LayerProfile, struct{}) (int, error) { return 1, nil },
		encode: func(LayerProfile, struct{}, *bin.Buffer) error { return nil },
		decode: func(LayerProfile, *bin.Buffer) (struct{}, error) { return struct{}{}, nil },
		decodeState: func(LayerProfile, *bin.Buffer, *layerCodecState) (struct{}, error) { return struct{}{}, nil },
	}
	zeroFrozen, err := FreezeLayer(zeroType, struct{}{})
	if err != nil || zeroFrozen.CanonicalSize() != 0 {
		t.Fatalf("freeze legal zero-byte value = size:%d err:%v", zeroFrozen.CanonicalSize(), err)
	}
	zeroPrepared, err := PrepareFrozenLayer(LayerProfile1, zeroFrozen)
	if err != nil || zeroPrepared.WireSize() != 0 {
		t.Fatalf("prepare legal zero-byte value = size:%d err:%v", zeroPrepared.WireSize(), err)
	}
	zeroTarget := bin.Buffer{Buf: []byte{0xfa}}
	if err := zeroPrepared.Encode(LayerProfile1, zeroType, &zeroTarget); err != nil || !bytes.Equal(zeroTarget.Raw(), []byte{0xfa}) {
		t.Fatalf("encode legal zero-byte value = %x, %v", zeroTarget.Raw(), err)
	}

	mismatch := bin.Buffer{Buf: append([]byte(nil), wire...)}
	if _, err := dispatcher.AdmitLayer(LayerProfile2, &mismatch); err == nil {
		t.Fatal("invokeWithLayer changed an already frozen exact profile")
	}
	trailing := bin.Buffer{Buf: append(append([]byte(nil), wire...), 0)}
	if _, err := dispatcher.AdmitUnprofiled(&trailing); err == nil {
		t.Fatal("admission accepted trailing request bytes")
	}
	unwrapped := bin.Buffer{}
	unwrapped.PutID(0x21000020)
	unwrapped.PutInt(7)
	if _, err := dispatcher.AdmitUnprofiled(&unwrapped); err == nil {
		t.Fatal("unprofiled admission guessed a profile without invokeWithLayer")
	}
}

func TestGeneratedLayerRPCAdmissionPreflightAndLimits(t *testing.T) {
	terminal := bin.Buffer{}
	terminal.PutID(0x21000010)
	terminal.PutString("historical")
	terminal.PutInt(42)

	dispatcher := NewServerDispatcher(nil)
	preflightCalls := 0
	var escaped LayerRPCAdmissionView
	dispatcher.OnLayerRPCAdmissionPreflight(func(view LayerRPCAdmissionView) error {
		preflightCalls++
		escaped = view
		if view.Profile() != LayerProfile1 || view.Semantic() != LayerSemanticMethodEcho || view.WireID() != 0x21000010 || view.WireSize() != terminal.Len() {
			t.Fatalf("terminal view = profile:%d semantic:%d wire:%#08x size:%d", view.Profile(), view.Semantic(), view.WireID(), view.WireSize())
		}
		wireID, err := view.Uint32At(0)
		if err != nil || wireID != 0x21000010 { t.Fatalf("terminal wire ID = %#08x, %v", wireID, err) }
		first, err := view.ByteAt(0)
		if err != nil || first != byte(0x10) { t.Fatalf("terminal first byte = %#02x, %v", first, err) }
		copied, err := view.ReadAt(0, 4)
		if err != nil || len(copied) != 4 { t.Fatalf("terminal copy = %x, %v", copied, err) }
		copied[0] ^= 0xff
		wireIDAgain, err := view.Uint32At(0)
		if err != nil || wireIDAgain != 0x21000010 { t.Fatalf("terminal copy mutated admission = %#08x, %v", wireIDAgain, err) }
		if _, err := view.ByteAt(-1); err == nil { t.Fatal("negative preflight byte offset was accepted") }
		if end, err := view.ReadAt(view.WireSize(), 0); err != nil || len(end) != 0 { t.Fatalf("empty terminal suffix = %x, %v", end, err) }
		return nil
	})
	wrapped := bin.Buffer{Buf: wrappedEchoWire()}
	if _, err := dispatcher.AdmitUnprofiledWithLimits(&wrapped, LayerDecodeLimits{}); err != nil { t.Fatal(err) }
	if preflightCalls != 1 { t.Fatalf("multi-wrapper preflight calls = %d", preflightCalls) }
	if _, err := escaped.ByteAt(0); err == nil { t.Fatal("escaped preflight ByteAt remained active") }
	if _, err := escaped.Uint32At(0); err == nil { t.Fatal("escaped preflight Uint32At remained active") }
	if _, err := escaped.ReadAt(0, 1); err == nil { t.Fatal("escaped preflight ReadAt remained active") }

	probeDispatcher := NewServerDispatcher(nil)
	probePreflightCalls := 0
	probeDispatcher.OnLayerRPCAdmissionPreflight(func(view LayerRPCAdmissionView) error {
		probePreflightCalls++
		if view.Profile() != LayerProfile2 || view.Semantic() != LayerSemanticMethodEcho || view.WireID() != 0x21000020 {
			t.Fatalf("fallback replay terminal view = profile:%d semantic:%d wire:%#08x", view.Profile(), view.Semantic(), view.WireID())
		}
		return nil
	})
	var probed bin.Buffer
	probed.PutID(0x42000002)
	probed.PutID(0xda9b0d0d)
	probed.PutInt(2)
	probed.PutID(0x21000020)
	probed.PutInt(7)
	if _, err := probeDispatcher.AdmitDefaultLayerWithLimits(LayerProfile1, &probed, LayerDecodeLimits{}); err != nil { t.Fatal(err) }
	if probePreflightCalls != 1 {
		t.Fatalf("prefix probe invoked terminal preflight %d times, want exact replay once", probePreflightCalls)
	}
	var probeDepthLimited bin.Buffer
	probeDepthLimited.PutID(0x42000002)
	probeDepthLimited.PutID(0xda9b0d0d)
	probeDepthLimited.PutInt(2)
	probeDepthLimited.PutID(0x21000020)
	probeDepthLimited.PutInt(7)
	probeDepthBefore := probeDepthLimited.Copy()
	probePreflightCalls = 0
	if _, err := probeDispatcher.AdmitDefaultLayerWithLimits(LayerProfile1, &probeDepthLimited, LayerDecodeLimits{MaxDepth: 2}); err == nil {
		t.Fatal("fallback exact replay ignored wrapper depth limit")
	}
	if probePreflightCalls != 0 {
		t.Fatalf("failed fallback probe/replay invoked terminal preflight %d times", probePreflightCalls)
	}
	if !bytes.Equal(probeDepthLimited.Raw(), probeDepthBefore) {
		t.Fatal("depth-limited fallback mutated caller input")
	}
	realState, err := newLayerCodecDecodeState(LayerProfile2, 0, layerCodecDecodeLimits{maxVectorElements: 3, maxAggregateElements: 3})
	if err != nil { t.Fatal(err) }
	work := layerRPCProbeWorkBudget{remainingAttempts: 2, remainingBytes: 4, remainingElements: 5, maxDepth: 2}
	firstProbe, err := cloneLayerRPCProbeState(realState, &work)
	if err != nil { t.Fatal(err) }
	secondProbe, err := cloneLayerRPCProbeState(realState, &work)
	if err != nil { t.Fatal(err) }
	if err := firstProbe.consumeDecodeVector(LayerProfile2, nil, 3); err != nil { t.Fatal(err) }
	if err := secondProbe.consumeDecodeVector(LayerProfile2, nil, 2); err != nil {
		t.Fatalf("failed candidate polluted another candidate's semantic budget: %v", err)
	}
	if realState.decodeBudget.remainingElements != 3 || firstProbe.decodeBudget.remainingElements != 0 || secondProbe.decodeBudget.remainingElements != 1 || work.remainingElements != 0 {
		t.Fatalf("probe budget isolation = real:%d first:%d second:%d work:%d, want 3/0/1/0", realState.decodeBudget.remainingElements, firstProbe.decodeBudget.remainingElements, secondProbe.decodeBudget.remainingElements, work.remainingElements)
	}
	if err := work.consumeBytes(4); err != nil { t.Fatal(err) }
	if err := work.consumeBytes(1); err == nil { t.Fatal("independent speculative byte budget was not enforced") }
	if err := work.checkDepth(1); err != nil { t.Fatal(err) }
	if err := work.checkDepth(2); err == nil { t.Fatal("independent speculative depth budget was not enforced") }
	if err := work.take(0x43000001); err != nil { t.Fatal(err) }
	if err := work.take(0x43000001); err != nil { t.Fatal(err) }
	if err := work.take(0x43000001); err == nil {
		t.Fatal("independent speculative candidate-attempt budget was not enforced")
	}

	// Resource exhaustion after an earlier candidate found profile evidence is
	// fatal: accepting before all generated layouts were checked could hide a
	// conflicting selector. The probe owns only copies and must not consume the
	// caller buffer on this failure.
	var exhaustAfterFound bin.Buffer
	exhaustAfterFound.PutID(0x43000001)
	exhaustAfterFound.PutVectorHeader(3)
	exhaustAfterFound.PutInt(1); exhaustAfterFound.PutInt(2); exhaustAfterFound.PutInt(3)
	exhaustAfterFound.PutID(0x44000001); exhaustAfterFound.PutInt(8)
	exhaustAfterFound.PutID(0xda9b0d0d); exhaustAfterFound.PutInt(1)
	exhaustAfterFound.PutID(0x21000010); exhaustAfterFound.PutString("historical"); exhaustAfterFound.PutInt(42)
	exhaustBefore := exhaustAfterFound.Copy()
	exhaustState, err := newLayerCodecDecodeState(LayerProfile1, exhaustAfterFound.Len(), layerCodecDecodeLimits{maxVectorElements: 3, maxAggregateElements: 3})
	if err != nil { t.Fatal(err) }
	exhaustWork := layerRPCProbeWorkBudget{remainingAttempts: 2, remainingBytes: 32, remainingElements: 6, maxDepth: 8}
	selected, found, err := probeDefaultLayerRPCProfile(&exhaustAfterFound, exhaustState, &exhaustWork, 0)
	if !errors.Is(err, errLayerRPCProbeWorkExhausted) || found || selected != LayerProfile(0) {
		t.Fatalf("found-then-exhausted probe = selected:%d found:%v err:%v", selected, found, err)
	}
	if !bytes.Equal(exhaustAfterFound.Raw(), exhaustBefore) {
		t.Fatal("found-then-exhausted probe mutated caller input")
	}

	rejecting := NewServerDispatcher(nil)
	handlerCalls := 0
	rejecting.OnBulk(func(context.Context, *BulkRequest) (*Pong, error) {
		handlerCalls++
		return &Pong{}, nil
	})
	var rejectedView LayerRPCAdmissionView
	rejecting.OnLayerRPCAdmissionPreflight(func(view LayerRPCAdmissionView) error {
		rejectedView = view
		if view.Profile() != LayerProfile2 || view.Semantic() != LayerSemanticMethodBulk || view.WireID() != 0x21000023 {
			t.Fatalf("rejected terminal view = profile:%d semantic:%d wire:%#08x", view.Profile(), view.Semantic(), view.WireID())
		}
		return context.Canceled
	})
	var hostile bin.Buffer
	hostile.PutID(0x21000023)
	hostile.PutVectorHeader(layerCodecMaxVectorElements + 1)
	hostileBefore := hostile.Copy()
	if _, err := rejecting.AdmitLayerWithLimits(LayerProfile2, &hostile, LayerDecodeLimits{}); err != context.Canceled {
		t.Fatalf("preflight rejection error = %v, want exact sentinel", err)
	}
	if !bytes.Equal(hostile.Raw(), hostileBefore) { t.Fatalf("preflight rejection consumed terminal input: %x", hostile.Raw()) }
	if handlerCalls != 0 { t.Fatalf("handler ran after preflight rejection: %d", handlerCalls) }
	if _, err := rejectedView.ByteAt(0); err == nil { t.Fatal("rejected escaped view remained active") }

	limitsDispatcher := NewServerDispatcher(nil)
	var naked bin.Buffer
	naked.PutID(0x21000020)
	naked.PutInt(7)
	nakedBefore := naked.Copy()
	if _, err := limitsDispatcher.AdmitLayerWithLimits(LayerProfile2, &naked, LayerDecodeLimits{MaxWireBytes: -1}); err == nil {
		t.Fatal("negative wire limit was accepted")
	}
	if !bytes.Equal(naked.Raw(), nakedBefore) { t.Fatal("negative limit consumed input") }
	naked = bin.Buffer{Buf: append([]byte(nil), nakedBefore...)}
	if _, err := limitsDispatcher.AdmitLayerWithLimits(LayerProfile2, &naked, LayerDecodeLimits{MaxWireBytes: len(nakedBefore) - 1}); err == nil {
		t.Fatal("wire byte limit was not enforced")
	}
	if !bytes.Equal(naked.Raw(), nakedBefore) { t.Fatal("wire limit consumed input") }

	vectorLimited := bin.Buffer{Buf: bulkWire(0x21000023, []int{1, 2}, []int{3})}
	if _, err := limitsDispatcher.AdmitLayerWithLimits(LayerProfile2, &vectorLimited, LayerDecodeLimits{MaxVectorElements: 1, MaxAggregateElements: 10}); err == nil {
		t.Fatal("per-vector element limit was not enforced")
	}
	aggregateLimited := bin.Buffer{Buf: bulkWire(0x21000023, []int{1, 2}, []int{3, 4})}
	if _, err := limitsDispatcher.AdmitLayerWithLimits(LayerProfile2, &aggregateLimited, LayerDecodeLimits{MaxVectorElements: 2, MaxAggregateElements: 3}); err == nil {
		t.Fatal("aggregate element limit was not enforced")
	}
	depthLimited := bin.Buffer{Buf: wrappedEchoWire()}
	if _, err := limitsDispatcher.AdmitUnprofiledWithLimits(&depthLimited, LayerDecodeLimits{MaxDepth: 1}); err == nil {
		t.Fatal("wrapper depth limit was not enforced")
	}
	unprofiledWireLimited := bin.Buffer{Buf: wrappedEchoWire()}
	unprofiledBefore := unprofiledWireLimited.Copy()
	if _, err := limitsDispatcher.AdmitUnprofiledWithLimits(&unprofiledWireLimited, LayerDecodeLimits{MaxWireBytes: 1}); err == nil {
		t.Fatal("unprofiled wire limit was not enforced")
	}
	if !bytes.Equal(unprofiledWireLimited.Raw(), unprofiledBefore) { t.Fatal("unprofiled wire limit consumed input") }
}

func privateBulkWire(first, second []int) []byte {
	return bulkWire(0xf1000001, first, second)
}

func registerPrivateBulkAdapter(t *testing.T, dispatcher *ServerDispatcher, calls *int) {
	t.Helper()
	dispatcher.OnLayerRPCUnknownMethod(func(view LayerRPCUnknownMethodView) (LayerOutboundCall, bool, error) {
		*calls++
		if view.WireID() != 0xf1000001 {
			return LayerOutboundCall{}, false, nil
		}
		private, err := view.Buffer()
		if err != nil { return LayerOutboundCall{}, true, err }
		if err := private.ConsumeID(0xf1000001); err != nil { return LayerOutboundCall{}, true, err }
		var canonical bin.Buffer
		canonical.PutID(0x21000023)
		canonical.Put(private.Raw())
		private.Buf = private.Buf[len(private.Buf):]
		outbound, err := view.AdaptCanonical(&canonical)
		return outbound, true, err
	})
}

func TestGeneratedUnknownInnermostMethodAdapter(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	adapterCalls := 0
	fieldCalls := 0
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldBulkFirst, func(view LayerRPCAdmissionFieldView) error {
		fieldCalls++
		length, ok := view.VectorLength()
		if !ok || length != 2 { t.Fatalf("private bulk first metric = %d/%v", length, ok) }
		return nil
	}); err != nil { t.Fatal(err) }
	registerPrivateBulkAdapter(t, dispatcher, &adapterCalls)

	naked := bin.Buffer{Buf: privateBulkWire([]int{1, 2}, []int{3})}
	admitted, err := dispatcher.AdmitLayer(LayerProfile2, &naked)
	if err != nil { t.Fatal(err) }
	if naked.Len() != 0 { t.Fatalf("naked private admission left %d bytes", naked.Len()) }
	if admitted.Call().Profile() != LayerProfile2 || admitted.Call().Method() != LayerSemanticMethodBulk || admitted.Call().WireID() != 0x21000023 {
		t.Fatalf("adapted call = profile:%d semantic:%d wire:%#08x", admitted.Call().Profile(), admitted.Call().Method(), admitted.Call().WireID())
	}
	if adapterCalls != 1 || fieldCalls != 1 {
		t.Fatalf("naked adapter/field calls = %d/%d, want 1/1", adapterCalls, fieldCalls)
	}
	defaultNaked := bin.Buffer{Buf: privateBulkWire([]int{1, 2}, []int{3})}
	defaultAdmission, err := dispatcher.AdmitDefaultLayer(LayerProfile2, &defaultNaked)
	if err != nil { t.Fatal(err) }
	if defaultNaked.Len() != 0 || defaultAdmission.Call().Profile() != LayerProfile2 ||
		defaultAdmission.Call().Method() != LayerSemanticMethodBulk || adapterCalls != 2 || fieldCalls != 2 {
		t.Fatalf("default unknown adapter = remaining:%d profile:%d semantic:%d calls:%d/%d",
			defaultNaked.Len(), defaultAdmission.Call().Profile(), defaultAdmission.Call().Method(), adapterCalls, fieldCalls)
	}
	var futureWrapped bin.Buffer
	futureWrapped.PutID(0x42000002)
	futureWrapped.PutID(0xda9b0d0d)
	futureWrapped.PutInt(2)
	futureWrapped.Put(privateBulkWire([]int{1, 2}, []int{3}))
	futurePrivate, err := dispatcher.AdmitDefaultLayer(LayerProfile1, &futureWrapped)
	if err != nil { t.Fatal(err) }
	if futureWrapped.Len() != 0 || futurePrivate.Call().Profile() != LayerProfile2 ||
		futurePrivate.Call().Method() != LayerSemanticMethodBulk || futurePrivate.WrapperCount() != 2 ||
		adapterCalls != 3 || fieldCalls != 3 {
		t.Fatalf("future wrapper private adapter = remaining:%d profile:%d semantic:%d wrappers:%d calls:%d/%d",
			futureWrapped.Len(), futurePrivate.Call().Profile(), futurePrivate.Call().Method(), futurePrivate.WrapperCount(), adapterCalls, fieldCalls)
	}

	var wrapped bin.Buffer
	wrapped.PutID(0xda9b0d0d)
	wrapped.PutInt(2)
	wrapped.PutID(0xcb9f372d)
	wrapped.PutLong(77)
	wrapped.Put(privateBulkWire([]int{1, 2}, []int{3}))
	wrappedBefore := wrapped.Copy()
	wrappedAdmission, err := dispatcher.AdmitUnprofiled(&wrapped)
	if err != nil { t.Fatal(err) }
	if wrapped.Len() != 0 || wrappedAdmission.WrapperCount() != 2 {
		t.Fatalf("wrapped private admission = remaining:%d wrappers:%d wire:%x", wrapped.Len(), wrappedAdmission.WrapperCount(), wrappedBefore)
	}
	if adapterCalls != 4 || fieldCalls != 4 {
		t.Fatalf("wrapped adapter/field calls = %d/%d, want 4/4", adapterCalls, fieldCalls)
	}

	// Official routes always win, even if the application adapter would claim
	// the same constructor as private.
	overlap := NewServerDispatcher(nil)
	overlapCalls := 0
	overlap.OnLayerRPCUnknownMethod(func(LayerRPCUnknownMethodView) (LayerOutboundCall, bool, error) {
		overlapCalls++
		return LayerOutboundCall{}, true, context.Canceled
	})
	official := canonicalRequest(0x21000020, 9)
	if _, err := overlap.AdmitLayer(LayerProfile2, official); err != nil { t.Fatal(err) }
	if overlapCalls != 0 { t.Fatalf("official route invoked private adapter %d times", overlapCalls) }

	malformed := bin.Buffer{}
	malformed.PutID(0xf1000001)
	malformedBefore := malformed.Copy()
	if _, err := dispatcher.AdmitLayer(LayerProfile2, &malformed); err == nil { t.Fatal("malformed private method was admitted") }
	if !bytes.Equal(malformed.Raw(), malformedBefore) { t.Fatal("malformed private method consumed caller input") }

	unhandled := bin.Buffer{}
	unhandled.PutID(0xf1000002)
	unhandledBefore := unhandled.Copy()
	if _, err := dispatcher.AdmitLayer(LayerProfile2, &unhandled); !errors.Is(err, ErrLayerUnknownRPCMethod) {
		t.Fatalf("unhandled private error = %v", err)
	}
	if !bytes.Equal(unhandled.Raw(), unhandledBefore) { t.Fatal("unhandled private method consumed caller input") }
}

func TestGeneratedUnknownMethodAdapterCannotBypassCanonicalAdmission(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	dispatcher.OnLayerRPCUnknownMethod(func(view LayerRPCUnknownMethodView) (LayerOutboundCall, bool, error) {
		private, err := view.Buffer()
		if err != nil { return LayerOutboundCall{}, true, err }
		private.Buf = private.Buf[len(private.Buf):]
		outbound, err := PrepareLayerOutboundCall(LayerProfile2, &BulkRequest{First: []int{1}, Second: []int{2}})
		return outbound, true, err
	})
	private := bin.Buffer{}
	private.PutID(0xf1000003)
	before := private.Copy()
	if _, err := dispatcher.AdmitLayer(LayerProfile2, &private); err == nil || !strings.Contains(err.Error(), "authoritative canonical admission bridge") {
		t.Fatalf("unapproved private call error = %v", err)
	}
	if !bytes.Equal(private.Raw(), before) { t.Fatal("unapproved private call consumed input") }

	notConsumed := NewServerDispatcher(nil)
	notConsumed.OnLayerRPCUnknownMethod(func(view LayerRPCUnknownMethodView) (LayerOutboundCall, bool, error) {
		var canonical bin.Buffer
		canonical.Put(privateBulkWire([]int{1}, []int{2}))
		canonical.Buf[0], canonical.Buf[1], canonical.Buf[2], canonical.Buf[3] = 0x23, 0x00, 0x00, 0x21
		outbound, err := view.AdaptCanonical(&canonical)
		return outbound, true, err
	})
	private = bin.Buffer{}
	private.PutID(0xf1000004)
	before = private.Copy()
	if _, err := notConsumed.AdmitLayer(LayerProfile2, &private); err == nil || !strings.Contains(err.Error(), "left") {
		t.Fatalf("unconsumed private terminal error = %v", err)
	}
	if !bytes.Equal(private.Raw(), before) { t.Fatal("unconsumed private terminal consumed caller input") }
}
`)
	formattedRuntimeTest, err := format.Source(runtimeTest)
	if err != nil {
		t.Fatalf("format generated RPC runtime test: %v\n%s", err, runtimeTest)
	}
	if err := os.WriteFile(filepath.Join(dir, "layer_rpc_runtime_test.go"), formattedRuntimeTest, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "test", "-mod=mod", "./...")
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("compile generated synthetic layer RPC package: %v\n%s", err, output)
	}
}

func TestLayerRPCWrapperMetadataPolicyRuntime(t *testing.T) {
	set := layerRPCWrapperPolicySchemaSet(t)
	policy := layerRPCWrapperPolicy(t, set)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy, GenerateFlags: GenerateFlags{Server: true}})
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
	model, err := generator.buildLayerRPCSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}
	route := findLayerRPCSourceRoute(t, model, 1, 0x41000011)
	for _, hook := range []string{"adaptMetaTagRPCMetadataDecode", "adaptMetaLimitRPCMetadataDecode"} {
		if count := strings.Count(route.Body, hook+"("); count != 1 {
			t.Fatalf("wrapper metadata hook %s call count = %d\n%s", hook, count, route.Body)
		}
	}
	for _, want := range []string{"LayerProfileCanonical, \"tag\"", "LayerProfileCanonical, \"limit\"", "rpcWrapperCanonicalField0", "rpcWrapperCanonicalField1"} {
		if !strings.Contains(route.Body, want) {
			t.Fatalf("normalized wrapper route is missing %q\n%s", want, route.Body)
		}
	}

	sources := sourceSnapshot{}
	if err := generator.WriteSource(sources, "wrapperfixture", Template()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	goMod := fmt.Sprintf("module wrapperfixture\n\ngo 1.25\n\nrequire github.com/iamxvbaba/td v0.0.0\nreplace github.com/iamxvbaba/td => %s\n", filepath.ToSlash(root))
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
	runtimeTest := []byte(`package wrapperfixture

import (
	"context"
	"testing"

	"github.com/iamxvbaba/td/bin"
)

var tagMetadataCalls, limitMetadataCalls int

func adaptMetaTagRPCMetadataDecode(_ LayerProfile, present bool, value string) (string, bool, error) {
	tagMetadataCalls++
	return "canonical:" + value, present, nil
}
func adaptMetaLimitRPCMetadataDecode(_ LayerProfile, present bool, value int64) (int, bool, error) {
	limitMetadataCalls++
	return int(value) + 1, present, nil
}
func adaptMetaTagEncode(_ LayerProfile, _ *InvokeWithMetaRequest, value string) (string, error) {
	return value, nil
}
func adaptMetaTagDecode(_ LayerProfile, _ *InvokeWithMetaRequest, _ bool, value string) (string, error) {
	return value, nil
}
func adaptMetaLimitEncode(_ LayerProfile, _ *InvokeWithMetaRequest, value int) (int64, error) {
	return int64(value), nil
}
func adaptMetaLimitDecode(_ LayerProfile, _ *InvokeWithMetaRequest, _ bool, value int64) (int, error) {
	return int(value), nil
}

func TestWrapperMetadataPolicyRuntime(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	dispatcher.OnEcho(func(context.Context, int) (*Pong, error) { return &Pong{}, nil })
	dispatcher.OnLayerRPCWrappers(func(ctx context.Context, request LayerRequest, next LayerRPCNext) error {
		metadata, ok := request.Wrapper(1)
		if request.WrapperCount() != 2 || !ok { t.Fatalf("metadata wrapper is absent: %d", request.WrapperCount()) }
		tag, present, ok, err := metadata.Value("tag")
		if err != nil || !ok || !present || tag != "canonical:legacy" { t.Fatalf("tag = (%#v,%v,%v,%v)", tag, present, ok, err) }
		limit, present, ok, err := metadata.Value("limit")
		if err != nil || !ok || !present || limit != 124 { t.Fatalf("limit = (%#v,%v,%v,%v)", limit, present, ok, err) }
		if _, _, ok, err := metadata.Value("legacy_tag"); err != nil || ok { t.Fatalf("historical metadata leaked: %v %v", ok, err) }
		return next(ctx)
	})
	// Layer 2 does not own the historical metadata-wrapper CRC. Its prefix
	// probe must decode only raw primitive bytes: metadata policy hooks run
	// exactly once during the authoritative Layer 1 replay.
	var fallback bin.Buffer
	fallback.PutID(0x41000011); fallback.PutString("legacy"); fallback.PutLong(123)
	fallback.PutID(0xda9b0d0d); fallback.PutInt(1)
	fallback.PutID(0x41000010); fallback.PutInt(7)
	fallbackAdmission, err := dispatcher.AdmitDefaultLayer(LayerProfile2, &fallback)
	if err != nil { t.Fatal(err) }
	if fallback.Len() != 0 || fallbackAdmission.Call().Profile() != LayerProfile1 || fallbackAdmission.WrapperCount() != 2 {
		t.Fatalf("metadata fallback = remaining:%d profile:%d wrappers:%d", fallback.Len(), fallbackAdmission.Call().Profile(), fallbackAdmission.WrapperCount())
	}
	if tagMetadataCalls != 1 || limitMetadataCalls != 1 { t.Fatalf("fallback probe/replay adapter calls = %d/%d", tagMetadataCalls, limitMetadataCalls) }
	tagMetadataCalls, limitMetadataCalls = 0, 0
	var wire bin.Buffer
	wire.PutID(0xda9b0d0d); wire.PutInt(1)
	wire.PutID(0x41000011); wire.PutString("legacy"); wire.PutLong(123)
	wire.PutID(0x41000010); wire.PutInt(7)
	admitted, err := dispatcher.AdmitUnprofiled(&wire)
	if err != nil { t.Fatal(err) }
	if tagMetadataCalls != 1 || limitMetadataCalls != 1 { t.Fatalf("adapter calls = %d/%d", tagMetadataCalls, limitMetadataCalls) }
	if _, err := dispatcher.DispatchAdmitted(context.Background(), admitted); err != nil { t.Fatal(err) }
	if tagMetadataCalls != 1 || limitMetadataCalls != 1 { t.Fatalf("adapters reran = %d/%d", tagMetadataCalls, limitMetadataCalls) }
}
`)
	formattedRuntime, err := format.Source(runtimeTest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wrapper_runtime_test.go"), formattedRuntime, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "test", "-mod=mod", "./...")
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("compile/run generated wrapper policy package: %v\n%s", err, output)
	}
}

func TestLayerRPCWrapperMetadataPolicyRejectsUnmappedAdapter(t *testing.T) {
	profileSource := strings.Replace(
		layerRPCWrapperPolicyOne,
		"legacy_tag:string limit:long query:!X",
		"legacy_tag:string limit:long extra:long query:!X",
		1,
	)
	set := layerRPCWrapperPolicySchemaSetFromSources(t, profileSource, layerRPCWrapperPolicyTwo)
	plan, err := AnalyzeLayerConversions(set, LayerObligationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	policy := LayerObligationPolicy{}
	for _, obligation := range plan.Report.Unresolved() {
		if obligation.Semantic.Category != semantic.CategoryFunction || obligation.Semantic.QName != "invokeWithMeta" || obligation.Layer != 1 {
			t.Fatalf("unexpected wrapper policy obligation: %+v", obligation)
		}
		resolution := LayerObligationResolution{}
		switch {
		case obligation.Kind == LayerObligationAlias && obligation.Field == "tag" && obligation.OtherField == "legacy_tag":
			resolution = LayerObligationResolution{Action: LayerResolveAlias, Hook: "adaptMetaTag"}
		case obligation.Kind == LayerObligationIncompatible && obligation.Field == "limit" && obligation.OtherField == "limit":
			resolution = LayerObligationResolution{Action: LayerResolveAdapter, Hook: "adaptMetaLimit"}
		case obligation.Kind == LayerObligationRequired && obligation.OtherField == "extra":
			resolution = LayerObligationResolution{Action: LayerResolveDefault}
		case obligation.Kind == LayerObligationDiscard && obligation.Field == "extra":
			resolution = LayerObligationResolution{Action: LayerResolveAdapter, Hook: "adaptMetaExtra"}
		default:
			t.Fatalf("unsupported wrapper policy obligation: %+v", obligation)
		}
		policy.Entries = append(policy.Entries, LayerObligationPolicyEntry{Key: obligation.Key, Resolution: resolution})
	}

	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy, GenerateFlags: GenerateFlags{Server: true}})
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
	_, err = generator.buildLayerRPCSourceModel(rpc, refs)
	if err == nil || !strings.Contains(err.Error(), "E_WRAPPER_METADATA_TARGET_ABSENT") {
		t.Fatalf("unsafe unmapped wrapper metadata adapter error = %v", err)
	}
}

func TestLayerRPCWrapperProbeRejectsNestedPolicyDecoder(t *testing.T) {
	const profileOne = `
---types---
pong#45000001 value:int = Pong;
probeMeta#45000002 value:long = ProbeMeta;
---functions---
echo#45000010 value:int = Pong;
profileEnvelope#45000020 {X:Type} meta:ProbeMeta query:!X = X;
invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;
// LAYER 1
`
	const profileTwo = `
---types---
pong#45000001 value:int = Pong;
probeMeta#45000003 value:int = ProbeMeta;
---functions---
echo#45000011 value:int = Pong;
profileEnvelope#45000020 {X:Type} meta:ProbeMeta query:!X = X;
invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;
// LAYER 2
`
	set := layerRPCWrapperPolicySchemaSetFromSources(t, profileOne, profileTwo)
	plan, err := AnalyzeLayerConversions(set, LayerObligationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	policy := LayerObligationPolicy{}
	for _, obligation := range plan.Report.Unresolved() {
		if obligation.Semantic.Category != semantic.CategoryType || obligation.Semantic.QName != "probeMeta" {
			t.Fatalf("unexpected nested probe-policy obligation: %+v", obligation)
		}
		policy.Entries = append(policy.Entries, LayerObligationPolicyEntry{
			Key:        obligation.Key,
			Resolution: LayerObligationResolution{Action: LayerResolveAdapter, Hook: "adaptProbeMetaValue"},
		})
	}
	if len(policy.Entries) == 0 {
		t.Fatal("test schema produced no nested constructor policy")
	}
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
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
	_, err = generator.buildLayerRPCSourceModel(rpc, refs)
	if err == nil || !strings.Contains(err.Error(), "E_WRAPPER_PROBE_POLICY_UNSAFE") {
		t.Fatalf("nested policy-bearing wrapper prefix error = %v", err)
	}
}

func layerRPCSourceSyntheticPolicy(t *testing.T, set *SchemaSet) LayerObligationPolicy {
	t.Helper()
	return layerRPCSourcePolicy(t, set, LayerObligationResolution{Action: LayerResolveReject})
}

const layerRPCWrapperPolicyOne = `
---types---
pong#41000001 value:int = Pong;
---functions---
echo#41000010 value:int = Pong;
invokeWithMeta#41000011 {X:Type} legacy_tag:string limit:long query:!X = X;
invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;
// LAYER 1
`

const layerRPCWrapperPolicyTwo = `
---types---
pong#41000001 value:int = Pong;
---functions---
echo#41000020 value:int = Pong;
invokeWithMeta#41000021 {X:Type} tag:string limit:int query:!X = X;
invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;
// LAYER 2
`

func layerRPCWrapperPolicySchemaSet(t *testing.T) *SchemaSet {
	t.Helper()
	return layerRPCWrapperPolicySchemaSetFromSources(t, layerRPCWrapperPolicyOne, layerRPCWrapperPolicyTwo)
}

func layerRPCWrapperPolicySchemaSetFromSources(t *testing.T, sources ...string) *SchemaSet {
	t.Helper()
	profiles := make([]*semantic.SchemaModel, 0, 2)
	for _, source := range sources {
		parsed, err := tl.Parse(bytes.NewBufferString(source))
		if err != nil {
			t.Fatal(err)
		}
		profile, err := semantic.BuildSchema(parsed, semantic.SourceRef{
			Layer:      parsed.Layer,
			Repository: "https://example.invalid/official.git",
			Path:       "api.tl",
		})
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

func layerRPCWrapperPolicy(t *testing.T, set *SchemaSet) LayerObligationPolicy {
	t.Helper()
	plan, err := AnalyzeLayerConversions(set, LayerObligationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	policy := LayerObligationPolicy{}
	for _, obligation := range plan.Report.Unresolved() {
		if obligation.Semantic.Category != semantic.CategoryFunction || obligation.Semantic.QName != "invokeWithMeta" || obligation.Layer != 1 {
			t.Fatalf("unexpected wrapper policy obligation: %+v", obligation)
		}
		resolution := LayerObligationResolution{}
		switch {
		case obligation.Kind == LayerObligationAlias && obligation.Field == "tag" && obligation.OtherField == "legacy_tag":
			resolution = LayerObligationResolution{Action: LayerResolveAlias, Hook: "adaptMetaTag"}
		case obligation.Kind == LayerObligationIncompatible && obligation.Field == "limit" && obligation.OtherField == "limit":
			resolution = LayerObligationResolution{Action: LayerResolveAdapter, Hook: "adaptMetaLimit"}
		default:
			t.Fatalf("unsupported wrapper policy obligation: %+v", obligation)
		}
		policy.Entries = append(policy.Entries, LayerObligationPolicyEntry{Key: obligation.Key, Resolution: resolution})
	}
	if len(policy.Entries) != 3 {
		t.Fatalf("wrapper policy entries = %+v", policy.Entries)
	}
	return policy
}

func layerRPCSourceAliasPolicy(t *testing.T, set *SchemaSet, target string) LayerObligationPolicy {
	t.Helper()
	return layerRPCSourcePolicy(t, set, LayerObligationResolution{
		Action: LayerResolveAlias,
		Hook:   "adaptLegacyRequest",
		Target: target,
	})
}

func layerRPCSourcePolicy(t *testing.T, set *SchemaSet, oldOnly LayerObligationResolution) LayerObligationPolicy {
	t.Helper()
	plan, err := AnalyzeLayerConversions(set, LayerObligationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	policy := LayerObligationPolicy{}
	for _, obligation := range plan.Report.Obligations {
		if obligation.Layer != 1 || obligation.Semantic.Category != semantic.CategoryFunction {
			continue
		}
		entry := LayerObligationPolicyEntry{Key: obligation.Key}
		switch {
		case obligation.Kind == LayerObligationResult && obligation.Semantic.QName == "join":
			hook := "adaptOldJoinResult"
			if obligation.Direction == LayerDirectionProfileToCanonical {
				hook = "adaptNewJoinResult"
			}
			entry.Resolution = LayerObligationResolution{Action: LayerResolveAdapter, Hook: hook}
		case obligation.Kind == LayerObligationOldOnly && obligation.Semantic.QName == "legacy":
			entry.Resolution = oldOnly
		case obligation.Kind == LayerObligationDiscard && obligation.Semantic.QName == "echo":
			entry.Resolution = LayerObligationResolution{Action: LayerResolveDrop}
		default:
			continue
		}
		policy.Entries = append(policy.Entries, entry)
	}
	if len(policy.Entries) != 4 {
		t.Fatalf("synthetic RPC source policy entries = %+v", policy.Entries)
	}
	return policy
}

// Keep the historical result constructor in the canonical schema so a typed
// result adapter has two real generated Go types. Profile-only constructor
// gates are covered by the shared wire-model tests.
func layerRPCSourceSyntheticSchemaSet(t *testing.T) *SchemaSet {
	t.Helper()
	profile, canonical := layerRPCSourceSyntheticSources()
	profiles := make([]*semantic.SchemaModel, 0, 2)
	for _, source := range []string{profile, canonical} {
		parsed, err := tl.Parse(bytes.NewBufferString(source))
		if err != nil {
			t.Fatal(err)
		}
		profile, err := semantic.BuildSchema(parsed, semantic.SourceRef{
			Layer:      parsed.Layer,
			Repository: "https://example.invalid/official.git",
			Path:       "api.tl",
		})
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

func layerRPCSourceSyntheticSources() (string, string) {
	profile := strings.Replace(
		layerRPCSyntheticOne,
		"legacy#21000012 value:int = Pong;",
		"legacy#21000012 value:int = Pong;\n"+
			"bulk#21000013 first:Vector<int> second:Vector<int> = Pong;\n"+
			"getInt#21000033 = int;\n"+
			"getLong#21000034 = long;\n"+
			"getDouble#21000035 = double;\n"+
			"getString#21000036 = string;\n"+
			"getBytes#21000037 = bytes;\n"+
			"getObject#21000038 = Object;\n"+
			"getBare#21000039 = %pong;",
		1,
	)
	canonical := strings.Replace(
		layerRPCSyntheticTwo,
		"newJoin#21000003 value:int = NewJoin;",
		"oldJoin#21000002 value:int = OldJoin;\nnewJoin#21000003 value:int = NewJoin;",
		1,
	)
	canonical = strings.Replace(
		canonical,
		"modern#21000022 value:int = Pong;",
		"modern#21000022 value:int = Pong;\n"+
			"bulk#21000023 first:Vector<int> second:Vector<int> = Pong;\n"+
			"getInt#21000043 = int;\n"+
			"getLong#21000044 = long;\n"+
			"getDouble#21000045 = double;\n"+
			"getString#21000046 = string;\n"+
			"getBytes#21000047 = bytes;\n"+
			"getObject#21000048 = Object;\n"+
			"getBare#21000049 = %pong;",
		1,
	)
	return profile, canonical
}

func findLayerRPCSourceRoute(t *testing.T, model *layerRPCSourceModel, layer int, wireID uint32) *layerRPCSourceRoute {
	t.Helper()
	for index := range model.Routes {
		route := &model.Routes[index]
		if route.Layer == layer && route.WireID == wireID {
			return route
		}
	}
	t.Fatalf("layer RPC source route %d/%#08x was not found", layer, wireID)
	return nil
}

func findLayerRPCSourceHandler(t *testing.T, model *layerRPCSourceModel, name string) *layerRPCSourceHandler {
	t.Helper()
	for index := range model.Handlers {
		handler := &model.Handlers[index]
		if handler.Name == name {
			return handler
		}
	}
	t.Fatalf("layer RPC source handler %q was not found", name)
	return nil
}

func findLayerRPCUnprofiledInvariant(model *layerRPCSourceModel, wireID uint32) *layerRPCUnprofiledInvariantSource {
	if model == nil || model.Unprofiled == nil {
		return nil
	}
	for index := range model.Unprofiled.Invariants {
		invariant := &model.Unprofiled.Invariants[index]
		if invariant.WireID == wireID {
			return invariant
		}
	}
	return nil
}
