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

	"github.com/gotd/td/gen/semantic"
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
	if model.WrapperCount != 8 {
		t.Fatalf("wrapper route count = %d, want four wrappers in two profiles", model.WrapperCount)
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
		"decodeLayerRPCRequestState(nestedProfile, b, state, preflight, depth+1)",
		"state.bind(0, admitted.call.result)",
		"defer state.restore(bindingSnapshot)",
		"layerFreezeRPCWrapperField(LayerProfileCanonical, \"layer\"",
		"admitted.wrappers = append(admitted.wrappers, wrapperFrame)",
	} {
		if !strings.Contains(withLayer.Body, want) {
			t.Errorf("invokeWithLayer admission is missing %q\n%s", want, withLayer.Body)
		}
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
		"func layerAdmitRPC1_21000011",
		"var _ func(LayerProfile, *NewJoin) (*OldJoin, error) = adaptOldJoinResult",
		"r.prepared.Call().EncodeResult(r.value, b)",
		"sha256.Sum256(wireRequest)",
		"func (s *ServerDispatcher) AdmitLayer(",
		"func (s *ServerDispatcher) AdmitUnprofiled(",
		"func (s *ServerDispatcher) DispatchAdmitted(ctx context.Context, admitted LayerRequest) (LayerRPCResult, error)",
		"func (s *ServerDispatcher) HasLayerRPCHandler(semantic LayerSemanticID) bool",
		"func (s *ServerDispatcher) HandleUnprofiled(",
		"type LayerRPCWrapperConsumer func(context.Context, LayerRequest, LayerRPCNext) error",
		"func (s *ServerDispatcher) OnLayerRPCWrappers(",
		"atomic.CompareAndSwapUint32(&lease.dispatched, 0, 1)",
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

func TestLayerRPCSourceTelegram220Through227Completeness(t *testing.T) {
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
		t.Fatalf("format Telegram Layers 220-227 generated RPC server: %v\n%s", err, rendered.String())
	}
	t.Logf("Telegram Layers 220-227 RPC source: exact_routes=%d wrapper_routes=%d", model.RouteCount, model.WrapperCount)
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
	goMod := fmt.Sprintf("module layerfixture\n\ngo 1.25\n\nrequire github.com/gotd/td v0.0.0\nreplace github.com/gotd/td => %s\n", filepath.ToSlash(root))
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gotd/td/bin"
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
	goMod := fmt.Sprintf("module wrapperfixture\n\ngo 1.25\n\nrequire github.com/gotd/td v0.0.0\nreplace github.com/gotd/td => %s\n", filepath.ToSlash(root))
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

	"github.com/gotd/td/bin"
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
			entry.Resolution = LayerObligationResolution{Action: LayerResolveAdapter, Hook: "adaptOldJoinResult"}
		case obligation.Kind == LayerObligationOldOnly && obligation.Semantic.QName == "legacy":
			entry.Resolution = oldOnly
		case obligation.Kind == LayerObligationDiscard && obligation.Semantic.QName == "echo":
			entry.Resolution = LayerObligationResolution{Action: LayerResolveDrop}
		default:
			continue
		}
		policy.Entries = append(policy.Entries, entry)
	}
	if len(policy.Entries) != 3 {
		t.Fatalf("synthetic RPC source policy entries = %+v", policy.Entries)
	}
	return policy
}

// Keep the historical result constructor in the canonical schema so a typed
// result adapter has two real generated Go types. Profile-only constructor
// gates are covered by the shared wire-model tests.
func layerRPCSourceSyntheticSchemaSet(t *testing.T) *SchemaSet {
	t.Helper()
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
			"getObject#21000038 = Object;",
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
			"getObject#21000048 = Object;",
		1,
	)
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
