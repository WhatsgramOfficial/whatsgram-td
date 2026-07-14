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
)

func TestLayerClientSourceUsesExactRequestAndCompleteResultTypeRef(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerClientSyntheticPolicy(t, set)})
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
	model, err := generator.buildLayerClientSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string]struct {
		result string
		kind   layerClientResultKind
	}{
		"GetInt":    {result: "int", kind: layerClientResultValue},
		"GetLong":   {result: "int64", kind: layerClientResultValue},
		"GetDouble": {result: "float64", kind: layerClientResultValue},
		"GetString": {result: "string", kind: layerClientResultValue},
		"GetBytes":  {result: "[]byte", kind: layerClientResultValue},
		"GetObject": {result: "bin.Object", kind: layerClientResultValue},
		"ListIDs":   {result: "[]int", kind: layerClientResultValue},
		"GetBare":   {result: "Pong", kind: layerClientResultPointerValue},
	} {
		method := findLayerClientSourceMethod(t, model, name)
		if method.ResultType != want.result || method.ResultKind != want.kind {
			t.Errorf("%s layer client result = (%q,%d), want (%q,%d)", name, method.ResultType, method.ResultKind, want.result, want.kind)
		}
	}
	join := findLayerClientSourceMethod(t, model, "Join")
	for _, want := range []string{
		"case LayerProfile1:",
		"wireID: 0x21000011",
		"encodeRequest: layerClientEncodeJoinRequest_21000011",
		"adaptResult: layerClientAdaptRPCResult1_21000011",
		"case LayerProfile2:",
		"wireID: 0x21000021",
	} {
		if !strings.Contains(join.PrepareBody, want) {
			t.Errorf("Join layer client route is missing %q\n%s", want, join.PrepareBody)
		}
	}
	if len(model.HookChecks) != 1 || model.HookChecks[0].Name != "adaptNewJoinResult" ||
		model.HookChecks[0].Signature != "func(LayerProfile, *OldJoin) (*NewJoin, error)" {
		t.Fatalf("layer client reverse result hook contracts = %+v", model.HookChecks)
	}

	var rendered bytes.Buffer
	if err := Template().ExecuteTemplate(&rendered, "layer_client", config{
		Package:           "layerfixture",
		LayerClientSource: model,
	}); err != nil {
		t.Fatal(err)
	}
	formatted, err := format.Source(rendered.Bytes())
	if err != nil {
		t.Fatalf("format generated layer client: %v\n%s", err, rendered.String())
	}
	text := string(formatted)
	for _, want := range []string{
		"type LayerOutboundCall struct",
		"func PrepareLayerOutboundCall(profile LayerProfile, request bin.Object) (LayerOutboundCall, error)",
		"func (c LayerOutboundCall) Append(dst []byte) ([]byte, error)",
		"type LayerClient struct",
		"func NewLayerClient(profile LayerProfile, invoker Invoker) (*LayerClient, error)",
		"func (c *LayerClient) Invoke(ctx context.Context, request bin.Object) (any, error)",
		"func (c *LayerClient) invoke(ctx context.Context, outbound LayerOutboundCall) (any, error)",
		"return layerPrepareClientGetInt(profile, typed)",
		"func layerPrepareClientGetInt(profile LayerProfile, request *GetIntRequest) (LayerOutboundCall, error)",
		"func (c *LayerClient) GetInt(ctx context.Context) (int, error)",
		"func (c *LayerClient) GetObject(ctx context.Context) (bin.Object, error)",
		"func (c *LayerClient) GetBare(ctx context.Context) (Pong, error)",
		"newLayerCodecDecodeState(d.call.profile, b.Len(), layerCodecDecodeLimits{})",
		"d.call.decodeResult.decode(d.call.profile, b, state)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("generated layer client is missing %q", want)
		}
	}
	if strings.Contains(text, "reflect.") || strings.Contains(text, "map[uint32]") {
		t.Fatal("generated layer client contains runtime reflection or a wire-ID map")
	}
}

func TestLayerClientSourceRejectsAmbiguousCanonicalRequestSwitch(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerClientSyntheticPolicy(t, set)})
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
	var first *structDef
	for index := range rpc.Methods {
		method := &rpc.Methods[index]
		if method.Key.QName == "getInt" {
			first = method.Canonical.Structure
		}
	}
	if first == nil {
		t.Fatal("getInt canonical request structure was not found")
	}
	for index := range rpc.Methods {
		method := &rpc.Methods[index]
		if method.Key.QName == "getLong" {
			duplicate := *first
			duplicate.Method = "GetLong"
			method.Canonical.Structure = &duplicate
		}
	}
	_, err = generator.buildLayerClientSourceModel(rpc, refs)
	if err == nil || !strings.Contains(err.Error(), "E_LAYER_CLIENT_REQUEST_AMBIGUOUS") {
		t.Fatalf("ambiguous canonical request switch error = %v", err)
	}
}

func TestLayerClientSourceRejectsIncompleteCanonicalResult(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerClientSyntheticPolicy(t, set)})
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
	for index := range refs.RPCs {
		plan := &refs.RPCs[index]
		if plan.Key.QName != "getInt" {
			continue
		}
		profile := plan.profile(set.CanonicalLayer)
		refs.Nodes[profile.CanonicalResult].Runnable = false
		break
	}
	_, err = generator.buildLayerClientSourceModel(rpc, refs)
	if err == nil || !strings.Contains(err.Error(), "E_LAYER_CLIENT_RESULT_UNSUPPORTED") {
		t.Fatalf("incomplete canonical result error = %v", err)
	}
}

func TestLayerClientSyntheticGeneratedPackageRuntime(t *testing.T) {
	set := layerRPCSourceSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{
		LayerPolicy: layerClientSyntheticPolicy(t, set),
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
	if len(sources["tl_layer_client_gen.go"]) == 0 {
		t.Fatal("schema-set client generation omitted tl_layer_client_gen.go")
	}
	if strings.Contains(string(sources["tl_client_gen.go"]), "LayerClient") {
		t.Fatal("existing Client API was rewritten instead of emitting a companion facade")
	}
	if !strings.Contains(string(sources["tl_server_gen.go"]), "func (r LayerRequest) PrepareOutbound(profile LayerProfile) (LayerOutboundCall, error)") {
		t.Fatal("server+client generation omitted the lease-consuming outbound admission bridge")
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
    "testing"

    "github.com/iamxvbaba/td/bin"
)

func adaptNewJoinResult(_ LayerProfile, value *OldJoin) (*NewJoin, error) {
    if value == nil { return nil, context.Canceled }
    return &NewJoin{Value: value.Value}, nil
}

func adaptOldJoinResult(_ LayerProfile, value *NewJoin) (*OldJoin, error) {
    if value == nil { return nil, context.Canceled }
    return &OldJoin{Value: value.Value}, nil
}

type layerClientTestInvoker struct {
    response []byte
    request []byte
}

func (i *layerClientTestInvoker) Invoke(_ context.Context, input bin.Encoder, output bin.Decoder) error {
    var request bin.Buffer
    if err := input.Encode(&request); err != nil { return err }
    i.request = request.Copy()
    response := bin.Buffer{Buf: append([]byte(nil), i.response...)}
    return output.Decode(&response)
}

func (i *layerClientTestInvoker) setResponse(encode func(*bin.Buffer)) {
    var response bin.Buffer
    encode(&response)
    i.response = response.Copy()
}

func requestID(t *testing.T, body []byte) uint32 {
    t.Helper()
    buffer := bin.Buffer{Buf: append([]byte(nil), body...)}
    id, err := buffer.PeekID()
    if err != nil { t.Fatal(err) }
    return id
}

func TestGeneratedLayerClientRoundTrip(t *testing.T) {
    invoker := &layerClientTestInvoker{}
    client, err := NewLayerClient(LayerProfile1, invoker)
    if err != nil { t.Fatal(err) }
    if client.Profile() != LayerProfile1 || client.Invoker() != invoker { t.Fatal("client did not freeze profile/invoker") }

    outbound, err := PrepareLayerOutboundCall(LayerProfile2, &GetIntRequest{})
    if err != nil { t.Fatal(err) }
    if outbound.Profile() != LayerProfile2 || outbound.Method() != LayerSemanticMethodGetInt || outbound.WireID() != 0x21000043 {
        t.Fatalf("outbound identity = profile %d method %x wire %#08x", outbound.Profile(), outbound.Method(), outbound.WireID())
    }
    var exact bin.Buffer
    if err := outbound.Encode(&exact); err != nil { t.Fatal(err) }
    if id := requestID(t, exact.Copy()); id != 0x21000043 { t.Fatalf("prepared request ID = %#08x", id) }
    prefix := []byte{0xaa, 0xbb}
    appended, err := outbound.Append(append([]byte(nil), prefix...))
    if err != nil { t.Fatal(err) }
    if !bytes.Equal(appended[:len(prefix)], prefix) { t.Fatalf("prepared append prefix = %x", appended) }
    if id := requestID(t, appended[len(prefix):]); id != 0x21000043 { t.Fatalf("appended request ID = %#08x", id) }

    invoker.setResponse(func(b *bin.Buffer) { b.PutInt(-7) })
    integer, err := client.GetInt(context.Background())
    if err != nil || integer != -7 { t.Fatalf("GetInt = %d,%v", integer, err) }
    if id := requestID(t, invoker.request); id != 0x21000033 { t.Fatalf("GetInt request ID = %#08x", id) }

    invoker.setResponse(func(b *bin.Buffer) { b.PutID(0x21000001); b.PutInt(12) })
    object, err := client.GetObject(context.Background())
    if err != nil { t.Fatal(err) }
    if pong, ok := object.(*Pong); !ok || pong.Value != 12 { t.Fatalf("GetObject = %#v", object) }
    if id := requestID(t, invoker.request); id != 0x21000038 { t.Fatalf("GetObject request ID = %#08x", id) }

    invoker.setResponse(func(b *bin.Buffer) { b.PutInt(13) })
    bare, err := client.GetBare(context.Background())
    if err != nil || bare.Value != 13 { t.Fatalf("GetBare = %#v,%v", bare, err) }
    if id := requestID(t, invoker.request); id != 0x21000039 { t.Fatalf("GetBare request ID = %#08x", id) }

    invoker.setResponse(func(b *bin.Buffer) { b.PutVectorHeader(2); b.PutInt(9); b.PutInt(10) })
    ids, err := client.ListIDs(context.Background())
    if err != nil || len(ids) != 2 || ids[0] != 9 || ids[1] != 10 { t.Fatalf("ListIDs = %#v,%v", ids, err) }

    invoker.setResponse(func(b *bin.Buffer) { b.PutID(0x997275b5) })
    confirmed, err := client.Confirm(context.Background())
    if err != nil || !confirmed { t.Fatalf("Confirm = %v,%v", confirmed, err) }

    invoker.setResponse(func(b *bin.Buffer) { b.PutID(0x21000002); b.PutInt(17) })
    joined, err := client.Join(context.Background(), 17)
    if err != nil || joined == nil || joined.Value != 17 { t.Fatalf("Join = %#v,%v", joined, err) }
    if id := requestID(t, invoker.request); id != 0x21000011 { t.Fatalf("Join request ID = %#08x", id) }

    invoker.setResponse(func(b *bin.Buffer) { b.PutBytes([]byte{1, 2, 3}) })
    dynamic, err := client.Invoke(context.Background(), &GetBytesRequest{})
    if err != nil || !bytes.Equal(dynamic.([]byte), []byte{1, 2, 3}) { t.Fatalf("Invoke GetBytes = %#v,%v", dynamic, err) }
}

func TestGeneratedLayerClientFailsClosed(t *testing.T) {
    if _, err := NewLayerClient(LayerProfile(99), &layerClientTestInvoker{}); err == nil { t.Fatal("unsupported profile was accepted") }
    if _, err := PrepareLayerOutboundCall(LayerProfile(99), &GetIntRequest{}); err == nil { t.Fatal("outbound call accepted an unsupported profile") }
    if _, err := PrepareLayerOutboundCall(LayerProfile1, &ModernRequest{Value: 1}); err == nil { t.Fatal("outbound call used a canonical fallback method") }
    if _, err := PrepareLayerOutboundCall(LayerProfile1, &InvokeWithLayerRequest{}); err == nil { t.Fatal("outbound call accepted a transparent wrapper") }
    if err := (LayerOutboundCall{}).Encode(&bin.Buffer{}); err == nil { t.Fatal("zero outbound call encoded") }
    client, err := NewLayerClient(LayerProfile1, &layerClientTestInvoker{})
    if err != nil { t.Fatal(err) }
    if _, err := client.Modern(context.Background(), 1); err == nil { t.Fatal("canonical-only method used a fallback wire ID") }
    if _, err := client.Invoke(context.Background(), &InvokeWithLayerRequest{}); err == nil { t.Fatal("transparent wrapper was accepted as a terminal method") }
}

func TestAdmittedRequestPrepareOutboundConsumesLease(t *testing.T) {
    dispatcher := NewServerDispatcher(nil)
    dispatched := 0
    dispatcher.OnGetInt(func(context.Context) (int, error) {
        dispatched++
        return 1, nil
    })

    canonical, err := PrepareLayerOutboundCall(LayerProfileCanonical, &GetIntRequest{})
    if err != nil { t.Fatal(err) }
    var body bin.Buffer
    if err := canonical.Encode(&body); err != nil { t.Fatal(err) }
    admitted, err := dispatcher.AdmitLayer(LayerProfileCanonical, &body)
    if err != nil { t.Fatal(err) }
    admittedCopy := admitted
    outbound, err := admitted.PrepareOutbound(LayerProfile1)
    if err != nil { t.Fatal(err) }
    if outbound.Profile() != LayerProfile1 || outbound.Method() != LayerSemanticMethodGetInt || outbound.WireID() != 0x21000033 {
        t.Fatalf("reprofiled outbound identity = profile %d method %x wire %#08x", outbound.Profile(), outbound.Method(), outbound.WireID())
    }
    var exact bin.Buffer
    if err := outbound.Encode(&exact); err != nil { t.Fatal(err) }
    if id := requestID(t, exact.Copy()); id != 0x21000033 { t.Fatalf("reprofiled request ID = %#08x", id) }
    if _, err := admittedCopy.PrepareOutbound(LayerProfile1); err == nil { t.Fatal("copied admission lease was reprofiled twice") }
    if _, err := dispatcher.DispatchAdmitted(context.Background(), admittedCopy); err == nil { t.Fatal("reprofiled admission lease was dispatched") }
    if dispatched != 0 { t.Fatalf("reprofiled request executed %d handlers", dispatched) }

    var wrapped bin.Buffer
    wrapped.PutID(0xda9b0d0d)
    wrapped.PutInt(int(LayerProfileCanonical))
    wrapped.PutID(0x21000043)
    wrappedAdmission, err := dispatcher.AdmitLayer(LayerProfileCanonical, &wrapped)
    if err != nil { t.Fatal(err) }
    if _, err := wrappedAdmission.PrepareOutbound(LayerProfile1); err == nil { t.Fatal("reprofile silently discarded transparent wrappers") }
    if _, err := dispatcher.DispatchAdmitted(context.Background(), wrappedAdmission); err != nil { t.Fatalf("failed outbound preparation consumed lease: %v", err) }
    if dispatched != 1 { t.Fatalf("wrapper rejection dispatch count = %d, want 1", dispatched) }
}
`)
	formattedRuntime, err := format.Source(runtimeTest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "layer_client_runtime_test.go"), formattedRuntime, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "test", "-mod=mod", "./...")
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("compile/run generated layer client package: %v\n%s", err, output)
	}
}

func findLayerClientSourceMethod(t *testing.T, model *layerClientSourceModel, name string) *layerClientSourceMethod {
	t.Helper()
	for index := range model.Methods {
		method := &model.Methods[index]
		if method.Name == name {
			return method
		}
	}
	t.Fatalf("layer client source method %q was not found", name)
	return nil
}

func layerClientSyntheticPolicy(t *testing.T, set *SchemaSet) LayerObligationPolicy {
	t.Helper()
	initial, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	policy := LayerObligationPolicy{}
	for _, obligation := range initial.LayerConversionPlan().Report.Unresolved() {
		resolution := LayerObligationResolution{Action: LayerResolveReject}
		switch obligation.Kind {
		case LayerObligationRequired:
			resolution.Action = LayerResolveDefault
		case LayerObligationDiscard, LayerObligationUpdateProjection:
			resolution.Action = LayerResolveDrop
		case LayerObligationPrivate:
			resolution.Action = LayerResolveAllow
		case LayerObligationResult:
			if obligation.Semantic.QName == "join" {
				hook := "adaptOldJoinResult"
				if obligation.Direction == LayerDirectionProfileToCanonical {
					hook = "adaptNewJoinResult"
				}
				resolution = LayerObligationResolution{Action: LayerResolveAdapter, Hook: hook}
			}
		}
		policy.Entries = append(policy.Entries, LayerObligationPolicyEntry{Key: obligation.Key, Resolution: resolution})
	}
	return policy
}
