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

const layerRPCFieldSynthetic227 = `
---types---
pong#51000001 value:int = Pong;
---functions---
metric#51000010 flags:# first:int ids:Vector<int> payload_old:bytes optional_old:flags.0?int = Pong;
invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;
// LAYER 227
`

const layerRPCFieldSynthetic228 = `
---types---
pong#51000001 value:int = Pong;
---functions---
metric#51000018 flags:# payload:bytes ids:Vector<int> optional:flags.1?int first:int = Pong;
invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;
// LAYER 228
`

const layerRPCFieldSynthetic229 = `
---types---
pong#51000001 value:int = Pong;
---functions---
metric#51000020 flags:# ids:Vector<int> first:int payload:bytes optional:flags.2?int = Pong;
invokeWithLayer#da9b0d0d {X:Type} layer:int query:!X = X;
// LAYER 229
`

func layerRPCFieldSyntheticSchemaSet(t *testing.T) *SchemaSet {
	t.Helper()
	profiles := make([]*semantic.SchemaModel, 0, 3)
	for _, source := range []string{layerRPCFieldSynthetic227, layerRPCFieldSynthetic228, layerRPCFieldSynthetic229} {
		parsed, err := tl.Parse(bytes.NewBufferString(source))
		if err != nil {
			t.Fatal(err)
		}
		profile, err := semantic.BuildSchema(parsed, semantic.SourceRef{Layer: parsed.Layer, Repository: "https://example.invalid/official.git", Path: "api.tl"})
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, profile)
	}
	set, err := NewSchemaSet(229, profiles...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func layerRPCFieldSyntheticPolicy(t *testing.T, set *SchemaSet) LayerObligationPolicy {
	t.Helper()
	plan, err := AnalyzeLayerConversions(set, LayerObligationPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	policy := LayerObligationPolicy{}
	for _, obligation := range plan.Report.Obligations {
		if obligation.Semantic.Category == semantic.CategoryFunction && obligation.Semantic.QName == "metric" && obligation.Kind == LayerObligationAlias {
			hook := "aliasMetricPayload"
			if obligation.Field == "optional" {
				hook = "aliasMetricOptional"
			}
			policy.Entries = append(policy.Entries, LayerObligationPolicyEntry{
				Key:        obligation.Key,
				Resolution: LayerObligationResolution{Action: LayerResolveAlias, Hook: hook},
			})
		}
	}
	if len(policy.Entries) == 0 {
		t.Fatal("synthetic rename produced no alias obligations")
	}
	return policy
}

func layerRPCFieldSyntheticGenerator(t *testing.T) *Generator {
	t.Helper()
	set := layerRPCFieldSyntheticSchemaSet(t)
	policy := layerRPCFieldSyntheticPolicy(t, set)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	return generator
}

func TestLayerRPCAdmissionFieldStableIDGolden(t *testing.T) {
	for _, test := range []struct {
		method string
		field  string
		want   uint64
	}{
		{method: "users.getUsers", field: "id", want: 0x6facbb22287aa39f},
		{method: "upload.saveBigFilePart", field: "bytes", want: 0x1955aaf274773661},
		{method: "upload.saveBigFilePart", field: "file_total_parts", want: 0x34552f779b373760},
	} {
		if got := layerRPCAdmissionFieldStableID(test.method, test.field); got != test.want {
			t.Errorf("stable ID %s/%s = %#016x, want %#016x", test.method, test.field, got, test.want)
		}
	}
	if a, b := layerRPCAdmissionFieldStableID("metric", "ids"), layerRPCAdmissionFieldStableID("metric", "ids"); a != b {
		t.Fatalf("identical semantic field IDs differ: %#x != %#x", a, b)
	}
}

func TestLayerRPCAdmissionFieldSynthetic228229MovedFieldsChangedCRC(t *testing.T) {
	generator := layerRPCFieldSyntheticGenerator(t)
	model, err := generator.buildLayerRPCModel()
	if err != nil {
		t.Fatal(err)
	}
	method := model.method(semantic.SemanticKey{Category: semantic.CategoryFunction, QName: "metric"})
	if method == nil {
		t.Fatal("metric method is absent")
	}
	if method.profile(227).WireID == method.profile(228).WireID || method.profile(229).WireID == method.profile(228).WireID {
		t.Fatalf("synthetic CRCs 227=%#x 228=%#x 229=%#x", method.profile(227).WireID, method.profile(228).WireID, method.profile(229).WireID)
	}
	for _, fieldName := range []string{"first", "ids", "payload", "optional"} {
		plan := findLayerRPCAdmissionFieldPlan(t, model, "metric", fieldName)
		if !plan.Complete || len(plan.Coverage) != 3 {
			t.Fatalf("metric/%s plan = %+v", fieldName, plan)
		}
		for _, coverage := range plan.Coverage {
			if coverage.Status != layerRPCAdmissionCoverageObservable {
				t.Fatalf("metric/%s layer %d coverage = %+v", fieldName, coverage.Layer, coverage)
			}
			profile := method.profile(coverage.Layer)
			index := -1
			for i := range profile.Fields {
				if profile.Fields[i].Name == coverage.ProfileField {
					index = i
					break
				}
			}
			if index < 0 || profile.Fields[index].Admission == nil || profile.Fields[index].Admission.ID != plan.ID {
				t.Fatalf("metric/%s layer %d decoder use is missing or unstable", fieldName, coverage.Layer)
			}
		}
	}
	payload := findLayerRPCAdmissionFieldPlan(t, model, "metric", "payload")
	if payload.Coverage[0].ProfileField != "payload_old" || payload.Coverage[0].Status != layerRPCAdmissionCoverageObservable {
		t.Fatalf("renamed payload coverage = %+v", payload.Coverage[0])
	}
}

func TestLayerRPCAdmissionFieldRejectsSameCRCDifferentLayout(t *testing.T) {
	conflicting := strings.Replace(layerRPCFieldSynthetic228, "metric#51000018", "metric#51000010", 1)
	profiles := make([]*semantic.SchemaModel, 0, 3)
	for _, source := range []string{layerRPCFieldSynthetic227, conflicting, layerRPCFieldSynthetic229} {
		parsed, err := tl.Parse(bytes.NewBufferString(source))
		if err != nil {
			t.Fatal(err)
		}
		profile, err := semantic.BuildSchema(parsed, semantic.SourceRef{Layer: parsed.Layer, Repository: "https://example.invalid/official.git", Path: "api.tl"})
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, profile)
	}
	if _, err := NewSchemaSet(229, profiles...); err == nil || !strings.Contains(err.Error(), "conflicting payload shapes") {
		t.Fatalf("same CRC/different layout error = %v", err)
	}
}

func TestLayerRPCAdmissionFieldCoverageFailsClosed(t *testing.T) {
	newModel := func(t *testing.T) *layerRPCModel {
		t.Helper()
		generator := layerRPCFieldSyntheticGenerator(t)
		model, err := generator.buildLayerRPCModel()
		if err != nil {
			t.Fatal(err)
		}
		return model
	}

	t.Run("unmapped", func(t *testing.T) {
		model := newModel(t)
		profile := model.method(semantic.SemanticKey{Category: semantic.CategoryFunction, QName: "metric"}).profile(227)
		for i := range profile.Conversion.Fields {
			if profile.Definition.Fields[i].Name == "ids" {
				profile.Conversion.Fields[i].CanonicalOrdinal = -1
			}
		}
		resetLayerRPCAdmissionFields(model)
		if err := buildLayerRPCAdmissionFields(model); err != nil {
			t.Fatal(err)
		}
		plan := findLayerRPCAdmissionFieldPlan(t, model, "metric", "ids")
		if plan.Complete || plan.Coverage[0].Status != layerRPCAdmissionCoverageUnmapped {
			t.Fatalf("unmapped plan = %+v", plan)
		}
	})

	t.Run("incompatible", func(t *testing.T) {
		model := newModel(t)
		profile := model.method(semantic.SemanticKey{Category: semantic.CategoryFunction, QName: "metric"}).profile(228)
		for i := range profile.Fields {
			if profile.Fields[i].Name == "payload" {
				copy := *profile.Fields[i].Shape
				profile.Fields[i].Shape = &copy
			}
		}
		resetLayerRPCAdmissionFields(model)
		if err := buildLayerRPCAdmissionFields(model); err != nil {
			t.Fatal(err)
		}
		plan := findLayerRPCAdmissionFieldPlan(t, model, "metric", "payload")
		if plan.Complete || plan.Coverage[1].Status != layerRPCAdmissionCoverageIncompatible {
			t.Fatalf("incompatible plan = %+v", plan)
		}
	})

	t.Run("adapter-unproven", func(t *testing.T) {
		model := newModel(t)
		profile := model.method(semantic.SemanticKey{Category: semantic.CategoryFunction, QName: "metric"}).profile(228)
		profile.Conversion.Obligations = append(profile.Conversion.Obligations, LayerObligation{
			Kind:       LayerObligationAlias,
			Direction:  LayerDirectionProfileToCanonical,
			Field:      "ids",
			OtherField: "ids",
			Resolution: LayerObligationResolution{Action: LayerResolveAdapter, Hook: "adaptMetricIDs"},
		})
		resetLayerRPCAdmissionFields(model)
		if err := buildLayerRPCAdmissionFields(model); err != nil {
			t.Fatal(err)
		}
		plan := findLayerRPCAdmissionFieldPlan(t, model, "metric", "ids")
		if plan.Complete || plan.Coverage[1].Status != layerRPCAdmissionCoverageAdapterUnproven {
			t.Fatalf("adapter plan = %+v", plan)
		}
	})

	t.Run("alias-without-pure-rename-proof", func(t *testing.T) {
		model := newModel(t)
		profile := model.method(semantic.SemanticKey{Category: semantic.CategoryFunction, QName: "metric"}).profile(228)
		profile.Conversion.Obligations = append(profile.Conversion.Obligations, LayerObligation{
			Kind:       LayerObligationAlias,
			Direction:  LayerDirectionBoth,
			Field:      "ids",
			OtherField: "ids",
			SourceType: "Vector<int>",
			TargetType: "Vector<int>",
			Resolution: LayerObligationResolution{Action: LayerResolveAlias, Hook: "aliasMetricIDs"},
		})
		resetLayerRPCAdmissionFields(model)
		if err := buildLayerRPCAdmissionFields(model); err != nil {
			t.Fatal(err)
		}
		plan := findLayerRPCAdmissionFieldPlan(t, model, "metric", "ids")
		if plan.Complete || plan.Coverage[1].Status != layerRPCAdmissionCoverageAdapterUnproven {
			t.Fatalf("unproven alias plan = %+v", plan)
		}
	})
}

func TestLayerRPCAdmissionFieldReal225Through228PolicyMetrics(t *testing.T) {
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
	model, err := generator.buildLayerRPCModel()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []struct{ method, name string }{
		{"users.getUsers", "id"},
		{"users.getRequirementsToContact", "id"},
		{"contacts.importContacts", "contacts"},
		{"contacts.deleteContacts", "id"},
		{"contacts.editCloseFriends", "id"},
		{"contacts.setBlocked", "id"},
		{"messages.getMessages", "id"},
		{"messages.getChats", "id"},
		{"messages.getPeerDialogs", "peers"},
		{"messages.readMessageContents", "id"},
		{"messages.getCustomEmojiDocuments", "document_id"},
		{"messages.deleteMessages", "id"},
		{"messages.createChat", "users"},
		{"channels.getChannels", "id"},
		{"upload.saveFilePart", "bytes"},
		{"upload.saveBigFilePart", "file_total_parts"},
		{"upload.saveBigFilePart", "bytes"},
	} {
		plan := findLayerRPCAdmissionFieldPlan(t, model, field.method, field.name)
		if !plan.Complete {
			t.Errorf("%s/%s coverage incomplete: %s", field.method, field.name, plan.Failure)
		}
		for _, coverage := range plan.Coverage {
			if coverage.Status != layerRPCAdmissionCoverageObservable {
				t.Errorf("%s/%s layer %d = %s: %s", field.method, field.name, coverage.Layer, coverage.Status, coverage.Reason)
			}
		}
	}
}

func TestLayerRPCAdmissionFieldOldOnlyTargetAdapterIsUnproven(t *testing.T) {
	set := layerRPCSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: layerRPCSyntheticPolicy(t, set)})
	if err != nil {
		t.Fatal(err)
	}
	model, err := generator.buildLayerRPCModel()
	if err != nil {
		t.Fatal(err)
	}
	plan := findLayerRPCAdmissionFieldPlan(t, model, "modern", "value")
	if plan.Complete || plan.Coverage[0].Status != layerRPCAdmissionCoverageAdapterUnproven {
		t.Fatalf("old-only adapter target coverage = %+v", plan)
	}
}

func TestLayerRPCAdmissionFieldPureRenameBypassesMutationHook(t *testing.T) {
	set := layerRPCFieldSyntheticSchemaSet(t)
	generator, err := NewSchemaSetGenerator(set, GeneratorOptions{
		LayerPolicy:   layerRPCFieldSyntheticPolicy(t, set),
		GenerateFlags: GenerateFlags{Server: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	sources := sourceSnapshot{}
	if err := generator.WriteSource(sources, "fieldfixture", Template()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	goMod := fmt.Sprintf("module fieldfixture\n\ngo 1.25\n\nrequire github.com/iamxvbaba/td v0.0.0\nreplace github.com/iamxvbaba/td => %s\n", filepath.ToSlash(root))
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
	runtimeTest := []byte(`package fieldfixture

import (
    "bytes"
    "context"
    "testing"

    "github.com/iamxvbaba/td/bin"
)

var payloadAliasCalls, optionalAliasCalls int

func aliasMetricPayloadEncode(_ LayerProfile, _ *MetricRequest, value []byte) ([]byte, error) {
    payloadAliasCalls++
    return append([]byte("mutated:"), value...), nil
}

func aliasMetricPayloadDecode(_ LayerProfile, _ *MetricRequest, _ bool, value []byte) ([]byte, error) {
    payloadAliasCalls++
    return append([]byte("mutated:"), value...), nil
}

func aliasMetricOptionalEncode(_ LayerProfile, _ *MetricRequest, _ bool, value int) (int, bool, error) {
    optionalAliasCalls++
    return value + 100, false, nil
}

func aliasMetricOptionalDecode(_ LayerProfile, _ *MetricRequest, _ bool, value int) (int, bool, error) {
    optionalAliasCalls++
    return value + 100, false, nil
}

func TestPureRenameIsMechanical(t *testing.T) {
    dispatcher := NewServerDispatcher(nil)
    dispatcher.OnMetric(func(_ context.Context, request *MetricRequest) (*Pong, error) {
        if !bytes.Equal(request.Payload, []byte("abc")) {
            t.Fatalf("canonical payload = %q", request.Payload)
        }
        if !request.Flags.Has(2) || request.Optional != 7 {
            t.Fatalf("canonical optional = (%d,%v)", request.Optional, request.Flags.Has(2))
        }
        return &Pong{}, nil
    })
    if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldMetricPayload, func(view LayerRPCAdmissionFieldView) error {
        length, ok := view.BytesLength()
        if !ok || length != 3 { t.Fatalf("payload metric = (%d,%v)", length, ok) }
        return nil
    }); err != nil { t.Fatal(err) }
    if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldMetricOptional, func(view LayerRPCAdmissionFieldView) error {
        value, ok := view.Int32()
        if !ok || value != 7 || !view.Present() { t.Fatalf("optional metric = (%d,%v,%v)", value, ok, view.Present()) }
        return nil
    }); err != nil { t.Fatal(err) }

    var wire bin.Buffer
    wire.PutID(0x51000010)
    wire.PutInt(1)
    wire.PutInt(11)
    wire.PutVectorHeader(1)
    wire.PutInt(12)
    if err := wire.PutBytesChecked([]byte("abc")); err != nil { t.Fatal(err) }
    wire.PutInt(7)
    admitted, err := dispatcher.AdmitLayer(LayerProfile227, &wire)
    if err != nil { t.Fatal(err) }
    if _, err := dispatcher.DispatchAdmitted(context.Background(), admitted); err != nil { t.Fatal(err) }
    if payloadAliasCalls != 0 || optionalAliasCalls != 0 {
        t.Fatalf("mutable alias hooks ran: payload=%d optional=%d", payloadAliasCalls, optionalAliasCalls)
    }
}
`)
	if err := os.WriteFile(filepath.Join(dir, "field_runtime_test.go"), runtimeTest, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "test", "-mod=mod", "./...")
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("compile/run generated field admission package: %v\n%s", err, output)
	}
}

func resetLayerRPCAdmissionFields(model *layerRPCModel) {
	model.AdmissionFields = nil
	for methodIndex := range model.Methods {
		for profileIndex := range model.Methods[methodIndex].Profiles {
			for fieldIndex := range model.Methods[methodIndex].Profiles[profileIndex].Fields {
				model.Methods[methodIndex].Profiles[profileIndex].Fields[fieldIndex].Admission = nil
			}
		}
	}
}

func findLayerRPCAdmissionFieldPlan(t *testing.T, model *layerRPCModel, method, field string) *layerRPCAdmissionFieldPlan {
	t.Helper()
	for i := range model.AdmissionFields {
		plan := &model.AdmissionFields[i]
		if plan.Method.QName == method && plan.CanonicalField == field {
			return plan
		}
	}
	t.Fatalf("admission field %s/%s is absent", method, field)
	return nil
}
