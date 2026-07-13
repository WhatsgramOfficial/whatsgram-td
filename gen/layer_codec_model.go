package gen

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gotd/td/gen/semantic"
)

const (
	layerCodecMaximumWireBytes         = 32 << 20
	layerCodecMaximumDepth             = 64
	layerCodecMaximumVectorSize        = 1 << 20
	layerCodecMaximumAggregateElements = 1 << 20

	layerCodecDefaultWireBytes         = layerCodecMaximumWireBytes
	layerCodecDefaultDepth             = 32
	layerCodecDefaultVectorSize        = 4096
	layerCodecDefaultAggregateElements = 1 << 17
)

// layerCodecModel is the source-emitter view of the multi-layer codec. It is
// deliberately made of Go identifiers and already-expanded statements: the
// generated package contains no schema walker, reflection, or runtime map.
type layerCodecModel struct {
	Package                  string
	MaxWireBytes             int
	MaxDepth                 int
	MaxVectorSize            int
	MaxAggregateElements     int
	DefaultWireBytes         int
	DefaultDepth             int
	DefaultVectorSize        int
	DefaultAggregateElements int
	Wires                    []layerCodecWire
	WireBuckets              []layerCodecWireBucket
	Declarations             []string
	FamilyDeclarations       []string
	ClassDeclarations        []string
	DynamicDeclarations      []string
	Hooks                    []layerCodecHookContract
}

type layerCodecWireBucket struct {
	Index int
	Wires []layerCodecWire
}

// layerCodecWire emits exactly one pair of boxed/bare functions for one
// globally unique wire constructor/method ID. CanonicalType is empty only for
// a profile-only historical method, for which RejectProfiles contains the
// complete admission stub. A historical-only constructor with an explicit
// bidirectional policy is instead emitted as an ordinary typed wire whose
// CanonicalType is the policy target.
type layerCodecWire struct {
	WireID         uint32
	Hex            string
	Semantic       string
	CanonicalType  string
	EncodeName     string
	EncodeBareName string
	PreflightName  string
	DecodeName     string
	DecodeBareName string
	ProfileOnly    bool
	Profiles       []layerCodecProfileBody
	ProfileGroups  []layerCodecProfileBody
	RejectProfiles []int
}

type layerCodecProfileBody struct {
	Layer        int
	Layers       []int
	Preflight    string
	Encode       string
	Decode       string
	EncodeReject string
	DecodeReject string
}

// layerCodecHookContract makes policy hooks ordinary statically linked Go
// functions. Reusing one hook name with another inferred signature is a hard
// generation error; an absent implementation is a compile error in the
// generated package.
type layerCodecHookContract struct {
	Name      string
	Signature string
}

type layerCodecEmitter struct {
	model        *layerCodecModel
	wire         *layerWireModel
	values       *layerValueCompiler
	hookByName   map[string]string
	genericSlots map[string]int
	temp         int
}

// buildLayerCodecModel compiles the shared wire/conversion/value plans into a
// static source model. It does not perform a second schema comparison.
func (g *Generator) buildLayerCodecModel(pkg string) (*layerCodecModel, error) {
	if g == nil || g.schemaSet == nil {
		return nil, fmt.Errorf("gen: layer codec requires a schema-set generator")
	}
	wire, err := g.buildLayerWireModel()
	if err != nil {
		return nil, fmt.Errorf("gen: layer codec wire model: %w", err)
	}
	values, err := g.newLayerValueCompilerForWire(wire)
	if err != nil {
		return nil, fmt.Errorf("gen: layer codec value compiler: %w", err)
	}
	if err := validateLayerCodecPolicy(g.LayerConversionPlan()); err != nil {
		return nil, err
	}

	emitter := &layerCodecEmitter{
		model: &layerCodecModel{
			Package:                  pkg,
			MaxWireBytes:             layerCodecMaximumWireBytes,
			MaxDepth:                 layerCodecMaximumDepth,
			MaxVectorSize:            layerCodecMaximumVectorSize,
			MaxAggregateElements:     layerCodecMaximumAggregateElements,
			DefaultWireBytes:         layerCodecDefaultWireBytes,
			DefaultDepth:             layerCodecDefaultDepth,
			DefaultVectorSize:        layerCodecDefaultVectorSize,
			DefaultAggregateElements: layerCodecDefaultAggregateElements,
		},
		wire:       wire,
		values:     values,
		hookByName: make(map[string]string),
	}
	if err := emitter.buildWires(); err != nil {
		return nil, err
	}
	emitter.buildWireBuckets(64)
	if err := emitter.buildFamilies(); err != nil {
		return nil, err
	}
	if err := emitter.buildClasses(); err != nil {
		return nil, err
	}
	if err := emitter.buildObjectDispatcher(); err != nil {
		return nil, err
	}
	sort.Slice(emitter.model.Hooks, func(i, j int) bool {
		return emitter.model.Hooks[i].Name < emitter.model.Hooks[j].Name
	})
	return emitter.model, nil
}

func (e *layerCodecEmitter) buildWireBuckets(count int) {
	if count <= 0 {
		return
	}
	e.model.WireBuckets = make([]layerCodecWireBucket, count)
	for index := range e.model.WireBuckets {
		e.model.WireBuckets[index].Index = index
	}
	for _, wire := range e.model.Wires {
		bucket := int(wire.WireID % uint32(count))
		e.model.WireBuckets[bucket].Wires = append(e.model.WireBuckets[bucket].Wires, wire)
	}
}

func validateLayerCodecPolicy(plan *LayerConversionPlan) error {
	if plan == nil {
		return fmt.Errorf("gen: layer codec requires the cached conversion plan")
	}
	var unresolved []LayerObligation
	for _, obligation := range plan.Report.Obligations {
		if !obligation.Resolution.resolved() {
			unresolved = append(unresolved, obligation)
		}
	}
	if len(unresolved) == 0 {
		return nil
	}
	first := unresolved[0]
	return fmt.Errorf(
		"gen: E_UNRESOLVED_LAYER_CODEC_POLICY: %d obligations remain; first=%s layer=%d semantic=%s direction=%s",
		len(unresolved), first.Key, first.Layer, first.Semantic, first.Direction,
	)
}

func (e *layerCodecEmitter) buildWires() error {
	e.model.Wires = make([]layerCodecWire, 0, len(e.wire.Wires))
	for wireIndex := range e.wire.Wires {
		plan := &e.wire.Wires[wireIndex]
		hex := fmt.Sprintf("%08x", plan.WireID)
		out := layerCodecWire{
			WireID:         plan.WireID,
			Hex:            hex,
			Semantic:       layerSemanticConstant(plan.Key),
			EncodeName:     "layerEncodeWire" + hex,
			EncodeBareName: "layerEncodeWire" + hex + "Bare",
			PreflightName:  "layerPreflightWire" + hex + "Bare",
			DecodeName:     "layerDecodeWire" + hex,
			DecodeBareName: "layerDecodeWire" + hex + "Bare",
		}
		if plan.Canonical == nil {
			if plan.Key.Category == semantic.CategoryFunction {
				out.ProfileOnly = true
				for _, action := range plan.Profiles {
					if action.Kind == layerWireReject {
						continue
					}
					if action.Conversion == nil || !layerCodecProfileOnlyAdmissionResolved(action.Conversion) {
						return fmt.Errorf(
							"gen: E_PROFILE_ONLY_CODEC_NOT_ADMITTED: layer %d wire %#08x semantic %s needs an old-only reject/alias/adapter RPC admission decision",
							action.Layer, plan.WireID, plan.Key,
						)
					}
					out.RejectProfiles = append(out.RejectProfiles, action.Layer)
				}
				e.model.Wires = append(e.model.Wires, out)
				continue
			}

			for _, action := range plan.Profiles {
				if action.Kind == layerWireReject {
					continue
				}
				historical := e.wire.historicalWire(action.Layer, plan.WireID)
				if historical == nil {
					return fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_PLAN_MISSING: layer %d wire %#08x semantic %s has no static historical mapping", action.Layer, plan.WireID, plan.Key)
				}
				if out.CanonicalType == "" {
					out.CanonicalType = historical.Target.Structure.Name
				} else if out.CanonicalType != historical.Target.Structure.Name {
					return fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_TARGET_DRIFT: wire %#08x maps to both %s and %s", plan.WireID, out.CanonicalType, historical.Target.Structure.Name)
				}
				body, err := e.buildHistoricalTypeProfileBody(historical)
				if err != nil {
					return fmt.Errorf("gen: layer %d historical wire %#08x %s: %w", action.Layer, plan.WireID, plan.Key, err)
				}
				out.Profiles = append(out.Profiles, body)
			}
			if len(out.Profiles) == 0 || out.CanonicalType == "" {
				return fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_NO_ACCEPTED_PROFILE: historical type wire %#08x has no statically encodable profile", plan.WireID)
			}
			out.ProfileGroups = groupLayerCodecProfileBodies(out.Profiles)
			e.model.Wires = append(e.model.Wires, out)
			continue
		}

		out.CanonicalType = plan.Canonical.Structure.Name
		for _, action := range plan.Profiles {
			if action.Kind == layerWireReject {
				continue
			}
			if action.Conversion == nil || action.Variant == nil {
				return fmt.Errorf("gen: layer %d wire %#08x has no conversion/profile variant", action.Layer, plan.WireID)
			}
			body, err := e.buildProfileBody(plan, &action)
			if err != nil {
				return fmt.Errorf("gen: layer %d wire %#08x %s: %w", action.Layer, plan.WireID, plan.Key, err)
			}
			out.Profiles = append(out.Profiles, body)
		}
		if len(out.Profiles) == 0 {
			return fmt.Errorf("gen: canonical wire %#08x has no accepted exact profiles", plan.WireID)
		}
		out.ProfileGroups = groupLayerCodecProfileBodies(out.Profiles)
		e.model.Wires = append(e.model.Wires, out)
	}
	return nil
}

type layerCodecHistoricalFieldPlan struct {
	Field        *semantic.FieldShape
	Plan         *layerValuePlan
	GoType       string
	Value        string
	Present      string
	PresenceOnly bool
}

type layerCodecHistoricalFlagSlot struct {
	Word string
	Bit  uint8
}

func (e *layerCodecEmitter) buildHistoricalTypeProfileBody(profile *layerHistoricalConstructorPlan) (layerCodecProfileBody, error) {
	if profile == nil || profile.Definition == nil || profile.Target == nil {
		return layerCodecProfileBody{}, fmt.Errorf("nil historical type profile")
	}
	body := layerCodecProfileBody{Layer: profile.Layer}
	var err error
	e.temp = 0
	body.Preflight, err = e.emitHistoricalTypePreflight(profile)
	if err != nil {
		return body, err
	}
	e.temp = 0
	body.Encode, err = e.emitHistoricalTypeEncode(profile)
	if err != nil {
		return body, err
	}
	e.temp = 0
	body.Decode, err = e.emitHistoricalTypeDecode(profile)
	if err != nil {
		return body, err
	}
	return body, nil
}

func (e *layerCodecEmitter) planHistoricalTypeFields(profile *layerHistoricalConstructorPlan) ([]layerCodecHistoricalFieldPlan, error) {
	definition := profile.Definition
	flags := make(map[string]struct{})
	for index := range definition.Fields {
		field := &definition.Fields[index]
		if field.Kind == semantic.FieldFlagsWord {
			flags[field.Name] = struct{}{}
		}
	}
	fields := make([]layerCodecHistoricalFieldPlan, 0, len(definition.Fields))
	for index := range definition.Fields {
		field := &definition.Fields[index]
		if field.Kind == semantic.FieldFlagsWord {
			continue
		}
		entry := layerCodecHistoricalFieldPlan{
			Field:   field,
			Value:   fmt.Sprintf("historicalValue%d", field.Ordinal),
			Present: "true",
		}
		if field.Condition != nil {
			if _, ok := flags[field.Condition.Word]; !ok {
				return nil, fmt.Errorf("historical field %q references missing flags word %q", field.Name, field.Condition.Word)
			}
			entry.Present = fmt.Sprintf("historicalPresent%d", field.Ordinal)
		}
		if field.Condition != nil && field.Condition.PresenceOnly {
			entry.PresenceOnly = true
			entry.GoType = "bool"
			fields = append(fields, entry)
			continue
		}
		plan, err := e.values.Compile(profile.Layer, &field.Type)
		if err != nil {
			return nil, fmt.Errorf("compile historical field %q TypeRef %s: %w", field.Name, field.Type.String(), err)
		}
		if err := e.validateHistoricalTypeValuePlan(profile.Layer, plan, "field "+field.Name); err != nil {
			return nil, err
		}
		goType, err := layerCodecGoType(plan)
		if err != nil {
			return nil, fmt.Errorf("historical field %q Go type: %w", field.Name, err)
		}
		entry.Plan = plan
		entry.GoType = goType
		fields = append(fields, entry)
	}
	return fields, nil
}

func (e *layerCodecEmitter) validateHistoricalTypeValuePlan(layer int, plan *layerValuePlan, context string) error {
	if plan == nil {
		return fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_TYPEREF: layer %d %s has a nil TypeRef plan", layer, context)
	}
	switch plan.Kind {
	case layerValuePrimitive, layerValueDynamicObject:
		return nil
	case layerValueDynamicGeneric:
		return fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_TYPEREF: layer %d %s uses an unbound generic Object", layer, context)
	case layerValueVector:
		return e.validateHistoricalTypeValuePlan(layer, plan.Element, context+" vector element")
	case layerValueExactBare, layerValueBoxedConcrete:
		if len(plan.Constructors) != 1 || plan.Constructors[0].Canonical == nil {
			return fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_TYPEREF: layer %d %s exact constructor is itself profile-only and has no directly emittable canonical Go value", layer, context)
		}
		return nil
	case layerValueBoxedAbstract:
		if plan.CanonicalClass == nil {
			return fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_TYPEREF: layer %d %s class %q has no canonical interface", layer, context, plan.Ref.QName)
		}
		for _, constructor := range plan.Constructors {
			if constructor.Canonical != nil {
				continue
			}
			if constructor.Conversion == nil || constructor.Conversion.Profile == nil || constructor.Conversion.Profile.Definition == nil {
				return fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_TYPEREF: layer %d %s class %q has an incomplete profile-only member", layer, context, plan.Ref.QName)
			}
			wireID := constructor.Conversion.Profile.Definition.WireID
			if e.wire.historicalWire(layer, wireID) == nil {
				return fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_TYPEREF: layer %d %s class %q member %#08x has no bidirectional historical mapping", layer, context, plan.Ref.QName, wireID)
			}
		}
		return nil
	default:
		return fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_TYPEREF: layer %d %s has unsupported value plan %s", layer, context, plan.Kind)
	}
}

func (e *layerCodecEmitter) addHistoricalTypeEncodeHook(profile *layerHistoricalConstructorPlan, fields []layerCodecHistoricalFieldPlan, errorReturn string) (string, error) {
	arguments := []string{"LayerProfile", "*" + profile.Target.Structure.Name}
	results := make([]string, 0, len(fields)*2)
	outputs := make([]string, 0, len(fields)*2)
	for _, field := range fields {
		if field.PresenceOnly {
			results = append(results, "bool")
			outputs = append(outputs, field.Present)
			continue
		}
		if field.Field.Condition != nil {
			results = append(results, "bool")
			outputs = append(outputs, field.Present)
		}
		results = append(results, field.GoType)
		outputs = append(outputs, field.Value)
	}
	hook := profile.Resolution.Hook + "Encode"
	var signature string
	var b strings.Builder
	if len(results) == 0 {
		signature = fmt.Sprintf("func(%s) error", strings.Join(arguments, ", "))
		fmt.Fprintf(&b, "if err := %s(profile, value); err != nil { %sfmt.Errorf(\"adapt historical constructor for encoding: %%w\", err) }\n", hook, errorReturn)
	} else {
		signature = fmt.Sprintf("func(%s) (%s, error)", strings.Join(arguments, ", "), strings.Join(results, ", "))
		fmt.Fprintf(&b, "%s, historicalHookErr := %s(profile, value)\nif historicalHookErr != nil { %sfmt.Errorf(\"adapt historical constructor for encoding: %%w\", historicalHookErr) }\n", strings.Join(outputs, ", "), hook, errorReturn)
	}
	if err := e.addHook(hook, signature); err != nil {
		return "", err
	}
	return b.String(), nil
}

func historicalTypeFlagExpressions(fields []layerCodecHistoricalFieldPlan, effective map[int]string) map[layerCodecHistoricalFlagSlot][]string {
	result := make(map[layerCodecHistoricalFlagSlot][]string)
	for _, field := range fields {
		if field.Field.Condition == nil {
			continue
		}
		present := field.Present
		if replacement := effective[field.Field.Ordinal]; replacement != "" {
			present = replacement
		}
		slot := layerCodecHistoricalFlagSlot{Word: field.Field.Condition.Word, Bit: field.Field.Condition.Bit}
		result[slot] = appendUniqueLayerCodecString(result[slot], present)
	}
	return result
}

func emitHistoricalTypeFlagConsistency(b *strings.Builder, profile *layerHistoricalConstructorPlan, fields []layerCodecHistoricalFieldPlan, effective map[int]string, errorReturn, operation string) {
	groups := historicalTypeFlagExpressions(fields, effective)
	slots := make([]layerCodecHistoricalFlagSlot, 0, len(groups))
	for slot := range groups {
		slots = append(slots, slot)
	}
	sort.Slice(slots, func(i, j int) bool {
		if slots[i].Word != slots[j].Word {
			return slots[i].Word < slots[j].Word
		}
		return slots[i].Bit < slots[j].Bit
	})
	for _, slot := range slots {
		group := strings.Join(groups[slot], " || ")
		for _, present := range groups[slot] {
			fmt.Fprintf(b, "if (%s) && !%s { %s&LayerCodecError{Operation: %q, Profile: profile, Semantic: %s, WireID: 0x%08x, Reason: %q} }\n", group, present, errorReturn, operation, layerSemanticConstant(profile.OldKey), profile.WireID, "historical adapter returned a partial shared flag group "+slot.Word+"."+strconv.Itoa(int(slot.Bit)))
		}
	}
}

func (e *layerCodecEmitter) emitHistoricalTypePreflight(profile *layerHistoricalConstructorPlan) (string, error) {
	fields, err := e.planHistoricalTypeFields(profile)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	hook, err := e.addHistoricalTypeEncodeHook(profile, fields, "return 0, ")
	if err != nil {
		return "", err
	}
	b.WriteString(hook)
	effective := make(map[int]string)
	for _, field := range fields {
		if field.PresenceOnly {
			continue
		}
		if field.Plan.Kind == layerValuePrimitive {
			fmt.Fprintf(&b, "_ = %s\n", field.Value)
			continue
		}
		statement, count, err := e.emitPreflightValue(field.Plan, field.Value, "state", "historical field "+field.Field.Name, "return 0, ")
		if err != nil {
			return "", err
		}
		if field.Field.Condition == nil {
			b.WriteString(statement)
			if count != "" {
				fmt.Fprintf(&b, "if %s == 0 { return 0, nil }\nif %s != 1 { return 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Semantic: %s, WireID: 0x%08x, Reason: \"required historical nested projection returned invalid cardinality\"} }\n", count, count, layerSemanticConstant(profile.OldKey), profile.WireID)
			}
			continue
		}
		effectivePresent := e.nextTemp("historicalPresent")
		fmt.Fprintf(&b, "%s := %s\nif %s {\n", effectivePresent, field.Present, effectivePresent)
		b.WriteString(indentLayerCodec(statement, "\t"))
		if count != "" {
			fmt.Fprintf(&b, "\tif %s < 0 || %s > 1 { return 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Semantic: %s, WireID: 0x%08x, Reason: \"optional historical nested projection returned invalid cardinality\"} }\n\tif %s == 0 { %s = false }\n", count, count, layerSemanticConstant(profile.OldKey), profile.WireID, count, effectivePresent)
		}
		b.WriteString("}\n")
		effective[field.Field.Ordinal] = effectivePresent
	}
	emitHistoricalTypeFlagConsistency(&b, profile, fields, effective, "return 0, ", "preflight")
	b.WriteString("return 1, nil\n")
	return b.String(), nil
}

func (e *layerCodecEmitter) emitHistoricalTypeEncode(profile *layerHistoricalConstructorPlan) (string, error) {
	fields, err := e.planHistoricalTypeFields(profile)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	hook, err := e.addHistoricalTypeEncodeHook(profile, fields, "return ")
	if err != nil {
		return "", err
	}
	b.WriteString(hook)
	effective := make(map[int]string)
	encoded := make(map[int]string)
	for _, field := range fields {
		if field.PresenceOnly || field.Field.Condition == nil || field.Plan.Kind == layerValuePrimitive {
			continue
		}
		present := e.nextTemp("historicalPresent")
		buffer := e.nextTemp("historicalEncoded")
		hookErr := e.nextTemp("historicalErr")
		statement, err := e.emitEncodeValue(field.Plan, field.Value, buffer, "state", "historical field "+field.Field.Name)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s := %s\n%s := &bin.Buffer{}\nif %s {\n\t%s := func() error {\n%s\t\treturn nil\n\t}()\n\tif %s != nil {\n\t\tif IsLayerProjectionDrop(%s) { %s = false; %s.Reset() } else { return fmt.Errorf(\"encode historical optional field %s: %%w\", %s) }\n\t}\n}\n", present, field.Present, buffer, present, hookErr, indentLayerCodec(statement, "\t\t"), hookErr, hookErr, present, buffer, field.Field.Name, hookErr)
		effective[field.Field.Ordinal] = present
		encoded[field.Field.Ordinal] = buffer
	}
	emitHistoricalTypeFlagConsistency(&b, profile, fields, effective, "return ", "encode")
	groups := historicalTypeFlagExpressions(fields, effective)
	for _, ordinal := range layerCodecFlagWords(profile.Definition) {
		fmt.Fprintf(&b, "var wireFlags%d bin.Fields\n", ordinal)
		word := profile.Definition.Fields[ordinal].Name
		bits := make([]int, 0)
		for slot := range groups {
			if slot.Word == word {
				bits = append(bits, int(slot.Bit))
			}
		}
		sort.Ints(bits)
		for _, bit := range bits {
			slot := layerCodecHistoricalFlagSlot{Word: word, Bit: uint8(bit)}
			fmt.Fprintf(&b, "if %s { wireFlags%d.Set(%d) }\n", strings.Join(groups[slot], " || "), ordinal, bit)
		}
	}
	for index := range profile.Definition.Fields {
		field := &profile.Definition.Fields[index]
		if field.Kind == semantic.FieldFlagsWord {
			fmt.Fprintf(&b, "if err := wireFlags%d.Encode(b); err != nil { return fmt.Errorf(\"encode historical flags %s: %%w\", err) }\n", field.Ordinal, field.Name)
			continue
		}
		var planned *layerCodecHistoricalFieldPlan
		for fieldIndex := range fields {
			if fields[fieldIndex].Field.Ordinal == field.Ordinal {
				planned = &fields[fieldIndex]
				break
			}
		}
		if planned == nil || planned.PresenceOnly {
			continue
		}
		statement := ""
		if buffer := encoded[field.Ordinal]; buffer != "" {
			statement = fmt.Sprintf("b.Buf = append(b.Buf, %s.Buf...)\n", buffer)
		} else {
			statement, err = e.emitEncodeValue(planned.Plan, planned.Value, "b", "state", "historical field "+field.Name)
			if err != nil {
				return "", err
			}
		}
		if field.Condition == nil {
			b.WriteString(statement)
			continue
		}
		flagsOrdinal, ok := layerCodecFlagOrdinal(profile.Definition, field.Condition.Word)
		if !ok {
			return "", fmt.Errorf("historical field %q references missing flags word %q", field.Name, field.Condition.Word)
		}
		fmt.Fprintf(&b, "if wireFlags%d.Has(%d) {\n%s}\n", flagsOrdinal, field.Condition.Bit, indentLayerCodec(statement, "\t"))
	}
	b.WriteString("return nil\n")
	return b.String(), nil
}

func (e *layerCodecEmitter) emitHistoricalTypeDecode(profile *layerHistoricalConstructorPlan) (string, error) {
	fields, err := e.planHistoricalTypeFields(profile)
	if err != nil {
		return "", err
	}
	fieldByOrdinal := make(map[int]*layerCodecHistoricalFieldPlan, len(fields))
	for index := range fields {
		fieldByOrdinal[fields[index].Field.Ordinal] = &fields[index]
	}
	var b strings.Builder
	for index := range profile.Definition.Fields {
		field := &profile.Definition.Fields[index]
		if field.Kind == semantic.FieldFlagsWord {
			fmt.Fprintf(&b, "var wireFlags%d bin.Fields\nif err := wireFlags%d.Decode(b); err != nil { return nil, fmt.Errorf(\"decode historical flags %s: %%w\", err) }\n", field.Ordinal, field.Ordinal, field.Name)
			continue
		}
		planned := fieldByOrdinal[field.Ordinal]
		if planned == nil {
			return "", fmt.Errorf("historical field %q has no decode plan", field.Name)
		}
		if field.Condition != nil {
			flagsOrdinal, ok := layerCodecFlagOrdinal(profile.Definition, field.Condition.Word)
			if !ok {
				return "", fmt.Errorf("historical field %q references missing flags word %q", field.Name, field.Condition.Word)
			}
			fmt.Fprintf(&b, "%s := wireFlags%d.Has(%d)\n", planned.Present, flagsOrdinal, field.Condition.Bit)
		}
		if planned.PresenceOnly {
			continue
		}
		fmt.Fprintf(&b, "var %s %s\n", planned.Value, planned.GoType)
		statement, err := e.emitDecodeValue(planned.Plan, planned.Value, "b", "state", "historical field "+field.Name)
		if err != nil {
			return "", err
		}
		if field.Condition != nil {
			fmt.Fprintf(&b, "if %s {\n%s}\n", planned.Present, indentLayerCodec(statement, "\t"))
		} else {
			b.WriteString(statement)
		}
	}
	arguments := []string{"profile"}
	types := []string{"LayerProfile"}
	for _, field := range fields {
		if field.PresenceOnly {
			arguments = append(arguments, field.Present)
			types = append(types, "bool")
			continue
		}
		if field.Field.Condition != nil {
			arguments = append(arguments, field.Present)
			types = append(types, "bool")
		}
		arguments = append(arguments, field.Value)
		types = append(types, field.GoType)
	}
	hook := profile.Resolution.Hook + "Decode"
	signature := fmt.Sprintf("func(%s) (*%s, error)", strings.Join(types, ", "), profile.Target.Structure.Name)
	if err := e.addHook(hook, signature); err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "adapted, err := %s(%s)\nif err != nil { return nil, fmt.Errorf(\"adapt historical constructor after decoding: %%w\", err) }\n", hook, strings.Join(arguments, ", "))
	fmt.Fprintf(&b, "if adapted == nil { return nil, &LayerCodecError{Operation: \"decode\", Profile: profile, Semantic: %s, WireID: 0x%08x, Reason: \"historical adapter returned nil canonical value\"} }\n", layerSemanticConstant(profile.OldKey), profile.WireID)
	b.WriteString("return adapted, nil\n")
	return b.String(), nil
}

func groupLayerCodecProfileBodies(profiles []layerCodecProfileBody) []layerCodecProfileBody {
	groups := make([]layerCodecProfileBody, 0, len(profiles))
	for _, profile := range profiles {
		match := -1
		for index := range groups {
			group := &groups[index]
			if group.Preflight == profile.Preflight && group.Encode == profile.Encode && group.Decode == profile.Decode &&
				group.EncodeReject == profile.EncodeReject && group.DecodeReject == profile.DecodeReject {
				match = index
				break
			}
		}
		if match >= 0 {
			groups[match].Layers = append(groups[match].Layers, profile.Layer)
			continue
		}
		profile.Layers = []int{profile.Layer}
		groups = append(groups, profile)
	}
	return groups
}

// layerCodecProfileOnlyAdmissionResolved deliberately does not make an
// historical-only CRC callable by the object codec. Reject is terminal;
// alias/adapter are consumed by the statically generated RPC admission route,
// after which the profile-only wire functions remain typed reject stubs.
func layerCodecProfileOnlyAdmissionResolved(conversion *LayerFamilyConversion) bool {
	if conversion == nil {
		return false
	}
	for _, obligation := range conversion.Obligations {
		if obligation.Kind != LayerObligationOldOnly || !layerCodecDirectionMatches(obligation.Direction, LayerDirectionProfileToCanonical) {
			continue
		}
		switch obligation.Resolution.Action {
		case LayerResolveReject:
			return true
		case LayerResolveAlias, LayerResolveAdapter:
			return obligation.Resolution.Target != ""
		default:
			return false
		}
	}
	return false
}

func layerCodecHasResolution(conversion *LayerFamilyConversion, direction LayerObligationDirection, action LayerResolutionAction) bool {
	if conversion == nil {
		return false
	}
	for _, obligation := range conversion.Obligations {
		if layerCodecDirectionMatches(obligation.Direction, direction) && obligation.Resolution.Action == action {
			return true
		}
	}
	return false
}

func layerCodecDirectionMatches(actual, wanted LayerObligationDirection) bool {
	return actual == wanted || actual == LayerDirectionBoth
}

func (e *layerCodecEmitter) buildProfileBody(wire *layerWirePlan, action *layerWireProfileAction) (layerCodecProfileBody, error) {
	// Temporary identifiers only need to be unique within one generated case.
	// Resetting them makes semantically identical profile bodies byte-identical,
	// allowing the source emitter to coalesce adjacent/future Layers without any
	// runtime indirection.
	e.temp = 0
	body := layerCodecProfileBody{Layer: action.Layer}
	conversion := action.Conversion
	canonicalPrimitiveFastPath := action.Layer == e.wire.CanonicalLayer &&
		action.Kind == layerWireDirect && layerCodecPrimitiveOnlyBody(wire.Canonical.Definition)
	preflight, err := e.emitPreflightBody(action.Layer, conversion, wire.Canonical)
	if err != nil {
		return body, err
	}
	body.Preflight = preflight
	if reason, ok := layerCodecRejected(conversion, LayerDirectionCanonicalToProfile); ok {
		body.EncodeReject = reason
	} else if canonicalPrimitiveFastPath {
		body.Encode = "return value.EncodeBare(b)\n"
	} else {
		encoded, err := e.emitEncodeBody(action.Layer, conversion, wire.Canonical)
		if err != nil {
			return body, err
		}
		body.Encode = encoded
	}

	if reason, ok := layerCodecRejected(conversion, LayerDirectionProfileToCanonical); ok {
		body.DecodeReject = reason
	} else if canonicalPrimitiveFastPath {
		body.Decode = "if err := value.DecodeBare(b); err != nil { return nil, fmt.Errorf(\"decode canonical bare body: %w\", err) }\nreturn value, nil\n"
	} else {
		decoded, err := e.emitDecodeBody(action.Layer, conversion, wire.Canonical)
		if err != nil {
			return body, err
		}
		body.Decode = decoded
	}
	return body, nil
}

// layerCodecPrimitiveOnlyBody is the conservative zero-overhead canonical
// fast path. It deliberately excludes every nested, generic, Object and vector
// reference so generated depth/vector limits and cross-layer projection can
// never be bypassed.
func layerCodecPrimitiveOnlyBody(definition *semantic.Definition) bool {
	if definition == nil {
		return false
	}
	for index := range definition.Fields {
		field := &definition.Fields[index]
		if field.Kind == semantic.FieldFlagsWord {
			continue
		}
		if field.Kind != semantic.FieldValue || field.Type.Kind != semantic.TypePrimitive || field.Type.QName == "Object" || field.Type.Arg != nil {
			return false
		}
		switch strings.ToLower(field.Type.QName) {
		case "string", "bytes":
			// The legacy generated encoder has no error channel for the TL
			// 24-bit payload limit. Keep these fields on the checked static path.
			return false
		}
	}
	return true
}

func layerCodecRejected(conversion *LayerFamilyConversion, direction LayerObligationDirection) (string, bool) {
	for _, obligation := range conversion.BodyObligations() {
		if obligation.Kind == LayerObligationFieldProjection {
			continue
		}
		if layerCodecDirectionMatches(obligation.Direction, direction) && obligation.Resolution.Action == LayerResolveReject {
			return fmt.Sprintf("policy %s rejects %s", obligation.Key, direction), true
		}
	}
	return "", false
}

func (e *layerCodecEmitter) addHook(name, signature string) error {
	if name == "" {
		return fmt.Errorf("empty layer codec hook")
	}
	if previous, exists := e.hookByName[name]; exists {
		if previous != signature {
			return fmt.Errorf("gen: E_LAYER_CODEC_HOOK_SIGNATURE: hook %s inferred as both %s and %s", name, previous, signature)
		}
		return nil
	}
	e.hookByName[name] = signature
	e.model.Hooks = append(e.model.Hooks, layerCodecHookContract{Name: name, Signature: signature})
	return nil
}

func (e *layerCodecEmitter) emitPreflightBody(layer int, conversion *LayerFamilyConversion, canonical *layerDefinitionBinding) (string, error) {
	restore := e.useGenericSlots(canonical.Definition)
	defer restore()
	var b strings.Builder
	b.WriteString(e.emitMalformedConditionalChecks(canonical, true))
	projection, err := e.emitFieldProjectionGate(conversion, canonical, true)
	if err != nil {
		return "", err
	}
	b.WriteString(projection)
	if canonical.Key.Category == semantic.CategoryFunction && canonical.Key.QName == "invokeWithLayer" {
		layerField := canonical.FieldByName["layer"]
		if layerField == nil {
			return "", fmt.Errorf("invokeWithLayer canonical binding has no layer field")
		}
		fmt.Fprintf(&b, "nestedProfile, ok := ResolveLayerProfile(value.%s)\nif !ok { return 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Semantic: %s, Reason: \"invokeWithLayer selected an unsupported exact profile\"} }\nprofile = nestedProfile\n", layerField.Go.Name, layerSemanticConstant(canonical.Key))
	}
	profile := conversion.Profile.Definition
	for profileOrdinal := range profile.Fields {
		field := &profile.Fields[profileOrdinal]
		if field.Kind != semantic.FieldValue || field.Condition != nil && field.Condition.PresenceOnly {
			continue
		}
		mapping := conversion.Fields[profileOrdinal]
		plan, err := e.values.Compile(layer, &field.Type)
		if err != nil {
			return "", err
		}
		obligation, err := layerCodecFieldAdapter(conversion, LayerDirectionCanonicalToProfile, field.Name, mapping.CanonicalName)
		if err != nil {
			return "", err
		}
		var canonicalField *layerFieldBinding
		expression := ""
		presence := "true"
		if mapping.CanonicalOrdinal >= 0 {
			canonicalField = &canonical.Fields[mapping.CanonicalOrdinal]
			expression = "value." + canonicalField.Go.Name
			presence, err = layerCodecPresenceExpression(canonicalField, expression)
			if err != nil {
				return "", err
			}
		} else if obligation != nil {
			// The typed adapter supplies the target value; no fake zero value is
			// needed (and concrete/interface targets may not have a legal one).
			expression = ""
			if field.Condition != nil {
				presence = "false"
			}
		} else if field.Condition != nil {
			expression, err = layerCodecZeroExpression(plan)
			if err != nil {
				return "", fmt.Errorf("optional profile-only preflight field %q: %w", field.Name, err)
			}
			presence = "false"
		} else {
			if !layerCodecDefaultedField(conversion, field.Name, LayerDirectionCanonicalToProfile) {
				return "", fmt.Errorf("required profile preflight field %q has no canonical mapping or default policy", field.Name)
			}
			expression, err = layerCodecZeroExpression(plan)
			if err != nil {
				return "", fmt.Errorf("default profile preflight field %q: %w", field.Name, err)
			}
		}
		if obligation != nil {
			if canonicalField == nil && obligation.Kind == LayerObligationDiscard && field.Condition != nil {
				canonicalField = layerCodecFieldAtFlagSlot(canonical, field.Condition.Word, field.Condition.Bit)
				if canonicalField == nil {
					return "", fmt.Errorf("discard preflight adapter %s has no canonical field at shared flags slot %s.%d", obligation.Key, field.Condition.Word, field.Condition.Bit)
				}
				expression = "value." + canonicalField.Go.Name
				presence, err = layerCodecPresenceExpression(canonicalField, expression)
				if err != nil {
					return "", err
				}
			}
			targetType, err := layerCodecGoType(plan)
			if err != nil {
				return "", err
			}
			hook := obligation.Resolution.Hook + "Encode"
			local := e.nextTemp("adapted")
			args := "profile, value"
			signatureArgs := fmt.Sprintf("LayerProfile, *%s", canonical.Structure.Name)
			if canonicalField == nil {
			} else if canonicalField.Semantic.Condition != nil {
				args += ", " + presence + ", " + expression
				signatureArgs += ", bool, " + layerCodecFieldGoType(canonicalField.Go)
			} else {
				args += ", " + expression
				signatureArgs += ", " + layerCodecFieldGoType(canonicalField.Go)
			}
			if field.Condition != nil {
				adaptedPresent := e.nextTemp("present")
				fmt.Fprintf(&b, "%s, %s, err := %s(%s)\nif err != nil { return 0, fmt.Errorf(\"preflight adapter for field %s: %%w\", err) }\n", local, adaptedPresent, hook, args, field.Name)
				presence = adaptedPresent
				if err := e.addHook(hook, fmt.Sprintf("func(%s) (%s, bool, error)", signatureArgs, targetType)); err != nil {
					return "", err
				}
			} else {
				fmt.Fprintf(&b, "%s, err := %s(%s)\nif err != nil { return 0, fmt.Errorf(\"preflight adapter for field %s: %%w\", err) }\n", local, hook, args, field.Name)
				if err := e.addHook(hook, fmt.Sprintf("func(%s) (%s, error)", signatureArgs, targetType)); err != nil {
					return "", err
				}
			}
			expression = local
		}
		if plan.Kind == layerValuePrimitive {
			if obligation != nil {
				fmt.Fprintf(&b, "_ = %s // adapter output validated during preflight\n", expression)
				if field.Condition != nil {
					fmt.Fprintf(&b, "_ = %s // adapter presence validated during preflight\n", presence)
				}
			}
			continue
		}
		statement, count, err := e.emitPreflightValue(plan, expression, "state", "field "+field.Name, "return 0, ")
		if err != nil {
			return "", err
		}
		if field.Condition != nil {
			fmt.Fprintf(&b, "if %s {\n%s", presence, indentLayerCodec(statement, "\t"))
			if count != "" {
				fmt.Fprintf(&b, "\tif %s < 0 || %s > 1 { return 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Semantic: %s, Reason: \"optional nested projection returned invalid cardinality\"} }\n", count, count, layerSemanticConstant(canonical.Key))
			}
			b.WriteString("}\n")
		} else {
			b.WriteString(statement)
			if count != "" {
				fmt.Fprintf(&b, "if %s == 0 { return 0, nil }\nif %s != 1 { return 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Semantic: %s, Reason: \"required nested projection returned invalid cardinality\"} }\n", count, count, layerSemanticConstant(canonical.Key))
			}
		}
	}
	b.WriteString("return 1, nil\n")
	return b.String(), nil
}

// emitMalformedConditionalChecks validates the canonical flags invariant before
// any projection policy can hide it. In particular, an explicitly present
// interface field must carry a value; dropping it for an older profile does not
// make a malformed canonical object valid.
func (e *layerCodecEmitter) emitMalformedConditionalChecks(canonical *layerDefinitionBinding, preflight bool) string {
	var b strings.Builder
	operation := "encode"
	errorReturn := "return "
	if preflight {
		operation = "preflight"
		errorReturn = "return 0, "
	}
	for index := range canonical.Fields {
		field := &canonical.Fields[index]
		if field.Semantic == nil || field.Semantic.Condition == nil || field.Go == nil || field.Go.Interface == "" {
			continue
		}
		fmt.Fprintf(
			&b,
			"if value.%s.Has(%d) && value.%s == nil { %s&LayerCodecError{Operation: %q, Profile: profile, Semantic: %s, Reason: %q} }\n",
			field.Go.ConditionalField,
			field.Semantic.Condition.Bit,
			field.Go.Name,
			errorReturn,
			operation,
			layerSemanticConstant(canonical.Key),
			"malformed canonical value: explicit flag has nil interface field "+field.Semantic.Name,
		)
	}
	return b.String()
}

func (e *layerCodecEmitter) emitFieldProjectionGate(conversion *LayerFamilyConversion, canonical *layerDefinitionBinding, preflight bool) (string, error) {
	var b strings.Builder
	operation := "encode"
	errorReturn := "return "
	if preflight {
		operation = "preflight"
		errorReturn = "return 0, "
	}
	for _, obligation := range conversion.FieldProjectionObligations() {
		field := canonical.FieldByName[obligation.Field]
		if field == nil {
			return "", fmt.Errorf("field projection %s references missing canonical field %q", obligation.Key, obligation.Field)
		}
		expression := "value." + field.Go.Name
		presence, err := layerCodecProjectionPresenceExpression(field, expression)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "if %s {\n", presence)
		switch obligation.Resolution.Action {
		case LayerResolveDrop:
			fmt.Fprintf(&b, "\t// %s explicitly permits dropping this field in the exact profile.\n", obligation.Key)
		case LayerResolveReject, LayerResolveRejectIfPresent:
			fmt.Fprintf(&b, "\t%s&LayerCodecError{Operation: %q, Profile: profile, Semantic: %s, Reason: %q}\n", errorReturn, operation, layerSemanticConstant(canonical.Key), "field projection rejected by policy "+string(obligation.Key))
		case LayerResolveAdapter:
			hook := obligation.Resolution.Hook + "Encode"
			signature := fmt.Sprintf("func(LayerProfile, *%s, %s) (*%s, error)", canonical.Structure.Name, layerCodecFieldGoType(field.Go), canonical.Structure.Name)
			if err := e.addHook(hook, signature); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "\tadapted, err := %s(profile, value, %s)\n\tif err != nil { %sfmt.Errorf(\"adapt projected field %s: %%w\", err) }\n\tif adapted == nil { %s&LayerCodecError{Operation: %q, Profile: profile, Semantic: %s, Reason: \"field adapter returned nil canonical value\"} }\n\tvalue = adapted\n", hook, expression, errorReturn, obligation.Field, errorReturn, operation, layerSemanticConstant(canonical.Key))
		case LayerResolveProject:
			hook := obligation.Resolution.Hook + "Project"
			signature := fmt.Sprintf("func(LayerProfile, *%s, %s) (*%s, bool, error)", canonical.Structure.Name, layerCodecFieldGoType(field.Go), canonical.Structure.Name)
			if err := e.addHook(hook, signature); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "\tprojected, keep, err := %s(profile, value, %s)\n\tif err != nil { %sfmt.Errorf(\"project field %s: %%w\", err) }\n", hook, expression, errorReturn, obligation.Field)
			if preflight {
				b.WriteString("\tif !keep { return 0, nil }\n")
			} else {
				fmt.Fprintf(&b, "\tif !keep { return &LayerProjectionError{Profile: profile, Semantic: %s, Dropped: true, Reason: \"field projection removed canonical value\"} }\n", layerSemanticConstant(canonical.Key))
			}
			fmt.Fprintf(&b, "\tif projected == nil { %s&LayerCodecError{Operation: %q, Profile: profile, Semantic: %s, Reason: \"field projector returned nil canonical value\"} }\n\tvalue = projected\n", errorReturn, operation, layerSemanticConstant(canonical.Key))
		default:
			return "", fmt.Errorf("field projection %s has unsupported action %q", obligation.Key, obligation.Resolution.Action)
		}
		b.WriteString("}\n")
	}
	return b.String(), nil
}

func layerCodecProjectionPresenceExpression(field *layerFieldBinding, expression string) (string, error) {
	if field == nil || field.Go == nil || field.Semantic == nil {
		return "", fmt.Errorf("nil canonical projection field binding")
	}
	if field.Semantic.Condition != nil {
		return layerCodecPresenceExpression(field, expression)
	}
	// A non-conditional TL field is present even when its Go value is the zero
	// value. Source-only required fields therefore always trigger their explicit
	// projection policy.
	return "true", nil
}

func (e *layerCodecEmitter) emitPreflightValue(plan *layerValuePlan, expression, state, context, errorReturn string) (string, string, error) {
	if plan == nil {
		return "", "", fmt.Errorf("preflight %s: nil value plan", context)
	}
	var b strings.Builder
	switch plan.Kind {
	case layerValuePrimitive:
		return "", "1", nil
	case layerValueExactBare, layerValueBoxedConcrete:
		if len(plan.Constructors) != 1 || plan.Constructors[0].Canonical == nil {
			return "", "", fmt.Errorf("preflight %s: concrete value has no canonical constructor", context)
		}
		wireID := plan.Constructors[0].Conversion.Profile.Definition.WireID
		count := e.nextTemp("count")
		fmt.Fprintf(&b, "%s, err := layerPreflightWire%08xBare(profile, &(%s), %s)\nif err != nil { %sfmt.Errorf(\"preflight %s: %%w\", err) }\n", count, wireID, expression, state, errorReturn, context)
		return b.String(), count, nil
	case layerValueBoxedAbstract:
		if plan.CanonicalClass == nil {
			return "", "", fmt.Errorf("preflight %s: profile-only abstract class", context)
		}
		count := e.nextTemp("count")
		fmt.Fprintf(&b, "%s, err := layerPreflightClass%s(profile, %s, %s)\nif err != nil { %sfmt.Errorf(\"preflight %s: %%w\", err) }\n", count, layerCodecClassSuffix(plan.CanonicalClass), expression, state, errorReturn, context)
		return b.String(), count, nil
	case layerValueDynamicGeneric:
		slot, ok := e.genericSlots[plan.GenericParam]
		if !ok {
			return "", "", fmt.Errorf("preflight %s: generic parameter %q has no enclosing static slot", context, plan.GenericParam)
		}
		count := e.nextTemp("count")
		fmt.Fprintf(&b, "if state == nil || %d >= len(state.generic) || !state.genericBound[%d] { %s&LayerCodecError{Operation: \"preflight\", Profile: profile, Reason: %q} }\n%s, err := state.generic[%d].preflight(profile, %s, state)\nif err != nil { %sfmt.Errorf(\"preflight %s: %%w\", err) }\n", slot, slot, errorReturn, "unbound generic slot "+plan.GenericParam, count, slot, expression, errorReturn, context)
		return b.String(), count, nil
	case layerValueDynamicObject:
		count := e.nextTemp("count")
		fmt.Fprintf(&b, "%s, err := layerPreflightDynamicObject(profile, %s, %s)\nif err != nil { %sfmt.Errorf(\"preflight %s: %%w\", err) }\n", count, expression, state, errorReturn, context)
		return b.String(), count, nil
	case layerValueVector:
		lenExpr := "len(" + expression + ")"
		fmt.Fprintf(&b, "if %s > layerCodecMaxVectorElements { %s&LayerCodecError{Operation: \"preflight\", Profile: profile, Reason: \"vector length exceeds generated limit\"} }\n", lenExpr, errorReturn)
		item := e.nextTemp("preflightItem")
		fmt.Fprintf(&b, "for _, %s := range %s {\n", item, expression)
		fmt.Fprintf(&b, "\t_ = %s\n", item)
		child, childCount, err := e.emitPreflightValue(plan.Element, item, state, context+" element", errorReturn)
		if err != nil {
			return "", "", err
		}
		b.WriteString(indentLayerCodec(child, "\t"))
		if childCount != "" {
			fmt.Fprintf(&b, "\tif %s < 0 || %s > 1 { %s&LayerCodecError{Operation: \"preflight\", Profile: profile, Reason: \"vector element projection returned invalid cardinality\"} }\n", childCount, childCount, errorReturn)
		}
		b.WriteString("}\n")
		// A vector field itself remains one TL value even if every projected
		// element is filtered out; only its encoded element count changes.
		return b.String(), "1", nil
	default:
		return "", "", fmt.Errorf("preflight %s: unsupported value kind %s", context, plan.Kind)
	}
}

func (e *layerCodecEmitter) emitEncodeBody(layer int, conversion *LayerFamilyConversion, canonical *layerDefinitionBinding) (string, error) {
	restore := e.useGenericSlots(canonical.Definition)
	defer restore()
	profile := conversion.Profile.Definition
	var b strings.Builder
	b.WriteString(e.emitMalformedConditionalChecks(canonical, false))
	projection, err := e.emitFieldProjectionGate(conversion, canonical, false)
	if err != nil {
		return "", err
	}
	b.WriteString(projection)
	if canonical.Key.Category == semantic.CategoryFunction && canonical.Key.QName == "invokeWithLayer" {
		layerField := canonical.FieldByName["layer"]
		if layerField == nil {
			return "", fmt.Errorf("invokeWithLayer canonical binding has no layer field")
		}
		fmt.Fprintf(&b, "nestedProfile, ok := ResolveLayerProfile(value.%s)\nif !ok { return &LayerCodecError{Operation: \"encode\", Profile: profile, Semantic: %s, Reason: \"invokeWithLayer selected an unsupported exact profile\"} }\nprofile = nestedProfile\n", layerField.Go.Name, layerSemanticConstant(canonical.Key))
	}
	type encodeField struct {
		plan    *layerValuePlan
		expr    string
		present string
		prelude string
		prepare string
		encoded string
	}
	planned := make(map[int]encodeField)
	for profileOrdinal := range profile.Fields {
		field := &profile.Fields[profileOrdinal]
		if field.Kind != semantic.FieldValue || field.Condition != nil && field.Condition.PresenceOnly {
			continue
		}
		plan, err := e.values.Compile(layer, &field.Type)
		if err != nil {
			return "", err
		}
		mapping := conversion.Fields[profileOrdinal]
		obligation, err := layerCodecFieldAdapter(conversion, LayerDirectionCanonicalToProfile, field.Name, mapping.CanonicalName)
		if err != nil {
			return "", err
		}
		entry := encodeField{plan: plan, present: "true"}
		var canonicalField *layerFieldBinding
		if mapping.CanonicalOrdinal >= 0 {
			canonicalField = &canonical.Fields[mapping.CanonicalOrdinal]
			entry.expr = "value." + canonicalField.Go.Name
			entry.present, err = layerCodecPresenceExpression(canonicalField, entry.expr)
			if err != nil {
				return "", err
			}
		} else if obligation != nil {
			if field.Condition != nil {
				entry.present = "false"
			}
		} else if field.Condition != nil {
			entry.expr, err = layerCodecZeroExpression(plan)
			if err != nil {
				return "", fmt.Errorf("optional profile-only field %q: %w", field.Name, err)
			}
			entry.present = "false"
		} else {
			if !layerCodecDefaultedField(conversion, field.Name, LayerDirectionCanonicalToProfile) {
				return "", fmt.Errorf("required profile field %q has no canonical mapping or default policy", field.Name)
			}
			entry.expr, err = layerCodecZeroExpression(plan)
			if err != nil {
				return "", fmt.Errorf("default profile field %q: %w", field.Name, err)
			}
		}

		if obligation != nil {
			if canonicalField == nil && obligation.Kind == LayerObligationDiscard && field.Condition != nil {
				canonicalField = layerCodecFieldAtFlagSlot(canonical, field.Condition.Word, field.Condition.Bit)
				if canonicalField == nil {
					return "", fmt.Errorf("discard adapter %s has no canonical field at shared flags slot %s.%d", obligation.Key, field.Condition.Word, field.Condition.Bit)
				}
				entry.expr = "value." + canonicalField.Go.Name
				entry.present, err = layerCodecPresenceExpression(canonicalField, entry.expr)
				if err != nil {
					return "", err
				}
			}
			if obligation.Kind == LayerObligationAtomicFlagGroup {
				return "", fmt.Errorf("atomic encode adapter %s must be represented as a generated group hook", obligation.Key)
			}
			targetType, err := layerCodecGoType(plan)
			if err != nil {
				return "", err
			}
			hook := obligation.Resolution.Hook + "Encode"
			local := e.nextTemp("adapted")
			args := "profile, value"
			signatureArgs := fmt.Sprintf("LayerProfile, *%s", canonical.Structure.Name)
			if canonicalField == nil {
			} else {
				sourceType := layerCodecFieldGoType(canonicalField.Go)
				if canonicalField.Semantic.Condition != nil {
					args += ", " + entry.present + ", " + entry.expr
					signatureArgs += ", bool, " + sourceType
				} else {
					args += ", " + entry.expr
					signatureArgs += ", " + sourceType
				}
			}
			if field.Condition != nil {
				present := e.nextTemp("present")
				entry.prelude = fmt.Sprintf("%s, %s, err := %s(%s)\nif err != nil { return fmt.Errorf(\"adapt field %s: %%w\", err) }\n", local, present, hook, args, field.Name)
				entry.present = present
				if err := e.addHook(hook, fmt.Sprintf("func(%s) (%s, bool, error)", signatureArgs, targetType)); err != nil {
					return "", err
				}
			} else {
				entry.prelude = fmt.Sprintf("%s, err := %s(%s)\nif err != nil { return fmt.Errorf(\"adapt field %s: %%w\", err) }\n", local, hook, args, field.Name)
				if err := e.addHook(hook, fmt.Sprintf("func(%s) (%s, error)", signatureArgs, targetType)); err != nil {
					return "", err
				}
			}
			entry.expr = local
		}
		planned[profileOrdinal] = entry
	}
	for _, obligation := range conversion.BodyObligations() {
		if obligation.Kind != LayerObligationAtomicFlagGroup ||
			!layerCodecDirectionMatches(obligation.Direction, LayerDirectionCanonicalToProfile) ||
			obligation.Resolution.Action != LayerResolveAdapter {
			continue
		}
		hook := obligation.Resolution.Hook + "Encode"
		present := e.nextTemp("atomicPresent")
		outputs := []string{present}
		resultTypes := []string{"bool"}
		var ordinals []int
		for profileOrdinal := range profile.Fields {
			field := &profile.Fields[profileOrdinal]
			if field.Kind != semantic.FieldValue || !containsLayerCodecString(obligation.Fields, field.Name) {
				continue
			}
			if field.Condition != nil && field.Condition.PresenceOnly {
				continue
			}
			entry, ok := planned[profileOrdinal]
			if !ok {
				return "", fmt.Errorf("atomic encode adapter %s references unplanned field %q", obligation.Key, field.Name)
			}
			local := e.nextTemp("atomic")
			outputs = append(outputs, local)
			goType, err := layerCodecGoType(entry.plan)
			if err != nil {
				return "", err
			}
			resultTypes = append(resultTypes, goType)
			ordinals = append(ordinals, profileOrdinal)
		}
		if len(ordinals) == 0 {
			return "", fmt.Errorf("atomic encode adapter %s has no encoded target fields", obligation.Key)
		}
		hookErr := e.nextTemp("err")
		outputs = append(outputs, hookErr)
		if err := e.addHook(hook, fmt.Sprintf("func(LayerProfile, *%s) (%s, error)", canonical.Structure.Name, strings.Join(resultTypes, ", "))); err != nil {
			return "", err
		}
		prelude := fmt.Sprintf("%s := %s(profile, value)\nif %s != nil { return fmt.Errorf(\"adapt atomic flags: %%w\", %s) }\n", strings.Join(outputs, ", "), hook, hookErr, hookErr)
		for index, profileOrdinal := range ordinals {
			entry := planned[profileOrdinal]
			entry.expr = outputs[index+1]
			entry.present = present
			if index == 0 {
				entry.prelude = prelude + entry.prelude
			}
			planned[profileOrdinal] = entry
		}
	}
	type flagSlot struct {
		word string
		bit  uint8
	}
	collectFlagExpressions := func() (map[flagSlot][]string, error) {
		bits := make(map[flagSlot][]string)
		for mappingIndex := range conversion.Fields {
			field := &profile.Fields[mappingIndex]
			if field.Kind != semantic.FieldValue || field.Condition == nil {
				continue
			}
			slot := flagSlot{word: field.Condition.Word, bit: field.Condition.Bit}
			if field.Condition.PresenceOnly {
				mapping := conversion.Fields[mappingIndex]
				if mapping.CanonicalOrdinal < 0 {
					continue
				}
				canonicalField := &canonical.Fields[mapping.CanonicalOrdinal]
				presence, err := layerCodecPresenceExpression(canonicalField, "value."+canonicalField.Go.Name)
				if err != nil {
					return nil, err
				}
				bits[slot] = appendUniqueLayerCodecString(bits[slot], presence)
				continue
			}
			entry, ok := planned[mappingIndex]
			if !ok {
				return nil, fmt.Errorf("conditional profile field %q has no encode plan", field.Name)
			}
			bits[slot] = appendUniqueLayerCodecString(bits[slot], entry.present)
		}
		return bits, nil
	}
	rawFlagExpressions, err := collectFlagExpressions()
	if err != nil {
		return "", err
	}
	// Encode optional nested fields exactly once into a field-local buffer before
	// rebuilding flags. Every field sharing a flag bit is prepared from the same
	// group presence, matching the canonical encoder's atomic flag semantics.
	// A dropped optional subtree clears its local presence; if another member
	// keeps the shared bit set, the consistency gate below rejects the malformed
	// partial group instead of emitting a truncated wire value.
	// Required fields stream directly: an enclosing transactional entry (or a
	// vector element checkpoint) rolls them back if a descendant projects out.
	// This keeps the hot path single-pass without paying a buffer+copy for every
	// required object field.
	for profileOrdinal := range profile.Fields {
		field := &profile.Fields[profileOrdinal]
		entry, ok := planned[profileOrdinal]
		if !ok || field.Condition == nil || entry.plan.Kind == layerValuePrimitive {
			continue
		}
		encoded := e.nextTemp("encoded")
		hookErr := e.nextTemp("err")
		statement, err := e.emitEncodeValue(entry.plan, entry.expr, encoded, "state", "prepared field "+field.Name)
		if err != nil {
			return "", err
		}
		entry.prepare += fmt.Sprintf("%s := &bin.Buffer{}\n", encoded)
		if field.Condition != nil {
			expressions := rawFlagExpressions[flagSlot{word: field.Condition.Word, bit: field.Condition.Bit}]
			if len(expressions) == 0 {
				return "", fmt.Errorf("conditional profile field %q has no flag group presence", field.Name)
			}
			present := e.nextTemp("present")
			entry.prepare += fmt.Sprintf("%s := %s\nif %s {\n\t%s := func() error {\n%s\t\treturn nil\n\t}()\n\tif %s != nil {\n\t\tif IsLayerProjectionDrop(%s) { %s = false; %s.Reset() } else { return fmt.Errorf(\"encode optional field %s: %%w\", %s) }\n\t}\n}\n", present, strings.Join(expressions, " || "), present, hookErr, indentLayerCodec(statement, "\t\t"), hookErr, hookErr, present, encoded, field.Name, hookErr)
			entry.present = present
		} else {
			entry.prepare += fmt.Sprintf("%s := func() error {\n%s\treturn nil\n}()\nif %s != nil { return fmt.Errorf(\"encode required field %s: %%w\", %s) }\n", hookErr, indentLayerCodec(statement, "\t"), hookErr, field.Name, hookErr)
		}
		entry.encoded = encoded
		planned[profileOrdinal] = entry
	}
	for ordinal := range profile.Fields {
		if entry, ok := planned[ordinal]; ok {
			b.WriteString(entry.prelude)
		}
	}
	for ordinal := range profile.Fields {
		if entry, ok := planned[ordinal]; ok {
			b.WriteString(entry.prepare)
		}
	}
	finalFlagExpressions, err := collectFlagExpressions()
	if err != nil {
		return "", err
	}
	flags := layerCodecFlagWords(profile)
	for _, ordinal := range flags {
		fmt.Fprintf(&b, "var wireFlags%d bin.Fields\n", ordinal)
		word := profile.Fields[ordinal].Name
		bits := make(map[uint8][]string)
		for slot, expressions := range finalFlagExpressions {
			if slot.word == word {
				bits[slot.bit] = expressions
			}
		}
		bitNumbers := make([]int, 0, len(bits))
		for bit := range bits {
			bitNumbers = append(bitNumbers, int(bit))
		}
		sort.Ints(bitNumbers)
		for _, bit := range bitNumbers {
			expressions := bits[uint8(bit)]
			groupPresence := strings.Join(expressions, " || ")
			for profileOrdinal := range profile.Fields {
				entry, ok := planned[profileOrdinal]
				if !ok {
					continue
				}
				field := &profile.Fields[profileOrdinal]
				if entry.encoded == "" || field.Condition == nil || field.Condition.Word != word || field.Condition.Bit != uint8(bit) ||
					(len(expressions) == 1 && expressions[0] == entry.present) {
					continue
				}
				fmt.Fprintf(&b, "if (%s) && !%s { return &LayerCodecError{Operation: \"encode\", Profile: profile, Semantic: %s, Reason: %q} }\n", groupPresence, entry.present, layerSemanticConstant(canonical.Key), "shared flag group "+word+"."+strconv.Itoa(bit)+" projected only partially")
			}
			fmt.Fprintf(&b, "if %s { wireFlags%d.Set(%d) }\n", groupPresence, ordinal, bit)
		}
	}

	for profileOrdinal := range profile.Fields {
		field := &profile.Fields[profileOrdinal]
		if field.Kind == semantic.FieldFlagsWord {
			fmt.Fprintf(&b, "if err := wireFlags%d.Encode(b); err != nil { return fmt.Errorf(\"encode flags %s: %%w\", err) }\n", profileOrdinal, field.Name)
			continue
		}
		if field.Condition != nil && field.Condition.PresenceOnly {
			continue
		}
		entry := planned[profileOrdinal]
		statement := ""
		if entry.encoded != "" {
			statement = fmt.Sprintf("b.Buf = append(b.Buf, %s.Buf...)\n", entry.encoded)
		} else {
			statement, err = e.emitEncodeValue(entry.plan, entry.expr, "b", "state", "field "+field.Name)
			if err != nil {
				return "", err
			}
		}
		if field.Condition != nil {
			flagsOrdinal, ok := layerCodecFlagOrdinal(profile, field.Condition.Word)
			if !ok {
				return "", fmt.Errorf("field %q references missing flags %q", field.Name, field.Condition.Word)
			}
			fmt.Fprintf(&b, "if wireFlags%d.Has(%d) {\n%s}\n", flagsOrdinal, field.Condition.Bit, indentLayerCodec(statement, "\t"))
		} else {
			b.WriteString(statement)
		}
	}
	b.WriteString("return nil\n")
	return b.String(), nil
}

func (e *layerCodecEmitter) emitDecodeBody(layer int, conversion *LayerFamilyConversion, canonical *layerDefinitionBinding) (string, error) {
	restore := e.useGenericSlots(canonical.Definition)
	defer restore()
	profile := conversion.Profile.Definition
	var b strings.Builder
	type decodedField struct {
		plan    *layerValuePlan
		local   string
		present string
		goType  string
	}
	decoded := make(map[int]decodedField)
	for profileOrdinal := range profile.Fields {
		field := &profile.Fields[profileOrdinal]
		if field.Kind == semantic.FieldFlagsWord {
			fmt.Fprintf(&b, "var wireFlags%d bin.Fields\nif err := wireFlags%d.Decode(b); err != nil { return nil, fmt.Errorf(\"decode flags %s: %%w\", err) }\n", profileOrdinal, profileOrdinal, field.Name)
			continue
		}
		local := e.nextTemp("decoded")
		present := "true"
		var flagsOrdinal int
		if field.Condition != nil {
			var ok bool
			flagsOrdinal, ok = layerCodecFlagOrdinal(profile, field.Condition.Word)
			if !ok {
				return "", fmt.Errorf("field %q references missing flags %q", field.Name, field.Condition.Word)
			}
			present = fmt.Sprintf("wireFlags%d.Has(%d)", flagsOrdinal, field.Condition.Bit)
		}
		var inner strings.Builder
		if field.Condition != nil && field.Condition.PresenceOnly {
			fmt.Fprintf(&b, "%s := %s\n", local, present)
			decoded[profileOrdinal] = decodedField{local: local, present: present, goType: "bool"}
			continue
		} else {
			plan, err := e.values.Compile(layer, &field.Type)
			if err != nil {
				return "", err
			}
			goType, err := layerCodecGoType(plan)
			if err != nil {
				return "", fmt.Errorf("decode field %q: %w", field.Name, err)
			}
			fmt.Fprintf(&b, "var %s %s\n", local, goType)
			statement, err := e.emitDecodeValue(plan, local, "b", "state", "field "+field.Name)
			if err != nil {
				return "", err
			}
			inner.WriteString(statement)
			decoded[profileOrdinal] = decodedField{plan: plan, local: local, present: present, goType: goType}
		}
		if field.Condition != nil {
			fmt.Fprintf(&b, "if %s {\n", present)
			b.WriteString(indentLayerCodec(inner.String(), "\t"))
			b.WriteString("}\n")
		} else {
			b.WriteString(inner.String())
		}
		if canonical.Key.Category == semantic.CategoryFunction && canonical.Key.QName == "invokeWithLayer" && field.Name == "layer" {
			fmt.Fprintf(&b, "nestedProfile, ok := ResolveLayerProfile(%s)\nif !ok { return nil, &LayerCodecError{Operation: \"decode\", Profile: profile, Semantic: %s, Reason: \"invokeWithLayer selected an unsupported exact profile\"} }\nprofile = nestedProfile\n", local, layerSemanticConstant(canonical.Key))
		}
	}

	atomicFields := make(map[string]struct{})
	for _, obligation := range conversion.BodyObligations() {
		if obligation.Kind != LayerObligationAtomicFlagGroup || !layerCodecDirectionMatches(obligation.Direction, LayerDirectionProfileToCanonical) || obligation.Resolution.Action != LayerResolveAdapter {
			continue
		}
		hook := obligation.Resolution.Hook + "Decode"
		args := []string{"profile", "value"}
		types := []string{"LayerProfile", "*" + canonical.Structure.Name}
		for profileOrdinal, mapping := range conversion.Fields {
			if mapping.CanonicalOrdinal < 0 {
				continue
			}
			name := canonical.Fields[mapping.CanonicalOrdinal].Semantic.Name
			if !containsLayerCodecString(obligation.Fields, name) {
				continue
			}
			entry := decoded[profileOrdinal]
			args = append(args, entry.present, entry.local)
			types = append(types, "bool", entry.goType)
			atomicFields[name] = struct{}{}
		}
		if err := e.addHook(hook, fmt.Sprintf("func(%s) error", strings.Join(types, ", "))); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "if err := %s(%s); err != nil { return nil, fmt.Errorf(\"adapt atomic flags: %%w\", err) }\n", hook, strings.Join(args, ", "))
	}

	for profileOrdinal, mapping := range conversion.Fields {
		field := &profile.Fields[profileOrdinal]
		if field.Kind != semantic.FieldValue {
			continue
		}
		entry := decoded[profileOrdinal]
		if mapping.CanonicalOrdinal < 0 {
			obligation, err := layerCodecFieldAdapter(conversion, LayerDirectionProfileToCanonical, field.Name, "")
			if err != nil {
				return "", err
			}
			if obligation == nil {
				if !layerCodecDroppedField(conversion, field.Name) {
					return "", fmt.Errorf("gen: E_LAYER_CODEC_UNMAPPED_PROFILE_FIELD: field %q needs explicit profile-to-canonical drop/adapter/reject", field.Name)
				}
				fmt.Fprintf(&b, "_ = %s // explicitly consumed and dropped historical field %s\n", entry.local, field.Name)
				continue
			}
			hook := obligation.Resolution.Hook + "Decode"
			signature := fmt.Sprintf("func(LayerProfile, *%s, %s) error", canonical.Structure.Name, entry.goType)
			if err := e.addHook(hook, signature); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "if %s { if err := %s(profile, value, %s); err != nil { return nil, fmt.Errorf(\"adapt discarded field %s: %%w\", err) } }\n", entry.present, hook, entry.local, field.Name)
			continue
		}
		canonicalField := &canonical.Fields[mapping.CanonicalOrdinal]
		if _, grouped := atomicFields[canonicalField.Semantic.Name]; grouped {
			continue
		}
		obligation, err := layerCodecFieldAdapter(conversion, LayerDirectionProfileToCanonical, field.Name, canonicalField.Semantic.Name)
		if err != nil {
			return "", err
		}
		assignment := entry.local
		present := entry.present
		if obligation != nil {
			hook := obligation.Resolution.Hook + "Decode"
			local := e.nextTemp("adapted")
			targetType := layerCodecFieldGoType(canonicalField.Go)
			if canonicalField.Semantic.Condition != nil {
				adaptedPresent := e.nextTemp("present")
				if err := e.addHook(hook, fmt.Sprintf("func(LayerProfile, *%s, bool, %s) (%s, bool, error)", canonical.Structure.Name, entry.goType, targetType)); err != nil {
					return "", err
				}
				fmt.Fprintf(&b, "%s, %s, err := %s(profile, value, %s, %s)\nif err != nil { return nil, fmt.Errorf(\"adapt field %s: %%w\", err) }\n", local, adaptedPresent, hook, entry.present, entry.local, field.Name)
				present = adaptedPresent
			} else {
				if err := e.addHook(hook, fmt.Sprintf("func(LayerProfile, *%s, bool, %s) (%s, error)", canonical.Structure.Name, entry.goType, targetType)); err != nil {
					return "", err
				}
				fmt.Fprintf(&b, "%s, err := %s(profile, value, %s, %s)\nif err != nil { return nil, fmt.Errorf(\"adapt field %s: %%w\", err) }\n", local, hook, entry.present, entry.local, field.Name)
			}
			assignment = local
		}
		fmt.Fprintf(&b, "if %s {\n", present)
		if canonicalField.Semantic.Condition != nil {
			flagBinding := canonical.FieldByName[canonicalField.Semantic.Condition.Word]
			if flagBinding == nil {
				return "", fmt.Errorf("canonical field %q references missing flags %q", canonicalField.Semantic.Name, canonicalField.Semantic.Condition.Word)
			}
			fmt.Fprintf(&b, "\tvalue.%s.Set(%d)\n", flagBinding.Go.Name, canonicalField.Semantic.Condition.Bit)
		}
		fmt.Fprintf(&b, "\tvalue.%s = %s\n}\n", canonicalField.Go.Name, assignment)
	}

	for _, obligation := range conversion.BodyObligations() {
		if obligation.Kind != LayerObligationRequired || !layerCodecDirectionMatches(obligation.Direction, LayerDirectionProfileToCanonical) || obligation.Field != "" {
			continue
		}
		if obligation.Resolution.Action == LayerResolveDefault {
			continue
		}
		if obligation.Resolution.Action != LayerResolveAdapter {
			continue
		}
		canonicalField := canonical.FieldByName[obligation.OtherField]
		if canonicalField == nil {
			return "", fmt.Errorf("required adapter %s targets missing canonical field %q", obligation.Key, obligation.OtherField)
		}
		hook := obligation.Resolution.Hook + "Decode"
		targetType := layerCodecFieldGoType(canonicalField.Go)
		if err := e.addHook(hook, fmt.Sprintf("func(LayerProfile, *%s) (%s, error)", canonical.Structure.Name, targetType)); err != nil {
			return "", err
		}
		local := e.nextTemp("required")
		fmt.Fprintf(&b, "%s, err := %s(profile, value)\nif err != nil { return nil, fmt.Errorf(\"adapt required field %s: %%w\", err) }\nvalue.%s = %s\n", local, hook, obligation.OtherField, canonicalField.Go.Name, local)
	}
	b.WriteString("return value, nil\n")
	return b.String(), nil
}

func (e *layerCodecEmitter) useGenericSlots(definition *semantic.Definition) func() {
	previous := e.genericSlots
	e.genericSlots = make(map[string]int, len(definition.GenericParams))
	for index, name := range definition.GenericParams {
		e.genericSlots[name] = index
	}
	return func() { e.genericSlots = previous }
}

func layerCodecFieldAdapter(conversion *LayerFamilyConversion, direction LayerObligationDirection, profileField, canonicalField string) (*LayerObligation, error) {
	var found *LayerObligation
	for index := range conversion.Obligations {
		obligation := &conversion.Obligations[index]
		if !layerCodecDirectionMatches(obligation.Direction, direction) ||
			(obligation.Resolution.Action != LayerResolveAdapter && obligation.Resolution.Action != LayerResolveAlias) {
			continue
		}
		if obligation.Kind == LayerObligationAtomicFlagGroup {
			continue
		}
		matches := false
		if direction == LayerDirectionCanonicalToProfile {
			matches = obligation.OtherField == profileField && (canonicalField == "" || obligation.Field == canonicalField || obligation.Field == "")
			if obligation.Kind == LayerObligationDiscard && obligation.Direction == LayerDirectionBoth {
				matches = obligation.Field == profileField
			}
		} else {
			matches = obligation.Field == profileField && (canonicalField == "" || obligation.OtherField == canonicalField || obligation.OtherField == "")
			if obligation.Kind == LayerObligationAlias || obligation.Kind == LayerObligationFieldReplacement {
				matches = obligation.OtherField == profileField && obligation.Field == canonicalField
			}
		}
		if !matches {
			continue
		}
		if found != nil && found.Resolution.Hook != obligation.Resolution.Hook {
			return nil, fmt.Errorf("field %q has multiple policy hooks %q and %q", profileField, found.Resolution.Hook, obligation.Resolution.Hook)
		}
		found = obligation
	}
	return found, nil
}

func layerCodecFieldAtFlagSlot(canonical *layerDefinitionBinding, word string, bit uint8) *layerFieldBinding {
	if canonical == nil {
		return nil
	}
	for index := range canonical.Fields {
		field := &canonical.Fields[index]
		if field.Semantic != nil && field.Semantic.Condition != nil &&
			field.Semantic.Condition.Word == word && field.Semantic.Condition.Bit == bit {
			return field
		}
	}
	return nil
}

func containsLayerCodecString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func appendUniqueLayerCodecString(values []string, target string) []string {
	if containsLayerCodecString(values, target) {
		return values
	}
	return append(values, target)
}

func layerCodecFieldGoType(field *fieldDef) string {
	if field == nil {
		return ""
	}
	prefix := ""
	if field.DoubleSlice || field.DoubleVector {
		prefix = "[][]"
	} else if field.Slice || field.Vector {
		prefix = "[]"
	}
	return prefix + field.Type
}

func layerCodecGoType(plan *layerValuePlan) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("nil layer value plan")
	}
	switch plan.Kind {
	case layerValuePrimitive:
		switch plan.Primitive {
		case "int", "Int":
			return "int", nil
		case "int32":
			return "int32", nil
		case "int53", "int64", "long", "Long":
			return "int64", nil
		case "int128":
			return "bin.Int128", nil
		case "int256":
			return "bin.Int256", nil
		case "double", "Double":
			return "float64", nil
		case "string", "String":
			return "string", nil
		case "bytes", "Bytes":
			return "[]byte", nil
		case "bool", "Bool", "true", "false", "True":
			return "bool", nil
		default:
			return "", fmt.Errorf("unsupported TL primitive %q", plan.Primitive)
		}
	case layerValueExactBare, layerValueBoxedConcrete:
		if len(plan.Constructors) != 1 || plan.Constructors[0].Canonical == nil {
			return "", fmt.Errorf("%s has no canonical concrete Go type", plan.Kind)
		}
		return plan.Constructors[0].Canonical.Structure.Name, nil
	case layerValueBoxedAbstract:
		if plan.CanonicalClass == nil {
			return "", fmt.Errorf("boxed class %q is profile-only", plan.Ref.QName)
		}
		return plan.CanonicalClass.Backend.Name, nil
	case layerValueVector:
		element, err := layerCodecGoType(plan.Element)
		if err != nil {
			return "", err
		}
		return "[]" + element, nil
	case layerValueDynamicGeneric, layerValueDynamicObject:
		return "bin.Object", nil
	default:
		return "", fmt.Errorf("unsupported layer value kind %s", plan.Kind)
	}
}

func layerCodecClassSuffix(class *layerClassBinding) string {
	if class == nil {
		return "Invalid"
	}
	if class.Backend.Func != "" {
		return class.Backend.Func
	}
	return class.Backend.Name
}

func (e *layerCodecEmitter) emitEncodeValue(plan *layerValuePlan, expression, buffer, state, context string) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("encode %s: nil value plan", context)
	}
	var statement string
	switch plan.Kind {
	case layerValuePrimitive:
		method, err := layerCodecPrimitiveMethod(plan.Primitive)
		if err != nil {
			return "", err
		}
		if method == "String" || method == "Bytes" {
			statement = fmt.Sprintf("if err := %s.Put%sChecked(%s); err != nil { return fmt.Errorf(%q, err) }\n", buffer, method, expression, "encode "+context+": %w")
		} else {
			statement = fmt.Sprintf("%s.Put%s(%s)\n", buffer, method, expression)
		}
	case layerValueExactBare, layerValueBoxedConcrete:
		if len(plan.Constructors) != 1 || plan.Constructors[0].Canonical == nil {
			return "", fmt.Errorf("encode %s: %s has no canonical constructor", context, plan.Kind)
		}
		wireID := plan.Constructors[0].Conversion.Profile.Definition.WireID
		var b strings.Builder
		if plan.Kind == layerValueBoxedConcrete {
			fmt.Fprintf(&b, "%s.PutID(0x%08x)\n", buffer, wireID)
		}
		fmt.Fprintf(&b, "if err := layerEncodeWire%08xBareBody(profile, &(%s), %s, %s); err != nil { return fmt.Errorf(\"encode %s: %%w\", err) }\n", wireID, expression, buffer, state, context)
		statement = b.String()
	case layerValueBoxedAbstract:
		if plan.CanonicalClass == nil {
			return "", fmt.Errorf("encode %s: profile-only abstract class %q", context, plan.Ref.QName)
		}
		name := "layerEncodeClass" + layerCodecClassSuffix(plan.CanonicalClass) + "Body"
		statement = fmt.Sprintf("if err := %s(profile, %s, %s, %s); err != nil { return fmt.Errorf(\"encode %s: %%w\", err) }\n", name, expression, buffer, state, context)
	case layerValueDynamicGeneric:
		slot, ok := e.genericSlots[plan.GenericParam]
		if !ok {
			return "", fmt.Errorf("encode %s: generic parameter %q has no enclosing static slot", context, plan.GenericParam)
		}
		statement = fmt.Sprintf("if %s == nil || %d >= len(%s.generic) || !%s.genericBound[%d] { return &LayerCodecError{Operation: \"encode\", Profile: profile, Reason: %q} }\nif err := %s.generic[%d].encode(profile, %s, %s, %s); err != nil { return fmt.Errorf(\"encode %s: %%w\", err) }\n", state, slot, state, state, slot, "unbound generic slot "+plan.GenericParam, state, slot, expression, buffer, state, context)
	case layerValueDynamicObject:
		statement = fmt.Sprintf("if err := layerEncodeObjectBody(profile, %s, %s, %s); err != nil { return fmt.Errorf(\"encode %s: %%w\", err) }\n", expression, buffer, state, context)
	case layerValueVector:
		length := e.nextTemp("length")
		itemIndex := e.nextTemp("index")
		var b strings.Builder
		fmt.Fprintf(&b, "if len(%s) > layerCodecMaxVectorElements { return &LayerCodecError{Operation: \"encode\", Profile: profile, Reason: \"vector length exceeds generated limit\"} }\n", expression)
		child, err := e.emitEncodeValue(plan.Element, fmt.Sprintf("%s[%s]", expression, itemIndex), buffer, state, context+" element")
		if err != nil {
			return "", err
		}
		if plan.Element.Kind == layerValuePrimitive {
			if plan.VectorMode == layerValueVectorBoxed {
				fmt.Fprintf(&b, "%s.PutVectorHeader(len(%s))\n", buffer, expression)
			} else {
				fmt.Fprintf(&b, "%s.PutInt(len(%s))\n", buffer, expression)
			}
			fmt.Fprintf(&b, "for %s := range %s {\n", itemIndex, expression)
			b.WriteString(indentLayerCodec(child, "\t"))
			b.WriteString("}\n")
			statement = b.String()
			break
		}
		vectorStart := e.nextTemp("vectorStart")
		countOffset := e.nextTemp("countOffset")
		itemStart := e.nextTemp("itemStart")
		hookErr := e.nextTemp("err")
		fmt.Fprintf(&b, "%s := len(%s.Buf)\n", vectorStart, buffer)
		if plan.VectorMode == layerValueVectorBoxed {
			fmt.Fprintf(&b, "%s.PutVectorHeader(0)\n%s := %s + 4\n", buffer, countOffset, vectorStart)
		} else {
			fmt.Fprintf(&b, "%s.PutInt(0)\n%s := %s\n", buffer, countOffset, vectorStart)
		}
		fmt.Fprintf(&b, "%s := 0\nfor %s := range %s {\n\t%s := len(%s.Buf)\n\t%s := func() error {\n", length, itemIndex, expression, itemStart, buffer, hookErr)
		b.WriteString(indentLayerCodec(child, "\t\t"))
		fmt.Fprintf(&b, "\t\treturn nil\n\t}()\n\tif %s != nil {\n\t\t%s.Buf = %s.Buf[:%s]\n\t\tif IsLayerProjectionDrop(%s) { continue }\n\t\t%s.Buf = %s.Buf[:%s]\n\t\treturn fmt.Errorf(\"encode %s: %%w\", %s)\n\t}\n\t%s++\n}\n", hookErr, buffer, buffer, itemStart, hookErr, buffer, buffer, vectorStart, context, hookErr, length)
		fmt.Fprintf(&b, "%s.Buf[%s] = byte(%s)\n%s.Buf[%s+1] = byte(%s >> 8)\n%s.Buf[%s+2] = byte(%s >> 16)\n%s.Buf[%s+3] = byte(%s >> 24)\n", buffer, countOffset, length, buffer, countOffset, length, buffer, countOffset, length, buffer, countOffset, length)
		statement = b.String()
	default:
		return "", fmt.Errorf("encode %s: unsupported value kind %s", context, plan.Kind)
	}
	return statement, nil
}

func (e *layerCodecEmitter) emitDecodeValue(plan *layerValuePlan, target, buffer, state, context string) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("decode %s: nil value plan", context)
	}
	var b strings.Builder
	switch plan.Kind {
	case layerValuePrimitive:
		method, err := layerCodecPrimitiveMethod(plan.Primitive)
		if err != nil {
			return "", err
		}
		local := e.nextTemp("primitive")
		fmt.Fprintf(&b, "%s, err := %s.%s()\nif err != nil { return nil, fmt.Errorf(\"decode %s: %%w\", err) }\n%s = %s\n", local, buffer, method, context, target, local)
	case layerValueExactBare, layerValueBoxedConcrete:
		if len(plan.Constructors) != 1 || plan.Constructors[0].Canonical == nil {
			return "", fmt.Errorf("decode %s: %s has no canonical constructor", context, plan.Kind)
		}
		wireID := plan.Constructors[0].Conversion.Profile.Definition.WireID
		name := fmt.Sprintf("layerDecodeWire%08x", wireID)
		if plan.Kind == layerValueExactBare {
			name += "Bare"
		}
		local := e.nextTemp("concrete")
		fmt.Fprintf(&b, "%s, err := %s(profile, %s, %s)\nif err != nil { return nil, fmt.Errorf(\"decode %s: %%w\", err) }\n%s = *%s\n", local, name, buffer, state, context, target, local)
	case layerValueBoxedAbstract:
		if plan.CanonicalClass == nil {
			return "", fmt.Errorf("decode %s: profile-only abstract class %q", context, plan.Ref.QName)
		}
		local := e.nextTemp("class")
		name := "layerDecodeClass" + layerCodecClassSuffix(plan.CanonicalClass)
		fmt.Fprintf(&b, "%s, err := %s(profile, %s, %s)\nif err != nil { return nil, fmt.Errorf(\"decode %s: %%w\", err) }\n%s = %s\n", local, name, buffer, state, context, target, local)
	case layerValueDynamicGeneric:
		slot, ok := e.genericSlots[plan.GenericParam]
		if !ok {
			return "", fmt.Errorf("decode %s: generic parameter %q has no enclosing static slot", context, plan.GenericParam)
		}
		local := e.nextTemp("generic")
		fmt.Fprintf(&b, "if %s == nil || %d >= len(%s.generic) || !%s.genericBound[%d] { return nil, &LayerCodecError{Operation: \"decode\", Profile: profile, Reason: %q} }\n%s, err := %s.generic[%d].decode(profile, %s, %s)\nif err != nil { return nil, fmt.Errorf(\"decode %s: %%w\", err) }\n%s, ok := %s.(bin.Object)\nif !ok { return nil, &LayerCodecError{Operation: \"decode\", Profile: profile, Reason: \"generic decoder returned non-object canonical value\"} }\n%s = %s\n", state, slot, state, state, slot, "unbound generic slot "+plan.GenericParam, local, state, slot, buffer, state, context, local+"Object", local, target, local+"Object")
	case layerValueDynamicObject:
		local := e.nextTemp("object")
		fmt.Fprintf(&b, "%s, err := layerDecodeObject(profile, %s, %s)\nif err != nil { return nil, fmt.Errorf(\"decode %s: %%w\", err) }\n%s = %s\n", local, buffer, state, context, target, local)
	case layerValueVector:
		goType, err := layerCodecGoType(plan)
		if err != nil {
			return "", err
		}
		vectorState := e.nextTemp("decodeState")
		fmt.Fprintf(&b, "%s, err := layerCodecDescend(profile, \"decode\", %s)\nif err != nil { return nil, fmt.Errorf(\"decode %s vector depth: %%w\", err) }\n", vectorState, state, context)
		vectorStatePtr := "&" + vectorState
		length := e.nextTemp("length")
		mode := "false"
		if plan.VectorMode == layerValueVectorBoxed {
			mode = "true"
		}
		fmt.Fprintf(&b, "%s, err := layerDecodeVectorLength(profile, nil, %s, %s, %s)\nif err != nil { return nil, fmt.Errorf(\"decode %s: %%w\", err) }\n", length, buffer, mode, vectorStatePtr, context)
		result := e.nextTemp("vector")
		fmt.Fprintf(&b, "var %s %s\nif %s > 0 { capacity := %s; if capacity > bin.PreallocateLimit { capacity = bin.PreallocateLimit }; %s = make(%s, 0, capacity) }\n", result, goType, length, length, result, goType)
		elementType, err := layerCodecGoType(plan.Element)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "for index := 0; index < %s; index++ {\n\tvar element %s\n", length, elementType)
		child, err := e.emitDecodeValue(plan.Element, "element", buffer, vectorStatePtr, context+" element")
		if err != nil {
			return "", err
		}
		b.WriteString(indentLayerCodec(child, "\t"))
		fmt.Fprintf(&b, "\t%s = append(%s, element)\n}\n%s = %s\n", result, result, target, result)
	default:
		return "", fmt.Errorf("decode %s: unsupported value kind %s", context, plan.Kind)
	}
	return b.String(), nil
}

func layerCodecPrimitiveMethod(primitive string) (string, error) {
	switch primitive {
	case "int", "Int":
		return "Int", nil
	case "int32":
		return "Int32", nil
	case "int53":
		return "Int53", nil
	case "int64", "long", "Long":
		return "Long", nil
	case "int128":
		return "Int128", nil
	case "int256":
		return "Int256", nil
	case "double", "Double":
		return "Double", nil
	case "string", "String":
		return "String", nil
	case "bytes", "Bytes":
		return "Bytes", nil
	case "bool", "Bool", "true", "false", "True":
		return "Bool", nil
	default:
		return "", fmt.Errorf("unsupported TL primitive %q", primitive)
	}
}

func (e *layerCodecEmitter) buildFamilies() error {
	type profileCase struct {
		layers    []int
		project   string
		preflight string
		encode    string
	}
	for familyIndex := range e.wire.Families {
		family := &e.wire.Families[familyIndex]
		if family.Canonical == nil {
			continue
		}
		goType := family.Canonical.Structure.Name
		semanticID := layerSemanticConstant(family.Key)
		projectName := "layerProjectFamily" + goType
		preflightName := "layerPreflightFamily" + goType
		encodeName := "layerEncodeFamily" + goType
		encodeBodyName := encodeName + "Body"
		var project, preflight, encode, encodeBody strings.Builder
		fmt.Fprintf(&project, "func %s(profile LayerProfile, value *%s) (bin.Object, bool, error) {\n", projectName, goType)
		project.WriteString("\tif value == nil { return nil, false, &LayerCodecError{Operation: \"project\", Profile: profile, Semantic: " + semanticID + ", Reason: \"nil canonical value\"} }\n\tswitch profile {\n")
		fmt.Fprintf(&encode, "func %s(profile LayerProfile, value *%s, b *bin.Buffer, state *layerCodecState) error {\n", encodeName, goType)
		fmt.Fprintf(&encode, "\treturn layerCodecEncodeAtomic(profile, b, func() error { return %s(profile, value, b, state) })\n}\n", encodeBodyName)
		fmt.Fprintf(&encodeBody, "func %s(profile LayerProfile, value *%s, b *bin.Buffer, state *layerCodecState) error {\n", encodeBodyName, goType)
		encodeBody.WriteString("\tif value == nil { return &LayerCodecError{Operation: \"encode\", Profile: profile, Semantic: " + semanticID + ", Reason: \"nil canonical value\"} }\n\tswitch profile {\n")
		fmt.Fprintf(&preflight, "func %s(profile LayerProfile, value *%s, state *layerCodecState) (int, error) {\n", preflightName, goType)
		preflight.WriteString("\tif value == nil { return 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Semantic: " + semanticID + ", Reason: \"nil canonical value\"} }\n\tswitch profile {\n")
		cases := make([]profileCase, 0, len(family.Profiles))
		for _, action := range family.Profiles {
			current := profileCase{layers: []int{action.Layer}}
			if historical := e.wire.historicalTarget(action.Layer, family.Key); historical != nil {
				current.project = "return value, true, nil\n"
				current.preflight = fmt.Sprintf("return layerPreflightWire%08xBare(profile, value, state)\n", historical.WireID)
				current.encode = fmt.Sprintf("b.PutID(0x%08x)\nreturn layerEncodeWire%08xBareBody(profile, value, b, state)\n", historical.WireID, historical.WireID)
			} else if action.WireIndex >= 0 && (action.Kind == layerWireDirect || action.Kind == layerWireRetag || action.Kind == layerWireRewrite || action.Kind == layerWirePolicy) {
				wire := e.wire.Wires[action.WireIndex]
				current.project = "return value, true, nil\n"
				current.preflight = fmt.Sprintf("return layerPreflightWire%08xBare(profile, value, state)\n", wire.WireID)
				current.encode = fmt.Sprintf("b.PutID(0x%08x)\nreturn layerEncodeWire%08xBareBody(profile, value, b, state)\n", wire.WireID, wire.WireID)
			} else {
				projection, hook := layerCodecProjectionDecision(action.Conversion)
				switch projection {
				case LayerResolveDrop:
					current.project = "return nil, false, nil\n"
					current.preflight = "return 0, nil\n"
					current.encode = fmt.Sprintf("return &LayerProjectionError{Profile: profile, Semantic: %s, Dropped: true, Reason: \"policy drops unavailable value\"}\n", semanticID)
				case LayerResolveProject:
					hook += "Project"
					signature := fmt.Sprintf("func(LayerProfile, *%s) (bin.Object, bool, error)", goType)
					if err := e.addHook(hook, signature); err != nil {
						return err
					}
					current.project = fmt.Sprintf("return %s(profile, value)\n", hook)
					current.preflight = fmt.Sprintf("projected, keep, err := %s(profile, value); if err != nil { return 0, err }; if !keep { return 0, nil }; return layerPreflightDynamicObject(profile, projected, state)\n", hook)
					current.encode = fmt.Sprintf("projected, keep, err := %s(profile, value); if err != nil { return err }; if !keep { return &LayerProjectionError{Profile: profile, Semantic: %s, Dropped: true, Reason: \"policy drops projected value\"} }; return layerEncodeObjectBody(profile, projected, b, state)\n", hook, semanticID)
				default:
					reason := "semantic family is unavailable in exact profile"
					current.project = fmt.Sprintf("return nil, false, &LayerCodecError{Operation: \"project\", Profile: profile, Semantic: %s, Reason: %q}\n", semanticID, reason)
					current.preflight = fmt.Sprintf("return 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Semantic: %s, Reason: %q}\n", semanticID, reason)
					current.encode = fmt.Sprintf("return &LayerCodecError{Operation: \"encode\", Profile: profile, Semantic: %s, Reason: %q}\n", semanticID, reason)
				}
			}
			matched := -1
			for index := range cases {
				if cases[index].project == current.project && cases[index].preflight == current.preflight && cases[index].encode == current.encode {
					matched = index
					break
				}
			}
			if matched >= 0 {
				cases[matched].layers = append(cases[matched].layers, action.Layer)
			} else {
				cases = append(cases, current)
			}
		}
		for _, current := range cases {
			writeLayerCodecCaseLabel(&project, "\t", current.layers)
			project.WriteString(indentLayerCodec(current.project, "\t\t"))
			writeLayerCodecCaseLabel(&preflight, "\t", current.layers)
			preflight.WriteString(indentLayerCodec(current.preflight, "\t\t"))
			writeLayerCodecCaseLabel(&encodeBody, "\t", current.layers)
			encodeBody.WriteString(indentLayerCodec(current.encode, "\t\t"))
		}
		project.WriteString("\tdefault:\n\t\treturn nil, false, &LayerCodecError{Operation: \"project\", Profile: profile, Semantic: " + semanticID + ", Reason: \"unsupported exact profile\"}\n\t}\n}\n")
		preflight.WriteString("\tdefault:\n\t\treturn 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Semantic: " + semanticID + ", Reason: \"unsupported exact profile\"}\n\t}\n}\n")
		encodeBody.WriteString("\tdefault:\n\t\treturn &LayerCodecError{Operation: \"encode\", Profile: profile, Semantic: " + semanticID + ", Reason: \"unsupported exact profile\"}\n\t}\n}\n")
		declarations := []string{project.String(), preflight.String(), encode.String(), encodeBody.String()}
		e.model.FamilyDeclarations = append(e.model.FamilyDeclarations, declarations...)
		e.model.Declarations = append(e.model.Declarations, declarations...)
	}
	return nil
}

func writeLayerCodecCaseLabel(b *strings.Builder, indent string, layers []int) {
	b.WriteString(indent)
	b.WriteString("case ")
	for index, layer := range layers {
		if index != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "LayerProfile%d", layer)
	}
	b.WriteString(":\n")
}

func layerCodecProjectionDecision(conversion *LayerFamilyConversion) (LayerResolutionAction, string) {
	if conversion == nil {
		return LayerResolveReject, ""
	}
	for _, obligation := range conversion.ProjectionObligations() {
		return obligation.Resolution.Action, obligation.Resolution.Hook
	}
	return LayerResolveReject, ""
}

type layerCodecClassConstructorCase struct {
	GoType string
	WireID uint32
}

type layerCodecClassProfileGroup struct {
	Layers       []int
	Constructors []layerCodecClassConstructorCase
	Signature    string
}

func (e *layerCodecEmitter) classProfileGroups(class *layerClassPlan) ([]layerCodecClassProfileGroup, error) {
	groups := make([]layerCodecClassProfileGroup, 0, len(class.Profiles))
	for _, profile := range class.Profiles {
		current := layerCodecClassProfileGroup{Layers: []int{profile.Layer}}
		for _, constructor := range profile.Constructors {
			if constructor.FamilyIndex < 0 || constructor.FamilyIndex >= len(e.wire.Families) {
				return nil, fmt.Errorf("gen: class %s layer %d wire %#08x has invalid family index", class.QName, profile.Layer, constructor.WireID)
			}
			family := &e.wire.Families[constructor.FamilyIndex]
			goType := ""
			if family.Canonical != nil {
				goType = family.Canonical.Structure.Name
			} else if historical := e.wire.historicalWire(profile.Layer, constructor.WireID); historical != nil {
				goType = historical.Target.Structure.Name
			} else {
				return nil, fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_CLASS_ROUTE: class %s layer %d wire %#08x has no canonical or bidirectional historical constructor", class.QName, profile.Layer, constructor.WireID)
			}
			current.Constructors = append(current.Constructors, layerCodecClassConstructorCase{GoType: goType, WireID: constructor.WireID})
		}
		sort.Slice(current.Constructors, func(i, j int) bool {
			if current.Constructors[i].GoType != current.Constructors[j].GoType {
				return current.Constructors[i].GoType < current.Constructors[j].GoType
			}
			return current.Constructors[i].WireID < current.Constructors[j].WireID
		})
		var signature strings.Builder
		for index, constructor := range current.Constructors {
			if index > 0 && current.Constructors[index-1].GoType == constructor.GoType {
				return nil, fmt.Errorf("gen: E_PROFILE_ONLY_TYPE_CLASS_AMBIGUOUS: class %s layer %d canonical type %s maps to multiple exact wires", class.QName, profile.Layer, constructor.GoType)
			}
			fmt.Fprintf(&signature, "%s:%08x;", constructor.GoType, constructor.WireID)
		}
		current.Signature = signature.String()
		matched := -1
		for index := range groups {
			if groups[index].Signature == current.Signature {
				matched = index
				break
			}
		}
		if matched >= 0 {
			groups[matched].Layers = append(groups[matched].Layers, profile.Layer)
		} else {
			groups = append(groups, current)
		}
	}
	return groups, nil
}

func (e *layerCodecEmitter) buildClasses() error {
	for classIndex := range e.wire.Classes {
		class := &e.wire.Classes[classIndex]
		if class.Canonical == nil || class.Canonical.Backend.Singular {
			continue
		}
		groups, err := e.classProfileGroups(class)
		if err != nil {
			return err
		}
		classType := class.Canonical.Backend.Name
		suffix := layerCodecClassSuffix(class.Canonical)
		projectName := "layerProjectClass" + suffix
		encodeName := "layerEncodeClass" + suffix
		encodeBodyName := encodeName + "Body"
		decodeName := "layerDecodeClass" + suffix

		var project strings.Builder
		fmt.Fprintf(&project, "func %s(profile LayerProfile, value %s) (%s, bool, error) {\n", projectName, classType, classType)
		project.WriteString("\tif value == nil { return nil, false, &LayerCodecError{Operation: \"project\", Profile: profile, Reason: \"nil class value\"} }\n\tswitch value := value.(type) {\n")
		for _, constructor := range class.Canonical.Constructors {
			fmt.Fprintf(&project, "\tcase *%s:\n\t\tprojected, keep, err := layerProjectFamily%s(profile, value)\n\t\tif err != nil || !keep { return nil, keep, err }\n\t\tresult, ok := projected.(%s)\n\t\tif !ok { return nil, false, &LayerCodecError{Operation: \"project\", Profile: profile, Semantic: %s, Reason: \"project hook returned a constructor outside class %s\"} }\n\t\treturn result, true, nil\n", constructor.Structure.Name, constructor.Structure.Name, classType, layerSemanticConstant(constructor.Key), class.QName)
		}
		project.WriteString("\tdefault:\n\t\treturn nil, false, &LayerCodecError{Operation: \"project\", Profile: profile, Reason: \"unknown canonical class constructor\"}\n\t}\n}\n")

		var preflight strings.Builder
		fmt.Fprintf(&preflight, "func layerPreflightClass%s(profile LayerProfile, value %s, state *layerCodecState) (int, error) {\n\tprojected, keep, err := %s(profile, value)\n\tif err != nil { return 0, err }\n\tif !keep { return 0, nil }\n\tswitch profile {\n", suffix, classType, projectName)
		for _, group := range groups {
			writeLayerCodecCaseLabel(&preflight, "\t", group.Layers)
			preflight.WriteString("\t\tswitch value := projected.(type) {\n")
			for _, constructor := range group.Constructors {
				fmt.Fprintf(&preflight, "\t\tcase *%s:\n\t\t\treturn layerPreflightWire%08xBare(profile, value, state)\n", constructor.GoType, constructor.WireID)
			}
			preflight.WriteString("\t\tdefault:\n\t\t\t_ = value\n\t\t\treturn 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Reason: \"constructor is unavailable in exact class profile\"}\n\t\t}\n")
		}
		preflight.WriteString("\tdefault:\n\t\treturn 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Reason: \"unsupported exact profile\"}\n\t}\n}\n")

		var encode, encodeBody strings.Builder
		fmt.Fprintf(&encode, "func %s(profile LayerProfile, value %s, b *bin.Buffer, state *layerCodecState) error {\n", encodeName, classType)
		fmt.Fprintf(&encode, "\treturn layerCodecEncodeAtomic(profile, b, func() error { return %s(profile, value, b, state) })\n}\n", encodeBodyName)
		fmt.Fprintf(&encodeBody, "func %s(profile LayerProfile, value %s, b *bin.Buffer, state *layerCodecState) error {\n", encodeBodyName, classType)
		fmt.Fprintf(&encodeBody, "\tprojected, keep, err := %s(profile, value)\n\tif err != nil { return err }\n\tif !keep { return &LayerProjectionError{Profile: profile, Dropped: true, Reason: \"class value was projected out before encoding\"} }\n\tswitch profile {\n", projectName)
		for _, group := range groups {
			writeLayerCodecCaseLabel(&encodeBody, "\t", group.Layers)
			encodeBody.WriteString("\t\tswitch value := projected.(type) {\n")
			for _, constructor := range group.Constructors {
				fmt.Fprintf(&encodeBody, "\t\tcase *%s:\n\t\t\tb.PutID(0x%08x)\n\t\t\treturn layerEncodeWire%08xBareBody(profile, value, b, state)\n", constructor.GoType, constructor.WireID, constructor.WireID)
			}
			encodeBody.WriteString("\t\tdefault:\n\t\t\t_ = value\n\t\t\treturn &LayerCodecError{Operation: \"encode\", Profile: profile, Reason: \"constructor is unavailable in exact class profile\"}\n\t\t}\n")
		}
		encodeBody.WriteString("\tdefault:\n\t\treturn &LayerCodecError{Operation: \"encode\", Profile: profile, Reason: \"unsupported exact profile\"}\n\t}\n}\n")

		var decode strings.Builder
		fmt.Fprintf(&decode, "func %s(profile LayerProfile, b *bin.Buffer, state *layerCodecState) (%s, error) {\n", decodeName, classType)
		decode.WriteString("\tid, err := b.PeekID()\n\tif err != nil { return nil, fmt.Errorf(\"peek class constructor: %w\", err) }\n\tswitch profile {\n")
		for _, group := range groups {
			writeLayerCodecCaseLabel(&decode, "\t", group.Layers)
			decode.WriteString("\t\tswitch id {\n")
			constructors := append([]layerCodecClassConstructorCase(nil), group.Constructors...)
			sort.Slice(constructors, func(i, j int) bool { return constructors[i].WireID < constructors[j].WireID })
			for _, constructor := range constructors {
				fmt.Fprintf(&decode, "\t\tcase 0x%08x:\n\t\t\treturn layerDecodeWire%08x(profile, b, state)\n", constructor.WireID, constructor.WireID)
			}
			decode.WriteString("\t\tdefault:\n\t\t\treturn nil, &LayerCodecError{Operation: \"decode\", Profile: profile, WireID: id, Reason: \"wire ID is not a constructor of exact class profile\"}\n\t\t}\n")
		}
		decode.WriteString("\tdefault:\n\t\treturn nil, &LayerCodecError{Operation: \"decode\", Profile: profile, WireID: id, Reason: \"unsupported exact profile\"}\n\t}\n}\n")
		declarations := []string{project.String(), preflight.String(), encode.String(), encodeBody.String(), decode.String()}
		e.model.ClassDeclarations = append(e.model.ClassDeclarations, declarations...)
		e.model.Declarations = append(e.model.Declarations, declarations...)
	}
	return nil
}

func (e *layerCodecEmitter) buildObjectDispatcher() error {
	var project, preflight, encode, encodeBody, decode strings.Builder
	project.WriteString("func layerProjectObject(profile LayerProfile, value bin.Object) (bin.Object, bool, error) {\n\tif value == nil { return nil, false, &LayerCodecError{Operation: \"project\", Profile: profile, Reason: \"nil dynamic object\"} }\n\tswitch value := value.(type) {\n")
	preflight.WriteString("func layerPreflightDynamicObject(profile LayerProfile, value bin.Object, state *layerCodecState) (int, error) {\n\tif value == nil { return 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Reason: \"nil dynamic object\"} }\n\tswitch value := value.(type) {\n")
	encode.WriteString("func layerEncodeObject(profile LayerProfile, value bin.Object, b *bin.Buffer, state *layerCodecState) error {\n\treturn layerCodecEncodeAtomic(profile, b, func() error { return layerEncodeObjectBody(profile, value, b, state) })\n}\n")
	encodeBody.WriteString("func layerEncodeObjectBody(profile LayerProfile, value bin.Object, b *bin.Buffer, state *layerCodecState) error {\n\tprojected, keep, err := layerProjectObject(profile, value)\n\tif err != nil { return err }\n\tif !keep { return &LayerProjectionError{Profile: profile, Dropped: true, Reason: \"dynamic object was projected out before encoding\"} }\n\tswitch value := projected.(type) {\n")
	for _, family := range e.wire.Families {
		if family.Canonical == nil {
			continue
		}
		goType := family.Canonical.Structure.Name
		fmt.Fprintf(&project, "\tcase *%s:\n\t\treturn layerProjectFamily%s(profile, value)\n", goType, goType)
		fmt.Fprintf(&preflight, "\tcase *%s:\n\t\treturn layerPreflightFamily%s(profile, value, state)\n", goType, goType)
		fmt.Fprintf(&encodeBody, "\tcase *%s:\n\t\treturn layerEncodeFamily%sBody(profile, value, b, state)\n", goType, goType)
	}
	project.WriteString("\tdefault:\n\t\treturn nil, false, &LayerCodecError{Operation: \"project\", Profile: profile, Reason: \"unknown canonical dynamic object\"}\n\t}\n}\n")
	preflight.WriteString("\tdefault:\n\t\treturn 0, &LayerCodecError{Operation: \"preflight\", Profile: profile, Reason: \"unknown canonical dynamic object\"}\n\t}\n}\n")
	encodeBody.WriteString("\tdefault:\n\t\treturn &LayerCodecError{Operation: \"encode\", Profile: profile, Reason: \"unknown canonical dynamic object\"}\n\t}\n}\n")

	decode.WriteString("func layerDecodeObject(profile LayerProfile, b *bin.Buffer, state *layerCodecState) (bin.Object, error) {\n\tid, err := b.PeekID()\n\tif err != nil { return nil, fmt.Errorf(\"peek dynamic object: %w\", err) }\n\tswitch id {\n")
	for _, wire := range e.wire.Wires {
		if wire.Canonical == nil {
			historicalType := false
			if wire.Key.Category == semantic.CategoryType {
				for _, layer := range e.wire.Profiles {
					if e.wire.historicalWire(layer, wire.WireID) != nil {
						historicalType = true
						break
					}
				}
			}
			if historicalType {
				fmt.Fprintf(&decode, "\tcase 0x%08x:\n\t\treturn layerDecodeWire%08x(profile, b, state)\n", wire.WireID, wire.WireID)
			} else {
				fmt.Fprintf(&decode, "\tcase 0x%08x:\n\t\treturn nil, &LayerCodecError{Operation: \"decode\", Profile: profile, WireID: id, Reason: \"profile-only method has no canonical object\"}\n", wire.WireID)
			}
			continue
		}
		fmt.Fprintf(&decode, "\tcase 0x%08x:\n\t\treturn layerDecodeWire%08x(profile, b, state)\n", wire.WireID, wire.WireID)
	}
	decode.WriteString("\tdefault:\n\t\treturn nil, &LayerCodecError{Operation: \"decode\", Profile: profile, WireID: id, Reason: \"unknown wire ID\"}\n\t}\n}\n")
	encode.WriteString("\nfunc layerEncodeDynamicObject(profile LayerProfile, value bin.Object, b *bin.Buffer, state *layerCodecState) error {\n\treturn layerEncodeObject(profile, value, b, state)\n}\n")
	encodeBody.WriteString("\nfunc layerEncodeDynamicObjectBody(profile LayerProfile, value bin.Object, b *bin.Buffer, state *layerCodecState) error {\n\treturn layerEncodeObjectBody(profile, value, b, state)\n}\n")
	decode.WriteString("\nfunc layerDecodeDynamicObject(profile LayerProfile, b *bin.Buffer, state *layerCodecState) (bin.Object, error) {\n\treturn layerDecodeObject(profile, b, state)\n}\n")
	declarations := []string{project.String(), preflight.String(), encode.String(), encodeBody.String(), decode.String()}
	e.model.DynamicDeclarations = append(e.model.DynamicDeclarations, declarations...)
	e.model.Declarations = append(e.model.Declarations, declarations...)
	return nil
}

func layerCodecFlagWords(definition *semantic.Definition) []int {
	var result []int
	for ordinal, field := range definition.Fields {
		if field.Kind == semantic.FieldFlagsWord {
			result = append(result, ordinal)
		}
	}
	return result
}

func layerCodecFlagOrdinal(definition *semantic.Definition, name string) (int, bool) {
	for ordinal, field := range definition.Fields {
		if field.Kind == semantic.FieldFlagsWord && field.Name == name {
			return ordinal, true
		}
	}
	return 0, false
}

func layerCodecPresenceExpression(field *layerFieldBinding, expression string) (string, error) {
	if field == nil || field.Go == nil || field.Semantic == nil {
		return "", fmt.Errorf("nil canonical field binding")
	}
	if field.Semantic.Condition == nil {
		return "true", nil
	}
	flag := field.Semantic.Condition
	var parts []string
	parts = append(parts, fmt.Sprintf("value.%s.Has(%d)", field.Go.ConditionalField, flag.Bit))
	switch {
	case field.Go.ConditionalBool:
		parts = append(parts, expression)
	case field.Go.Slice || field.Go.DoubleSlice:
		parts = append(parts, expression+" != nil")
	case field.Go.Type == "bin.Int128":
		parts = append(parts, expression+" != (bin.Int128{})")
	case field.Go.Type == "bin.Int256":
		parts = append(parts, expression+" != (bin.Int256{})")
	case strings.HasPrefix(field.Go.Type, "int") || strings.HasPrefix(field.Go.Type, "float"):
		parts = append(parts, expression+" != 0")
	case field.Go.Type == "string":
		parts = append(parts, expression+` != ""`)
	case field.Go.Type == "bool":
		parts = append(parts, expression)
	case field.Go.Type == "bin.Object" || strings.HasSuffix(field.Go.Type, "Class"):
		parts = append(parts, expression+" != nil")
	default:
		parts = append(parts, "!"+expression+".Zero()")
	}
	return "(" + strings.Join(parts, " || ") + ")", nil
}

func layerCodecDefaultedField(conversion *LayerFamilyConversion, profileField string, direction LayerObligationDirection) bool {
	for _, obligation := range conversion.BodyObligations() {
		if layerCodecDirectionMatches(obligation.Direction, direction) && obligation.Resolution.Action == LayerResolveDefault &&
			(obligation.OtherField == profileField || obligation.Field == profileField) {
			return true
		}
	}
	return false
}

func layerCodecDroppedField(conversion *LayerFamilyConversion, profileField string) bool {
	for _, obligation := range conversion.BodyObligations() {
		if layerCodecDirectionMatches(obligation.Direction, LayerDirectionProfileToCanonical) &&
			obligation.Field == profileField && obligation.Resolution.Action == LayerResolveDrop {
			return true
		}
	}
	return false
}

func layerCodecZeroExpression(plan *layerValuePlan) (string, error) {
	if plan == nil {
		return "", fmt.Errorf("nil value plan")
	}
	switch plan.Kind {
	case layerValuePrimitive:
		switch plan.Primitive {
		case "string", "String":
			return `""`, nil
		case "bytes", "Bytes":
			return "nil", nil
		case "bool", "Bool", "true", "false", "True":
			return "false", nil
		case "double", "Double":
			return "0", nil
		case "int128":
			return "bin.Int128{}", nil
		case "int256":
			return "bin.Int256{}", nil
		default:
			return "0", nil
		}
	case layerValueVector:
		return "nil", nil
	default:
		return "", fmt.Errorf("default action for %s requires a typed adapter", plan.Kind)
	}
}

func (e *layerCodecEmitter) nextTemp(prefix string) string {
	e.temp++
	return fmt.Sprintf("layer%s%d", pascal(prefix), e.temp)
}

func indentLayerCodec(source, prefix string) string {
	if source == "" {
		return ""
	}
	lines := strings.Split(source, "\n")
	var b strings.Builder
	for _, line := range lines {
		if line == "" {
			continue
		}
		b.WriteString(prefix)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
