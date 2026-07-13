package gen

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"go/token"
	"hash"
	"sort"
	"strings"

	"github.com/gotd/td/gen/semantic"
)

// LayerObligationKind is one non-mechanical cross-layer decision exposed by
// schema generation. Values are stable policy identifiers.
type LayerObligationKind string

const (
	LayerObligationAlias            LayerObligationKind = "alias"
	LayerObligationRequired         LayerObligationKind = "required"
	LayerObligationIncompatible     LayerObligationKind = "incompatible"
	LayerObligationResult           LayerObligationKind = "result"
	LayerObligationOldOnly          LayerObligationKind = "old-only"
	LayerObligationNewOnly          LayerObligationKind = "new-only"
	LayerObligationAtomicFlagGroup  LayerObligationKind = "atomic-flag-group"
	LayerObligationUpdateProjection LayerObligationKind = "update-projection"
	LayerObligationPrivate          LayerObligationKind = "private"
)

// LayerObligationDirection identifies the conversion path requiring policy.
type LayerObligationDirection string

const (
	LayerDirectionCanonicalToProfile LayerObligationDirection = "canonical-to-profile"
	LayerDirectionProfileToCanonical LayerObligationDirection = "profile-to-canonical"
	LayerDirectionBoth               LayerObligationDirection = "both"
	LayerDirectionProfile            LayerObligationDirection = "profile"
)

// LayerObligationKey is copied verbatim into policy. It is a domain-separated
// digest of all machine-relevant coordinates, not of diagnostic prose.
type LayerObligationKey string

// LayerResolutionAction is a generated behavior, not free-form approval text.
type LayerResolutionAction string

const (
	LayerResolveUnavailable LayerResolutionAction = "unavailable"
	LayerResolveReject      LayerResolutionAction = "reject"
	LayerResolveDrop        LayerResolutionAction = "drop"
	LayerResolveAlias       LayerResolutionAction = "alias"
	LayerResolveDefault     LayerResolutionAction = "default"
	LayerResolveAdapter     LayerResolutionAction = "adapter"
	LayerResolveProject     LayerResolutionAction = "project"
	LayerResolveAllow       LayerResolutionAction = "allow"
)

// LayerObligationResolution is the machine-checked action for one exact key.
// Hook is required for generated adapter/project/alias calls. Note is human
// context only and never resolves an obligation by itself.
type LayerObligationResolution struct {
	Action LayerResolutionAction
	Hook   string
	Note   string
}

func (r LayerObligationResolution) resolved() bool { return r.Action != "" }

// LayerObligation describes one explicit compatibility decision.
type LayerObligation struct {
	Key       LayerObligationKey
	Kind      LayerObligationKind
	Layer     int
	Direction LayerObligationDirection

	Semantic      semantic.SemanticKey
	OtherSemantic semantic.SemanticKey
	WireID        uint32
	OtherWireID   uint32
	Field         string
	OtherField    string
	FlagWord      string
	FlagBit       uint8
	Fields        []string
	SourceType    string
	TargetType    string
	SourceShape   semantic.ShapeDigest
	TargetShape   semantic.ShapeDigest

	// Resolution is copied from an exact matching policy entry. A zero Action
	// means the obligation is unresolved.
	Resolution LayerObligationResolution
}

// LayerObligationPolicyEntry resolves exactly one generated key.
type LayerObligationPolicyEntry struct {
	Key        LayerObligationKey
	Resolution LayerObligationResolution
}

// LayerObligationPolicy is deliberately a slice: duplicate keys are rejected
// instead of being silently overwritten by a map literal or decoder.
type LayerObligationPolicy struct {
	Entries []LayerObligationPolicyEntry
}

// LayerObligationReport is deterministic for a SchemaSet and policy.
type LayerObligationReport struct {
	Obligations []LayerObligation
}

// Unresolved returns a detached list of obligations with no policy decision.
func (r LayerObligationReport) Unresolved() []LayerObligation {
	result := make([]LayerObligation, 0, len(r.Obligations))
	for _, obligation := range r.Obligations {
		if !obligation.Resolution.resolved() {
			result = append(result, obligation)
		}
	}
	return result
}

// LayerObligations analyzes the normalized SchemaSet attached to Generator.
func (g *Generator) LayerObligations(policy LayerObligationPolicy) (LayerObligationReport, error) {
	if g == nil || g.schemaSet == nil {
		return LayerObligationReport{}, fmt.Errorf("gen: layer obligations require a schema-set generator")
	}
	return AnalyzeLayerObligations(g.schemaSet, policy)
}

// AnalyzeLayerObligations discovers non-mechanical compatibility decisions and
// applies policy by exact generated key. Unknown policy keys are stale errors.
func AnalyzeLayerObligations(schemaSet *SchemaSet, policy LayerObligationPolicy) (LayerObligationReport, error) {
	plan, err := AnalyzeLayerConversions(schemaSet, policy)
	if err != nil {
		return LayerObligationReport{}, err
	}
	return plan.Report, nil
}

func privateProfile(canonical, profile *semantic.SchemaModel) bool {
	return profile.Source.Repository != canonical.Source.Repository || profile.Source.Path != canonical.Source.Path
}

func isUpdateDefinition(definition *semantic.Definition) bool {
	return definition.Key.Category == semantic.CategoryType &&
		definition.Result.Kind == semantic.TypeNamed &&
		!definition.Result.Bare && definition.Result.QName == "Update"
}

func makeDefinitionObligation(kind LayerObligationKind, layer int, direction LayerObligationDirection, definition *semantic.Definition) LayerObligation {
	return makeLayerObligation(LayerObligation{
		Kind:        kind,
		Layer:       layer,
		Direction:   direction,
		Semantic:    definition.Key,
		WireID:      definition.WireID,
		SourceType:  definition.Result.String(),
		SourceShape: definition.SemanticShape,
	})
}

type fieldAlias struct {
	canonical string
	profile   string
}

func compareLayerDefinitions(layer int, canonical, profile *semantic.Definition) []LayerObligation {
	aliases := findFieldAliases(canonical, profile)
	result := make([]LayerObligation, 0, len(aliases)+4)
	for _, alias := range aliases {
		result = append(result, makeLayerObligation(LayerObligation{
			Kind:        LayerObligationAlias,
			Layer:       layer,
			Direction:   LayerDirectionBoth,
			Semantic:    canonical.Key,
			WireID:      canonical.WireID,
			OtherWireID: profile.WireID,
			Field:       alias.canonical,
			OtherField:  alias.profile,
			SourceType:  fieldTypeString(findValueField(canonical, alias.canonical)),
			TargetType:  fieldTypeString(findValueField(profile, alias.profile)),
			SourceShape: canonical.SemanticShape,
			TargetShape: profile.SemanticShape,
		}))
	}
	result = append(result, compareDirection(
		layer, canonical, profile, LayerDirectionCanonicalToProfile, aliasMap(aliases, true),
	)...)
	result = append(result, compareDirection(
		layer, profile, canonical, LayerDirectionProfileToCanonical, aliasMap(aliases, false),
	)...)
	if canonical.Key.Category == semantic.CategoryFunction && !canonical.Result.Equal(profile.Result) {
		result = append(result, makeLayerObligation(LayerObligation{
			Kind:        LayerObligationResult,
			Layer:       layer,
			Direction:   LayerDirectionCanonicalToProfile,
			Semantic:    canonical.Key,
			WireID:      canonical.WireID,
			OtherWireID: profile.WireID,
			SourceType:  canonical.Result.String(),
			TargetType:  profile.Result.String(),
			SourceShape: canonical.SemanticShape,
			TargetShape: profile.SemanticShape,
		}))
	}
	return result
}

func compareDirection(layer int, source, target *semantic.Definition, direction LayerObligationDirection, aliases map[string]string) []LayerObligation {
	sourceFields := valueFieldMap(source)
	result := make([]LayerObligation, 0)
	for _, targetField := range target.Fields {
		if targetField.Kind != semantic.FieldValue {
			continue
		}
		sourceName := targetField.Name
		for candidate, mapped := range aliases {
			if mapped == targetField.Name {
				sourceName = candidate
				break
			}
		}
		sourceField, exists := sourceFields[sourceName]
		if !exists {
			if targetField.Condition == nil {
				result = append(result, makeFieldObligation(
					LayerObligationRequired, layer, direction, source, target, nil, &targetField,
				))
			}
			continue
		}
		if incompatibleFields(sourceField, targetField) {
			result = append(result, makeFieldObligation(
				LayerObligationIncompatible, layer, direction, source, target, &sourceField, &targetField,
			))
			continue
		}
		if sourceField.Condition != nil && targetField.Condition == nil {
			result = append(result, makeFieldObligation(
				LayerObligationRequired, layer, direction, source, target, &sourceField, &targetField,
			))
		}
	}
	result = append(result, atomicFlagGroupObligations(layer, direction, source, target, aliases)...)
	return result
}

func incompatibleFields(source, target semantic.FieldShape) bool {
	if !source.Type.Equal(target.Type) {
		return true
	}
	sourcePresence := source.Condition != nil && source.Condition.PresenceOnly
	targetPresence := target.Condition != nil && target.Condition.PresenceOnly
	return sourcePresence != targetPresence
}

func makeFieldObligation(kind LayerObligationKind, layer int, direction LayerObligationDirection, source, target *semantic.Definition, sourceField, targetField *semantic.FieldShape) LayerObligation {
	obligation := LayerObligation{
		Kind:          kind,
		Layer:         layer,
		Direction:     direction,
		Semantic:      source.Key,
		OtherSemantic: target.Key,
		WireID:        source.WireID,
		OtherWireID:   target.WireID,
		SourceShape:   source.SemanticShape,
		TargetShape:   target.SemanticShape,
	}
	if sourceField != nil {
		obligation.Field = sourceField.Name
		obligation.SourceType = fieldTypeString(sourceField)
	}
	if targetField != nil {
		obligation.OtherField = targetField.Name
		obligation.TargetType = fieldTypeString(targetField)
	}
	return makeLayerObligation(obligation)
}

func findFieldAliases(canonical, profile *semantic.Definition) []fieldAlias {
	canonicalFields := valueFieldMap(canonical)
	profileFields := valueFieldMap(profile)
	var canonicalOnly, profileOnly []semantic.FieldShape
	for _, field := range canonical.Fields {
		if field.Kind == semantic.FieldValue {
			if _, exists := profileFields[field.Name]; !exists {
				canonicalOnly = append(canonicalOnly, field)
			}
		}
	}
	for _, field := range profile.Fields {
		if field.Kind == semantic.FieldValue {
			if _, exists := canonicalFields[field.Name]; !exists {
				profileOnly = append(profileOnly, field)
			}
		}
	}

	var result []fieldAlias
	usedProfile := make(map[string]struct{})
	for _, canonicalField := range canonicalOnly {
		var match *semantic.FieldShape
		for i := range profileOnly {
			profileField := &profileOnly[i]
			if _, used := usedProfile[profileField.Name]; used || !aliasCompatible(canonicalField, *profileField) {
				continue
			}
			if match != nil {
				match = nil // Ambiguous candidates must not be guessed.
				break
			}
			match = profileField
		}
		if match != nil {
			usedProfile[match.Name] = struct{}{}
			result = append(result, fieldAlias{canonical: canonicalField.Name, profile: match.Name})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].canonical != result[j].canonical {
			return result[i].canonical < result[j].canonical
		}
		return result[i].profile < result[j].profile
	})
	return result
}

func aliasCompatible(canonical, profile semantic.FieldShape) bool {
	if canonical.Ordinal != profile.Ordinal || !canonical.Type.Equal(profile.Type) {
		return false
	}
	if canonical.Condition == nil || profile.Condition == nil {
		return canonical.Condition == nil && profile.Condition == nil
	}
	return canonical.Condition.PresenceOnly == profile.Condition.PresenceOnly
}

func aliasMap(aliases []fieldAlias, canonicalToProfile bool) map[string]string {
	result := make(map[string]string, len(aliases))
	for _, alias := range aliases {
		if canonicalToProfile {
			result[alias.canonical] = alias.profile
		} else {
			result[alias.profile] = alias.canonical
		}
	}
	return result
}

type flagGroupKey struct {
	word string
	bit  uint8
}

func atomicFlagGroupObligations(layer int, direction LayerObligationDirection, source, target *semantic.Definition, aliases map[string]string) []LayerObligation {
	groups := make(map[flagGroupKey][]semantic.FieldShape)
	for _, field := range target.Fields {
		if field.Kind == semantic.FieldValue && field.Condition != nil {
			key := flagGroupKey{word: field.Condition.Word, bit: field.Condition.Bit}
			groups[key] = append(groups[key], field)
		}
	}
	keys := make([]flagGroupKey, 0, len(groups))
	for key, fields := range groups {
		if len(fields) > 1 {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].word != keys[j].word {
			return keys[i].word < keys[j].word
		}
		return keys[i].bit < keys[j].bit
	})

	sourceFields := valueFieldMap(source)
	var result []LayerObligation
	for _, key := range keys {
		fields := groups[key]
		var expected string
		compatible := true
		names := make([]string, 0, len(fields))
		for i, field := range fields {
			names = append(names, field.Name)
			sourceName := field.Name
			for candidate, mapped := range aliases {
				if mapped == field.Name {
					sourceName = candidate
					break
				}
			}
			presence := fieldPresence(sourceFields[sourceName])
			if i == 0 {
				expected = presence
			} else if presence != expected {
				compatible = false
			}
		}
		if compatible {
			continue
		}
		sort.Strings(names)
		result = append(result, makeLayerObligation(LayerObligation{
			Kind:          LayerObligationAtomicFlagGroup,
			Layer:         layer,
			Direction:     direction,
			Semantic:      source.Key,
			OtherSemantic: target.Key,
			WireID:        source.WireID,
			OtherWireID:   target.WireID,
			FlagWord:      key.word,
			FlagBit:       key.bit,
			Fields:        names,
			SourceShape:   source.SemanticShape,
			TargetShape:   target.SemanticShape,
		}))
	}
	return result
}

func fieldPresence(field semantic.FieldShape) string {
	if field.Name == "" {
		return "absent"
	}
	if field.Condition == nil {
		return "required"
	}
	return fmt.Sprintf("conditional:%s:%d", field.Condition.Word, field.Condition.Bit)
}

func valueFieldMap(definition *semantic.Definition) map[string]semantic.FieldShape {
	result := make(map[string]semantic.FieldShape, len(definition.Fields))
	for _, field := range definition.Fields {
		if field.Kind == semantic.FieldValue {
			result[field.Name] = field
		}
	}
	return result
}

func findValueField(definition *semantic.Definition, name string) *semantic.FieldShape {
	for i := range definition.Fields {
		if definition.Fields[i].Kind == semantic.FieldValue && definition.Fields[i].Name == name {
			return &definition.Fields[i]
		}
	}
	return nil
}

func fieldTypeString(field *semantic.FieldShape) string {
	if field == nil {
		return ""
	}
	return field.Type.String()
}

func applyLayerObligationPolicy(obligations []LayerObligation, policy LayerObligationPolicy) (LayerObligationReport, error) {
	index := make(map[LayerObligationKey]int, len(obligations))
	for i := range obligations {
		index[obligations[i].Key] = i
	}
	seen := make(map[LayerObligationKey]struct{}, len(policy.Entries))
	for _, entry := range policy.Entries {
		if _, duplicate := seen[entry.Key]; duplicate {
			return LayerObligationReport{}, fmt.Errorf("gen: E_DUPLICATE_LAYER_POLICY: key %q is repeated", entry.Key)
		}
		seen[entry.Key] = struct{}{}
		obligationIndex, ok := index[entry.Key]
		if !ok {
			return LayerObligationReport{}, fmt.Errorf("gen: E_STALE_LAYER_POLICY: key %q does not match a generated obligation", entry.Key)
		}
		if err := validateLayerObligationResolution(obligations[obligationIndex].Kind, entry.Resolution); err != nil {
			return LayerObligationReport{}, fmt.Errorf("gen: E_INVALID_LAYER_POLICY: key %q: %w", entry.Key, err)
		}
		obligations[obligationIndex].Resolution = entry.Resolution
	}
	return LayerObligationReport{Obligations: obligations}, nil
}

func validateLayerObligationResolution(kind LayerObligationKind, resolution LayerObligationResolution) error {
	allowed := false
	switch kind {
	case LayerObligationAlias:
		allowed = resolution.Action == LayerResolveAlias || resolution.Action == LayerResolveAdapter || resolution.Action == LayerResolveReject
	case LayerObligationRequired:
		allowed = resolution.Action == LayerResolveDefault || resolution.Action == LayerResolveAdapter || resolution.Action == LayerResolveReject
	case LayerObligationIncompatible, LayerObligationAtomicFlagGroup, LayerObligationResult:
		allowed = resolution.Action == LayerResolveAdapter || resolution.Action == LayerResolveReject
	case LayerObligationOldOnly:
		allowed = resolution.Action == LayerResolveAlias || resolution.Action == LayerResolveAdapter || resolution.Action == LayerResolveReject
	case LayerObligationNewOnly:
		allowed = resolution.Action == LayerResolveUnavailable || resolution.Action == LayerResolveDrop ||
			resolution.Action == LayerResolveProject || resolution.Action == LayerResolveReject
	case LayerObligationUpdateProjection:
		allowed = resolution.Action == LayerResolveDrop || resolution.Action == LayerResolveProject || resolution.Action == LayerResolveReject
	case LayerObligationPrivate:
		allowed = resolution.Action == LayerResolveAllow || resolution.Action == LayerResolveReject
	}
	if !allowed {
		return fmt.Errorf("action %q is not valid for %s", resolution.Action, kind)
	}
	requiresHook := resolution.Action == LayerResolveAdapter || resolution.Action == LayerResolveProject || resolution.Action == LayerResolveAlias
	hook := strings.TrimSpace(resolution.Hook)
	if requiresHook {
		if !token.IsIdentifier(hook) || token.Lookup(hook).IsKeyword() {
			return fmt.Errorf("action %q requires a non-keyword Go hook identifier", resolution.Action)
		}
	} else if hook != "" {
		return fmt.Errorf("action %q does not accept hook %q", resolution.Action, hook)
	}
	return nil
}

func makeLayerObligation(obligation LayerObligation) LayerObligation {
	obligation.Key = obligationDigestKey(obligation)
	return obligation
}

func obligationDigestKey(obligation LayerObligation) LayerObligationKey {
	w := &obligationHashWriter{h: sha256.New()}
	w.string("gotd.tl.layer-obligation.v1")
	w.string(string(obligation.Kind))
	w.integer(obligation.Layer)
	w.string(string(obligation.Direction))
	w.string(obligation.Semantic.String())
	w.string(obligation.OtherSemantic.String())
	w.uint32(obligation.WireID)
	w.uint32(obligation.OtherWireID)
	w.string(obligation.Field)
	w.string(obligation.OtherField)
	w.string(obligation.FlagWord)
	w.uint32(uint32(obligation.FlagBit))
	w.integer(len(obligation.Fields))
	for _, field := range obligation.Fields {
		w.string(field)
	}
	w.string(obligation.SourceType)
	w.string(obligation.TargetType)
	w.string(obligation.SourceShape.String())
	w.string(obligation.TargetShape.String())
	return LayerObligationKey(fmt.Sprintf("layer-obligation/v1/%s/%s", obligation.Kind, hex.EncodeToString(w.h.Sum(nil))))
}

type obligationHashWriter struct {
	h hash.Hash
}

func (w *obligationHashWriter) uint64(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	_, _ = w.h.Write(data[:])
}

func (w *obligationHashWriter) uint32(value uint32) {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	_, _ = w.h.Write(data[:])
}

func (w *obligationHashWriter) integer(value int) {
	w.uint64(uint64(value))
}

func (w *obligationHashWriter) string(value string) {
	w.uint64(uint64(len(value)))
	_, _ = w.h.Write([]byte(value))
}
