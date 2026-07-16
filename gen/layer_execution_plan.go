package gen

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"sort"

	"github.com/iamxvbaba/td/gen/semantic"
)

// layerExecutionMode is the runtime amount of work for one exact route. It is
// deliberately distinct from wire IDs: IDs select plans but never identify
// plan bodies.
type layerExecutionMode uint8

const (
	layerExecutionDirect layerExecutionMode = iota
	layerExecutionRetag
	layerExecutionRewrite
	layerExecutionUnavailable
	layerExecutionPolicy
	layerExecutionProfileOnly
)

func (m layerExecutionMode) String() string {
	switch m {
	case layerExecutionDirect:
		return "direct"
	case layerExecutionRetag:
		return "retag"
	case layerExecutionRewrite:
		return "rewrite"
	case layerExecutionUnavailable:
		return "unavailable"
	case layerExecutionPolicy:
		return "policy"
	case layerExecutionProfileOnly:
		return "profile-only"
	default:
		return fmt.Sprintf("layerExecutionMode(%d)", m)
	}
}

type layerExecutionDigest [sha256.Size]byte

// layerExecutionRoute is the compact generated routing fact for one admitted
// schema definition. BodyPlan is -1 only for canonical-direct routes.
type layerExecutionRoute struct {
	Layer         int
	Key           semantic.SemanticKey
	WireID        uint32
	Mode          layerExecutionMode
	BodyPlan      int
	PreflightPlan int
	ResultPlan    int
}

// layerExecutionPlan is one emitted body shared by every route with the same
// complete execution digest.
type layerExecutionPlan struct {
	ID       int
	Digest   layerExecutionDigest
	Mode     layerExecutionMode
	Semantic semantic.SemanticKey
	Routes   []layerExecutionRoute
}

// layerPreflightPlan is a non-materializing request scanner. It is separate
// from a body codec because direct canonical requests still require bounded
// validation before the canonical decoder may allocate.
type layerPreflightPlan struct {
	ID     int
	Digest layerExecutionDigest
	Routes []layerExecutionRoute
}

// layerResultExecutionPlan freezes a complete method result TypeRef graph.
// Result plans intentionally deduplicate across unrelated methods when their
// canonical/profile TypeRefs and transitive routes are identical.
type layerResultExecutionPlan struct {
	ID     int
	Digest layerExecutionDigest
	Routes []layerExecutionRoute
}

type layerExecutionModel struct {
	CanonicalLayer int
	Profiles       []int
	Routes         []layerExecutionRoute
	BodyPlans      []layerExecutionPlan
	PreflightPlans []layerPreflightPlan
	ResultPlans    []layerResultExecutionPlan
}

type layerExecutionHasher struct {
	h hash.Hash
}

func newLayerExecutionHasher(domain string) *layerExecutionHasher {
	w := &layerExecutionHasher{h: sha256.New()}
	w.string(domain)
	return w
}

func (w *layerExecutionHasher) uint64(v uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], v)
	_, _ = w.h.Write(data[:])
}

func (w *layerExecutionHasher) string(v string) {
	w.uint64(uint64(len(v)))
	_, _ = w.h.Write([]byte(v))
}

func (w *layerExecutionHasher) bytes(v []byte) {
	w.uint64(uint64(len(v)))
	_, _ = w.h.Write(v)
}

func (w *layerExecutionHasher) digest(v layerExecutionDigest) {
	_, _ = w.h.Write(v[:])
}

func (w *layerExecutionHasher) sum() (out layerExecutionDigest) {
	copy(out[:], w.h.Sum(nil))
	return out
}

type layerExecutionDraft struct {
	digest   layerExecutionDigest
	mode     layerExecutionMode
	semantic semantic.SemanticKey
	routes   []int
}

func (g *Generator) buildLayerExecutionModel() (*layerExecutionModel, error) {
	if g == nil || g.schemaSet == nil || g.layerPlan == nil {
		return nil, fmt.Errorf("gen: layer execution model requires a schema-set conversion plan")
	}
	wire, err := g.buildLayerWireModel()
	if err != nil {
		return nil, fmt.Errorf("gen: layer execution wire model: %w", err)
	}

	model := &layerExecutionModel{
		CanonicalLayer: g.schemaSet.CanonicalLayer,
		Profiles:       append([]int(nil), wire.Profiles...),
	}
	bodyDrafts := make(map[layerExecutionDigest]*layerExecutionDraft)
	preflightDrafts := make(map[layerExecutionDigest]*layerExecutionDraft)
	resultDrafts := make(map[layerExecutionDigest]*layerExecutionDraft)

	for familyIndex := range wire.Families {
		family := &wire.Families[familyIndex]
		for actionIndex := range family.Profiles {
			action := &family.Profiles[actionIndex]
			if action.Conversion == nil || action.Conversion.Profile == nil {
				continue
			}
			mode, err := layerExecutionModeForWire(action.Kind)
			if err != nil {
				return nil, fmt.Errorf("gen: layer %d family %s: %w", action.Layer, family.Key, err)
			}
			route := layerExecutionRoute{
				Layer:         action.Layer,
				Key:           family.Key,
				WireID:        action.Conversion.Profile.Definition.WireID,
				Mode:          mode,
				BodyPlan:      -1,
				PreflightPlan: -1,
				ResultPlan:    -1,
			}
			routeIndex := len(model.Routes)
			model.Routes = append(model.Routes, route)

			if mode != layerExecutionDirect {
				digest, err := g.layerBodyExecutionDigest(action.Layer, family.Key, mode, action.Conversion)
				if err != nil {
					return nil, err
				}
				draft := bodyDrafts[digest]
				if draft == nil {
					draft = &layerExecutionDraft{digest: digest, mode: mode, semantic: family.Key}
					bodyDrafts[digest] = draft
				}
				draft.routes = append(draft.routes, routeIndex)
			}

			if family.Key.Category == semantic.CategoryFunction {
				digest, err := g.layerPreflightExecutionDigest(action.Layer, family.Key, action.Conversion)
				if err != nil {
					return nil, err
				}
				draft := preflightDrafts[digest]
				if draft == nil {
					draft = &layerExecutionDraft{digest: digest, semantic: family.Key}
					preflightDrafts[digest] = draft
				}
				draft.routes = append(draft.routes, routeIndex)

				if action.Conversion.Canonical != nil {
					resultDigest, err := g.layerResultExecutionDigest(action.Layer, family.Key, action.Conversion)
					if err != nil {
						return nil, err
					}
					resultDraft := resultDrafts[resultDigest]
					if resultDraft == nil {
						resultDraft = &layerExecutionDraft{digest: resultDigest}
						resultDrafts[resultDigest] = resultDraft
					}
					resultDraft.routes = append(resultDraft.routes, routeIndex)
				}
			}
		}
	}

	model.BodyPlans = materializeLayerBodyPlans(bodyDrafts, model.Routes)
	model.PreflightPlans = materializeLayerPreflightPlans(preflightDrafts, model.Routes)
	model.ResultPlans = materializeLayerResultPlans(resultDrafts, model.Routes)
	for index := range model.Routes {
		route := &model.Routes[index]
		if route.Mode != layerExecutionDirect && route.BodyPlan < 0 {
			return nil, fmt.Errorf("gen: layer %d route %s has no body execution plan", route.Layer, route.Key)
		}
		if route.Key.Category == semantic.CategoryFunction && route.PreflightPlan < 0 {
			return nil, fmt.Errorf("gen: layer %d method %s has no preflight execution plan", route.Layer, route.Key)
		}
	}
	return model, nil
}

func layerExecutionModeForWire(kind layerWireActionKind) (layerExecutionMode, error) {
	switch kind {
	case layerWireDirect:
		return layerExecutionDirect, nil
	case layerWireRetag:
		return layerExecutionRetag, nil
	case layerWireRewrite:
		return layerExecutionRewrite, nil
	case layerWireUnavailable, layerWireAbsent:
		return layerExecutionUnavailable, nil
	case layerWirePolicy:
		return layerExecutionPolicy, nil
	case layerWireProfileOnly:
		return layerExecutionProfileOnly, nil
	default:
		return 0, fmt.Errorf("unsupported wire action %s", kind)
	}
}

func (g *Generator) layerBodyExecutionDigest(layer int, key semantic.SemanticKey, mode layerExecutionMode, conversion *LayerFamilyConversion) (layerExecutionDigest, error) {
	w := newLayerExecutionHasher("gotd.tlprofile.body-plan.v1")
	w.uint64(uint64(mode))
	w.string(key.String())
	writeLayerConversionDigest(w, conversion, false)
	transitive, err := layerTransitiveDefinitionDigest(g.schemaSet.Schemas[layer], conversion.Profile.Definition)
	if err != nil {
		return layerExecutionDigest{}, fmt.Errorf("gen: layer %d body plan %s: %w", layer, key, err)
	}
	w.digest(transitive)
	return w.sum(), nil
}

func (g *Generator) layerPreflightExecutionDigest(layer int, key semantic.SemanticKey, conversion *LayerFamilyConversion) (layerExecutionDigest, error) {
	w := newLayerExecutionHasher("gotd.tlprofile.preflight-plan.v1")
	// Field callbacks and method-specific limits are keyed by semantic method,
	// so unrelated methods must not accidentally share a scanner contract.
	w.string(key.String())
	w.bytes(conversion.Profile.Definition.WireShape[:])
	transitive, err := layerTransitiveDefinitionDigest(g.schemaSet.Schemas[layer], conversion.Profile.Definition)
	if err != nil {
		return layerExecutionDigest{}, fmt.Errorf("gen: layer %d preflight plan %s: %w", layer, key, err)
	}
	w.digest(transitive)
	return w.sum(), nil
}

func (g *Generator) layerResultExecutionDigest(layer int, key semantic.SemanticKey, conversion *LayerFamilyConversion) (layerExecutionDigest, error) {
	w := newLayerExecutionHasher("gotd.tlprofile.result-plan.v1")
	w.string(conversion.Canonical.Definition.Result.String())
	w.string(conversion.Profile.Definition.Result.String())
	if layerTypeRefDynamic(conversion.Canonical.Definition.Result) || layerTypeRefDynamic(conversion.Profile.Definition.Result) {
		// Generic slots are owner-scoped. Keep wrapper result plans separate even
		// when they use the same spelling such as !X.
		w.string(key.String())
	}
	writeLayerConversionDigest(w, conversion, true)
	canonicalDigest, err := layerTransitiveTypeRefDigest(g.schemaSet.Schemas[g.schemaSet.CanonicalLayer], conversion.Canonical.Definition.Result)
	if err != nil {
		return layerExecutionDigest{}, fmt.Errorf("gen: canonical result plan %s: %w", key, err)
	}
	profileDigest, err := layerTransitiveTypeRefDigest(g.schemaSet.Schemas[layer], conversion.Profile.Definition.Result)
	if err != nil {
		return layerExecutionDigest{}, fmt.Errorf("gen: layer %d result plan %s: %w", layer, key, err)
	}
	w.digest(canonicalDigest)
	w.digest(profileDigest)
	return w.sum(), nil
}

func writeLayerConversionDigest(w *layerExecutionHasher, conversion *LayerFamilyConversion, resultOnly bool) {
	if conversion == nil {
		w.string("nil")
		return
	}
	w.uint64(uint64(conversion.Availability))
	if !resultOnly {
		w.uint64(uint64(len(conversion.Fields)))
		for _, field := range conversion.Fields {
			w.uint64(uint64(field.CanonicalOrdinal + 1))
			w.uint64(uint64(field.ProfileOrdinal + 1))
			w.string(field.CanonicalName)
			w.string(field.ProfileName)
		}
	}
	obligations := conversion.Obligations
	w.uint64(uint64(len(obligations)))
	for _, obligation := range obligations {
		isResult := obligation.Kind == LayerObligationResult
		if resultOnly != isResult {
			continue
		}
		w.string(string(obligation.Key))
		w.string(string(obligation.Kind))
		w.string(string(obligation.Direction))
		w.string(string(obligation.Resolution.Action))
		w.string(obligation.Resolution.Hook)
		w.string(obligation.Resolution.Target)
	}
}

func layerTypeRefDynamic(ref semantic.TypeRef) bool {
	if ref.Kind == semantic.TypeGenericRef || (ref.Kind == semantic.TypePrimitive && ref.QName == "Object") {
		return true
	}
	return ref.Arg != nil && layerTypeRefDynamic(*ref.Arg)
}

func layerTransitiveDefinitionDigest(schema *semantic.SchemaModel, root *semantic.Definition) (layerExecutionDigest, error) {
	if schema == nil || root == nil {
		return layerExecutionDigest{}, fmt.Errorf("nil schema or definition")
	}
	return layerTransitiveGraphDigest(schema, []semantic.SemanticKey{root.Key})
}

func layerTransitiveTypeRefDigest(schema *semantic.SchemaModel, ref semantic.TypeRef) (layerExecutionDigest, error) {
	if schema == nil {
		return layerExecutionDigest{}, fmt.Errorf("nil schema")
	}
	keys := make(map[semantic.SemanticKey]struct{})
	dynamic := collectLayerExecutionTypeDependencies(schema, ref, keys)
	if dynamic {
		for _, definition := range schema.Definitions {
			keys[definition.Key] = struct{}{}
		}
	}
	ordered := make([]semantic.SemanticKey, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sortSemanticKeys(ordered)
	w := newLayerExecutionHasher("gotd.tlprofile.typeref-closure.v1")
	w.string(ref.String())
	digest, err := layerTransitiveGraphDigest(schema, ordered)
	if err != nil {
		return layerExecutionDigest{}, err
	}
	w.digest(digest)
	return w.sum(), nil
}

// layerTransitiveGraphDigest hashes the sorted reachable subgraph instead of
// recursively hashing nodes. This is cycle-safe and still captures exact
// constructor membership, IDs, local physical shapes and dependency edges.
func layerTransitiveGraphDigest(schema *semantic.SchemaModel, roots []semantic.SemanticKey) (layerExecutionDigest, error) {
	seen := make(map[semantic.SemanticKey]struct{})
	queue := append([]semantic.SemanticKey(nil), roots...)
	for head := 0; head < len(queue); head++ {
		key := queue[head]
		if _, ok := seen[key]; ok {
			continue
		}
		definition := schema.ByKey[key]
		if definition == nil {
			return layerExecutionDigest{}, fmt.Errorf("definition %s is absent from layer %d", key, schema.Layer)
		}
		seen[key] = struct{}{}
		dependencies := make(map[semantic.SemanticKey]struct{})
		dynamic := false
		for _, field := range definition.Fields {
			if field.Kind == semantic.FieldValue {
				dynamic = collectLayerExecutionTypeDependencies(schema, field.Type, dependencies) || dynamic
			}
		}
		if dynamic {
			for _, candidate := range schema.Definitions {
				dependencies[candidate.Key] = struct{}{}
			}
		}
		ordered := make([]semantic.SemanticKey, 0, len(dependencies))
		for dependency := range dependencies {
			ordered = append(ordered, dependency)
		}
		sortSemanticKeys(ordered)
		queue = append(queue, ordered...)
	}

	keys := make([]semantic.SemanticKey, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sortSemanticKeys(keys)
	w := newLayerExecutionHasher("gotd.tlprofile.transitive-graph.v1")
	w.uint64(uint64(len(keys)))
	for _, key := range keys {
		definition := schema.ByKey[key]
		w.string(key.String())
		w.uint64(uint64(definition.WireID))
		w.bytes(definition.WireShape[:])
		w.bytes(definition.BodyShape[:])
		dependencies := make(map[semantic.SemanticKey]struct{})
		dynamic := false
		for _, field := range definition.Fields {
			if field.Kind == semantic.FieldValue {
				dynamic = collectLayerExecutionTypeDependencies(schema, field.Type, dependencies) || dynamic
			}
		}
		if dynamic {
			for _, candidate := range schema.Definitions {
				dependencies[candidate.Key] = struct{}{}
			}
		}
		ordered := make([]semantic.SemanticKey, 0, len(dependencies))
		for dependency := range dependencies {
			ordered = append(ordered, dependency)
		}
		sortSemanticKeys(ordered)
		w.uint64(uint64(len(ordered)))
		for _, dependency := range ordered {
			w.string(dependency.String())
		}
	}
	return w.sum(), nil
}

func collectLayerExecutionTypeDependencies(schema *semantic.SchemaModel, ref semantic.TypeRef, out map[semantic.SemanticKey]struct{}) bool {
	switch ref.Kind {
	case semantic.TypeVector:
		if ref.Arg != nil {
			return collectLayerExecutionTypeDependencies(schema, *ref.Arg, out)
		}
	case semantic.TypeNamed:
		if ref.Bare || ref.Percent {
			key := semantic.SemanticKey{Category: semantic.CategoryType, QName: ref.QName}
			if schema.ByKey[key] != nil {
				out[key] = struct{}{}
			}
			return false
		}
		constructors := schema.ConstructorsByClass[ref.QName]
		if len(constructors) == 0 {
			key := semantic.SemanticKey{Category: semantic.CategoryType, QName: ref.QName}
			if schema.ByKey[key] != nil {
				out[key] = struct{}{}
			}
			return false
		}
		for _, key := range constructors {
			out[key] = struct{}{}
		}
	case semantic.TypeGenericRef:
		return true
	case semantic.TypePrimitive:
		return ref.QName == "Object"
	}
	return false
}

func sortedLayerExecutionDrafts(drafts map[layerExecutionDigest]*layerExecutionDraft) []*layerExecutionDraft {
	result := make([]*layerExecutionDraft, 0, len(drafts))
	for _, draft := range drafts {
		result = append(result, draft)
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].digest[:], result[j].digest[:]) < 0
	})
	return result
}

func materializeLayerBodyPlans(drafts map[layerExecutionDigest]*layerExecutionDraft, routes []layerExecutionRoute) []layerExecutionPlan {
	ordered := sortedLayerExecutionDrafts(drafts)
	result := make([]layerExecutionPlan, 0, len(ordered))
	for id, draft := range ordered {
		plan := layerExecutionPlan{ID: id, Digest: draft.digest, Mode: draft.mode, Semantic: draft.semantic}
		for _, routeIndex := range draft.routes {
			routes[routeIndex].BodyPlan = id
			plan.Routes = append(plan.Routes, routes[routeIndex])
		}
		result = append(result, plan)
	}
	return result
}

func materializeLayerPreflightPlans(drafts map[layerExecutionDigest]*layerExecutionDraft, routes []layerExecutionRoute) []layerPreflightPlan {
	ordered := sortedLayerExecutionDrafts(drafts)
	result := make([]layerPreflightPlan, 0, len(ordered))
	for id, draft := range ordered {
		plan := layerPreflightPlan{ID: id, Digest: draft.digest}
		for _, routeIndex := range draft.routes {
			routes[routeIndex].PreflightPlan = id
			plan.Routes = append(plan.Routes, routes[routeIndex])
		}
		result = append(result, plan)
	}
	return result
}

func materializeLayerResultPlans(drafts map[layerExecutionDigest]*layerExecutionDraft, routes []layerExecutionRoute) []layerResultExecutionPlan {
	ordered := sortedLayerExecutionDrafts(drafts)
	result := make([]layerResultExecutionPlan, 0, len(ordered))
	for id, draft := range ordered {
		plan := layerResultExecutionPlan{ID: id, Digest: draft.digest}
		for _, routeIndex := range draft.routes {
			routes[routeIndex].ResultPlan = id
			plan.Routes = append(plan.Routes, routes[routeIndex])
		}
		result = append(result, plan)
	}
	return result
}
