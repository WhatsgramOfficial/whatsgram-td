package semantic

import (
	"fmt"
	"sort"

	"github.com/gotd/tl"
)

// Variant is one distinct wire/signature form of a semantic definition.
// Layers can be non-contiguous; callers must not infer ranges from endpoints.
type Variant struct {
	WireID         uint32
	BodyShape      ShapeDigest
	SignatureShape ShapeDigest
	Definition     *Definition
	Layers         []int
}

// Family groups the same category-qualified definition across layers.
type Family struct {
	Key      DefinitionKey
	ByLayer  map[int]*Definition
	Variants []*Variant
}

// Universe is the validated collection of all supported layer schemas.
type Universe struct {
	CanonicalLayer int
	Schemas        map[int]*SchemaModel
	Families       map[DefinitionKey]*Family
	ByWire         map[int]map[uint32]*Definition
	SemanticDigest ShapeDigest
}

// NewUniverse validates layer identity and groups definitions by semantic key.
func NewUniverse(canonicalLayer int, schemas ...*SchemaModel) (*Universe, error) {
	if canonicalLayer <= 0 {
		return nil, fmt.Errorf("semantic: invalid canonical layer %d", canonicalLayer)
	}
	u := &Universe{
		CanonicalLayer: canonicalLayer,
		Schemas:        make(map[int]*SchemaModel, len(schemas)),
		Families:       make(map[DefinitionKey]*Family),
		ByWire:         make(map[int]map[uint32]*Definition, len(schemas)),
	}
	for _, schema := range schemas {
		if schema == nil {
			return nil, fmt.Errorf("semantic: nil schema in universe")
		}
		if schema.Layer <= 0 {
			return nil, fmt.Errorf("semantic: invalid schema layer %d", schema.Layer)
		}
		if _, duplicate := u.Schemas[schema.Layer]; duplicate {
			return nil, fmt.Errorf("semantic: duplicate schema layer %d", schema.Layer)
		}
		u.Schemas[schema.Layer] = schema
		u.ByWire[schema.Layer] = schema.ByWire
	}
	if _, ok := u.Schemas[canonicalLayer]; !ok {
		return nil, fmt.Errorf("semantic: canonical layer %d is not loaded", canonicalLayer)
	}

	layers := u.Layers()
	for _, layer := range layers {
		for _, definition := range u.Schemas[layer].Definitions {
			family := u.Families[definition.Key]
			if family == nil {
				family = &Family{
					Key:     definition.Key,
					ByLayer: make(map[int]*Definition),
				}
				u.Families[definition.Key] = family
			}
			family.ByLayer[layer] = definition

			var variant *Variant
			for _, candidate := range family.Variants {
				if candidate.WireID == definition.WireID && candidate.SignatureShape == definition.SignatureShape {
					variant = candidate
					break
				}
			}
			if variant == nil {
				variant = &Variant{
					WireID:         definition.WireID,
					BodyShape:      definition.BodyShape,
					SignatureShape: definition.SignatureShape,
					Definition:     definition,
				}
				family.Variants = append(family.Variants, variant)
			}
			variant.Layers = append(variant.Layers, layer)
		}
	}
	u.SemanticDigest = universeDigest(u, layers)
	return u, nil
}

// Layers returns supported layers in ascending order.
func (u *Universe) Layers() []int {
	layers := make([]int, 0, len(u.Schemas))
	for layer := range u.Schemas {
		layers = append(layers, layer)
	}
	sort.Ints(layers)
	return layers
}

// CanonicalSchema returns a deep copy suitable for the existing Go backend.
// Mutating the returned schema cannot alter the Universe.
func (u *Universe) CanonicalSchema() *tl.Schema {
	return cloneSchema(u.Schemas[u.CanonicalLayer].raw)
}

func universeDigest(u *Universe, layers []int) ShapeDigest {
	w := newShapeWriter("gotd.tl.semantic.universe.v1")
	w.uint64(uint64(u.CanonicalLayer))
	w.uint64(uint64(len(layers)))
	for _, layer := range layers {
		schema := u.Schemas[layer]
		w.uint64(uint64(layer))
		w.digest(schema.Source.SHA256)
		w.uint64(uint64(len(schema.Definitions)))
		for _, definition := range schema.Definitions {
			w.byte(byte(definition.Key.Category))
			w.string(definition.Key.QName)
			w.uint64(uint64(definition.WireID))
			w.digest(definition.SignatureShape)
		}
	}
	return w.sum()
}

// DefinitionChange compares one shared semantic definition with canonical.
type DefinitionChange struct {
	Key           DefinitionKey
	Target        *Definition
	Canonical     *Definition
	WireIDChanged bool
	BodyChanged   bool
	ResultChanged bool
}

// SignatureChanged reports whether fields or result TypeRef changed. Wire ID
// is intentionally independent: equal IDs do not imply equal signatures.
func (c DefinitionChange) SignatureChanged() bool {
	return c.BodyChanged || c.ResultChanged
}

// ResultOnly reports a method/type whose body is stable but result TypeRef is
// different. Such RPC methods require method-aware result encoding.
func (c DefinitionChange) ResultOnly() bool {
	return !c.BodyChanged && c.ResultChanged
}

// SameWireSignatureChanged identifies the same-ID/different-shape class of
// compatibility bug.
func (c DefinitionChange) SameWireSignatureChanged() bool {
	return !c.WireIDChanged && c.SignatureChanged()
}

// Difference is a target-layer comparison against canonical.
type Difference struct {
	Layer         int
	Changes       []DefinitionChange
	CanonicalOnly []*Definition
	OldOnly       []*Definition
}

// Diff compares a supported target layer against canonical by semantic key.
func (u *Universe) Diff(layer int) (Difference, error) {
	target, ok := u.Schemas[layer]
	if !ok {
		return Difference{}, fmt.Errorf("semantic: layer %d is not loaded", layer)
	}
	canonical := u.Schemas[u.CanonicalLayer]
	result := Difference{Layer: layer}
	for _, current := range canonical.Definitions {
		old, exists := target.ByKey[current.Key]
		if !exists {
			result.CanonicalOnly = append(result.CanonicalOnly, current)
			continue
		}
		change := DefinitionChange{
			Key:           current.Key,
			Target:        old,
			Canonical:     current,
			WireIDChanged: old.WireID != current.WireID,
			BodyChanged:   old.BodyShape != current.BodyShape,
			ResultChanged: !old.Result.Equal(current.Result),
		}
		if change.WireIDChanged || change.SignatureChanged() {
			result.Changes = append(result.Changes, change)
		}
	}
	for _, old := range target.Definitions {
		if _, exists := canonical.ByKey[old.Key]; !exists {
			result.OldOnly = append(result.OldOnly, old)
		}
	}
	return result, nil
}

// SignatureChanges returns changes whose fields and/or result differ.
func (d Difference) SignatureChanges() []DefinitionChange {
	result := make([]DefinitionChange, 0, len(d.Changes))
	for _, change := range d.Changes {
		if change.SignatureChanged() {
			result = append(result, change)
		}
	}
	return result
}

// SameWireSignatureChanges returns all same-ID/different-shape changes.
func (d Difference) SameWireSignatureChanges() []DefinitionChange {
	result := make([]DefinitionChange, 0, len(d.Changes))
	for _, change := range d.Changes {
		if change.SameWireSignatureChanged() {
			result = append(result, change)
		}
	}
	return result
}

// ResultOnlyChanges returns all body-stable/result-changing definitions.
func (d Difference) ResultOnlyChanges() []DefinitionChange {
	result := make([]DefinitionChange, 0, len(d.Changes))
	for _, change := range d.Changes {
		if change.ResultOnly() {
			result = append(result, change)
		}
	}
	return result
}
