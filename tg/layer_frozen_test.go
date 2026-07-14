package tg

import (
	"bytes"
	"testing"

	"github.com/iamxvbaba/td/bin"
)

type layerFrozenProbe struct {
	Value int
}

func TestPrepareFrozenLayerUsesOnlyProvenWireEquivalentFastPath(t *testing.T) {
	ref := &LayerTypeRef{kind: LayerTypePrimitive, qname: "test.frozen.probe"}
	encodeCalls := 0
	decodeCalls := 0
	typ := LayerType[*layerFrozenProbe]{
		ref: ref,
		preflight: func(LayerProfile, *layerFrozenProbe) (int, error) {
			return 1, nil
		},
		encode: func(profile LayerProfile, value *layerFrozenProbe, b *bin.Buffer) error {
			encodeCalls++
			encoded := value.Value
			if profile == LayerProfile226 {
				encoded += 1000
			}
			b.PutInt(encoded)
			return nil
		},
		decode: func(profile LayerProfile, b *bin.Buffer) (*layerFrozenProbe, error) {
			decodeCalls++
			value, err := b.Int()
			if err != nil {
				return nil, err
			}
			return &layerFrozenProbe{Value: value}, nil
		},
		decodeState: func(profile LayerProfile, b *bin.Buffer, _ *layerCodecState) (*layerFrozenProbe, error) {
			decodeCalls++
			value, err := b.Int()
			if err != nil {
				return nil, err
			}
			return &layerFrozenProbe{Value: value}, nil
		},
		wireEquivalent: func(profile LayerProfile) bool {
			return profile == LayerProfile225 || profile == LayerProfileCanonical
		},
	}

	source := &layerFrozenProbe{Value: 7}
	frozen, err := FreezeLayer(typ, source)
	if err != nil {
		t.Fatal(err)
	}
	if encodeCalls != 1 || decodeCalls != 0 {
		t.Fatalf("freeze calls = encode:%d decode:%d", encodeCalls, decodeCalls)
	}
	source.Value = 99

	canonical, err := PrepareFrozenLayer(LayerProfileCanonical, frozen)
	if err != nil {
		t.Fatal(err)
	}
	equivalent, err := PrepareFrozenLayer(LayerProfile225, frozen)
	if err != nil {
		t.Fatal(err)
	}
	if encodeCalls != 1 || decodeCalls != 0 {
		t.Fatalf("wire-equivalent prepare re-encoded: encode:%d decode:%d", encodeCalls, decodeCalls)
	}
	if got := preparedProbeValue(t, canonical, LayerProfileCanonical, typ); got != 7 {
		t.Fatalf("canonical prepared value = %d, want 7", got)
	}
	if got := preparedProbeValue(t, equivalent, LayerProfile225, typ); got != 7 {
		t.Fatalf("equivalent prepared value = %d, want 7", got)
	}

	canonical.body[0] = 8
	if got := frozenProbeValue(t, frozen.body); got != 7 {
		t.Fatalf("prepared snapshot aliases frozen body: %d", got)
	}
	if got := preparedProbeValue(t, equivalent, LayerProfile225, typ); got != 7 {
		t.Fatalf("prepared profile snapshots alias each other: %d", got)
	}

	rewritten, err := PrepareFrozenLayer(LayerProfile226, frozen)
	if err != nil {
		t.Fatal(err)
	}
	if encodeCalls != 2 || decodeCalls != 1 {
		t.Fatalf("non-equivalent prepare calls = encode:%d decode:%d, want 2/1", encodeCalls, decodeCalls)
	}
	if got := preparedProbeValue(t, rewritten, LayerProfile226, typ); got != 1007 {
		t.Fatalf("non-equivalent prepared value = %d, want 1007", got)
	}

	beforeEncode, beforeDecode := encodeCalls, decodeCalls
	if _, err := PrepareFrozenLayer(LayerProfile(999), frozen); err == nil {
		t.Fatal("unsupported profile was accepted")
	}
	if encodeCalls != beforeEncode || decodeCalls != beforeDecode {
		t.Fatal("unsupported profile reached a codec")
	}

	wrongType := typ
	wrongType.ref = &LayerTypeRef{kind: LayerTypePrimitive, qname: "test.frozen.other"}
	var target bin.Buffer
	if err := equivalent.Encode(LayerProfile225, wrongType, &target); err == nil || target.Len() != 0 {
		t.Fatalf("prepared snapshot accepted wrong TypeRef: bytes=%x err=%v", target.Raw(), err)
	}

	var first, second bin.Buffer
	if err := equivalent.Encode(LayerProfile225, typ, &first); err != nil {
		t.Fatal(err)
	}
	first.Buf[0] = 0xff
	if err := equivalent.Encode(LayerProfile225, typ, &second); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Raw(), second.Raw()) || frozenProbeValue(t, second.Raw()) != 7 {
		t.Fatal("prepared Encode exposed its immutable backing bytes")
	}
}

func preparedProbeValue(t *testing.T, prepared LayerPreparedValue[*layerFrozenProbe], profile LayerProfile, typ LayerType[*layerFrozenProbe]) int {
	t.Helper()
	var encoded bin.Buffer
	if err := prepared.Encode(profile, typ, &encoded); err != nil {
		t.Fatal(err)
	}
	return frozenProbeValue(t, encoded.Raw())
}

func frozenProbeValue(t *testing.T, encoded []byte) int {
	t.Helper()
	input := bin.Buffer{Buf: append([]byte(nil), encoded...)}
	value, err := input.Int()
	if err != nil || input.Len() != 0 {
		t.Fatalf("decode probe: remaining=%d err=%v", input.Len(), err)
	}
	return value
}
