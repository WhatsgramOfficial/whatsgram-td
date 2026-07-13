package tg

import (
	"testing"

	"github.com/gotd/td/bin"
)

var layerBenchmarkValue = &UpdateUserStatus{
	UserID: 42,
	Status: &UserStatusOnline{Expires: 1_900_000_000},
}

var layerBenchmarkDecoded *UpdateUserStatus

func BenchmarkLayerEncodeUpdateUserStatus(b *testing.B) {
	typ := LayerConstructorUpdateUserStatusType()
	for _, profile := range []LayerProfile{LayerProfile220, LayerProfile227} {
		b.Run(layerBenchmarkProfileName(profile), func(b *testing.B) {
			var encoded bin.Buffer
			b.ReportAllocs()
			for b.Loop() {
				encoded.Reset()
				if err := EncodeLayer(profile, typ, layerBenchmarkValue, &encoded); err != nil {
					b.Fatal(err)
				}
			}
			b.SetBytes(int64(encoded.Len()))
		})
	}
}

func BenchmarkLayerDecodeUpdateUserStatus(b *testing.B) {
	typ := LayerConstructorUpdateUserStatusType()
	for _, profile := range []LayerProfile{LayerProfile220, LayerProfile227} {
		var encoded bin.Buffer
		if err := EncodeLayer(profile, typ, layerBenchmarkValue, &encoded); err != nil {
			b.Fatal(err)
		}
		wire := encoded.Copy()
		b.Run(layerBenchmarkProfileName(profile), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				input := bin.Buffer{Buf: wire}
				value, err := DecodeLayer(profile, typ, &input)
				if err != nil || input.Len() != 0 {
					b.Fatalf("decode: remaining=%d err=%v", input.Len(), err)
				}
				layerBenchmarkDecoded = value
			}
			b.SetBytes(int64(len(wire)))
		})
	}
}

func BenchmarkLayerPreparedFanout(b *testing.B) {
	typ := LayerConstructorUpdateUserStatusType()
	frozen, err := FreezeLayer(typ, layerBenchmarkValue)
	if err != nil {
		b.Fatal(err)
	}
	for _, profile := range []LayerProfile{LayerProfile220, LayerProfile227} {
		prepared, err := PrepareFrozenLayer(profile, frozen)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(layerBenchmarkProfileName(profile), func(b *testing.B) {
			var encoded bin.Buffer
			b.ReportAllocs()
			for b.Loop() {
				encoded.Reset()
				if err := prepared.Encode(profile, typ, &encoded); err != nil {
					b.Fatal(err)
				}
			}
			b.SetBytes(int64(prepared.WireSize()))
		})
	}
}

func layerBenchmarkProfileName(profile LayerProfile) string {
	if profile == LayerProfile220 {
		return "layer_220"
	}
	return "layer_227"
}
