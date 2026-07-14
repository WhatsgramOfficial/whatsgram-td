package tg

import (
	"fmt"
	"testing"

	"github.com/iamxvbaba/td/bin"
)

var layerBenchmarkValue = &UpdateUserStatus{
	UserID: 42,
	Status: &UserStatusOnline{Expires: 1_900_000_000},
}

var layerBenchmarkDecoded *UpdateUserStatus

var layerBenchmarkFanoutBytes int

var layerBenchmarkProfiles = []LayerProfile{
	LayerProfile225,
	LayerProfile226,
	LayerProfile227,
	LayerProfile228,
}

func BenchmarkLayerEncodeUpdateUserStatus(b *testing.B) {
	typ := LayerConstructorUpdateUserStatusType()
	for _, profile := range []LayerProfile{LayerProfile225, LayerProfile228} {
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
	for _, profile := range []LayerProfile{LayerProfile225, LayerProfile228} {
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
	for _, profile := range []LayerProfile{LayerProfile225, LayerProfile228} {
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

// BenchmarkLayerFrozenFanout models one immutable active update delivered to
// N physical connections distributed across P exact wire profiles. The
// profile-cache case is the intended server boundary: prepare at most once per
// profile, then copy the immutable prepared body into each connection buffer.
func BenchmarkLayerFrozenFanout(b *testing.B) {
	const connections = 1024
	typ := LayerConstructorUpdateUserStatusType()
	frozen, err := FreezeLayer(typ, layerBenchmarkValue)
	if err != nil {
		b.Fatal(err)
	}
	profiles := layerBenchmarkProfiles
	prepared := make([]LayerPreparedValue[*UpdateUserStatus], len(profiles))
	var totalWire int64
	for index, profile := range profiles {
		prepared[index], err = PrepareFrozenLayer(profile, frozen)
		if err != nil {
			b.Fatal(err)
		}
	}
	for connection := 0; connection < connections; connection++ {
		totalWire += int64(prepared[connection%len(prepared)].WireSize())
	}

	b.Run(fmt.Sprintf("prepare_per_connection/N=%d/P=%d", connections, len(profiles)), func(b *testing.B) {
		outputs := make([][]byte, connections)
		b.ReportAllocs()
		b.ReportMetric(connections, "connections/op")
		b.ReportMetric(float64(len(profiles)), "profiles/op")
		b.SetBytes(totalWire)
		for b.Loop() {
			written := 0
			for connection := 0; connection < connections; connection++ {
				profile := profiles[connection%len(profiles)]
				value, err := PrepareFrozenLayer(profile, frozen)
				if err != nil {
					b.Fatal(err)
				}
				outputs[connection] = outputs[connection][:0]
				outputs[connection], err = value.Append(profile, typ, outputs[connection])
				if err != nil {
					b.Fatal(err)
				}
				written += len(outputs[connection])
			}
			layerBenchmarkFanoutBytes = written
		}
	})

	b.Run(fmt.Sprintf("prepare_cache_by_profile/N=%d/P=%d", connections, len(profiles)), func(b *testing.B) {
		outputs := make([][]byte, connections)
		cache := make([]LayerPreparedValue[*UpdateUserStatus], len(profiles))
		b.ReportAllocs()
		b.ReportMetric(connections, "connections/op")
		b.ReportMetric(float64(len(profiles)), "profiles/op")
		b.SetBytes(totalWire)
		for b.Loop() {
			for index, profile := range profiles {
				cache[index], err = PrepareFrozenLayer(profile, frozen)
				if err != nil {
					b.Fatal(err)
				}
			}
			written := 0
			for connection := 0; connection < connections; connection++ {
				profileIndex := connection % len(profiles)
				profile := profiles[profileIndex]
				outputs[connection] = outputs[connection][:0]
				outputs[connection], err = cache[profileIndex].Append(profile, typ, outputs[connection])
				if err != nil {
					b.Fatal(err)
				}
				written += len(outputs[connection])
			}
			layerBenchmarkFanoutBytes = written
		}
	})
}

func layerBenchmarkProfileName(profile LayerProfile) string {
	return fmt.Sprintf("layer_%d", profile)
}
