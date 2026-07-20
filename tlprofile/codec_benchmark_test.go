package tlprofile

import (
	"testing"

	"github.com/iamxvbaba/td/bin"
	"github.com/iamxvbaba/td/tg"
)

var benchmarkRouteSink tlRoute

func BenchmarkExactObjectCodec(b *testing.B) {
	direct := &tg.UpdateUserStatus{
		UserID: 42,
		Status: &tg.UserStatusOnline{Expires: 1_900_000_000},
	}
	rewrite := &tg.Channel{
		ID:    100,
		Title: "layer benchmark",
		Photo: &tg.ChatPhotoEmpty{},
		Date:  1,
	}

	benchmarkExactEncode(b, "direct", Profile225, direct)
	benchmarkExactDecode(b, "direct", Profile225, direct)
	benchmarkExactEncode(b, "rewrite", Profile225, rewrite)
	benchmarkExactDecode(b, "rewrite", Profile225, rewrite)
}

func benchmarkExactEncode(b *testing.B, name string, profile Profile, value bin.Object) {
	b.Helper()
	var out bin.Buffer
	if err := EncodeObject(profile, value, &out); err != nil {
		b.Fatal(err)
	}
	capacity := len(out.Buf)

	b.Run(name+"/encode", func(b *testing.B) {
		b.ReportAllocs()
		out.Buf = make([]byte, 0, capacity)
		b.ResetTimer()
		for b.Loop() {
			out.Buf = out.Buf[:0]
			if err := EncodeObject(profile, value, &out); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func benchmarkExactDecode(b *testing.B, name string, profile Profile, value bin.Object) {
	b.Helper()
	var encoded bin.Buffer
	if err := EncodeObject(profile, value, &encoded); err != nil {
		b.Fatal(err)
	}
	wire := encoded.Copy()

	b.Run(name+"/decode", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			input := bin.Buffer{Buf: wire}
			if _, err := DecodeObject(profile, &input, Limits{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkExactAdmission(b *testing.B) {
	cases := []struct {
		name    string
		request bin.Object
	}{
		{name: "direct", request: &tg.HelpGetConfigRequest{}},
		{name: "rewrite", request: &tg.AccountGetNotifySettingsRequest{Peer: &tg.InputNotifyUsers{}}},
	}
	dispatcher := NewDispatcher()

	for _, test := range cases {
		b.Run(test.name, func(b *testing.B) {
			var encoded bin.Buffer
			if err := EncodeObject(Profile225, test.request, &encoded); err != nil {
				b.Fatal(err)
			}
			wire := encoded.Copy()

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				input := bin.Buffer{Buf: wire}
				if _, err := dispatcher.Admit(Profile225, &input, Limits{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLookupRoute(b *testing.B) {
	cases := []struct {
		name    string
		profile Profile
		wireID  uint32
	}{
		{name: "universal-direct", profile: Profile225, wireID: tg.HelpGetConfigRequestTypeID},
		{name: "split-rewrite", profile: Profile225, wireID: tg.AccountGetNotifySettingsRequestTypeID},
	}

	for _, test := range cases {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				route, ok := tlLookupRoute(test.profile, test.wireID)
				if !ok {
					b.Fatal("route not found")
				}
				benchmarkRouteSink = route
			}
		})
	}
}
