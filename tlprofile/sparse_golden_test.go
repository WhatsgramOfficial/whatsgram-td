package tlprofile

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/iamxvbaba/td/bin"
	"github.com/iamxvbaba/td/tg"
)

func TestSparseCodecMatchesDenseOracleAcrossProfiles(t *testing.T) {
	cases := []struct {
		name  string
		value bin.Object
	}{
		{"direct", &tg.UpdateUserStatus{UserID: 42, Status: &tg.UserStatusOnline{Expires: 1_900_000_000}}},
		{"same-crc-flags", &tg.ChatAdminRights{}},
		{"changed-id-and-shape", &tg.Channel{ID: 100, Title: "layer proof", Photo: &tg.ChatPhotoEmpty{}, Date: 1}},
		{"nested-vector-projection", &tg.Updates{Updates: []tg.UpdateClass{&tg.UpdateNewEphemeralMessage{Message: tg.EphemeralMessage{ID: 1, FromID: &tg.PeerUser{UserID: 1}, PeerID: &tg.PeerUser{UserID: 2}, ReceiverID: 2, Date: 1, Message: "ephemeral"}}}, Users: []tg.UserClass{}, Chats: []tg.ChatClass{}, Date: 1, Seq: 1}},
	}
	for _, profile := range []Profile{Profile225, Profile226, Profile227, Profile228} {
		for _, test := range cases {
			t.Run(test.name+"/layer"+strconv.Itoa(int(profile)), func(t *testing.T) {
				var got, want bin.Buffer
				gotErr := EncodeObject(profile, test.value, &got)
				wantErr := tg.EncodeLayer(tg.LayerProfile(profile), tg.LayerObjectType(), test.value, &want)
				if (gotErr == nil) != (wantErr == nil) {
					t.Fatalf("encode success differs: sparse=%v dense=%v", gotErr, wantErr)
				}
				if gotErr != nil {
					return
				}
				if !bytes.Equal(got.Raw(), want.Raw()) {
					t.Fatalf("wire differs:\nsparse=%x\ndense =%x", got.Raw(), want.Raw())
				}
				decoded, err := DecodeObject(profile, &bin.Buffer{Buf: got.Copy()}, Limits{})
				if err != nil {
					t.Fatal(err)
				}
				var roundtrip bin.Buffer
				if err := EncodeObject(profile, decoded, &roundtrip); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(roundtrip.Raw(), got.Raw()) {
					t.Fatalf("roundtrip differs: got=%x want=%x", roundtrip.Raw(), got.Raw())
				}
			})
		}
	}
}

func TestSparseCodecHistoricalPolicyAdapter(t *testing.T) {
	wire226 := &bin.Buffer{}
	wire226.PutID(0x774bbdf4)
	wire226.PutLong(10)
	wire226.PutString("https://example.test")
	wire226.PutLong(42)
	wire226.PutVectorHeader(0)
	decoded, err := DecodeObject(Profile226, wire226, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	value, ok := decoded.(*tg.MessagesChatInviteJoinResultWebView)
	if !ok || value.QueryID != 42 {
		t.Fatalf("historical policy projection = %#v", decoded)
	}
	if err := EncodeObject(Profile226, value, &bin.Buffer{}); err == nil {
		t.Fatal("sparse codec fabricated removed historical URL")
	}
}

func TestSparseResultPlansMatchDenseOracle(t *testing.T) {
	cases := []struct {
		name    string
		request bin.Object
		result  any
	}{
		{"boxed-concrete", &tg.HelpGetConfigRequest{}, &tg.Config{Date: 1, Expires: 2, ThisDC: 1}},
		{"vector-class", &tg.UsersGetUsersRequest{ID: []tg.InputUserClass{}}, []tg.UserClass{}},
		{"boxed-abstract", &tg.ChannelsJoinChannelRequest{Channel: &tg.InputChannelEmpty{}}, &tg.Updates{Users: []tg.UserClass{}, Chats: []tg.ChatClass{}, Updates: []tg.UpdateClass{}}},
		{"result-adapter", &tg.MessagesImportChatInviteRequest{Hash: "x"}, &tg.MessagesChatInviteJoinResultOk{Updates: &tg.Updates{Users: []tg.UserClass{}, Chats: []tg.ChatClass{}, Updates: []tg.UpdateClass{}}}},
	}
	for _, profile := range []Profile{Profile225, Profile226, Profile227, Profile228} {
		for _, test := range cases {
			t.Run(test.name+"/layer"+strconv.Itoa(int(profile)), func(t *testing.T) {
				outbound, err := tg.PrepareLayerOutboundCall(tg.LayerProfile(profile), test.request)
				if err != nil {
					t.Skipf("request unavailable: %v", err)
				}
				var requestWire bin.Buffer
				if err := outbound.Encode(&requestWire); err != nil {
					t.Fatal(err)
				}
				admission, err := tg.NewServerDispatcher(nil).AdmitLayer(tg.LayerProfile(profile), &requestWire)
				if err != nil {
					t.Fatal(err)
				}
				semantic := SemanticID(admission.Call().Method())
				plan, ok := tlLookupResultPlan(profile, semantic)
				if !ok {
					t.Fatalf("no sparse result plan for %#016x", semantic)
				}
				var got, want bin.Buffer
				gotErr := tlEncodeResultPlan(plan, profile, test.result, &got)
				wantErr := admission.Call().EncodeResult(test.result, &want)
				if (gotErr == nil) != (wantErr == nil) {
					t.Fatalf("result success differs: sparse=%v dense=%v", gotErr, wantErr)
				}
				if gotErr == nil && !bytes.Equal(got.Raw(), want.Raw()) {
					t.Fatalf("result wire differs:\nsparse=%x\ndense =%x", got.Raw(), want.Raw())
				}
			})
		}
	}
}
