package tg

import (
	"encoding/binary"
	"testing"

	"github.com/iamxvbaba/td/bin"
)

func TestLayer227And228ChannelWireIDs(t *testing.T) {
	channel := &Channel{
		ID:    100,
		Title: "layer proof",
		Photo: &ChatPhotoEmpty{},
		Date:  1,
	}
	encoded227 := encodeLayerValue(t, LayerProfile227, LayerConstructorChannelType(), channel)
	encoded228 := encodeLayerValue(t, LayerProfile228, LayerConstructorChannelType(), channel)
	if got, want := binary.LittleEndian.Uint32(encoded227), uint32(0x1c32b11c); got != want {
		t.Fatalf("Layer 227 channel ID = %#08x, want %#08x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(encoded228), uint32(0xd49f34c6); got != want {
		t.Fatalf("Layer 228 channel ID = %#08x, want %#08x", got, want)
	}
	if _, err := DecodeLayer(LayerProfile228, LayerConstructorChannelType(), &bin.Buffer{Buf: encoded227}); err == nil {
		t.Fatal("Layer 228 accepted a Layer 227 channel constructor")
	}
	if _, err := DecodeLayer(LayerProfile227, LayerConstructorChannelType(), &bin.Buffer{Buf: encoded228}); err == nil {
		t.Fatal("Layer 227 accepted a Layer 228 channel constructor")
	}

	channel.SetLinkedCommunityID(200)
	if err := EncodeLayer(LayerProfile227, LayerConstructorChannelType(), channel, &bin.Buffer{}); err == nil {
		t.Fatal("Layer 227 silently discarded linked_community_id")
	}
	encoded228 = encodeLayerValue(t, LayerProfile228, LayerConstructorChannelType(), channel)
	decoded228, err := DecodeLayer(LayerProfile228, LayerConstructorChannelType(), &bin.Buffer{Buf: encoded228})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := decoded228.GetLinkedCommunityID(); !ok || got != 200 {
		t.Fatalf("Layer 228 linked community = %d,%v", got, ok)
	}
}

func TestLayer228SameCRCNewFlagSemantics(t *testing.T) {
	rights := &ChatAdminRights{}
	encoded227 := encodeLayerValue(t, LayerProfile227, LayerConstructorChatAdminRightsType(), rights)
	encoded228 := encodeLayerValue(t, LayerProfile228, LayerConstructorChatAdminRightsType(), rights)
	for layer, encoded := range map[int][]byte{227: encoded227, 228: encoded228} {
		if got, want := binary.LittleEndian.Uint32(encoded), uint32(ChatAdminRightsTypeID); got != want {
			t.Fatalf("Layer %d chatAdminRights ID = %#08x, want %#08x", layer, got, want)
		}
		if flags := binary.LittleEndian.Uint32(encoded[4:]); flags&(1<<19) != 0 {
			t.Fatalf("Layer %d unexpectedly set manage_linked_peers: %#08x", layer, flags)
		}
	}

	rights.SetManageLinkedPeers(true)
	if err := EncodeLayer(LayerProfile227, LayerConstructorChatAdminRightsType(), rights, &bin.Buffer{}); err == nil {
		t.Fatal("Layer 227 silently accepted Layer 228 manage_linked_peers")
	}
	encoded228 = encodeLayerValue(t, LayerProfile228, LayerConstructorChatAdminRightsType(), rights)
	if flags := binary.LittleEndian.Uint32(encoded228[4:]); flags&(1<<19) == 0 {
		t.Fatalf("Layer 228 lost manage_linked_peers: %#08x", flags)
	}
}

func TestLayer228ChatInviteWebViewProjection(t *testing.T) {
	canonical := &MessagesChatInviteJoinResultWebView{BotID: 10, QueryID: 42, Users: []UserClass{}}
	encoded228 := encodeLayerValue(t, LayerProfile228, LayerConstructorMessagesChatInviteJoinResultWebViewType(), canonical)
	if got, want := binary.LittleEndian.Uint32(encoded228), uint32(0x61ca29d3); got != want {
		t.Fatalf("Layer 228 chat invite ID = %#08x, want %#08x", got, want)
	}
	for _, profile := range []LayerProfile{LayerProfile226, LayerProfile227} {
		if err := EncodeLayer(profile, LayerConstructorMessagesChatInviteJoinResultWebViewType(), canonical, &bin.Buffer{}); err == nil {
			t.Fatalf("Layer %d fabricated a removed chat invite URL", profile)
		}
	}

	wire226 := &bin.Buffer{}
	wire226.PutID(0x774bbdf4)
	wire226.PutLong(10)
	wire226.PutString("https://example.test")
	wire226.PutLong(42)
	wire226.PutVectorHeader(0)
	decoded226, err := DecodeLayer(LayerProfile226, LayerConstructorMessagesChatInviteJoinResultWebViewType(), wire226)
	if err != nil || decoded226.QueryID != 42 {
		t.Fatalf("Layer 226 projection = %#v,%v", decoded226, err)
	}

	wire227 := &bin.Buffer{}
	wire227.PutID(0x2f51c337)
	wire227.PutLong(10)
	wire227.PutID(WebViewResultURLTypeID)
	wire227.PutInt(1)
	wire227.PutLong(42)
	wire227.PutString("https://example.test")
	wire227.PutVectorHeader(0)
	decoded227, err := DecodeLayer(LayerProfile227, LayerConstructorMessagesChatInviteJoinResultWebViewType(), wire227)
	if err != nil || decoded227.QueryID != 42 {
		t.Fatalf("Layer 227 projection = %#v,%v", decoded227, err)
	}
}

func TestLayer228OnlyUpdateDropsFromLegacyVector(t *testing.T) {
	value := &Updates{
		Updates: []UpdateClass{&UpdateNewEphemeralMessage{Message: EphemeralMessage{
			ID: 1, FromID: &PeerUser{UserID: 1}, PeerID: &PeerUser{UserID: 2}, ReceiverID: 2, Date: 1, Message: "ephemeral",
		}}},
		Users: []UserClass{},
		Chats: []ChatClass{},
		Date:  1,
		Seq:   1,
	}
	encoded227 := encodeLayerValue(t, LayerProfile227, LayerConstructorUpdatesType(), value)
	decoded227, err := DecodeLayer(LayerProfile227, LayerConstructorUpdatesType(), &bin.Buffer{Buf: encoded227})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded227.Updates) != 0 {
		t.Fatalf("Layer 227 retained Layer 228-only updates: %#v", decoded227.Updates)
	}
	encoded228 := encodeLayerValue(t, LayerProfile228, LayerConstructorUpdatesType(), value)
	decoded228, err := DecodeLayer(LayerProfile228, LayerConstructorUpdatesType(), &bin.Buffer{Buf: encoded228})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded228.Updates) != 1 {
		t.Fatalf("Layer 228 updates = %d, want 1", len(decoded228.Updates))
	}
}

func TestLayer228DialogPeerCapability(t *testing.T) {
	type dialogWithPeer interface {
		GetPeer() PeerClass
	}

	for name, dialog := range map[string]DialogClass{
		"dialog":       &Dialog{Peer: &PeerUser{UserID: 1}},
		"dialogFolder": &DialogFolder{Peer: &PeerUser{UserID: 1}},
	} {
		withPeer, ok := dialog.(dialogWithPeer)
		if !ok || withPeer.GetPeer().(*PeerUser).UserID != 1 {
			t.Fatalf("%s peer capability = %#v,%v", name, withPeer, ok)
		}
	}

	var community DialogClass = &DialogCommunity{CommunityID: 2}
	if _, ok := community.(dialogWithPeer); ok {
		t.Fatal("dialogCommunity unexpectedly exposes a message Peer")
	}
}

func encodeLayerValue[T any](t *testing.T, profile LayerProfile, typ LayerType[T], value T) []byte {
	t.Helper()
	buffer := &bin.Buffer{}
	if err := EncodeLayer(profile, typ, value, buffer); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer.Buf...)
}
