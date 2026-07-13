package tg

import (
	"bytes"
	"testing"
)

func TestLayerComposeMessageToneAdapter(t *testing.T) {
	profile := LayerProfile(224)
	owner := &MessagesComposeMessageWithAIRequest{}
	wire, present, err := layerAdaptComposeMessageToneEncode(profile, owner, true, &InputAiComposeToneDefault{Tone: "formal"})
	if err != nil || !present || wire != "formal" {
		t.Fatalf("encode default tone = %q,%v,%v", wire, present, err)
	}
	canonical, present, err := layerAdaptComposeMessageToneDecode(profile, owner, true, wire)
	if err != nil || !present {
		t.Fatalf("decode default tone = %T,%v,%v", canonical, present, err)
	}
	value, ok := canonical.(*InputAiComposeToneDefault)
	if !ok || value.Tone != "formal" {
		t.Fatalf("decoded tone = %#v", canonical)
	}
	if _, _, err := layerAdaptComposeMessageToneEncode(profile, owner, true, &InputAiComposeToneSlug{Slug: "formal"}); err == nil {
		t.Fatal("historical string accepted an unrepresentable slug tone")
	}
}

func TestLayerInputMediaPollCorrectAnswersAdapter(t *testing.T) {
	profile := LayerProfile(220)
	owner := &InputMediaPoll{Poll: Poll{Answers: []PollAnswerClass{
		&PollAnswer{Option: []byte("a")},
		&PollAnswer{Option: []byte{0, 2}},
		&PollAnswer{Option: []byte("c")},
	}}}
	wire, present, err := layerAdaptInputMediaPollCorrectAnswersEncode(profile, owner, true, []int{2, 0})
	if err != nil || !present || len(wire) != 2 || !bytes.Equal(wire[0], []byte("c")) || !bytes.Equal(wire[1], []byte("a")) {
		t.Fatalf("encode positions = %#v,%v,%v", wire, present, err)
	}
	positions, present, err := layerAdaptInputMediaPollCorrectAnswersDecode(profile, owner, true, wire)
	if err != nil || !present || len(positions) != 2 || positions[0] != 2 || positions[1] != 0 {
		t.Fatalf("decode options = %#v,%v,%v", positions, present, err)
	}
	if positions, present, err := layerAdaptInputMediaPollCorrectAnswersDecode(profile, owner, true, [][]byte{}); err != nil || !present || positions == nil || len(positions) != 0 {
		t.Fatalf("present-empty was not preserved: %#v,%v,%v", positions, present, err)
	}
	if positions, present, err := layerAdaptInputMediaPollCorrectAnswersDecode(profile, owner, false, nil); err != nil || present || positions != nil {
		t.Fatalf("absent was not preserved: %#v,%v,%v", positions, present, err)
	}
	if _, _, err := layerAdaptInputMediaPollCorrectAnswersEncode(profile, owner, true, []int{3}); err == nil {
		t.Fatal("out-of-range answer position was accepted")
	}
	if _, _, err := layerAdaptInputMediaPollCorrectAnswersDecode(profile, owner, true, [][]byte{[]byte("missing")}); err == nil {
		t.Fatal("unknown answer option was accepted")
	}
	duplicate := &InputMediaPoll{Poll: Poll{Answers: []PollAnswerClass{
		&PollAnswer{Option: []byte("same")}, &PollAnswer{Option: []byte("same")},
	}}}
	if _, _, err := layerAdaptInputMediaPollCorrectAnswersEncode(profile, duplicate, true, []int{0}); err == nil {
		t.Fatal("poll with ambiguous duplicate option bytes was accepted")
	}
}

func TestLayerChatInviteWebViewAdapters(t *testing.T) {
	profile := LayerProfile(226)
	value := &MessagesChatInviteJoinResultWebView{}
	if err := layerCaptureChatInviteJoinWebViewQueryIDDecode(profile, value, 42); err != nil {
		t.Fatal(err)
	}
	if err := layerCaptureChatInviteJoinWebViewURLDecode(profile, value, "https://example.test"); err != nil {
		t.Fatal(err)
	}
	webview, err := layerRequireChatInviteJoinWebViewDecode(profile, value)
	if err != nil {
		t.Fatal(err)
	}
	queryID, ok := webview.GetQueryID()
	if !ok || queryID != 42 || webview.URL != "https://example.test" {
		t.Fatalf("webview = %#v", webview)
	}
	if got, err := layerEncodeChatInviteJoinWebViewQueryIDEncode(profile, value); err != nil || got != 42 {
		t.Fatalf("query id = %d,%v", got, err)
	}
	if got, err := layerEncodeChatInviteJoinWebViewURLEncode(profile, value); err != nil || got != "https://example.test" {
		t.Fatalf("URL = %q,%v", got, err)
	}
}

func TestLayerStarGiftRarityAdapters(t *testing.T) {
	profile := LayerProfile(220)
	model := &StarGiftAttributeModel{}
	if err := layerCaptureStarGiftAttributeModelRarityPermilleDecode(profile, model, 17); err != nil {
		t.Fatal(err)
	}
	if got, err := layerEncodeStarGiftAttributeModelRarityPermilleEncode(profile, model); err != nil || got != 17 {
		t.Fatalf("exact rarity = %d,%v", got, err)
	}
	model.Rarity = &StarGiftAttributeRarityRare{}
	if _, err := layerEncodeStarGiftAttributeModelRarityPermilleEncode(profile, model); err == nil {
		t.Fatal("categorical rarity was silently converted to historical permille")
	}
	if _, err := layerExactStarGiftRarity(1001); err == nil {
		t.Fatal("out-of-range permille was accepted")
	}
}

func TestLayerHistoricalCreatorAliases(t *testing.T) {
	profile := LayerProfile(220)
	channel := &InputChannel{ChannelID: 10, AccessHash: 20}
	request, err := layerAliasChannelsEditCreator(profile, channel, &InputUserSelf{}, &InputCheckPasswordEmpty{})
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := request.Peer.(*InputPeerChannel)
	if !ok || peer.ChannelID != 10 || peer.AccessHash != 20 {
		t.Fatalf("aliased peer = %#v", request.Peer)
	}
	future, err := layerAliasChannelsGetFutureCreatorAfterLeave(profile, &InputChannelFromMessage{
		Peer: &InputPeerUser{UserID: 1, AccessHash: 2}, MsgID: 3, ChannelID: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := future.Peer.(*InputPeerChannelFromMessage); !ok {
		t.Fatalf("aliased from-message peer = %#v", future.Peer)
	}
}

func TestLayerResultAdapters(t *testing.T) {
	profile := LayerProfile(225)
	updates := &UpdatesTooLong{}
	got, err := layerAdaptChatInviteJoinResultToUpdates(profile, &MessagesChatInviteJoinResultOk{Updates: updates})
	if err != nil || got != updates {
		t.Fatalf("join result = %T,%v", got, err)
	}
	if _, err := layerAdaptChatInviteJoinResultToUpdates(profile, &MessagesChatInviteJoinResultWebView{}); err == nil {
		t.Fatal("webview join result was accepted as historical Updates")
	}
	if ok, err := layerAdaptWebBrowserSettingsExceptionResult(LayerProfile(226), updates); err != nil || !ok {
		t.Fatalf("updates-to-bool = %v,%v", ok, err)
	}
	if ok, err := layerAdaptBotGuestChatResult(profile, &InputBotInlineMessageID{}); err != nil || !ok {
		t.Fatalf("inline-id-to-bool = %v,%v", ok, err)
	}
	var nilMessageID *InputBotInlineMessageID
	if _, err := layerAdaptBotGuestChatResult(profile, nilMessageID); err == nil {
		t.Fatal("typed-nil inline message ID was accepted")
	}
}

func TestLayerPollAnswerVotersAtomicDecode(t *testing.T) {
	value := &PollAnswerVoters{}
	if err := layerAdaptPollAnswerVotersAtomicDecode(LayerProfile(220), value, true, 9); err != nil {
		t.Fatal(err)
	}
	if !value.Flags.Has(2) || value.Voters != 9 || value.RecentVoters != nil {
		t.Fatalf("canonical voters = %#v", value)
	}
}
