package gen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sort"
	"testing"

	"github.com/gotd/td/gen/semantic"
)

// TestRealLayerPolicy is deliberately both a review gate and the only writer
// for _schema/layers/policy.json. UPDATE_LAYER_POLICY=1 rewrites the checked-in
// document from semantic coordinates; the normal test path requires a byte-for-
// byte match and then proves that applying it leaves no unresolved obligation.
func TestRealLayerPolicy(t *testing.T) {
	set, err := semantic.LoadUniverse("../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := NewSchemaSetGenerator(set, GeneratorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	document, err := buildRealLayerPolicy(initial.LayerConversionPlan().Report)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := "../_schema/layers/policy.json"
	if os.Getenv("UPDATE_LAYER_POLICY") == "1" {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, data) {
		t.Fatal("_schema/layers/policy.json is stale; in PowerShell run: $env:UPDATE_LAYER_POLICY='1'; go test ./gen -run TestRealLayerPolicy")
	}

	policy := LayerObligationPolicy{Entries: document.Entries}
	resolved, err := NewSchemaSetGenerator(set, GeneratorOptions{LayerPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	if unresolved := resolved.LayerConversionPlan().Report.Unresolved(); len(unresolved) != 0 {
		t.Fatalf("real policy leaves %d unresolved obligations; first=%+v", len(unresolved), unresolved[0])
	}
	if got, want := len(document.Entries), 178; got != want {
		t.Fatalf("reviewed policy entry count = %d, want %d", got, want)
	}
	codec, err := resolved.buildLayerCodecModel("tg")
	if err != nil {
		t.Fatal(err)
	}
	// inputStorePaymentAuthCode exists in historical profiles, but the reviewed
	// required-field policy rejects every profile-to-canonical projection. Keep
	// that all-reject shape explicit so the template cannot emit a dead boxed
	// decode tail after a terminating switch (go vet must remain clean).
	paymentAuthCode := findLayerCodecWire(t, codec, 0x9bb2636d)
	if !paymentAuthCode.Encodable || paymentAuthCode.Decodable {
		t.Fatalf("inputStorePaymentAuthCode codec capability = encode:%v decode:%v, want true/false", paymentAuthCode.Encodable, paymentAuthCode.Decodable)
	}
	rpc, err := resolved.buildLayerRPCModel()
	if err != nil {
		t.Fatal(err)
	}
	refs, err := resolved.buildLayerTypeRefModel()
	if err != nil {
		t.Fatal(err)
	}
	source, err := resolved.buildLayerRPCSourceModel(rpc, refs)
	if err != nil {
		t.Fatal(err)
	}
	assertRealLayerHookContracts(t, codec.Hooks, source.HookChecks)
}

func assertRealLayerHookContracts(t *testing.T, codec []layerCodecHookContract, rpc []layerRPCSourceHookCheck) {
	t.Helper()
	wantCodec := map[string]string{
		"layerAdaptComposeMessageToneDecode":                        "func(LayerProfile, *MessagesComposeMessageWithAIRequest, bool, string) (InputAiComposeToneClass, bool, error)",
		"layerAdaptComposeMessageToneEncode":                        "func(LayerProfile, *MessagesComposeMessageWithAIRequest, bool, InputAiComposeToneClass) (string, bool, error)",
		"layerAdaptInputMediaPollCorrectAnswersDecode":              "func(LayerProfile, *InputMediaPoll, bool, [][]byte) ([]int, bool, error)",
		"layerAdaptInputMediaPollCorrectAnswersEncode":              "func(LayerProfile, *InputMediaPoll, bool, []int) ([][]byte, bool, error)",
		"layerAdaptPollAnswerVotersAtomicDecode":                    "func(LayerProfile, *PollAnswerVoters, bool, int) error",
		"layerCaptureChatInviteJoinWebViewQueryIDDecode":            "func(LayerProfile, *MessagesChatInviteJoinResultWebView, int64) error",
		"layerCaptureChatInviteJoinWebViewURLDecode":                "func(LayerProfile, *MessagesChatInviteJoinResultWebView, string) error",
		"layerCaptureStarGiftAttributeBackdropRarityPermilleDecode": "func(LayerProfile, *StarGiftAttributeBackdrop, int) error",
		"layerCaptureStarGiftAttributeModelRarityPermilleDecode":    "func(LayerProfile, *StarGiftAttributeModel, int) error",
		"layerCaptureStarGiftAttributePatternRarityPermilleDecode":  "func(LayerProfile, *StarGiftAttributePattern, int) error",
		"layerEncodeChatInviteJoinWebViewQueryIDEncode":             "func(LayerProfile, *MessagesChatInviteJoinResultWebView) (int64, error)",
		"layerEncodeChatInviteJoinWebViewURLEncode":                 "func(LayerProfile, *MessagesChatInviteJoinResultWebView) (string, error)",
		"layerEncodeStarGiftAttributeBackdropRarityPermilleEncode":  "func(LayerProfile, *StarGiftAttributeBackdrop) (int, error)",
		"layerEncodeStarGiftAttributeModelRarityPermilleEncode":     "func(LayerProfile, *StarGiftAttributeModel) (int, error)",
		"layerEncodeStarGiftAttributePatternRarityPermilleEncode":   "func(LayerProfile, *StarGiftAttributePattern) (int, error)",
		"layerRequireChatInviteJoinWebViewDecode":                   "func(LayerProfile, *MessagesChatInviteJoinResultWebView) (WebViewResultURL, error)",
		"layerRequireSendBotRequestedPeerMessageIDEncode":           "func(LayerProfile, *MessagesSendBotRequestedPeerRequest, bool, int) (int, error)",
		"layerRequireStarGiftAttributeBackdropRarityDecode":         "func(LayerProfile, *StarGiftAttributeBackdrop) (StarGiftAttributeRarityClass, error)",
		"layerRequireStarGiftAttributeModelRarityDecode":            "func(LayerProfile, *StarGiftAttributeModel) (StarGiftAttributeRarityClass, error)",
		"layerRequireStarGiftAttributePatternRarityDecode":          "func(LayerProfile, *StarGiftAttributePattern) (StarGiftAttributeRarityClass, error)",
		"layerRequireURLAuthResultAcceptedURLEncode":                "func(LayerProfile, *URLAuthResultAccepted, bool, string) (string, error)",
	}
	gotCodec := make(map[string]string, len(codec))
	for _, hook := range codec {
		gotCodec[hook.Name] = hook.Signature
	}
	if !maps.Equal(gotCodec, wantCodec) {
		t.Fatalf("real codec hook contracts changed\ngot:  %v\nwant: %v", gotCodec, wantCodec)
	}

	wantRPC := map[string]string{
		"layerAdaptBotGuestChatResult":                 "func(LayerProfile, InputBotInlineMessageIDClass) (bool, error)",
		"layerAdaptChatInviteJoinResultToUpdates":      "func(LayerProfile, MessagesChatInviteJoinResultClass) (UpdatesClass, error)",
		"layerAdaptWebBrowserSettingsExceptionResult":  "func(LayerProfile, UpdatesClass) (bool, error)",
		"layerAliasChannelsEditCreator":                "func(LayerProfile, InputChannelClass, InputUserClass, InputCheckPasswordSRPClass) (*MessagesEditChatCreatorRequest, error)",
		"layerAliasChannelsGetFutureCreatorAfterLeave": "func(LayerProfile, InputChannelClass) (*MessagesGetFutureChatCreatorAfterLeaveRequest, error)",
	}
	gotRPC := make(map[string]string, len(rpc))
	for _, hook := range rpc {
		gotRPC[hook.Name] = hook.Signature
	}
	if !maps.Equal(gotRPC, wantRPC) {
		t.Fatalf("real RPC hook contracts changed\ngot:  %v\nwant: %v", gotRPC, wantRPC)
	}
}

func buildRealLayerPolicy(report LayerObligationReport) (LayerPolicyDocument, error) {
	document := LayerPolicyDocument{Version: LayerPolicyVersion}
	for _, obligation := range report.Obligations {
		resolution, include, err := realLayerResolution(obligation)
		if err != nil {
			return LayerPolicyDocument{}, err
		}
		if !include {
			continue
		}
		resolution.Note = formatLayerPolicyTemplateNote(obligation)
		document.Entries = append(document.Entries, LayerObligationPolicyEntry{
			Key:        obligation.Key,
			Resolution: resolution,
		})
	}
	sort.Slice(document.Entries, func(i, j int) bool { return document.Entries[i].Key < document.Entries[j].Key })
	return document, nil
}

func realLayerResolution(obligation LayerObligation) (LayerObligationResolution, bool, error) {
	// Mechanical field projections remain fail-closed with the analyzer's
	// reject-if-present default. These seven reviewed replacements are carried
	// by required/discard adapters and therefore explicitly permit the original
	// canonical field to disappear from the historical shape.
	if obligation.Kind == LayerObligationFieldProjection {
		if obligation.Direction == LayerDirectionCanonicalToProfile &&
			obligation.Semantic.QName == "messages.chatInviteJoinResultWebView" &&
			obligation.Layer == 226 && obligation.Field == "webview" {
			return LayerObligationResolution{Action: LayerResolveDrop}, true, nil
		}
		if obligation.Direction == LayerDirectionCanonicalToProfile &&
			(obligation.Semantic.QName == "starGiftAttributeBackdrop" ||
				obligation.Semantic.QName == "starGiftAttributeModel" ||
				obligation.Semantic.QName == "starGiftAttributePattern") &&
			(obligation.Layer == 220 || obligation.Layer == 221) && obligation.Field == "rarity" {
			return LayerObligationResolution{Action: LayerResolveDrop}, true, nil
		}
		return LayerObligationResolution{}, false, nil
	}
	if obligation.Resolution.resolved() {
		return LayerObligationResolution{}, false, nil
	}

	adapter := func(hook string) (LayerObligationResolution, bool, error) {
		return LayerObligationResolution{Action: LayerResolveAdapter, Hook: hook}, true, nil
	}
	switch obligation.Kind {
	case LayerObligationAtomicFlagGroup:
		if obligation.Semantic.QName == "pollAnswerVoters" {
			return adapter("layerAdaptPollAnswerVotersAtomic")
		}
	case LayerObligationDiscard:
		switch obligation.Semantic.QName + ":" + obligation.Field {
		case "messages.chatInviteJoinResultWebView:query_id":
			return adapter("layerCaptureChatInviteJoinWebViewQueryID")
		case "messages.chatInviteJoinResultWebView:url":
			return adapter("layerCaptureChatInviteJoinWebViewURL")
		case "starGiftAttributeBackdrop:rarity_permille":
			return adapter("layerCaptureStarGiftAttributeBackdropRarityPermille")
		case "starGiftAttributeModel:rarity_permille":
			return adapter("layerCaptureStarGiftAttributeModelRarityPermille")
		case "starGiftAttributePattern:rarity_permille":
			return adapter("layerCaptureStarGiftAttributePatternRarityPermille")
		}
	case LayerObligationFieldReplacement:
		if obligation.Semantic.QName == "messages.composeMessageWithAI" && obligation.Field == "tone" && obligation.OtherField == "change_tone" {
			return adapter("layerAdaptComposeMessageTone")
		}
	case LayerObligationIncompatible:
		if obligation.Semantic.QName == "inputMediaPoll" && obligation.Field == "correct_answers" {
			return adapter("layerAdaptInputMediaPollCorrectAnswers")
		}
	case LayerObligationOldOnly:
		switch obligation.Semantic.QName {
		case "channels.editCreator":
			return LayerObligationResolution{
				Action: LayerResolveAlias,
				Hook:   "layerAliasChannelsEditCreator",
				Target: "function:messages.editChatCreator",
			}, true, nil
		case "channels.getFutureCreatorAfterLeave":
			return LayerObligationResolution{
				Action: LayerResolveAlias,
				Hook:   "layerAliasChannelsGetFutureCreatorAfterLeave",
				Target: "function:messages.getFutureChatCreatorAfterLeave",
			}, true, nil
		}
	case LayerObligationRequired:
		return realRequiredLayerResolution(obligation)
	case LayerObligationResult:
		if obligation.Direction == LayerDirectionProfileToCanonical {
			switch obligation.Semantic.QName {
			case "channels.joinChannel", "messages.importChatInvite":
				return adapter("layerAdaptUpdatesToChatInviteJoinResult")
			case "account.toggleWebBrowserSettingsException", "messages.setBotGuestChatResult":
				// The historical Bool contains no canonical result payload. A
				// layer-aware client must reject these exact profiles rather than
				// invent Updates or an inline-message identifier.
				return LayerObligationResolution{Action: LayerResolveReject}, true, nil
			}
		}
		switch obligation.Semantic.QName {
		case "channels.joinChannel", "messages.importChatInvite":
			return adapter("layerAdaptChatInviteJoinResultToUpdates")
		case "account.toggleWebBrowserSettingsException":
			return adapter("layerAdaptWebBrowserSettingsExceptionResult")
		case "messages.setBotGuestChatResult":
			return adapter("layerAdaptBotGuestChatResult")
		}
	case LayerObligationUpdateProjection:
		return LayerObligationResolution{Action: LayerResolveDrop}, true, nil
	}
	return LayerObligationResolution{}, false, fmt.Errorf("unreviewed real layer obligation: %+v", obligation)
}

func realRequiredLayerResolution(obligation LayerObligation) (LayerObligationResolution, bool, error) {
	adapter := func(hook string) (LayerObligationResolution, bool, error) {
		return LayerObligationResolution{Action: LayerResolveAdapter, Hook: hook}, true, nil
	}
	defaulted := func() (LayerObligationResolution, bool, error) {
		return LayerObligationResolution{Action: LayerResolveDefault}, true, nil
	}
	switch obligation.Semantic.QName {
	case "channels.editAdmin", "messages.getPollResults", "auth.sentCodePaymentRequired",
		"dialog", "forumTopic", "pageListOrderedItemBlocks", "pageListOrderedItemText",
		"poll", "pollAnswerVoters", "updateMessagePollVote":
		return defaulted()
	case "messages.sendBotRequestedPeer":
		return adapter("layerRequireSendBotRequestedPeerMessageID")
	case "inputStorePaymentAuthCode":
		return LayerObligationResolution{Action: LayerResolveReject}, true, nil
	case "urlAuthResultAccepted":
		return adapter("layerRequireURLAuthResultAcceptedURL")
	case "messages.chatInviteJoinResultWebView":
		if obligation.Direction == LayerDirectionCanonicalToProfile {
			switch obligation.OtherField {
			case "query_id":
				return adapter("layerEncodeChatInviteJoinWebViewQueryID")
			case "url":
				return adapter("layerEncodeChatInviteJoinWebViewURL")
			}
		}
		if obligation.Direction == LayerDirectionProfileToCanonical && obligation.OtherField == "webview" {
			return adapter("layerRequireChatInviteJoinWebView")
		}
	case "starGiftAttributeBackdrop", "starGiftAttributeModel", "starGiftAttributePattern":
		var suffix string
		switch obligation.Semantic.QName {
		case "starGiftAttributeBackdrop":
			suffix = "Backdrop"
		case "starGiftAttributeModel":
			suffix = "Model"
		case "starGiftAttributePattern":
			suffix = "Pattern"
		}
		if obligation.Direction == LayerDirectionCanonicalToProfile && obligation.OtherField == "rarity_permille" {
			return adapter("layerEncodeStarGiftAttribute" + suffix + "RarityPermille")
		}
		if obligation.Direction == LayerDirectionProfileToCanonical && obligation.OtherField == "rarity" {
			return adapter("layerRequireStarGiftAttribute" + suffix + "Rarity")
		}
	}
	return LayerObligationResolution{}, false, fmt.Errorf("unreviewed required layer obligation: %+v", obligation)
}
