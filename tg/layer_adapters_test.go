package tg

import "testing"

func TestLayerChatInviteWebViewAdapters(t *testing.T) {
	profile := LayerProfile(227)
	value := &MessagesChatInviteJoinResultWebView{}
	webview := WebViewResultURL{URL: "https://example.test"}
	webview.SetQueryID(42)
	if err := layerCaptureChatInviteJoinQueryIDFromWebViewDecode(profile, value, webview); err != nil {
		t.Fatal(err)
	}
	queryID, err := layerRequireCapturedChatInviteJoinQueryIDDecode(profile, value)
	if err != nil {
		t.Fatal(err)
	}
	if queryID != 42 {
		t.Fatalf("query id = %d", queryID)
	}
	missing := WebViewResultURL{URL: "https://example.test"}
	if err := layerCaptureChatInviteJoinQueryIDFromWebViewDecode(profile, value, missing); err == nil {
		t.Fatal("historical webview without query ID was accepted")
	}
	presentZero := WebViewResultURL{URL: "https://example.test"}
	presentZero.SetQueryID(0)
	if err := layerCaptureChatInviteJoinQueryIDFromWebViewDecode(profile, value, presentZero); err != nil {
		t.Fatalf("present zero query ID was rejected: %v", err)
	}
	if err := layerCaptureChatInviteJoinQueryIDFromWebViewDecode(profile, nil, webview); err == nil {
		t.Fatal("nil chat invite target was accepted")
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
	reversed, err := layerAdaptUpdatesToChatInviteJoinResult(profile, updates)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := reversed.(*MessagesChatInviteJoinResultOk); !ok || value.Updates != updates {
		t.Fatalf("reversed historical Updates = %#v", reversed)
	}
	if _, err := layerAdaptUpdatesToChatInviteJoinResult(profile, nil); err == nil {
		t.Fatal("nil historical Updates was accepted as a canonical join result")
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
