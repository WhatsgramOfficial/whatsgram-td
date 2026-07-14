package tg

import "fmt"

// This file contains the deliberately non-mechanical semantic conversions
// referenced by _schema/layers/policy.json. gotdgen emits compile-time function
// type assertions for every hook; changing a policy coordinate or inferred
// signature therefore fails the tg build instead of falling back at runtime.

func layerCaptureChatInviteJoinQueryIDFromWebViewDecode(_ LayerProfile, value *MessagesChatInviteJoinResultWebView, webview WebViewResultURL) error {
	if value == nil {
		return fmt.Errorf("chat invite webview target is nil")
	}
	queryID, ok := webview.GetQueryID()
	if !ok {
		return fmt.Errorf("historical chat invite webview omitted its query ID")
	}
	value.QueryID = queryID
	return nil
}

func layerRequireCapturedChatInviteJoinQueryIDDecode(_ LayerProfile, value *MessagesChatInviteJoinResultWebView) (int64, error) {
	if value == nil {
		return 0, fmt.Errorf("chat invite webview target is nil")
	}
	return value.QueryID, nil
}

func layerAdaptChatInviteJoinResultToUpdates(_ LayerProfile, result MessagesChatInviteJoinResultClass) (UpdatesClass, error) {
	value, ok := result.(*MessagesChatInviteJoinResultOk)
	if !ok || value == nil || value.Updates == nil {
		return nil, fmt.Errorf("historical Updates result cannot represent chat invite result %T", result)
	}
	return value.Updates, nil
}

func layerAdaptUpdatesToChatInviteJoinResult(_ LayerProfile, updates UpdatesClass) (MessagesChatInviteJoinResultClass, error) {
	if updates == nil {
		return nil, fmt.Errorf("chat invite join returned nil historical Updates")
	}
	return &MessagesChatInviteJoinResultOk{Updates: updates}, nil
}

func layerAdaptWebBrowserSettingsExceptionResult(_ LayerProfile, updates UpdatesClass) (bool, error) {
	if updates == nil {
		return false, fmt.Errorf("web browser settings exception returned nil Updates")
	}
	return true, nil
}

func layerAdaptBotGuestChatResult(_ LayerProfile, messageID InputBotInlineMessageIDClass) (bool, error) {
	switch value := messageID.(type) {
	case *InputBotInlineMessageID:
		if value == nil {
			return false, fmt.Errorf("set bot guest chat result returned nil inline message ID")
		}
	case *InputBotInlineMessageID64:
		if value == nil {
			return false, fmt.Errorf("set bot guest chat result returned nil inline message ID")
		}
	case nil:
		return false, fmt.Errorf("set bot guest chat result returned nil inline message ID")
	default:
		return false, fmt.Errorf("set bot guest chat result returned unsupported inline message ID %T", messageID)
	}
	return true, nil
}
