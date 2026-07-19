package tlprofile

import (
	"fmt"

	"github.com/iamxvbaba/td/tg"
)

func layerCaptureChatInviteJoinQueryIDFromWebViewDecode(_ LayerProfile, value *tg.MessagesChatInviteJoinResultWebView, webview tg.WebViewResultURL) error {
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

func layerRequireCapturedChatInviteJoinQueryIDDecode(_ LayerProfile, value *tg.MessagesChatInviteJoinResultWebView) (int64, error) {
	if value == nil {
		return 0, fmt.Errorf("chat invite webview target is nil")
	}
	return value.QueryID, nil
}

func layerAdaptChatInviteJoinResultToUpdates(_ LayerProfile, result tg.MessagesChatInviteJoinResultClass) (tg.UpdatesClass, error) {
	value, ok := result.(*tg.MessagesChatInviteJoinResultOk)
	if !ok || value == nil || value.Updates == nil {
		return nil, fmt.Errorf("historical Updates result cannot represent chat invite result %T", result)
	}
	return value.Updates, nil
}

func layerAdaptUpdatesToChatInviteJoinResult(_ LayerProfile, updates tg.UpdatesClass) (tg.MessagesChatInviteJoinResultClass, error) {
	if updates == nil {
		return nil, fmt.Errorf("chat invite join returned nil historical Updates")
	}
	return &tg.MessagesChatInviteJoinResultOk{Updates: updates}, nil
}

func layerAdaptWebBrowserSettingsExceptionResult(_ LayerProfile, updates tg.UpdatesClass) (bool, error) {
	if updates == nil {
		return false, fmt.Errorf("web browser settings exception returned nil Updates")
	}
	return true, nil
}

func layerAdaptBotGuestChatResult(_ LayerProfile, messageID tg.InputBotInlineMessageIDClass) (bool, error) {
	switch value := messageID.(type) {
	case *tg.InputBotInlineMessageID:
		if value == nil {
			return false, fmt.Errorf("set bot guest chat result returned nil inline message ID")
		}
	case *tg.InputBotInlineMessageID64:
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

// layerProjectEphemeralBotCommandProject removes a Layer 228 ephemeral command when
// encoding a command vector for a profile that cannot represent its privacy
// bit. Keeping the command and merely dropping the bit would make an older
// client send the command as an ordinary visible group message.
func layerProjectEphemeralBotCommandProject(
	profile LayerProfile,
	value *tg.BotCommand,
	ephemeral bool,
) (*tg.BotCommand, bool, error) {
	if value == nil {
		return nil, false, fmt.Errorf("bot command target is nil")
	}
	if profile >= LayerProfile228 {
		return nil, false, fmt.Errorf("ephemeral bot command projector used for profile %d", profile)
	}
	if ephemeral || value.Flags.Has(0) {
		return nil, false, nil
	}
	return value, true, nil
}
