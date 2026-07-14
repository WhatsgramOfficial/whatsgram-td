package tg

import (
	"bytes"
	"fmt"
)

// This file contains the deliberately non-mechanical semantic conversions
// referenced by _schema/layers/policy.json. gotdgen emits compile-time function
// type assertions for every hook; changing a policy coordinate or inferred
// signature therefore fails the tg build instead of falling back at runtime.

func layerAdaptPollAnswerVotersAtomicDecode(_ LayerProfile, value *PollAnswerVoters, present bool, voters int) error {
	if value == nil {
		return fmt.Errorf("poll answer voters target is nil")
	}
	if !present {
		return fmt.Errorf("historical pollAnswerVoters omitted its required voters field")
	}
	value.Flags.Set(2)
	value.Voters = voters
	value.RecentVoters = nil
	return nil
}

func layerAdaptComposeMessageToneEncode(_ LayerProfile, owner *MessagesComposeMessageWithAIRequest, present bool, tone InputAiComposeToneClass) (string, bool, error) {
	if owner == nil {
		return "", false, fmt.Errorf("compose message request is nil")
	}
	if !present {
		return "", false, nil
	}
	switch value := tone.(type) {
	case *InputAiComposeToneDefault:
		if value == nil {
			return "", false, fmt.Errorf("present input AI compose tone is nil")
		}
		return value.Tone, true, nil
	case nil:
		return "", false, fmt.Errorf("present input AI compose tone is nil")
	default:
		return "", false, fmt.Errorf("historical change_tone string cannot represent %T", tone)
	}
}

func layerAdaptComposeMessageToneDecode(_ LayerProfile, owner *MessagesComposeMessageWithAIRequest, present bool, tone string) (InputAiComposeToneClass, bool, error) {
	if owner == nil {
		return nil, false, fmt.Errorf("compose message request is nil")
	}
	if !present {
		return nil, false, nil
	}
	return &InputAiComposeToneDefault{Tone: tone}, true, nil
}

func layerRequireSendBotRequestedPeerMessageIDEncode(_ LayerProfile, owner *MessagesSendBotRequestedPeerRequest, present bool, messageID int) (int, error) {
	if owner == nil {
		return 0, fmt.Errorf("send bot requested peer request is nil")
	}
	if !present || messageID <= 0 {
		return 0, fmt.Errorf("historical messages.sendBotRequestedPeer requires a positive msg_id")
	}
	return messageID, nil
}

func layerRequireURLAuthResultAcceptedURLEncode(_ LayerProfile, owner *URLAuthResultAccepted, present bool, url string) (string, error) {
	if owner == nil {
		return "", fmt.Errorf("URL auth result is nil")
	}
	if !present || url == "" {
		return "", fmt.Errorf("historical urlAuthResultAccepted requires a non-empty URL")
	}
	return url, nil
}

func layerCaptureChatInviteJoinWebViewQueryIDDecode(_ LayerProfile, value *MessagesChatInviteJoinResultWebView, queryID int64) error {
	if value == nil {
		return fmt.Errorf("chat invite webview target is nil")
	}
	if queryID != 0 {
		value.Webview.SetQueryID(queryID)
	}
	return nil
}

func layerCaptureChatInviteJoinWebViewURLDecode(_ LayerProfile, value *MessagesChatInviteJoinResultWebView, url string) error {
	if value == nil {
		return fmt.Errorf("chat invite webview target is nil")
	}
	if url == "" {
		return fmt.Errorf("historical chat invite webview URL is empty")
	}
	value.Webview.URL = url
	return nil
}

func layerRequireChatInviteJoinWebViewDecode(_ LayerProfile, value *MessagesChatInviteJoinResultWebView) (WebViewResultURL, error) {
	if value == nil || value.Webview.URL == "" {
		return WebViewResultURL{}, fmt.Errorf("historical chat invite webview did not produce a non-empty URL")
	}
	return value.Webview, nil
}

func layerEncodeChatInviteJoinWebViewQueryIDEncode(_ LayerProfile, value *MessagesChatInviteJoinResultWebView) (int64, error) {
	if value == nil {
		return 0, fmt.Errorf("chat invite webview source is nil")
	}
	queryID, _ := value.Webview.GetQueryID()
	return queryID, nil
}

func layerEncodeChatInviteJoinWebViewURLEncode(_ LayerProfile, value *MessagesChatInviteJoinResultWebView) (string, error) {
	if value == nil || value.Webview.URL == "" {
		return "", fmt.Errorf("historical chat invite webview requires a non-empty URL")
	}
	return value.Webview.URL, nil
}

func layerCaptureStarGiftAttributeBackdropRarityPermilleDecode(_ LayerProfile, value *StarGiftAttributeBackdrop, permille int) error {
	if value == nil {
		return fmt.Errorf("star gift backdrop target is nil")
	}
	rarity, err := layerExactStarGiftRarity(permille)
	if err != nil {
		return err
	}
	value.Rarity = rarity
	return nil
}

func layerCaptureStarGiftAttributeModelRarityPermilleDecode(_ LayerProfile, value *StarGiftAttributeModel, permille int) error {
	if value == nil {
		return fmt.Errorf("star gift model target is nil")
	}
	rarity, err := layerExactStarGiftRarity(permille)
	if err != nil {
		return err
	}
	value.Rarity = rarity
	return nil
}

func layerCaptureStarGiftAttributePatternRarityPermilleDecode(_ LayerProfile, value *StarGiftAttributePattern, permille int) error {
	if value == nil {
		return fmt.Errorf("star gift pattern target is nil")
	}
	rarity, err := layerExactStarGiftRarity(permille)
	if err != nil {
		return err
	}
	value.Rarity = rarity
	return nil
}

func layerRequireStarGiftAttributeBackdropRarityDecode(_ LayerProfile, value *StarGiftAttributeBackdrop) (StarGiftAttributeRarityClass, error) {
	if value == nil || value.Rarity == nil {
		return nil, fmt.Errorf("historical star gift backdrop did not produce rarity")
	}
	return value.Rarity, nil
}

func layerRequireStarGiftAttributeModelRarityDecode(_ LayerProfile, value *StarGiftAttributeModel) (StarGiftAttributeRarityClass, error) {
	if value == nil || value.Rarity == nil {
		return nil, fmt.Errorf("historical star gift model did not produce rarity")
	}
	return value.Rarity, nil
}

func layerRequireStarGiftAttributePatternRarityDecode(_ LayerProfile, value *StarGiftAttributePattern) (StarGiftAttributeRarityClass, error) {
	if value == nil || value.Rarity == nil {
		return nil, fmt.Errorf("historical star gift pattern did not produce rarity")
	}
	return value.Rarity, nil
}

func layerEncodeStarGiftAttributeBackdropRarityPermilleEncode(_ LayerProfile, value *StarGiftAttributeBackdrop) (int, error) {
	if value == nil {
		return 0, fmt.Errorf("star gift backdrop source is nil")
	}
	return layerStarGiftRarityPermille(value.Rarity)
}

func layerEncodeStarGiftAttributeModelRarityPermilleEncode(_ LayerProfile, value *StarGiftAttributeModel) (int, error) {
	if value == nil {
		return 0, fmt.Errorf("star gift model source is nil")
	}
	return layerStarGiftRarityPermille(value.Rarity)
}

func layerEncodeStarGiftAttributePatternRarityPermilleEncode(_ LayerProfile, value *StarGiftAttributePattern) (int, error) {
	if value == nil {
		return 0, fmt.Errorf("star gift pattern source is nil")
	}
	return layerStarGiftRarityPermille(value.Rarity)
}

func layerExactStarGiftRarity(permille int) (StarGiftAttributeRarityClass, error) {
	if permille < 0 || permille > 1000 {
		return nil, fmt.Errorf("star gift rarity permille %d is outside [0,1000]", permille)
	}
	return &StarGiftAttributeRarity{Permille: permille}, nil
}

func layerStarGiftRarityPermille(rarity StarGiftAttributeRarityClass) (int, error) {
	switch value := rarity.(type) {
	case *StarGiftAttributeRarity:
		if value == nil {
			return 0, fmt.Errorf("star gift exact rarity is nil")
		}
		if _, err := layerExactStarGiftRarity(value.Permille); err != nil {
			return 0, err
		}
		return value.Permille, nil
	case nil:
		return 0, fmt.Errorf("star gift rarity is nil")
	default:
		return 0, fmt.Errorf("historical rarity_permille cannot represent %T", rarity)
	}
}

// The owner parameter is required: the new schema stores answer positions,
// while layers 220-223 stored the corresponding opaque PollAnswer.option bytes.
func layerAdaptInputMediaPollCorrectAnswersEncode(_ LayerProfile, owner *InputMediaPoll, present bool, positions []int) ([][]byte, bool, error) {
	if !present {
		return nil, false, nil
	}
	options, err := layerPollOptions(owner)
	if err != nil {
		return nil, false, err
	}
	result := make([][]byte, 0, len(positions))
	seen := make(map[int]struct{}, len(positions))
	for _, position := range positions {
		if position < 0 || position >= len(options) {
			return nil, false, fmt.Errorf("correct answer position %d is outside poll answers", position)
		}
		if _, duplicate := seen[position]; duplicate {
			return nil, false, fmt.Errorf("correct answer position %d is repeated", position)
		}
		seen[position] = struct{}{}
		result = append(result, bytes.Clone(options[position]))
	}
	return result, true, nil
}

func layerAdaptInputMediaPollCorrectAnswersDecode(_ LayerProfile, owner *InputMediaPoll, present bool, wireOptions [][]byte) ([]int, bool, error) {
	if !present {
		return nil, false, nil
	}
	options, err := layerPollOptions(owner)
	if err != nil {
		return nil, false, err
	}
	result := make([]int, 0, len(wireOptions))
	seen := make(map[int]struct{}, len(wireOptions))
	for _, wireOption := range wireOptions {
		position := -1
		for index, option := range options {
			if bytes.Equal(wireOption, option) {
				if position != -1 {
					return nil, false, fmt.Errorf("poll contains duplicate option bytes for a correct answer")
				}
				position = index
			}
		}
		if position == -1 {
			return nil, false, fmt.Errorf("historical correct answer does not match any poll option")
		}
		if _, duplicate := seen[position]; duplicate {
			return nil, false, fmt.Errorf("historical correct answer position %d is repeated", position)
		}
		seen[position] = struct{}{}
		result = append(result, position)
	}
	return result, true, nil
}

func layerPollOptions(owner *InputMediaPoll) ([][]byte, error) {
	if owner == nil {
		return nil, fmt.Errorf("input media poll owner is nil")
	}
	result := make([][]byte, len(owner.Poll.Answers))
	for index, answer := range owner.Poll.Answers {
		value, ok := answer.(*PollAnswer)
		if !ok || value == nil {
			return nil, fmt.Errorf("poll answer %d has unsupported value %T", index, answer)
		}
		for previous := 0; previous < index; previous++ {
			if bytes.Equal(result[previous], value.Option) {
				return nil, fmt.Errorf("poll answers %d and %d have duplicate option bytes", previous, index)
			}
		}
		result[index] = value.Option
	}
	return result, nil
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

func layerAliasChannelsEditCreator(_ LayerProfile, channel InputChannelClass, user InputUserClass, password InputCheckPasswordSRPClass) (*MessagesEditChatCreatorRequest, error) {
	peer, err := layerInputChannelToPeer(channel)
	if err != nil {
		return nil, err
	}
	if user == nil || password == nil {
		return nil, fmt.Errorf("channels.editCreator requires non-nil user and password")
	}
	return &MessagesEditChatCreatorRequest{Peer: peer, UserID: user, Password: password}, nil
}

func layerAliasChannelsGetFutureCreatorAfterLeave(_ LayerProfile, channel InputChannelClass) (*MessagesGetFutureChatCreatorAfterLeaveRequest, error) {
	peer, err := layerInputChannelToPeer(channel)
	if err != nil {
		return nil, err
	}
	return &MessagesGetFutureChatCreatorAfterLeaveRequest{Peer: peer}, nil
}

func layerInputChannelToPeer(channel InputChannelClass) (InputPeerClass, error) {
	switch value := channel.(type) {
	case *InputChannelEmpty:
		if value == nil {
			return nil, fmt.Errorf("input channel is nil")
		}
		return &InputPeerEmpty{}, nil
	case *InputChannel:
		if value == nil {
			return nil, fmt.Errorf("input channel is nil")
		}
		return &InputPeerChannel{ChannelID: value.ChannelID, AccessHash: value.AccessHash}, nil
	case *InputChannelFromMessage:
		if value == nil || value.Peer == nil {
			return nil, fmt.Errorf("input channel from message is incomplete")
		}
		return &InputPeerChannelFromMessage{Peer: value.Peer, MsgID: value.MsgID, ChannelID: value.ChannelID}, nil
	case nil:
		return nil, fmt.Errorf("input channel is nil")
	default:
		return nil, fmt.Errorf("unsupported input channel %T", channel)
	}
}
