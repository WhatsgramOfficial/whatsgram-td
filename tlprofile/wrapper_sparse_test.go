package tlprofile

import (
	"bytes"
	"errors"
	"testing"

	"github.com/iamxvbaba/td/bin"
	"github.com/iamxvbaba/td/tg"
)

func TestSparseWrapperAdmissionAndDefaultProfileOverride(t *testing.T) {
	var body bin.Buffer
	putInvokeWithLayer(&body, 225)
	body.PutID(tg.InitConnectionRequestTypeID)
	body.PutUint32(0)
	body.PutInt(77)
	body.PutString("desktop")
	body.PutString("test-os")
	body.PutString("1.2.3")
	body.PutString("en")
	body.PutString("tdesktop")
	body.PutString("en")
	body.PutID(tg.HelpGetConfigRequestTypeID)
	fullSize := body.Len()

	d := NewDispatcher()
	admitted, err := d.AdmitDefault(Profile228, &body, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if body.Len() != 0 {
		t.Fatalf("remaining body = %d", body.Len())
	}
	if admitted.Call().Profile() != Profile225 || admitted.Call().Method() != SemanticMethodHelpGetConfig {
		t.Fatalf("terminal = profile %d method %#x", admitted.Call().Profile(), admitted.Call().Method())
	}
	if effective, ok := admitted.EffectiveProfile(); !ok || effective != Profile225 {
		t.Fatalf("effective profile = %d/%v", effective, ok)
	}
	if evidence, ok := admitted.ProfileEvidence(); !ok || evidence != Profile225 {
		t.Fatalf("profile evidence = %d/%v", evidence, ok)
	}
	if admitted.Prepared().WireSize() != fullSize {
		t.Fatalf("prepared wire size = %d, want %d", admitted.Prepared().WireSize(), fullSize)
	}
	if admitted.WrapperCount() != 2 {
		t.Fatalf("wrapper count = %d", admitted.WrapperCount())
	}

	outer, ok := admitted.Wrapper(0)
	if !ok || outer.Semantic() != SemanticMethodInvokeWithLayer || outer.Profile() != Profile228 {
		t.Fatalf("outer wrapper = %#v/%v", outer, ok)
	}
	layer, present, found, err := outer.Value("layer")
	if err != nil || !present || !found || layer != 225 {
		t.Fatalf("layer metadata = %#v/%v/%v/%v", layer, present, found, err)
	}
	inner, ok := admitted.Wrapper(1)
	if !ok || inner.Semantic() != SemanticMethodInitConnection || inner.Profile() != Profile225 {
		t.Fatalf("inner wrapper = %#v/%v", inner, ok)
	}
	device, present, found, err := inner.Value("device_model")
	if err != nil || !present || !found || device != "desktop" {
		t.Fatalf("device metadata = %#v/%v/%v/%v", device, present, found, err)
	}
	if _, present, found, err := inner.Value("proxy"); err != nil || present || !found {
		t.Fatalf("proxy metadata = present:%v found:%v err:%v", present, found, err)
	}
}

func TestSparseStrictAdmissionRejectsConflictingInvokeWithLayerTransactionally(t *testing.T) {
	var body bin.Buffer
	putInvokeWithLayer(&body, 225)
	body.PutID(tg.HelpGetConfigRequestTypeID)
	original := append([]byte(nil), body.Raw()...)
	_, err := NewDispatcher().Admit(Profile228, &body, Limits{})
	if !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("admit error = %v", err)
	}
	if !bytes.Equal(original, body.Raw()) {
		t.Fatal("conflicting wrapper admission consumed input")
	}
}

func TestSparseWrapperVectorMetadataIsImmutable(t *testing.T) {
	request := &tg.InvokeAfterMsgsRequest{MsgIDs: []int64{11, 22}, Query: &tg.HelpGetConfigRequest{}}
	var body bin.Buffer
	if err := EncodeObject(Profile228, request, &body); err != nil {
		t.Fatal(err)
	}
	admitted, err := NewDispatcher().Admit(Profile228, &body, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	wrapper, ok := admitted.Wrapper(0)
	if !ok {
		t.Fatal("missing invokeAfterMsgs wrapper")
	}
	first, present, found, err := wrapper.Value("msg_ids")
	if err != nil || !present || !found {
		t.Fatalf("first metadata read = %v/%v/%v", present, found, err)
	}
	firstIDs := first.([]int64)
	firstIDs[0] = 99
	second, _, _, err := wrapper.Value("msg_ids")
	if err != nil {
		t.Fatal(err)
	}
	if got := second.([]int64); !bytes.Equal(int64SliceBytes(got), int64SliceBytes([]int64{11, 22})) {
		t.Fatalf("mutable metadata leaked: %v", got)
	}
}

func TestSparseUnprofiledAdmission(t *testing.T) {
	t.Run("invariant terminal", func(t *testing.T) {
		var body bin.Buffer
		body.PutID(tg.HelpGetConfigRequestTypeID)
		admitted, err := NewDispatcher().AdmitUnprofiled(&body, Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if admitted.Call().Profile() != ProfileCanonical || !admitted.Call().WireInvariant() {
			t.Fatalf("call profile/invariant = %d/%v", admitted.Call().Profile(), admitted.Call().WireInvariant())
		}
		if effective, ok := admitted.EffectiveProfile(); ok || effective != 0 {
			t.Fatalf("effective profile = %d/%v", effective, ok)
		}
		if evidence, ok := admitted.ProfileEvidence(); ok || evidence != 0 {
			t.Fatalf("profile evidence = %d/%v", evidence, ok)
		}
	})

	t.Run("explicit selector", func(t *testing.T) {
		var body bin.Buffer
		putInvokeWithLayer(&body, 226)
		body.PutID(tg.HelpGetConfigRequestTypeID)
		admitted, err := NewDispatcher().AdmitUnprofiled(&body, Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if admitted.Call().Profile() != Profile226 || admitted.WrapperCount() != 1 {
			t.Fatalf("call profile/wrappers = %d/%d", admitted.Call().Profile(), admitted.WrapperCount())
		}
		if evidence, ok := admitted.ProfileEvidence(); !ok || evidence != Profile226 {
			t.Fatalf("profile evidence = %d/%v", evidence, ok)
		}
	})

	t.Run("known method requires profile", func(t *testing.T) {
		if tlUnprofiledInvariant(tg.MessagesSendMessageRequestTypeID) {
			t.Fatal("messages.sendMessage unexpectedly became an unprofiled invariant")
		}
		var body bin.Buffer
		body.PutID(tg.MessagesSendMessageRequestTypeID)
		before := body.Copy()
		_, err := NewDispatcher().AdmitUnprofiled(&body, Limits{})
		if !errors.Is(err, ErrProfileRequired) {
			t.Fatalf("admit error = %v", err)
		}
		if !bytes.Equal(before, body.Raw()) {
			t.Fatal("profile-required rejection consumed input")
		}
	})

	t.Run("unknown method", func(t *testing.T) {
		var body bin.Buffer
		body.PutID(0x7f00aa55)
		_, err := NewDispatcher().AdmitUnprofiled(&body, Limits{})
		if !errors.Is(err, ErrUnknownRPCMethod) {
			t.Fatalf("admit error = %v", err)
		}
	})
}

func TestSparseUnknownWrappedTerminalEvidence(t *testing.T) {
	const unknown = uint32(0xd1435160)
	for _, profile := range []Profile{Profile225, Profile226, Profile227, Profile228} {
		var body bin.Buffer
		putInvokeWithLayer(&body, int(profile))
		body.PutID(tg.InitConnectionRequestTypeID)
		body.PutUint32(0)
		body.PutInt(1)
		for _, value := range []string{"device", "system", "app", "en", "", "en"} {
			body.PutString(value)
		}
		body.PutID(unknown)
		before := body.Copy()
		_, err := NewDispatcher().Admit(profile, &body, Limits{})
		if !errors.Is(err, ErrUnknownRPCMethod) {
			t.Fatalf("profile %d error = %v", profile, err)
		}
		var terminal *UnknownTerminalError
		if !errors.As(err, &terminal) {
			t.Fatalf("profile %d error type = %T", profile, err)
		}
		if terminal.Profile != profile || terminal.WireID != unknown || terminal.WireSize != 4 || terminal.WrapperCount() != 2 {
			t.Fatalf("profile %d terminal = %+v wrappers=%d", profile, terminal, terminal.WrapperCount())
		}
		outer, outerOK := terminal.Wrapper(0)
		inner, innerOK := terminal.Wrapper(1)
		if !outerOK || !innerOK || outer.Semantic() != SemanticMethodInvokeWithLayer || inner.Semantic() != SemanticMethodInitConnection {
			t.Fatalf("profile %d wrapper chain = %#v/%v %#v/%v", profile, outer, outerOK, inner, innerOK)
		}
		if !bytes.Equal(body.Raw(), before) {
			t.Fatalf("profile %d failed admission consumed input", profile)
		}
	}
}

func int64SliceBytes(values []int64) []byte {
	var b bin.Buffer
	for _, value := range values {
		b.PutLong(value)
	}
	return b.Copy()
}

func putInvokeWithLayer(body *bin.Buffer, layer int) {
	body.PutID(tg.InvokeWithLayerRequestTypeID)
	body.PutInt(layer)
}
