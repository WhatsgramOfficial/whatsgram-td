package tg

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/gotd/td/bin"
)

const layerUnknownTerminalTestID = uint32(0xd1435160)

func layerUnknownTerminalWrappedBody(layer int, trailing bool) bin.Buffer {
	var body bin.Buffer
	body.PutID(InvokeWithLayerRequestTypeID)
	body.PutInt(layer)
	body.PutID(InitConnectionRequestTypeID)
	body.PutInt(0) // flags
	body.PutInt(1) // api_id
	for _, value := range []string{"device", "system", "app", "en", "", "en"} {
		body.PutString(value)
	}
	body.PutID(layerUnknownTerminalTestID)
	if trailing {
		body.PutInt(7)
	}
	return body
}

func TestLayerRPCUnknownTerminalEvidence225Through228(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	for _, profile := range []LayerProfile{LayerProfile225, LayerProfile226, LayerProfile227, LayerProfile228} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			body := layerUnknownTerminalWrappedBody(int(profile), false)
			before := body.Copy()
			_, err := dispatcher.AdmitLayer(profile, &body)
			if !errors.Is(err, ErrLayerUnknownRPCMethod) {
				t.Fatalf("wrapped unknown classification = %v, want ErrLayerUnknownRPCMethod", err)
			}
			var terminal *LayerRPCUnknownTerminalError
			if !errors.As(err, &terminal) {
				t.Fatalf("wrapped unknown type = %T, want *LayerRPCUnknownTerminalError", err)
			}
			if terminal.Profile != profile || terminal.WireID != layerUnknownTerminalTestID || terminal.WireSize != 4 {
				t.Fatalf("wrapped unknown evidence = %+v", terminal)
			}
			if terminal.WrapperCount() != 2 {
				t.Fatalf("wrapped unknown chain count = %d, want 2", terminal.WrapperCount())
			}
			outer, outerOK := terminal.Wrapper(0)
			inner, innerOK := terminal.Wrapper(1)
			if !outerOK || outer.Profile() != profile || outer.Semantic() != LayerSemanticMethodInvokeWithLayer || outer.WireID() != InvokeWithLayerRequestTypeID {
				t.Fatalf("outer wrapper evidence = %v/%+v", outerOK, outer)
			}
			if !innerOK || inner.Profile() != profile || inner.Semantic() != LayerSemanticMethodInitConnection || inner.WireID() != InitConnectionRequestTypeID {
				t.Fatalf("inner wrapper evidence = %v/%+v", innerOK, inner)
			}
			if _, ok := terminal.Wrapper(-1); ok {
				t.Fatal("negative wrapper index was accepted")
			}
			if _, ok := terminal.Wrapper(2); ok {
				t.Fatal("wrapper index beyond chain was accepted")
			}
			if !bytes.Equal(body.Raw(), before) {
				t.Fatal("failed admission consumed caller input")
			}
		})
	}
}

func TestLayerRPCUnknownTerminalEvidenceIncludesTrailingBytes(t *testing.T) {
	body := layerUnknownTerminalWrappedBody(228, true)
	_, err := NewServerDispatcher(nil).AdmitLayer(LayerProfile228, &body)
	var terminal *LayerRPCUnknownTerminalError
	if !errors.As(err, &terminal) {
		t.Fatalf("wrapped unknown type = %T, want *LayerRPCUnknownTerminalError: %v", err, err)
	}
	if terminal.Profile != LayerProfile228 || terminal.WireID != layerUnknownTerminalTestID || terminal.WireSize != 8 {
		t.Fatalf("wrapped unknown trailing evidence = %+v", terminal)
	}
	if terminal.WrapperCount() != 2 {
		t.Fatalf("wrapped unknown trailing chain count = %d, want 2", terminal.WrapperCount())
	}
}

func TestLayerRPCUnknownTerminalEvidenceRejectsFalseProofs(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)

	var naked bin.Buffer
	naked.PutID(layerUnknownTerminalTestID)
	_, err := dispatcher.AdmitLayer(LayerProfile228, &naked)
	var terminal *LayerRPCUnknownTerminalError
	if !errors.Is(err, ErrLayerUnknownRPCMethod) || errors.As(err, &terminal) {
		t.Fatalf("naked unknown was classified as decoded wrapper terminal: %#v / %v", terminal, err)
	}

	var malformed bin.Buffer
	malformed.PutID(InvokeWithLayerRequestTypeID)
	malformed.PutInt(228)
	malformed.PutID(InitConnectionRequestTypeID)
	malformed.PutInt(0) // flags, then required initConnection fields are absent
	_, err = dispatcher.AdmitLayer(LayerProfile228, &malformed)
	terminal = nil
	if err == nil || errors.As(err, &terminal) {
		t.Fatalf("malformed wrapper was classified as decoded terminal: %#v / %v", terminal, err)
	}
}
