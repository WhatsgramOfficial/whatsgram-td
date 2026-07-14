package tg

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/gotd/td/bin"
)

func TestLayerUnprofiledInvariantAuthBindTempAuthKey(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	dispatcher.OnAuthBindTempAuthKey(func(_ context.Context, request *AuthBindTempAuthKeyRequest) (bool, error) {
		if request.PermAuthKeyID != 11 || request.Nonce != 22 || request.ExpiresAt != 33 ||
			!bytes.Equal(request.EncryptedMessage, []byte{1, 2, 3}) {
			t.Fatalf("decoded auth.bindTempAuthKey request = %+v", request)
		}
		return true, nil
	})

	var body bin.Buffer
	if err := (&AuthBindTempAuthKeyRequest{
		PermAuthKeyID:    11,
		Nonce:            22,
		ExpiresAt:        33,
		EncryptedMessage: []byte{1, 2, 3},
	}).Encode(&body); err != nil {
		t.Fatal(err)
	}
	admitted, err := dispatcher.AdmitUnprofiled(&body)
	if err != nil {
		t.Fatal(err)
	}
	if body.Len() != 0 {
		t.Fatalf("auth.bindTempAuthKey admission left %d bytes", body.Len())
	}
	if evidence, ok := admitted.ProfileEvidence(); ok || evidence != LayerProfile(0) {
		t.Fatalf("invariant auth.bindTempAuthKey fabricated profile evidence: %d/%v", evidence, ok)
	}
	if effective, ok := admitted.EffectiveProfile(); ok || effective != LayerProfile(0) {
		t.Fatalf("invariant auth.bindTempAuthKey fabricated effective profile: %d/%v", effective, ok)
	}
	if admitted.Call().Profile() != LayerProfileCanonical {
		t.Fatalf("invariant internal codec profile = %d, want canonical", admitted.Call().Profile())
	}
	if !admitted.Call().WireInvariant() {
		t.Fatal("auth.bindTempAuthKey admission lost generated wire-invariant proof")
	}
	result, err := dispatcher.DispatchAdmitted(context.Background(), admitted)
	if err != nil {
		t.Fatal(err)
	}
	if !result.WireInvariant() {
		t.Fatal("auth.bindTempAuthKey result lost generated wire-invariant proof")
	}
	var encoded bin.Buffer
	if err := result.Encode(&encoded); err != nil {
		t.Fatal(err)
	}
	var want bin.Buffer
	want.PutID(BoolTrueTypeID)
	if !bytes.Equal(encoded.Raw(), want.Raw()) {
		t.Fatalf("auth.bindTempAuthKey Bool result = %x, want %x", encoded.Raw(), want.Raw())
	}
}

func TestLayerUnprofiledProfileEvidenceAndInvariantReplayIdentity(t *testing.T) {
	var wrapped bin.Buffer
	wrapped.PutID(InvokeWithLayerRequestTypeID)
	wrapped.PutInt(225)
	wrapped.PutID(HelpGetConfigRequestTypeID)
	wrappedAdmission, err := NewServerDispatcher(nil).AdmitUnprofiled(&wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if evidence, ok := wrappedAdmission.ProfileEvidence(); !ok || evidence != LayerProfile225 {
		t.Fatalf("invokeWithLayer profile evidence = %d/%v, want 225/true", evidence, ok)
	}
	if effective, ok := wrappedAdmission.EffectiveProfile(); !ok || effective != LayerProfile225 {
		t.Fatalf("invokeWithLayer effective profile = %d/%v, want 225/true", effective, ok)
	}

	request := &AuthBindTempAuthKeyRequest{
		PermAuthKeyID:    44,
		Nonce:            55,
		ExpiresAt:        66,
		EncryptedMessage: []byte{7, 8, 9},
	}
	var unprofiledBody bin.Buffer
	if err := request.Encode(&unprofiledBody); err != nil {
		t.Fatal(err)
	}
	unprofiled, err := NewServerDispatcher(nil).AdmitUnprofiled(&unprofiledBody)
	if err != nil {
		t.Fatal(err)
	}
	var profiledBody bin.Buffer
	if err := request.Encode(&profiledBody); err != nil {
		t.Fatal(err)
	}
	profiled, err := NewServerDispatcher(nil).AdmitLayer(LayerProfile225, &profiledBody)
	if err != nil {
		t.Fatal(err)
	}
	if evidence, ok := profiled.ProfileEvidence(); !ok || evidence != LayerProfile225 {
		t.Fatalf("frozen-profile admission evidence = %d/%v, want 225/true", evidence, ok)
	}
	if effective, ok := profiled.EffectiveProfile(); !ok || effective != LayerProfile225 {
		t.Fatalf("frozen-profile effective profile = %d/%v, want 225/true", effective, ok)
	}
	var canonicalBody bin.Buffer
	if err := request.Encode(&canonicalBody); err != nil {
		t.Fatal(err)
	}
	canonical, err := NewServerDispatcher(nil).AdmitLayer(LayerProfile227, &canonicalBody)
	if err != nil {
		t.Fatal(err)
	}
	if !profiled.Call().WireInvariant() || !canonical.Call().WireInvariant() {
		t.Fatal("auth.bindTempAuthKey Layer 225/227 routes do not share wire-invariant proof")
	}
	if unprofiled.Call().Profile() == profiled.Call().Profile() {
		t.Fatal("test did not exercise canonical representative followed by Layer 225")
	}
	if unprofiled.Prepared().Identity() != profiled.Prepared().Identity() {
		t.Fatal("invariant auth.bindTempAuthKey replay identity changed after Layer 225 freeze")
	}
	prepared, err := unprofiled.Call().prepareResult(true)
	if err != nil {
		t.Fatal(err)
	}
	var replayed bin.Buffer
	if err := prepared.Encode(profiled.Call(), &replayed); err != nil {
		t.Fatalf("reuse invariant result after Layer 225 freeze: %v", err)
	}
}

func TestLayerDefaultAdmissionExplicitOverride(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)

	var naked bin.Buffer
	naked.PutID(HelpGetConfigRequestTypeID)
	admitted, err := dispatcher.AdmitDefaultLayer(LayerProfile227, &naked)
	if err != nil {
		t.Fatal(err)
	}
	if effective, ok := admitted.EffectiveProfile(); !ok || effective != LayerProfile227 {
		t.Fatalf("naked inherited effective profile = %d/%v, want 227/true", effective, ok)
	}
	if evidence, ok := admitted.ProfileEvidence(); ok || evidence != LayerProfile(0) {
		t.Fatalf("naked inherited default became explicit evidence: %d/%v", evidence, ok)
	}

	var wrapped bin.Buffer
	wrapped.PutID(InvokeAfterMsgRequestTypeID)
	wrapped.PutLong(99)
	wrapped.PutID(InvokeWithLayerRequestTypeID)
	wrapped.PutInt(225)
	wrapped.PutID(HelpGetConfigRequestTypeID)
	strict := bin.Buffer{Buf: wrapped.Copy()}
	strictBefore := strict.Copy()
	admitted, err = dispatcher.AdmitDefaultLayer(LayerProfile227, &wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if effective, ok := admitted.EffectiveProfile(); !ok || effective != LayerProfile225 {
		t.Fatalf("explicit override effective profile = %d/%v, want 225/true", effective, ok)
	}
	if evidence, ok := admitted.ProfileEvidence(); !ok || evidence != LayerProfile225 {
		t.Fatalf("explicit override evidence = %d/%v, want 225/true", evidence, ok)
	}
	if admitted.Call().Profile() != LayerProfile225 || admitted.WrapperCount() != 2 {
		t.Fatalf("explicit override call profile/wrappers = %d/%d", admitted.Call().Profile(), admitted.WrapperCount())
	}
	if _, err := dispatcher.AdmitLayer(LayerProfile227, &strict); err == nil {
		t.Fatal("strict frozen admission accepted a conflicting invokeWithLayer")
	}
	if !bytes.Equal(strict.Raw(), strictBefore) {
		t.Fatal("strict frozen conflict mutated caller input")
	}
}

func TestLayerUnprofiledErrorClassification(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)

	var unsupported bin.Buffer
	unsupported.PutID(InvokeWithLayerRequestTypeID)
	unsupported.PutInt(224)
	unsupported.PutID(HelpGetConfigRequestTypeID)
	unsupportedBefore := unsupported.Copy()
	if _, err := dispatcher.AdmitUnprofiled(&unsupported); err == nil {
		t.Fatal("Layer 224 was accepted outside the maintained profile window")
	}
	if !bytes.Equal(unsupported.Raw(), unsupportedBefore) {
		t.Fatal("unsupported Layer 224 admission mutated caller input")
	}

	var known bin.Buffer
	known.PutID(MessagesGetHistoryRequestTypeID)
	knownBefore := known.Copy()
	if _, err := dispatcher.AdmitUnprofiled(&known); !errors.Is(err, ErrLayerProfileRequired) {
		t.Fatalf("known unprofiled RPC error = %v, want ErrLayerProfileRequired", err)
	}
	if !bytes.Equal(known.Raw(), knownBefore) {
		t.Fatal("profile-required classification mutated caller input")
	}

	var unknown bin.Buffer
	unknown.PutID(0xfeedbeef)
	if _, err := dispatcher.AdmitUnprofiled(&unknown); !errors.Is(err, ErrLayerUnknownRPCMethod) {
		t.Fatalf("unknown unprofiled constructor error = %v, want ErrLayerUnknownRPCMethod", err)
	}

	var malformed bin.Buffer
	malformed.PutID(InvokeWithLayerRequestTypeID)
	if _, err := dispatcher.AdmitUnprofiled(&malformed); err == nil || errors.Is(err, ErrLayerProfileRequired) || errors.Is(err, ErrLayerUnknownRPCMethod) {
		t.Fatalf("malformed invokeWithLayer classification = %v", err)
	}
}
