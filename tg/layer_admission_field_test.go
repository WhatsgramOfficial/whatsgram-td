package tg

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/iamxvbaba/td/bin"
)

func encodeLayerAdmissionFixture(t testing.TB, value bin.Encoder) []byte {
	t.Helper()
	var b bin.Buffer
	if err := value.Encode(&b); err != nil {
		t.Fatal(err)
	}
	return b.Copy()
}

func TestLayerRPCAdmissionFieldRegistrationCoverage(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	callback := func(LayerRPCAdmissionFieldView) error { return nil }
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(0, callback); err == nil {
		t.Fatal("unknown field ID was accepted")
	}
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUsersGetUsersID, nil); err == nil {
		t.Fatal("nil field callback was accepted")
	}
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldAccountToggleWebBrowserSettingsExceptionURL, callback); err != nil {
		t.Fatalf("field observable on every admitted profile was rejected: %v", err)
	}
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUsersGetUsersID, callback); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUsersGetUsersID, callback); err == nil {
		t.Fatal("duplicate field callback was accepted")
	}

	profiles := 0
	if err := VisitLayerRPCAdmissionFieldCoverage(LayerRPCFieldUsersGetUsersID, func(coverage LayerRPCAdmissionFieldCoverage) bool {
		profiles++
		if coverage.Status != LayerRPCAdmissionFieldObservable || coverage.ProfileField != "id" || coverage.WireID == 0 {
			t.Fatalf("users.getUsers/id coverage = %+v", coverage)
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	wantProfiles := 0
	for layer := 1; layer <= int(LayerProfileCanonical); layer++ {
		if _, ok := ResolveLayerProfile(layer); ok {
			wantProfiles++
		}
	}
	if profiles != wantProfiles {
		t.Fatalf("coverage profiles = %d, want every supported profile (%d)", profiles, wantProfiles)
	}
}

func TestLayerRPCAdmissionFieldVectorAndWrappedTerminalOnce(t *testing.T) {
	request := &UsersGetUsersRequest{ID: []InputUserClass{&InputUserSelf{}}}
	wrapper := &InvokeWithLayerRequest{Layer: int(LayerProfileCanonical), Query: request}
	wire := encodeLayerAdmissionFixture(t, wrapper)
	dispatcher := NewServerDispatcher(nil)
	rootCalls, fieldCalls := 0, 0
	dispatcher.OnLayerRPCAdmissionPreflight(func(view LayerRPCAdmissionView) error {
		rootCalls++
		if view.Semantic() != LayerSemanticMethodUsersGetUsers || view.WireID() != UsersGetUsersRequestTypeID {
			t.Fatalf("terminal root view = semantic:%v wire:%#08x", view.Semantic(), view.WireID())
		}
		return nil
	})
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUsersGetUsersID, func(view LayerRPCAdmissionFieldView) error {
		fieldCalls++
		length, ok := view.VectorLength()
		if !ok || length != 1 || !view.Present() || view.Profile() != LayerProfileCanonical ||
			view.Semantic() != LayerSemanticMethodUsersGetUsers || view.WireID() != UsersGetUsersRequestTypeID ||
			view.FieldID() != LayerRPCFieldUsersGetUsersID {
			t.Fatalf("vector field view = %+v length=%d ok=%v", view, length, ok)
		}
		if _, ok := view.BytesLength(); ok {
			t.Fatal("vector field exposed bytes metric")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b := bin.Buffer{Buf: wire}
	if _, err := dispatcher.AdmitLayer(LayerProfileCanonical, &b); err != nil {
		t.Fatal(err)
	}
	if rootCalls != 1 || fieldCalls != 1 || b.Len() != 0 {
		t.Fatalf("callbacks root=%d field=%d remaining=%d", rootCalls, fieldCalls, b.Len())
	}
}

func TestLayerRPCAdmissionFieldConditionalAbsentExactlyOnce(t *testing.T) {
	wire := encodeLayerAdmissionFixture(t, &ContactsGetLocatedRequest{GeoPoint: &InputGeoPointEmpty{}})
	dispatcher := NewServerDispatcher(nil)
	calls := 0
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldContactsGetLocatedSelfExpires, func(view LayerRPCAdmissionFieldView) error {
		calls++
		if view.Present() {
			t.Fatal("absent conditional field reported present")
		}
		if _, ok := view.Int32(); ok {
			t.Fatal("absent conditional field exposed an int32 value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b := bin.Buffer{Buf: wire}
	if _, err := dispatcher.AdmitLayer(LayerProfileCanonical, &b); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("absent callback calls = %d, want 1", calls)
	}
}

func TestLayerRPCAdmissionFieldRejectIsTransactionalBeforeBytesCopy(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 1<<20)
	wire := encodeLayerAdmissionFixture(t, &UploadSaveBigFilePartRequest{
		FileID: 1, FilePart: 2, FileTotalParts: 3, Bytes: payload,
	})
	original := append([]byte(nil), wire...)
	sentinel := errors.New("reject upload bytes")
	dispatcher := NewServerDispatcher(nil)
	calls, intCalls := 0, 0
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUploadSaveBigFilePartFileTotalParts, func(view LayerRPCAdmissionFieldView) error {
		intCalls++
		value, ok := view.Int32()
		if !ok || value != 3 || !view.Present() {
			t.Fatalf("int32 field view value=%d ok=%v present=%v", value, ok, view.Present())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUploadSaveBigFilePartBytes, func(view LayerRPCAdmissionFieldView) error {
		calls++
		length, ok := view.BytesLength()
		if !ok || length != len(payload) || !view.Present() {
			t.Fatalf("bytes field view length=%d ok=%v present=%v", length, ok, view.Present())
		}
		return sentinel
	}); err != nil {
		t.Fatal(err)
	}
	b := bin.Buffer{Buf: wire}
	if _, err := dispatcher.AdmitLayer(LayerProfileCanonical, &b); !errors.Is(err, sentinel) {
		t.Fatalf("admission error = %v, want sentinel", err)
	}
	if calls != 1 || intCalls != 1 || !bytes.Equal(b.Raw(), original) {
		t.Fatalf("rejected admission bytes_calls=%d int_calls=%d len=%d; input cursor/body changed", calls, intCalls, b.Len())
	}
}

func TestLayerRPCAdmissionFieldMalformedWireBeforeCallback(t *testing.T) {
	dispatcher := NewServerDispatcher(nil)
	vectorCalls := 0
	if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUsersGetUsersID, func(LayerRPCAdmissionFieldView) error {
		vectorCalls++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var vector bin.Buffer
	vector.PutID(UsersGetUsersRequestTypeID)
	vector.PutVectorHeader(2) // No element constructor IDs follow.
	originalVector := vector.Copy()
	if _, err := dispatcher.AdmitLayer(LayerProfileCanonical, &vector); err == nil {
		t.Fatal("truncated vector was admitted")
	}
	if vectorCalls != 0 || !bytes.Equal(vector.Raw(), originalVector) {
		t.Fatalf("truncated vector callback=%d input changed", vectorCalls)
	}

	bytesDispatcher := NewServerDispatcher(nil)
	bytesCalls := 0
	if err := bytesDispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUploadSaveBigFilePartBytes, func(LayerRPCAdmissionFieldView) error {
		bytesCalls++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	full := encodeLayerAdmissionFixture(t, &UploadSaveBigFilePartRequest{FileID: 1, FilePart: 2, FileTotalParts: 3, Bytes: []byte("payload")})
	truncated := append([]byte(nil), full[:len(full)-4]...)
	originalBytes := append([]byte(nil), truncated...)
	b := bin.Buffer{Buf: truncated}
	if _, err := bytesDispatcher.AdmitLayer(LayerProfileCanonical, &b); err == nil {
		t.Fatal("truncated bytes were admitted")
	}
	if bytesCalls != 0 || !bytes.Equal(b.Raw(), originalBytes) {
		t.Fatalf("truncated bytes callback=%d input changed", bytesCalls)
	}
}

func TestLayerRPCAdmissionFieldAddsNoPerAdmissionAllocation(t *testing.T) {
	wire := encodeLayerAdmissionFixture(t, &UsersGetUsersRequest{})
	without := NewServerDispatcher(nil)
	with := NewServerDispatcher(nil)
	if err := with.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUsersGetUsersID, func(LayerRPCAdmissionFieldView) error { return nil }); err != nil {
		t.Fatal(err)
	}
	measure := func(dispatcher *ServerDispatcher) float64 {
		var b bin.Buffer
		return testing.AllocsPerRun(100, func() {
			b.ResetTo(wire)
			if _, err := dispatcher.AdmitLayer(LayerProfileCanonical, &b); err != nil {
				panic(err)
			}
		})
	}
	base, observed := measure(without), measure(with)
	if observed != base {
		t.Fatalf("field callback allocations/admission = %.0f, no callback = %.0f", observed, base)
	}
}

func BenchmarkLayerRPCAdmissionField(b *testing.B) {
	vectorWire := encodeLayerAdmissionFixture(b, &UsersGetUsersRequest{})
	for _, observed := range []bool{false, true} {
		name := "NoCallback"
		dispatcher := NewServerDispatcher(nil)
		if observed {
			name = "VectorLengthCallback"
			if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUsersGetUsersID, func(LayerRPCAdmissionFieldView) error { return nil }); err != nil {
				b.Fatal(err)
			}
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			var wire bin.Buffer
			for i := 0; i < b.N; i++ {
				wire.ResetTo(vectorWire)
				if _, err := dispatcher.AdmitLayer(LayerProfileCanonical, &wire); err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	sentinel := errors.New("benchmark reject")
	for _, size := range []int{1 << 10, 1 << 20} {
		payload := bytes.Repeat([]byte{0x5a}, size)
		encoded := encodeLayerAdmissionFixture(b, &UploadSaveBigFilePartRequest{FileID: 1, FilePart: 2, FileTotalParts: 3, Bytes: payload})
		dispatcher := NewServerDispatcher(nil)
		if err := dispatcher.OnLayerRPCAdmissionFieldPreflight(LayerRPCFieldUploadSaveBigFilePartBytes, func(LayerRPCAdmissionFieldView) error { return sentinel }); err != nil {
			b.Fatal(err)
		}
		b.Run("RejectBytes"+strconv.Itoa(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			var wire bin.Buffer
			for i := 0; i < b.N; i++ {
				wire.ResetTo(encoded)
				if _, err := dispatcher.AdmitLayer(LayerProfileCanonical, &wire); !errors.Is(err, sentinel) {
					b.Fatalf("admission error = %v", err)
				}
			}
		})
	}
}
