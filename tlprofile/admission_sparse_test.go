package tlprofile

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/iamxvbaba/td/bin"
	"github.com/iamxvbaba/td/tg"
)

func TestSparseAdmissionPreflightAndFieldMetrics(t *testing.T) {
	profiles := []Profile{Profile225, Profile226, Profile227, Profile228}
	for _, profile := range profiles {
		t.Run(fmt.Sprintf("%d", profile), func(t *testing.T) {
			d := NewDispatcher()
			var order []string
			d.OnAdmissionPreflight(func(view AdmissionView) error {
				order = append(order, "raw")
				if view.Profile() != profile || view.Semantic() != SemanticMethodUploadSaveBigFilePart || view.WireID() == 0 || view.WireSize() == 0 {
					t.Fatalf("unexpected admission view: profile=%d semantic=%#x wire=%#x size=%d", view.Profile(), view.Semantic(), view.WireID(), view.WireSize())
				}
				wireID, err := view.Uint32At(0)
				if err != nil || wireID != view.WireID() {
					t.Fatalf("wire ID = %#x, %v", wireID, err)
				}
				prefix, err := view.ReadAt(0, 4)
				if err != nil || len(prefix) != 4 {
					t.Fatalf("prefix = %x, %v", prefix, err)
				}
				prefix[0] ^= 0xff
				actual, err := view.ByteAt(0)
				if err != nil || actual != byte(wireID) {
					t.Fatalf("immutable prefix byte = %#x, %v", actual, err)
				}
				return nil
			})
			if err := d.OnFieldPreflight(FieldUploadSaveBigFilePartFileTotalParts, func(view FieldView) error {
				order = append(order, "parts")
				value, ok := view.Int32()
				if !ok || value != 3 || !view.Present() {
					t.Fatalf("parts = %d, %v, present=%v", value, ok, view.Present())
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := d.OnFieldPreflight(FieldUploadSaveBigFilePartBytes, func(view FieldView) error {
				order = append(order, "bytes")
				length, ok := view.BytesLength()
				if !ok || length != 5 || !view.Present() {
					t.Fatalf("bytes = %d, %v, present=%v", length, ok, view.Present())
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			var body bin.Buffer
			if err := EncodeObject(profile, &tg.UploadSaveBigFilePartRequest{FileID: 9, FilePart: 1, FileTotalParts: 3, Bytes: []byte("hello")}, &body); err != nil {
				t.Fatal(err)
			}
			if _, err := d.Admit(profile, &body, Limits{}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal([]byte("raw,parts,bytes"), []byte(joinTestOrder(order))) {
				t.Fatalf("callback order = %v", order)
			}
		})
	}
}

func TestSparseAdmissionReportsAbsentConditionalField(t *testing.T) {
	d := NewDispatcher()
	calls := 0
	if err := d.OnFieldPreflight(FieldContactsGetLocatedSelfExpires, func(view FieldView) error {
		calls++
		if view.Present() {
			t.Fatal("self_expires unexpectedly present")
		}
		if _, ok := view.Int32(); ok {
			t.Fatal("absent int32 exposed a value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var body bin.Buffer
	if err := EncodeObject(Profile225, &tg.ContactsGetLocatedRequest{GeoPoint: &tg.InputGeoPointEmpty{}}, &body); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Admit(Profile225, &body, Limits{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("absent callback calls = %d", calls)
	}
}

func TestSparseFieldPreflightRejectsBeforeConsumption(t *testing.T) {
	sentinel := errors.New("field rejected")
	d := NewDispatcher()
	if err := d.OnFieldPreflight(FieldUsersGetUsersID, func(view FieldView) error {
		length, ok := view.VectorLength()
		if !ok || length != 1 {
			t.Fatalf("vector length = %d, %v", length, ok)
		}
		return sentinel
	}); err != nil {
		t.Fatal(err)
	}
	var body bin.Buffer
	if err := EncodeObject(Profile228, &tg.UsersGetUsersRequest{ID: []tg.InputUserClass{&tg.InputUserSelf{}}}, &body); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), body.Raw()...)
	if _, err := d.Admit(Profile228, &body, Limits{}); !errors.Is(err, sentinel) {
		t.Fatalf("admit error = %v", err)
	}
	if !bytes.Equal(original, body.Raw()) {
		t.Fatal("rejected admission consumed or mutated input")
	}
}

func joinTestOrder(values []string) string {
	var out []byte
	for index, value := range values {
		if index != 0 {
			out = append(out, ',')
		}
		out = append(out, value...)
	}
	return string(out)
}
