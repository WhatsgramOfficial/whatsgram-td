package tlprofile

import (
	"bytes"
	"testing"

	"github.com/iamxvbaba/td/bin"
	"github.com/iamxvbaba/td/tg"
)

func TestFrozenObjectOwnsCanonicalSnapshotAndEncodesExactProfiles(t *testing.T) {
	value := &tg.Updates{Updates: []tg.UpdateClass{}, Users: []tg.UserClass{}, Chats: []tg.ChatClass{}, Date: 1, Seq: 2}
	frozen, err := FreezeObject(value)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.CanonicalSize() <= 0 {
		t.Fatal("frozen canonical size is empty")
	}
	value.Date = 99
	for _, profile := range []Profile{Profile225, Profile226, Profile227, Profile228} {
		var first, second bin.Buffer
		if err := frozen.Encode(profile, &first); err != nil {
			t.Fatal(err)
		}
		if err := frozen.Encode(profile, &second); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Raw(), second.Raw()) {
			t.Fatalf("profile %d frozen encode changed", profile)
		}
		decoded, err := DecodeObject(profile, &bin.Buffer{Buf: first.Copy()}, Limits{})
		if err != nil {
			t.Fatal(err)
		}
		updates, ok := decoded.(*tg.Updates)
		if !ok || updates.Date != 1 {
			t.Fatalf("profile %d snapshot = %#v", profile, decoded)
		}
	}
}
