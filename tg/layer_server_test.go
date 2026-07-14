package tg

import (
	"errors"
	"testing"

	"github.com/gotd/td/bin"
)

func TestLayerUnknownRPCMethodHasTypedClassification(t *testing.T) {
	var body bin.Buffer
	body.PutID(0x01020304)
	_, err := NewServerDispatcher(nil).AdmitLayer(LayerProfileCanonical, &body)
	if !errors.Is(err, ErrLayerUnknownRPCMethod) {
		t.Fatalf("AdmitLayer error = %v, want ErrLayerUnknownRPCMethod", err)
	}
}
