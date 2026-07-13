package semantic

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// ShapeDigest is a stable SHA-256 digest of TL semantic wire shape.
type ShapeDigest [sha256.Size]byte

func (d ShapeDigest) String() string {
	return hex.EncodeToString(d[:])
}

type shapeWriter struct {
	h hash.Hash
}

func newShapeWriter(domain string) *shapeWriter {
	w := &shapeWriter{h: sha256.New()}
	w.string(domain)
	return w
}

func (w *shapeWriter) byte(v byte) {
	_, _ = w.h.Write([]byte{v})
}

func (w *shapeWriter) bool(v bool) {
	if v {
		w.byte(1)
		return
	}
	w.byte(0)
}

func (w *shapeWriter) uint64(v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	_, _ = w.h.Write(buf[:])
}

func (w *shapeWriter) string(v string) {
	w.uint64(uint64(len(v)))
	_, _ = w.h.Write([]byte(v))
}

func (w *shapeWriter) digest(v ShapeDigest) {
	_, _ = w.h.Write(v[:])
}

func (w *shapeWriter) typeRef(ref TypeRef) {
	w.byte(byte(ref.Kind))
	w.string(ref.QName)
	w.bool(ref.Bare)
	w.bool(ref.Percent)
	w.bool(ref.Arg != nil)
	if ref.Arg != nil {
		w.typeRef(*ref.Arg)
	}
}

func (w *shapeWriter) sum() (result ShapeDigest) {
	copy(result[:], w.h.Sum(nil))
	return result
}

func bodyShape(def *Definition) ShapeDigest {
	w := newShapeWriter("gotd.tl.semantic.body.v1")
	w.bool(def.Base)
	w.uint64(uint64(len(def.GenericParams)))
	for _, parameter := range def.GenericParams {
		w.string(parameter)
	}
	w.uint64(uint64(len(def.Fields)))
	for _, field := range def.Fields {
		w.byte(byte(field.Kind))
		w.string(field.Name)
		w.uint64(uint64(field.Ordinal))
		if field.Kind == FieldValue {
			w.typeRef(field.Type)
		}
		w.bool(field.Condition != nil)
		if field.Condition != nil {
			w.string(field.Condition.Word)
			w.byte(field.Condition.Bit)
			w.bool(field.Condition.PresenceOnly)
		}
	}
	return w.sum()
}

func signatureShape(def *Definition) ShapeDigest {
	w := newShapeWriter("gotd.tl.semantic.signature.v1")
	w.digest(def.BodyShape)
	w.typeRef(def.Result)
	return w.sum()
}
