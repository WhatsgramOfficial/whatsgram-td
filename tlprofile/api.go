package tlprofile

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/iamxvbaba/td/bin"
)

// Limits bounds one exact admission or decode. Zero fields select generated
// defaults; the generated hard limits remain authoritative.
type Limits struct {
	MaxWireBytes         int
	MaxVectorElements    int
	MaxAggregateElements int
	MaxDepth             int
}

// FieldID is the stable identity of one observable top-level request field.
type FieldID uint64

// FieldView is an immutable scalar observation made before typed request
// materialization.
type FieldView struct {
	profile  Profile
	semantic SemanticID
	wireID   uint32
	fieldID  FieldID
	present  bool
	metric   tlFieldMetric
	value    int64
}

func (v FieldView) Profile() Profile     { return v.profile }
func (v FieldView) Semantic() SemanticID { return v.semantic }
func (v FieldView) WireID() uint32       { return v.wireID }
func (v FieldView) FieldID() FieldID     { return v.fieldID }
func (v FieldView) Present() bool        { return v.present }
func (v FieldView) VectorLength() (int, bool) {
	return int(v.value), v.present && v.metric == tlFieldMetricVectorLength
}
func (v FieldView) BytesLength() (int, bool) {
	return int(v.value), v.present && v.metric == tlFieldMetricBytesLength
}
func (v FieldView) Int32() (int32, bool) {
	return int32(v.value), v.present && v.metric == tlFieldMetricInt32
}

type FieldPreflight func(FieldView) error

// AdmissionView exposes a bounded immutable prefix view before an ordinary
// terminal request is consumed.
type AdmissionView struct {
	profile  Profile
	semantic SemanticID
	wireID   uint32
	raw      []byte
}

func (v AdmissionView) Profile() Profile     { return v.profile }
func (v AdmissionView) Semantic() SemanticID { return v.semantic }
func (v AdmissionView) WireID() uint32       { return v.wireID }
func (v AdmissionView) WireSize() int        { return len(v.raw) }
func (v AdmissionView) ByteAt(offset int) (byte, error) {
	if offset < 0 || offset >= len(v.raw) {
		return 0, fmt.Errorf("tlprofile: byte offset %d outside wire size %d", offset, len(v.raw))
	}
	return v.raw[offset], nil
}
func (v AdmissionView) Uint32At(offset int) (uint32, error) {
	if offset < 0 || offset > len(v.raw)-4 {
		return 0, fmt.Errorf("tlprofile: uint32 offset %d outside wire size %d", offset, len(v.raw))
	}
	return binary.LittleEndian.Uint32(v.raw[offset:]), nil
}
func (v AdmissionView) ReadAt(offset, length int) ([]byte, error) {
	if offset < 0 || length < 0 || offset > len(v.raw)-length {
		return nil, fmt.Errorf("tlprofile: range [%d,%d) outside wire size %d", offset, offset+length, len(v.raw))
	}
	return append([]byte(nil), v.raw[offset:offset+length]...), nil
}

type AdmissionPreflight func(AdmissionView) error

// OutboundCall is an opaque exact-profile request produced by an audited
// private-schema adapter.
type OutboundCall struct {
	sparse *sparseOutboundCall
}

func (c OutboundCall) Profile() Profile {
	if c.sparse == nil {
		return 0
	}
	return c.sparse.profile
}
func (c OutboundCall) Method() SemanticID {
	if c.sparse == nil {
		return 0
	}
	return c.sparse.method
}
func (c OutboundCall) WireID() uint32 {
	if c.sparse == nil {
		return 0
	}
	return c.sparse.wireID
}
func (c OutboundCall) Encode(out *bin.Buffer) error {
	if c.sparse == nil {
		return errors.New("tlprofile: encode empty outbound call")
	}
	return EncodeObject(c.sparse.profile, c.sparse.request, out)
}

// UnknownMethodView is a transactional view of an unknown innermost terminal.
type UnknownMethodView struct {
	sparse *sparseUnknownMethodView
}

func (v UnknownMethodView) Profile() Profile {
	if v.sparse == nil {
		return 0
	}
	return v.sparse.profile
}
func (v UnknownMethodView) WireID() uint32 {
	if v.sparse == nil {
		return 0
	}
	return v.sparse.wireID
}
func (v UnknownMethodView) WireSize() int {
	if v.sparse == nil {
		return 0
	}
	return len(v.sparse.raw)
}
func (v UnknownMethodView) Buffer() (*bin.Buffer, error) {
	if v.sparse == nil || !v.sparse.active.Load() {
		return nil, errors.New("tlprofile: unknown-method view is no longer active")
	}
	return &bin.Buffer{Buf: append([]byte(nil), v.sparse.raw...)}, nil
}
func (v UnknownMethodView) AdaptCanonical(canonical *bin.Buffer) (OutboundCall, error) {
	if v.sparse == nil {
		return OutboundCall{}, errors.New("tlprofile: inactive unknown-method view")
	}
	return v.sparse.adaptCanonical(canonical)
}
func (v UnknownMethodView) AdaptClientRPCOverlay(overlay ClientRPCOverlay) (OutboundCall, bool, error) {
	if v.sparse == nil {
		return OutboundCall{}, true, errors.New("tlprofile: inactive unknown-method view")
	}
	return v.sparse.adaptOverlay(overlay)
}

type UnknownMethodAdapter func(UnknownMethodView) (OutboundCall, bool, error)

type sparseOutboundCall struct {
	profile Profile
	method  SemanticID
	wireID  uint32
	request bin.Object
}

type sparseUnknownMethodView struct {
	profile Profile
	wireID  uint32
	raw     []byte
	limits  Limits
	active  atomic.Bool
	used    atomic.Bool
}

func (v *sparseUnknownMethodView) claim() error {
	if v == nil || !v.active.Load() {
		return errors.New("tlprofile: unknown-method view is no longer active")
	}
	if !v.used.CompareAndSwap(false, true) {
		return errors.New("tlprofile: unknown-method adapter may produce only one outbound call")
	}
	return nil
}

func (v *sparseUnknownMethodView) adaptCanonical(canonical *bin.Buffer) (OutboundCall, error) {
	if canonical == nil {
		return OutboundCall{}, errors.New("tlprofile: adapt nil canonical request")
	}
	if err := v.claim(); err != nil {
		return OutboundCall{}, err
	}
	return prepareSparseOutbound(v.profile, canonical, v.limits)
}

func (v *sparseUnknownMethodView) adaptOverlay(overlay ClientRPCOverlay) (OutboundCall, bool, error) {
	if v == nil || !v.active.Load() {
		return OutboundCall{}, true, errors.New("tlprofile: unknown-method view is no longer active")
	}
	cursor := &bin.Buffer{Buf: append([]byte(nil), v.raw...)}
	canonical, handled, err := adaptClientRPCOverlay(v.profile, overlay, cursor, v.limits)
	if !handled {
		return OutboundCall{}, false, err
	}
	if err != nil {
		return OutboundCall{}, true, err
	}
	if err := v.claim(); err != nil {
		return OutboundCall{}, true, err
	}
	call, err := prepareSparseOutbound(v.profile, canonical, v.limits)
	return call, true, err
}

func prepareSparseOutbound(profile Profile, canonical *bin.Buffer, limits Limits) (OutboundCall, error) {
	if canonical == nil {
		return OutboundCall{}, errors.New("tlprofile: prepare nil canonical outbound request")
	}
	cursor := &bin.Buffer{Buf: append([]byte(nil), canonical.Raw()...)}
	request, err := DecodeObject(ProfileCanonical, cursor, limits)
	if err != nil {
		return OutboundCall{}, fmt.Errorf("tlprofile: decode canonical outbound request: %w", err)
	}
	if cursor.Len() != 0 {
		return OutboundCall{}, fmt.Errorf("tlprofile: canonical outbound request left %d bytes", cursor.Len())
	}
	typed, ok := request.(interface{ TypeID() uint32 })
	if !ok {
		return OutboundCall{}, fmt.Errorf("tlprofile: canonical outbound request %T has no TypeID", request)
	}
	semantic, ok := SemanticForWireID(ProfileCanonical, typed.TypeID())
	if !ok {
		return OutboundCall{}, fmt.Errorf("tlprofile: canonical outbound wire %#08x has no semantic", typed.TypeID())
	}
	category, _, ok := SemanticName(semantic)
	if !ok || category != "function" {
		return OutboundCall{}, fmt.Errorf("tlprofile: canonical outbound semantic %#016x is not a method", semantic)
	}
	wireID, ok := WireID(profile, semantic)
	if !ok {
		return OutboundCall{}, fmt.Errorf("tlprofile: outbound semantic %#016x is unavailable in profile %d", semantic, profile)
	}
	if _, ordinary := tlLookupResultPlan(profile, semantic); !ordinary {
		return OutboundCall{}, fmt.Errorf("tlprofile: outbound semantic %#016x is not an ordinary method", semantic)
	}
	var exact bin.Buffer
	if err := EncodeObject(profile, request, &exact); err != nil {
		return OutboundCall{}, err
	}
	return OutboundCall{sparse: &sparseOutboundCall{profile: profile, method: semantic, wireID: wireID, request: request}}, nil
}

// AdaptClientRPCOverlayWithLimits exposes the provenance-locked private-schema
// adapter for tests and compatibility gates. Production admission should use
// UnknownMethodView so the result is revalidated as one exact ordinary call.
func AdaptClientRPCOverlayWithLimits(profile Profile, overlay ClientRPCOverlay, in *bin.Buffer, limits Limits) (*bin.Buffer, bool, error) {
	if in == nil {
		return nil, false, errors.New("tlprofile: adapt nil client RPC overlay")
	}
	cursor := &bin.Buffer{Buf: append([]byte(nil), in.Raw()...)}
	canonical, handled, err := adaptClientRPCOverlay(profile, overlay, cursor, limits)
	if err == nil && handled {
		in.Skip(in.Len())
	}
	return canonical, handled, err
}

// PreparedIdentity is the comparable exact request/cache identity.
type PreparedIdentity struct {
	sparse sparsePreparedIdentity
}

// SemanticIdentity is the comparable innermost canonical request identity.
type SemanticIdentity struct {
	sparse sparseSemanticIdentity
}

func (i SemanticIdentity) Method() SemanticID {
	return i.sparse.method
}
func (i SemanticIdentity) CanonicalSize() int {
	return i.sparse.canonicalSize
}
func (i SemanticIdentity) CanonicalDigest() [32]byte {
	return i.sparse.canonicalDigest
}

// PreparedCall is immutable admission metadata.
type PreparedCall struct {
	sparse *sparsePreparedCall
}

func (p PreparedCall) Call() Call {
	if p.sparse == nil {
		return Call{}
	}
	return Call{sparse: &p.sparse.call}
}
func (p PreparedCall) WireSize() int {
	if p.sparse == nil {
		return 0
	}
	return p.sparse.wireSize
}
func (p PreparedCall) WireDigest() [32]byte {
	if p.sparse == nil {
		return [32]byte{}
	}
	return p.sparse.wireDigest
}
func (p PreparedCall) Identity() PreparedIdentity {
	if p.sparse == nil {
		return PreparedIdentity{}
	}
	return PreparedIdentity{sparse: p.sparse.identity}
}
func (p PreparedCall) SemanticIdentity() SemanticIdentity {
	if p.sparse == nil {
		return SemanticIdentity{}
	}
	return SemanticIdentity{sparse: p.sparse.semanticIdentity}
}

// ResultPlan is an opaque complete method-result plan. It deliberately does
// not expose the old runtime TypeRef catalog.
type ResultPlan struct {
	sparse int
}

// CallIdentity is the comparable immutable codec/result-plan identity selected
// by exact admission. It contains no runtime schema or TypeRef handle.
type CallIdentity struct {
	profile       Profile
	method        SemanticID
	wireID        uint32
	resultPlan    int
	wireInvariant bool
}

// Call freezes the exact profile, method route and result plan selected during
// admission.
type Call struct {
	sparse *sparseCall
}

func (c Call) Profile() Profile {
	if c.sparse == nil {
		return 0
	}
	return c.sparse.profile
}
func (c Call) Method() SemanticID {
	if c.sparse == nil {
		return 0
	}
	return c.sparse.method
}
func (c Call) WireID() uint32 {
	if c.sparse == nil {
		return 0
	}
	return c.sparse.wireID
}
func (c Call) WireInvariant() bool {
	return c.sparse != nil && c.sparse.wireInvariant
}
func (c Call) Identity() CallIdentity {
	if c.sparse == nil {
		return CallIdentity{}
	}
	return CallIdentity{
		profile: c.sparse.profile, method: c.sparse.method, wireID: c.sparse.wireID,
		resultPlan: c.sparse.resultPlan, wireInvariant: c.sparse.wireInvariant,
	}
}
func (c Call) ResultPlan() ResultPlan {
	if c.sparse == nil {
		return ResultPlan{}
	}
	return ResultPlan{sparse: c.sparse.resultPlan}
}
func (c Call) EncodeResult(value any, out *bin.Buffer) error {
	if c.sparse == nil {
		return errors.New("tlprofile: encode result for empty call")
	}
	return tlEncodeResultPlan(c.sparse.resultPlan, c.sparse.profile, value, out)
}

// Wrapper is immutable metadata for one transparently consumed RPC envelope.
type Wrapper struct {
	sparse *sparseWrapper
}

func (w Wrapper) Profile() Profile {
	if w.sparse == nil {
		return 0
	}
	return w.sparse.profile
}
func (w Wrapper) Semantic() SemanticID {
	if w.sparse == nil {
		return 0
	}
	return w.sparse.semantic
}
func (w Wrapper) WireID() uint32 {
	if w.sparse == nil {
		return 0
	}
	return w.sparse.wireID
}
func (w Wrapper) Value(name string) (value any, present bool, ok bool, err error) {
	if w.sparse == nil {
		return nil, false, false, nil
	}
	for index := range w.sparse.fields {
		field := &w.sparse.fields[index]
		if field.name == name {
			if !field.present {
				return nil, false, true, nil
			}
			value, err := cloneSparseWrapperValue(field.value)
			return value, true, true, err
		}
	}
	return nil, false, false, nil
}

// Admission is a one-shot exact canonical request and its immutable wire
// proof. Value copies share the same dispatch lease.
type Admission struct {
	sparse *sparseAdmission
}

func (a Admission) Prepared() PreparedCall {
	if a.sparse == nil {
		return PreparedCall{}
	}
	return PreparedCall{sparse: &a.sparse.prepared}
}
func (a Admission) Call() Call {
	if a.sparse == nil {
		return Call{}
	}
	return Call{sparse: &a.sparse.prepared.call}
}
func (a Admission) EffectiveProfile() (Profile, bool) {
	if a.sparse == nil || !a.sparse.effectiveProfile {
		return 0, false
	}
	return a.sparse.prepared.call.profile, true
}
func (a Admission) ProfileEvidence() (Profile, bool) {
	if a.sparse == nil || !a.sparse.profileEvidence {
		return 0, false
	}
	return a.sparse.prepared.call.profile, true
}
func (a Admission) WrapperCount() int {
	if a.sparse == nil {
		return 0
	}
	return len(a.sparse.wrappers)
}
func (a Admission) Wrapper(index int) (Wrapper, bool) {
	if a.sparse == nil || index < 0 || index >= len(a.sparse.wrappers) {
		return Wrapper{}, false
	}
	return Wrapper{sparse: &a.sparse.wrappers[index]}, true
}

type sparseWrapperField struct {
	name    string
	present bool
	value   any
}

type sparseWrapper struct {
	profile  Profile
	semantic SemanticID
	wireID   uint32
	fields   []sparseWrapperField
}

func cloneSparseWrapperValue(value any) (any, error) {
	switch typed := value.(type) {
	case []byte:
		return append([]byte(nil), typed...), nil
	case []int64:
		return append([]int64(nil), typed...), nil
	case bin.Object:
		var encoded bin.Buffer
		if err := typed.Encode(&encoded); err != nil {
			return nil, fmt.Errorf("tlprofile: freeze wrapper object %T: %w", typed, err)
		}
		wireID, err := encoded.PeekID()
		if err != nil {
			return nil, err
		}
		clone, ok := tlNewCanonical(wireID)
		if !ok {
			return nil, fmt.Errorf("tlprofile: wrapper object wire %#08x has no canonical factory", wireID)
		}
		if err := clone.Decode(&encoded); err != nil {
			return nil, err
		}
		if encoded.Len() != 0 {
			return nil, fmt.Errorf("tlprofile: wrapper object clone left %d bytes", encoded.Len())
		}
		return clone, nil
	default:
		return value, nil
	}
}

type sparsePreparedIdentity struct {
	profile         Profile
	method          SemanticID
	wireID          uint32
	wireSize        int
	wireDigest      [32]byte
	canonicalDigest [32]byte
}

type sparseSemanticIdentity struct {
	method          SemanticID
	canonicalSize   int
	canonicalDigest [32]byte
}

type sparseCall struct {
	profile       Profile
	method        SemanticID
	wireID        uint32
	resultPlan    int
	wireInvariant bool
}

type sparsePreparedCall struct {
	call             sparseCall
	wireSize         int
	wireDigest       [32]byte
	identity         sparsePreparedIdentity
	semanticIdentity sparseSemanticIdentity
}

type sparseAdmission struct {
	prepared         sparsePreparedCall
	request          bin.Object
	profileEvidence  bool
	effectiveProfile bool
	wrappers         []sparseWrapper
	claimed          atomic.Bool
}

func (a *sparseAdmission) take() (bin.Object, error) {
	if a == nil || a.request == nil {
		return nil, errors.New("tlprofile: empty sparse admission")
	}
	if !a.claimed.CompareAndSwap(false, true) {
		return nil, errors.New("tlprofile: sparse admission dispatched more than once")
	}
	return a.request, nil
}

// Result is bound to the exact admission that produced it.
type Result interface {
	bin.Encoder
	Prepared() PreparedCall
	WireInvariant() bool
}

type result struct {
	prepared PreparedCall
	call     Call
	value    any
}

func (r *result) Prepared() PreparedCall { return r.prepared }
func (r *result) WireInvariant() bool    { return r.call.WireInvariant() }
func (r *result) Encode(out *bin.Buffer) error {
	if r == nil {
		return errors.New("tlprofile: encode nil result")
	}
	return r.call.EncodeResult(r.value, out)
}

// Handler receives the canonical tg request selected by exact admission and
// returns a canonical handler value. Call owns all result projection.
type Handler func(context.Context, bin.Object) (any, error)

// Next is a synchronous one-shot capability supplied to a wrapper consumer.
type Next func(context.Context) error

// WrapperConsumer owns non-layer wrapper side effects and must call next
// synchronously exactly once.
type WrapperConsumer func(context.Context, Admission, Next) error

var ErrHandlerNotRegistered = errors.New("tlprofile: semantic handler is not registered")

var (
	ErrProfileRequired  = errors.New("tlprofile: exact client profile is required")
	ErrProfileConflict  = errors.New("tlprofile: invokeWithLayer conflicts with the frozen profile")
	ErrUnknownRPCMethod = errors.New("tlprofile: unknown RPC method")
)

// UnknownTerminalError proves that exact static wrapper parsers reached an
// unknown terminal without reinterpreting the request at runtime. It is
// emitted only for a non-empty, fully decoded wrapper chain.
type UnknownTerminalError struct {
	Profile  Profile
	WireID   uint32
	WireSize int
	wrappers []sparseWrapper
	cause    error
}

func (e *UnknownTerminalError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("tlprofile: unknown wrapped terminal profile=%d wire=%#08x size=%d", e.Profile, e.WireID, e.WireSize)
}

func (e *UnknownTerminalError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *UnknownTerminalError) WrapperCount() int {
	if e == nil {
		return 0
	}
	return len(e.wrappers)
}

func (e *UnknownTerminalError) Wrapper(index int) (Wrapper, bool) {
	if e == nil || index < 0 || index >= len(e.wrappers) {
		return Wrapper{}, false
	}
	return Wrapper{sparse: &e.wrappers[index]}, true
}

// Dispatcher is the compact semantic handler registry plus exact admission
// boundary. Codec routing remains generated static code; this map contains
// application callbacks, never schema or codec programs.
type Dispatcher struct {
	mu              sync.RWMutex
	handlers        map[SemanticID]Handler
	wrappers        WrapperConsumer
	preflight       AdmissionPreflight
	fieldPreflights map[FieldID]FieldPreflight
	unknown         UnknownMethodAdapter
}

func NewDispatcher() *Dispatcher {
	return &Dispatcher{handlers: make(map[SemanticID]Handler)}
}

func (d *Dispatcher) Register(method SemanticID, handler Handler) error {
	if d == nil {
		return errors.New("tlprofile: register on nil dispatcher")
	}
	category, name, ok := SemanticName(method)
	if !ok || category != "function" || name == "" {
		return fmt.Errorf("tlprofile: invalid method semantic %#016x", uint64(method))
	}
	if handler == nil {
		return fmt.Errorf("tlprofile: register nil handler for %s", name)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handlers[method] != nil {
		return fmt.Errorf("tlprofile: duplicate handler for %s", name)
	}
	d.handlers[method] = handler
	return nil
}

func (d *Dispatcher) Has(method SemanticID) bool {
	if d == nil {
		return false
	}
	d.mu.RLock()
	handler := d.handlers[method]
	d.mu.RUnlock()
	return handler != nil
}

func (d *Dispatcher) OnWrappers(consumer WrapperConsumer) {
	if d == nil || consumer == nil {
		panic("tlprofile: register nil wrapper consumer or dispatcher")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.wrappers != nil {
		panic("tlprofile: duplicate wrapper consumer")
	}
	d.wrappers = consumer
}

func (d *Dispatcher) OnAdmissionPreflight(callback AdmissionPreflight) {
	if d == nil || callback == nil {
		panic("tlprofile: register nil admission preflight or dispatcher")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.preflight != nil {
		panic("tlprofile: duplicate admission preflight")
	}
	d.preflight = callback
}

func (d *Dispatcher) OnFieldPreflight(field FieldID, callback FieldPreflight) error {
	if d == nil || callback == nil {
		return errors.New("tlprofile: register nil field preflight or dispatcher")
	}
	if err := tlFieldRegistration(field); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fieldPreflights == nil {
		d.fieldPreflights = make(map[FieldID]FieldPreflight)
	}
	if d.fieldPreflights[field] != nil {
		return fmt.Errorf("tlprofile: duplicate field preflight for %#016x", uint64(field))
	}
	d.fieldPreflights[field] = callback
	return nil
}

func (d *Dispatcher) OnUnknownMethod(callback UnknownMethodAdapter) {
	if d == nil || callback == nil {
		panic("tlprofile: register nil unknown-method adapter or dispatcher")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.unknown != nil {
		panic("tlprofile: duplicate unknown-method adapter")
	}
	d.unknown = callback
}

func (d *Dispatcher) Admit(profile Profile, body *bin.Buffer, limits Limits) (Admission, error) {
	if d == nil {
		return Admission{}, errors.New("tlprofile: admit on nil dispatcher")
	}
	d.mu.RLock()
	admission, handled, err := admitSparse(profile, body, limits, sparseAdmissionExact, d.preflight, d.fieldPreflights, d.unknown)
	d.mu.RUnlock()
	if !handled && err == nil {
		return Admission{}, fmt.Errorf("%w: profile=%d", ErrUnknownRPCMethod, profile)
	}
	return admission, err
}

type sparseAdmissionMode uint8

const (
	sparseAdmissionExact sparseAdmissionMode = iota
	sparseAdmissionDefault
)

func admitSparse(initial Profile, body *bin.Buffer, limits Limits, mode sparseAdmissionMode, preflight AdmissionPreflight, fields map[FieldID]FieldPreflight, unknown UnknownMethodAdapter) (Admission, bool, error) {
	if body == nil {
		return Admission{}, true, errors.New("tlprofile: admit nil body")
	}
	if _, ok := ResolveProfile(int(initial)); !ok {
		return Admission{}, true, fmt.Errorf("tlprofile: unsupported exact profile %d", initial)
	}
	// Validate the complete generic wire graph and all allocation budgets before
	// any wrapper metadata or terminal request is materialized.
	if err := tlScanExact(initial, body, limits); err != nil {
		var unknownWire *tlScanUnknownWireError
		if !errors.As(err, &unknownWire) {
			return Admission{}, true, err
		}
	}
	fullWire := body.Raw()
	working := &bin.Buffer{Buf: fullWire}
	profile := initial
	explicitProfile := Profile(0)
	var wrappers []sparseWrapper
	for depth := 0; depth < tlScanMaxDepth; depth++ {
		wireID, err := working.PeekID()
		if err != nil {
			return Admission{}, true, err
		}
		if parser, ok := tlLookupWrapperParser(profile, wireID); ok {
			frame, nested, explicit, err := parser(profile, working, limits)
			if err != nil {
				return Admission{}, true, err
			}
			wrappers = append(wrappers, frame)
			if explicit {
				if mode == sparseAdmissionExact && nested != initial {
					return Admission{}, true, fmt.Errorf("%w: inherited=%d selected=%d", ErrProfileConflict, initial, nested)
				}
				if explicitProfile != 0 && explicitProfile != nested {
					return Admission{}, true, fmt.Errorf("%w: previous=%d selected=%d", ErrProfileConflict, explicitProfile, nested)
				}
				explicitProfile = nested
				profile = nested
			}
			continue
		}
		admission, handled, err := admitSparseOrdinary(profile, working, limits, false, preflight, fields)
		if !handled {
			admission, handled, err = adaptSparseUnknown(profile, working, limits, preflight, fields, unknown)
		}
		if !handled || err != nil {
			if err != nil && len(wrappers) != 0 && errors.Is(err, ErrUnknownRPCMethod) {
				wireID, _ := working.PeekID()
				return Admission{}, true, &UnknownTerminalError{
					Profile: profile, WireID: wireID, WireSize: working.Len(),
					wrappers: wrappers, cause: err,
				}
			}
			return admission, handled, err
		}
		if working.Len() != 0 {
			return Admission{}, true, fmt.Errorf("tlprofile: wrapped terminal left %d bytes", working.Len())
		}
		wireDigest := sha256.Sum256(fullWire)
		admission.sparse.prepared.wireSize = len(fullWire)
		admission.sparse.prepared.wireDigest = wireDigest
		admission.sparse.prepared.identity.wireSize = len(fullWire)
		admission.sparse.prepared.identity.wireDigest = wireDigest
		admission.sparse.wrappers = wrappers
		admission.sparse.effectiveProfile = true
		admission.sparse.profileEvidence = mode == sparseAdmissionExact || explicitProfile != 0
		body.ResetTo(working.Raw())
		return admission, true, nil
	}
	return Admission{}, true, fmt.Errorf("tlprofile: wrapper nesting exceeds %d", tlScanMaxDepth)
}

func admitSparseOrdinary(profile Profile, body *bin.Buffer, limits Limits, evidence bool, preflight AdmissionPreflight, fields map[FieldID]FieldPreflight) (Admission, bool, error) {
	if body == nil {
		return Admission{}, true, errors.New("tlprofile: admit nil body")
	}
	wireID, err := body.PeekID()
	if err != nil {
		return Admission{}, true, err
	}
	route, ok := tlLookupRoute(profile, wireID)
	if !ok {
		return Admission{}, false, nil
	}
	category, _, ok := SemanticName(route.semantic)
	if !ok || category != "function" {
		return Admission{}, true, fmt.Errorf("tlprofile: wire %#08x is not an RPC method", wireID)
	}
	resultPlan, ordinary := tlLookupResultPlan(profile, route.semantic)
	if !ordinary {
		// Generic wrappers and explicit historical-only adapters are admitted by
		// the wrapper/unknown-method path until their dedicated sparse parser runs.
		return Admission{}, false, nil
	}
	wireBytes := body.Raw()
	if preflight != nil {
		if err := preflight(AdmissionView{profile: profile, semantic: route.semantic, wireID: wireID, raw: wireBytes}); err != nil {
			return Admission{}, true, err
		}
	}
	var observer tlFieldObserver
	if len(fields) != 0 {
		observer = func(field FieldID, present bool, metric tlFieldMetric, value int64) error {
			callback := fields[field]
			if callback == nil {
				return nil
			}
			return callback(FieldView{profile: profile, semantic: route.semantic, wireID: wireID, fieldID: field, present: present, metric: metric, value: value})
		}
	}
	if err := tlScanExactObserved(profile, body, limits, observer); err != nil {
		return Admission{}, true, err
	}
	wireSize := len(wireBytes)
	wireDigest := sha256.Sum256(wireBytes)
	request, err := DecodeObject(profile, body, limits)
	if err != nil {
		return Admission{}, true, err
	}
	if body.Len() != 0 {
		return Admission{}, true, fmt.Errorf("tlprofile: ordinary RPC left %d bytes", body.Len())
	}
	var canonical bin.Buffer
	if err := request.Encode(&canonical); err != nil {
		return Admission{}, true, fmt.Errorf("tlprofile: canonicalize admitted RPC: %w", err)
	}
	canonicalDigest := sha256.Sum256(canonical.Raw())
	call := sparseCall{profile: profile, method: route.semantic, wireID: wireID, resultPlan: resultPlan}
	identity := sparsePreparedIdentity{
		profile: profile, method: route.semantic, wireID: wireID, wireSize: wireSize,
		wireDigest: wireDigest, canonicalDigest: canonicalDigest,
	}
	prepared := sparsePreparedCall{
		call: call, wireSize: wireSize, wireDigest: wireDigest, identity: identity,
		semanticIdentity: sparseSemanticIdentity{method: route.semantic, canonicalSize: canonical.Len(), canonicalDigest: canonicalDigest},
	}
	return Admission{sparse: &sparseAdmission{prepared: prepared, request: request, profileEvidence: evidence, effectiveProfile: true}}, true, nil
}

func adaptSparseUnknown(profile Profile, body *bin.Buffer, limits Limits, preflight AdmissionPreflight, fields map[FieldID]FieldPreflight, callback UnknownMethodAdapter) (Admission, bool, error) {
	if body == nil {
		return Admission{}, true, errors.New("tlprofile: adapt nil unknown terminal")
	}
	wireID, err := body.PeekID()
	if err != nil {
		return Admission{}, true, err
	}
	if callback == nil {
		return Admission{}, true, fmt.Errorf("%w: profile=%d wire=%#08x", ErrUnknownRPCMethod, profile, wireID)
	}
	view := &sparseUnknownMethodView{profile: profile, wireID: wireID, raw: append([]byte(nil), body.Raw()...), limits: limits}
	view.active.Store(true)
	outbound, handled, callbackErr := callback(UnknownMethodView{sparse: view})
	view.active.Store(false)
	if callbackErr != nil {
		return Admission{}, true, callbackErr
	}
	if !handled {
		return Admission{}, true, fmt.Errorf("%w: profile=%d wire=%#08x", ErrUnknownRPCMethod, profile, wireID)
	}
	if outbound.sparse == nil || outbound.sparse.request == nil {
		return Admission{}, true, errors.New("tlprofile: unknown-method adapter returned an invalid sparse outbound call")
	}
	if outbound.Profile() != profile {
		return Admission{}, true, fmt.Errorf("tlprofile: unknown-method adapter changed profile %d to %d", profile, outbound.Profile())
	}
	var exact bin.Buffer
	if err := outbound.Encode(&exact); err != nil {
		return Admission{}, true, err
	}
	admission, ordinary, err := admitSparseOrdinary(profile, &exact, limits, false, preflight, fields)
	if err != nil {
		return Admission{}, true, err
	}
	if !ordinary || admission.Call().Method() != outbound.Method() || admission.Call().WireID() != outbound.WireID() {
		return Admission{}, true, errors.New("tlprofile: adapted unknown method failed exact route revalidation")
	}
	body.Skip(body.Len())
	return admission, true, nil
}

func (d *Dispatcher) AdmitDefault(profile Profile, body *bin.Buffer, limits Limits) (Admission, error) {
	if d == nil {
		return Admission{}, errors.New("tlprofile: default admit on nil dispatcher")
	}
	d.mu.RLock()
	admission, handled, err := admitSparse(profile, body, limits, sparseAdmissionDefault, d.preflight, d.fieldPreflights, d.unknown)
	d.mu.RUnlock()
	if !handled && err == nil {
		return Admission{}, fmt.Errorf("%w: profile=%d", ErrUnknownRPCMethod, profile)
	}
	return admission, err
}

func (d *Dispatcher) AdmitUnprofiled(body *bin.Buffer, limits Limits) (Admission, error) {
	if d == nil {
		return Admission{}, errors.New("tlprofile: unprofiled admit on nil dispatcher")
	}
	if body == nil {
		return Admission{}, errors.New("tlprofile: unprofiled admit nil body")
	}
	wireID, err := body.PeekID()
	if err != nil {
		return Admission{}, err
	}
	d.mu.RLock()
	if wireID == tlUnprofiledSelectorWireID {
		probe := &bin.Buffer{Buf: body.Raw()}
		if err := probe.ConsumeID(tlUnprofiledSelectorWireID); err != nil {
			d.mu.RUnlock()
			return Admission{}, err
		}
		layer, err := probe.Int()
		if err != nil {
			d.mu.RUnlock()
			return Admission{}, err
		}
		profile, ok := ResolveProfile(layer)
		if !ok {
			d.mu.RUnlock()
			return Admission{}, fmt.Errorf("tlprofile: invokeWithLayer selected unsupported exact profile %d", layer)
		}
		admission, handled, err := admitSparse(profile, body, limits, sparseAdmissionExact, d.preflight, d.fieldPreflights, d.unknown)
		d.mu.RUnlock()
		if !handled && err == nil {
			return Admission{}, fmt.Errorf("%w: profile=%d wire=%#08x", ErrUnknownRPCMethod, profile, wireID)
		}
		return admission, err
	} else if tlUnprofiledInvariant(wireID) {
		admission, handled, err := admitSparse(ProfileCanonical, body, limits, sparseAdmissionExact, d.preflight, d.fieldPreflights, d.unknown)
		d.mu.RUnlock()
		if !handled && err == nil {
			return Admission{}, fmt.Errorf("%w: wire=%#08x", ErrUnknownRPCMethod, wireID)
		}
		if err == nil {
			admission.sparse.profileEvidence = false
			admission.sparse.effectiveProfile = false
			admission.sparse.prepared.call.wireInvariant = true
		}
		return admission, err
	} else {
		d.mu.RUnlock()
		if tlKnownRPCWireID(wireID) {
			return Admission{}, fmt.Errorf("%w: wire %#08x", ErrProfileRequired, wireID)
		}
		return Admission{}, fmt.Errorf("%w: wire %#08x", ErrUnknownRPCMethod, wireID)
	}
}

func (d *Dispatcher) Dispatch(ctx context.Context, admission Admission) (Result, error) {
	if d == nil {
		return nil, errors.New("tlprofile: dispatch on nil dispatcher")
	}
	method := admission.Call().Method()
	d.mu.RLock()
	handler := d.handlers[method]
	consumer := d.wrappers
	d.mu.RUnlock()
	if handler == nil {
		return nil, ErrHandlerNotRegistered
	}

	var output any
	var attempts atomic.Uint32
	var returned atomic.Bool
	next := func(nextCtx context.Context) error {
		if returned.Load() || attempts.Add(1) != 1 {
			return errors.New("tlprofile: wrapper consumer called next more than once or asynchronously")
		}
		if admission.sparse == nil {
			return errors.New("tlprofile: dispatch empty admission")
		}
		request, err := admission.sparse.take()
		if err != nil {
			return err
		}
		output, err = handler(nextCtx, request)
		return err
	}
	needsConsumer := false
	for index := 0; index < admission.WrapperCount(); index++ {
		wrapper, _ := admission.Wrapper(index)
		if wrapper.Semantic() != SemanticMethodInvokeWithLayer {
			needsConsumer = true
			break
		}
	}
	if needsConsumer {
		if consumer == nil {
			return nil, errors.New("tlprofile: admitted wrappers require a consumer")
		}
		err := consumer(ctx, admission, next)
		returned.Store(true)
		if err != nil {
			return nil, err
		}
		if attempts.Load() != 1 {
			return nil, errors.New("tlprofile: wrapper consumer did not call next exactly once")
		}
	} else if err := next(ctx); err != nil {
		returned.Store(true)
		return nil, err
	} else {
		returned.Store(true)
	}
	return &result{prepared: admission.Prepared(), call: admission.Call(), value: output}, nil
}

// EncodeObject encodes one canonical boxed TL object for an exact profile.
func EncodeObject(profile Profile, value bin.Object, out *bin.Buffer) error {
	if value == nil || out == nil {
		return errors.New("tlprofile: encode nil object or buffer")
	}
	if _, ok := ResolveProfile(int(profile)); !ok {
		return fmt.Errorf("tlprofile: unsupported exact profile %d", profile)
	}
	typed, ok := value.(interface{ TypeID() uint32 })
	if !ok {
		return fmt.Errorf("tlprofile: canonical object %T has no TypeID", value)
	}
	semantic, ok := SemanticForWireID(ProfileCanonical, typed.TypeID())
	if !ok {
		return fmt.Errorf("tlprofile: canonical object wire %#08x has no semantic route", typed.TypeID())
	}
	wireID, ok := WireID(profile, semantic)
	if !ok {
		return fmt.Errorf("tlprofile: semantic %#016x is unavailable in exact profile %d", semantic, profile)
	}
	route, ok := tlLookupRoute(profile, wireID)
	if !ok || route.semantic != semantic {
		return fmt.Errorf("tlprofile: exact wire %#08x has inconsistent semantic route", wireID)
	}
	start := out.Len()
	err := func() error {
		switch route.mode {
		case tlRouteDirect:
			return value.Encode(out)
		case tlRouteRetag:
			bare, ok := value.(bin.BareEncoder)
			if !ok {
				return fmt.Errorf("tlprofile: retag canonical value %T has no bare encoder", value)
			}
			out.PutID(wireID)
			return bare.EncodeBare(out)
		case tlRouteRewrite, tlRoutePolicy:
			return tlEncodeSparse(profile, semantic, value, out)
		default:
			return fmt.Errorf("tlprofile: route for semantic %#016x is not encodable (%d)", semantic, route.mode)
		}
	}()
	if err != nil {
		out.Buf = out.Buf[:start]
	}
	return err
}

func DecodeObject(profile Profile, in *bin.Buffer, limits Limits) (bin.Object, error) {
	if err := tlScanExact(profile, in, limits); err != nil {
		return nil, err
	}
	return tlDecodeObjectPrefixScanned(profile, in, limits)
}

// tlDecodeObjectPrefixScanned materializes one boxed value after an enclosing
// static scanner has already proved its exact TypeRef and allocation bounds.
// It intentionally permits trailing bytes for wrapper-prefix parsing.
func tlDecodeObjectPrefixScanned(profile Profile, in *bin.Buffer, limits Limits) (bin.Object, error) {
	wireID, err := in.PeekID()
	if err != nil {
		return nil, err
	}
	route, ok := tlLookupRoute(profile, wireID)
	if !ok {
		return nil, fmt.Errorf("tlprofile: scanned wire %#08x has no exact route in profile %d", wireID, profile)
	}
	if route.mode == tlRouteDirect || route.mode == tlRouteRetag {
		value, ok := tlNewCanonical(route.canonicalWireID)
		if !ok {
			return nil, fmt.Errorf("tlprofile: direct semantic %#016x has no canonical factory", route.semantic)
		}
		cursor := &bin.Buffer{Buf: in.Raw()}
		if route.mode == tlRouteDirect {
			err = value.Decode(cursor)
		} else {
			if err = cursor.ConsumeID(wireID); err == nil {
				bare, bareOK := value.(bin.BareDecoder)
				if !bareOK {
					return nil, fmt.Errorf("tlprofile: retag canonical value %T has no bare decoder", value)
				}
				err = bare.DecodeBare(cursor)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("tlprofile: decode validated direct route: %w", err)
		}
		in.ResetTo(cursor.Raw())
		return value, nil
	}
	if route.mode == tlRouteRewrite || route.mode == tlRoutePolicy {
		cursor := &bin.Buffer{Buf: in.Raw()}
		value, err := tlDecodeSparse(profile, wireID, cursor, limits)
		if err != nil {
			return nil, err
		}
		in.ResetTo(cursor.Raw())
		return value, nil
	}
	return nil, fmt.Errorf("tlprofile: exact route %#08x is not an object codec route (%d)", wireID, route.mode)
}
