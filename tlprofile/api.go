package tlprofile

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/iamxvbaba/td/bin"
	"github.com/iamxvbaba/td/tg"
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
	legacy tg.LayerRPCAdmissionFieldView
}

func (v FieldView) Profile() Profile          { return Profile(v.legacy.Profile()) }
func (v FieldView) Semantic() SemanticID      { return SemanticID(v.legacy.Semantic()) }
func (v FieldView) WireID() uint32            { return v.legacy.WireID() }
func (v FieldView) FieldID() FieldID          { return FieldID(v.legacy.FieldID()) }
func (v FieldView) Present() bool             { return v.legacy.Present() }
func (v FieldView) VectorLength() (int, bool) { return v.legacy.VectorLength() }
func (v FieldView) BytesLength() (int, bool)  { return v.legacy.BytesLength() }
func (v FieldView) Int32() (int32, bool)      { return v.legacy.Int32() }

type FieldPreflight func(FieldView) error

// AdmissionView exposes a bounded immutable prefix view before an ordinary
// terminal request is consumed.
type AdmissionView struct {
	legacy tg.LayerRPCAdmissionView
}

func (v AdmissionView) Profile() Profile                    { return Profile(v.legacy.Profile()) }
func (v AdmissionView) Semantic() SemanticID                { return SemanticID(v.legacy.Semantic()) }
func (v AdmissionView) WireID() uint32                      { return v.legacy.WireID() }
func (v AdmissionView) WireSize() int                       { return v.legacy.WireSize() }
func (v AdmissionView) ByteAt(offset int) (byte, error)     { return v.legacy.ByteAt(offset) }
func (v AdmissionView) Uint32At(offset int) (uint32, error) { return v.legacy.Uint32At(offset) }
func (v AdmissionView) ReadAt(offset, length int) ([]byte, error) {
	return v.legacy.ReadAt(offset, length)
}

type AdmissionPreflight func(AdmissionView) error

// OutboundCall is an opaque exact-profile request produced by an audited
// private-schema adapter.
type OutboundCall struct {
	legacy tg.LayerOutboundCall
}

func (c OutboundCall) Profile() Profile             { return Profile(c.legacy.Profile()) }
func (c OutboundCall) Method() SemanticID           { return SemanticID(c.legacy.Method()) }
func (c OutboundCall) WireID() uint32               { return c.legacy.WireID() }
func (c OutboundCall) Encode(out *bin.Buffer) error { return c.legacy.Encode(out) }

type ClientRPCOverlay uint8

const (
	ClientRPCOverlayDrkloAndroid      ClientRPCOverlay = ClientRPCOverlay(tg.LayerClientRPCOverlayDrkloAndroid)
	ClientRPCOverlayDrkloAndroidTheme ClientRPCOverlay = ClientRPCOverlay(tg.LayerClientRPCOverlayDrkloAndroidTheme)
)

// UnknownMethodView is a transactional view of an unknown innermost terminal.
type UnknownMethodView struct {
	legacy tg.LayerRPCUnknownMethodView
}

func (v UnknownMethodView) Profile() Profile             { return Profile(v.legacy.Profile()) }
func (v UnknownMethodView) WireID() uint32               { return v.legacy.WireID() }
func (v UnknownMethodView) WireSize() int                { return v.legacy.WireSize() }
func (v UnknownMethodView) Buffer() (*bin.Buffer, error) { return v.legacy.Buffer() }
func (v UnknownMethodView) AdaptCanonical(canonical *bin.Buffer) (OutboundCall, error) {
	call, err := v.legacy.AdaptCanonical(canonical)
	return OutboundCall{legacy: call}, err
}
func (v UnknownMethodView) AdaptClientRPCOverlay(overlay ClientRPCOverlay) (OutboundCall, bool, error) {
	call, handled, err := v.legacy.AdaptClientRPCOverlay(tg.LayerClientRPCOverlay(overlay))
	return OutboundCall{legacy: call}, handled, err
}

type UnknownMethodAdapter func(UnknownMethodView) (OutboundCall, bool, error)

func (l Limits) legacy() tg.LayerDecodeLimits {
	return tg.LayerDecodeLimits{
		MaxWireBytes: l.MaxWireBytes, MaxVectorElements: l.MaxVectorElements,
		MaxAggregateElements: l.MaxAggregateElements, MaxDepth: l.MaxDepth,
	}
}

// PreparedIdentity is the comparable exact request/cache identity.
type PreparedIdentity struct {
	legacy tg.LayerPreparedCallIdentity
	sparse sparsePreparedIdentity
	kind   uint8
}

// SemanticIdentity is the comparable innermost canonical request identity.
type SemanticIdentity struct {
	legacy tg.LayerSemanticRequestIdentity
	sparse sparseSemanticIdentity
	kind   uint8
}

func (i SemanticIdentity) Method() SemanticID {
	if i.kind == 1 {
		return i.sparse.method
	}
	return SemanticID(i.legacy.Method())
}
func (i SemanticIdentity) CanonicalSize() int {
	if i.kind == 1 {
		return i.sparse.canonicalSize
	}
	return i.legacy.CanonicalSize()
}
func (i SemanticIdentity) CanonicalDigest() [32]byte {
	if i.kind == 1 {
		return i.sparse.canonicalDigest
	}
	return i.legacy.CanonicalDigest()
}

// PreparedCall is immutable admission metadata.
type PreparedCall struct {
	legacy tg.LayerPreparedCall
	sparse *sparsePreparedCall
}

func (p PreparedCall) Call() Call {
	if p.sparse != nil {
		return Call{sparse: &p.sparse.call}
	}
	return Call{legacy: p.legacy.Call()}
}
func (p PreparedCall) WireSize() int {
	if p.sparse != nil {
		return p.sparse.wireSize
	}
	return p.legacy.WireSize()
}
func (p PreparedCall) WireDigest() [32]byte {
	if p.sparse != nil {
		return p.sparse.wireDigest
	}
	return p.legacy.WireDigest()
}
func (p PreparedCall) Identity() PreparedIdentity {
	if p.sparse != nil {
		return PreparedIdentity{kind: 1, sparse: p.sparse.identity}
	}
	return PreparedIdentity{legacy: p.legacy.Identity()}
}
func (p PreparedCall) SemanticIdentity() SemanticIdentity {
	if p.sparse != nil {
		return SemanticIdentity{kind: 1, sparse: p.sparse.semanticIdentity}
	}
	return SemanticIdentity{legacy: p.legacy.SemanticIdentity()}
}

// ResultPlan is an opaque complete method-result plan. It deliberately does
// not expose the old runtime TypeRef catalog.
type ResultPlan struct {
	legacy *tg.LayerTypeRef
	sparse int
	kind   uint8
}

// Call freezes the exact profile, method route and result plan selected during
// admission.
type Call struct {
	legacy tg.LayerCall
	sparse *sparseCall
}

func (c Call) Profile() Profile {
	if c.sparse != nil {
		return c.sparse.profile
	}
	return Profile(c.legacy.Profile())
}
func (c Call) Method() SemanticID {
	if c.sparse != nil {
		return c.sparse.method
	}
	return SemanticID(c.legacy.Method())
}
func (c Call) WireID() uint32 {
	if c.sparse != nil {
		return c.sparse.wireID
	}
	return c.legacy.WireID()
}
func (c Call) WireInvariant() bool {
	if c.sparse != nil {
		return c.sparse.wireInvariant
	}
	return c.legacy.WireInvariant()
}
func (c Call) ResultPlan() ResultPlan {
	if c.sparse != nil {
		return ResultPlan{kind: 1, sparse: c.sparse.resultPlan}
	}
	return ResultPlan{legacy: c.legacy.WireResultType()}
}
func (c Call) EncodeResult(value any, out *bin.Buffer) error {
	if c.sparse != nil {
		return tlEncodeResultPlan(c.sparse.resultPlan, c.sparse.profile, value, out)
	}
	return c.legacy.EncodeResult(value, out)
}

// Wrapper is immutable metadata for one transparently consumed RPC envelope.
type Wrapper struct {
	legacy tg.LayerRPCWrapper
}

func (w Wrapper) Profile() Profile     { return Profile(w.legacy.Profile()) }
func (w Wrapper) Semantic() SemanticID { return SemanticID(w.legacy.Semantic()) }
func (w Wrapper) WireID() uint32       { return w.legacy.WireID() }
func (w Wrapper) Value(name string) (value any, present bool, ok bool, err error) {
	return w.legacy.Value(name)
}

// Admission is a one-shot exact canonical request and its immutable wire
// proof. Value copies share the same dispatch lease.
type Admission struct {
	legacy tg.LayerRequest
	sparse *sparseAdmission
}

func (a Admission) Prepared() PreparedCall {
	if a.sparse != nil {
		return PreparedCall{sparse: &a.sparse.prepared}
	}
	return PreparedCall{legacy: a.legacy.Prepared()}
}
func (a Admission) Call() Call {
	if a.sparse != nil {
		return Call{sparse: &a.sparse.prepared.call}
	}
	return Call{legacy: a.legacy.Call()}
}
func (a Admission) EffectiveProfile() (Profile, bool) {
	if a.sparse != nil {
		return a.sparse.prepared.call.profile, true
	}
	profile, ok := a.legacy.EffectiveProfile()
	return Profile(profile), ok
}
func (a Admission) ProfileEvidence() (Profile, bool) {
	if a.sparse != nil {
		return a.sparse.prepared.call.profile, a.sparse.profileEvidence
	}
	profile, ok := a.legacy.ProfileEvidence()
	return Profile(profile), ok
}
func (a Admission) WrapperCount() int {
	if a.sparse != nil {
		return 0
	}
	return a.legacy.WrapperCount()
}
func (a Admission) Wrapper(index int) (Wrapper, bool) {
	wrapper, ok := a.legacy.Wrapper(index)
	return Wrapper{legacy: wrapper}, ok
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
	prepared        sparsePreparedCall
	request         bin.Object
	profileEvidence bool
	claimed         atomic.Bool
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

// Dispatcher is the compact semantic handler registry plus exact admission
// boundary. Codec routing remains generated static code; this map contains
// application callbacks, never schema or codec programs.
type Dispatcher struct {
	admitter *tg.ServerDispatcher

	mu              sync.RWMutex
	handlers        map[SemanticID]Handler
	wrappers        WrapperConsumer
	legacyAdmission bool
}

func NewDispatcher() *Dispatcher {
	return &Dispatcher{admitter: tg.NewServerDispatcher(nil), handlers: make(map[SemanticID]Handler)}
}

func (d *Dispatcher) Register(method SemanticID, handler Handler) error {
	if d == nil || d.admitter == nil {
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
	if d == nil || d.admitter == nil || callback == nil {
		panic("tlprofile: register nil admission preflight or dispatcher")
	}
	d.admitter.OnLayerRPCAdmissionPreflight(func(view tg.LayerRPCAdmissionView) error {
		return callback(AdmissionView{legacy: view})
	})
	d.mu.Lock()
	d.legacyAdmission = true
	d.mu.Unlock()
}

func (d *Dispatcher) OnFieldPreflight(field FieldID, callback FieldPreflight) error {
	if d == nil || d.admitter == nil || callback == nil {
		return errors.New("tlprofile: register nil field preflight or dispatcher")
	}
	err := d.admitter.OnLayerRPCAdmissionFieldPreflight(tg.LayerRPCFieldID(field), func(view tg.LayerRPCAdmissionFieldView) error {
		return callback(FieldView{legacy: view})
	})
	if err == nil {
		d.mu.Lock()
		d.legacyAdmission = true
		d.mu.Unlock()
	}
	return err
}

func (d *Dispatcher) OnUnknownMethod(callback UnknownMethodAdapter) {
	if d == nil || d.admitter == nil || callback == nil {
		panic("tlprofile: register nil unknown-method adapter or dispatcher")
	}
	d.admitter.OnLayerRPCUnknownMethod(func(view tg.LayerRPCUnknownMethodView) (tg.LayerOutboundCall, bool, error) {
		call, handled, err := callback(UnknownMethodView{legacy: view})
		return call.legacy, handled, err
	})
	d.mu.Lock()
	d.legacyAdmission = true
	d.mu.Unlock()
}

func (d *Dispatcher) Admit(profile Profile, body *bin.Buffer, limits Limits) (Admission, error) {
	if d == nil || d.admitter == nil {
		return Admission{}, errors.New("tlprofile: admit on nil dispatcher")
	}
	d.mu.RLock()
	legacy := d.legacyAdmission
	d.mu.RUnlock()
	if !legacy {
		if admission, handled, err := admitSparseOrdinary(profile, body, limits, true); handled || err != nil {
			return admission, err
		}
	}
	request, err := d.admitter.AdmitLayerWithLimits(tg.LayerProfile(profile), body, limits.legacy())
	return Admission{legacy: request}, err
}

func admitSparseOrdinary(profile Profile, body *bin.Buffer, limits Limits, evidence bool) (Admission, bool, error) {
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
	return Admission{sparse: &sparseAdmission{prepared: prepared, request: request, profileEvidence: evidence}}, true, nil
}

func (d *Dispatcher) AdmitDefault(profile Profile, body *bin.Buffer, limits Limits) (Admission, error) {
	if d == nil || d.admitter == nil {
		return Admission{}, errors.New("tlprofile: default admit on nil dispatcher")
	}
	request, err := d.admitter.AdmitDefaultLayerWithLimits(tg.LayerProfile(profile), body, limits.legacy())
	return Admission{legacy: request}, err
}

func (d *Dispatcher) AdmitUnprofiled(body *bin.Buffer, limits Limits) (Admission, error) {
	if d == nil || d.admitter == nil {
		return Admission{}, errors.New("tlprofile: unprofiled admit on nil dispatcher")
	}
	request, err := d.admitter.AdmitUnprofiledWithLimits(body, limits.legacy())
	return Admission{legacy: request}, err
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
		var request bin.Object
		var err error
		if admission.sparse != nil {
			request, err = admission.sparse.take()
		} else {
			request, err = admission.legacy.TakeCanonicalForTLProfile()
		}
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
	// The generated scanner validates the complete exact-profile wire graph and
	// all allocation budgets before the temporary dense bridge materializes a
	// canonical value. This call remains after the bridge is deleted.
	if err := tlScanExact(profile, in, limits); err != nil {
		return nil, err
	}
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
