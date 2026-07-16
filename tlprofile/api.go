package tlprofile

import (
	"context"
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

func (l Limits) legacy() tg.LayerDecodeLimits {
	return tg.LayerDecodeLimits{
		MaxWireBytes: l.MaxWireBytes, MaxVectorElements: l.MaxVectorElements,
		MaxAggregateElements: l.MaxAggregateElements, MaxDepth: l.MaxDepth,
	}
}

// PreparedIdentity is the comparable exact request/cache identity.
type PreparedIdentity struct {
	legacy tg.LayerPreparedCallIdentity
}

// SemanticIdentity is the comparable innermost canonical request identity.
type SemanticIdentity struct {
	legacy tg.LayerSemanticRequestIdentity
}

func (i SemanticIdentity) Method() SemanticID { return SemanticID(i.legacy.Method()) }
func (i SemanticIdentity) CanonicalSize() int { return i.legacy.CanonicalSize() }
func (i SemanticIdentity) CanonicalDigest() [32]byte {
	return i.legacy.CanonicalDigest()
}

// PreparedCall is immutable admission metadata.
type PreparedCall struct {
	legacy tg.LayerPreparedCall
}

func (p PreparedCall) Call() Call           { return Call{legacy: p.legacy.Call()} }
func (p PreparedCall) WireSize() int        { return p.legacy.WireSize() }
func (p PreparedCall) WireDigest() [32]byte { return p.legacy.WireDigest() }
func (p PreparedCall) Identity() PreparedIdentity {
	return PreparedIdentity{legacy: p.legacy.Identity()}
}
func (p PreparedCall) SemanticIdentity() SemanticIdentity {
	return SemanticIdentity{legacy: p.legacy.SemanticIdentity()}
}

// ResultPlan is an opaque complete method-result plan. It deliberately does
// not expose the old runtime TypeRef catalog.
type ResultPlan struct {
	legacy *tg.LayerTypeRef
}

// Call freezes the exact profile, method route and result plan selected during
// admission.
type Call struct {
	legacy tg.LayerCall
}

func (c Call) Profile() Profile       { return Profile(c.legacy.Profile()) }
func (c Call) Method() SemanticID     { return SemanticID(c.legacy.Method()) }
func (c Call) WireID() uint32         { return c.legacy.WireID() }
func (c Call) WireInvariant() bool    { return c.legacy.WireInvariant() }
func (c Call) ResultPlan() ResultPlan { return ResultPlan{legacy: c.legacy.WireResultType()} }
func (c Call) EncodeResult(value any, out *bin.Buffer) error {
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
}

func (a Admission) Prepared() PreparedCall { return PreparedCall{legacy: a.legacy.Prepared()} }
func (a Admission) Call() Call             { return Call{legacy: a.legacy.Call()} }
func (a Admission) EffectiveProfile() (Profile, bool) {
	profile, ok := a.legacy.EffectiveProfile()
	return Profile(profile), ok
}
func (a Admission) ProfileEvidence() (Profile, bool) {
	profile, ok := a.legacy.ProfileEvidence()
	return Profile(profile), ok
}
func (a Admission) WrapperCount() int { return a.legacy.WrapperCount() }
func (a Admission) Wrapper(index int) (Wrapper, bool) {
	wrapper, ok := a.legacy.Wrapper(index)
	return Wrapper{legacy: wrapper}, ok
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

	mu       sync.RWMutex
	handlers map[SemanticID]Handler
	wrappers WrapperConsumer
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

func (d *Dispatcher) Admit(profile Profile, body *bin.Buffer, limits Limits) (Admission, error) {
	if d == nil || d.admitter == nil {
		return Admission{}, errors.New("tlprofile: admit on nil dispatcher")
	}
	request, err := d.admitter.AdmitLayerWithLimits(tg.LayerProfile(profile), body, limits.legacy())
	return Admission{legacy: request}, err
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
		request, err := admission.legacy.TakeCanonicalForTLProfile()
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
// The current implementation delegates to the generated static core; the
// public API does not expose its dense TypeRef catalog.
func EncodeObject(profile Profile, value bin.Object, out *bin.Buffer) error {
	return tg.EncodeLayer(tg.LayerProfile(profile), tg.LayerObjectType(), value, out)
}

func DecodeObject(profile Profile, in *bin.Buffer, limits Limits) (bin.Object, error) {
	return tg.DecodeLayerWithLimits(tg.LayerProfile(profile), tg.LayerObjectType(), in, limits.legacy())
}
