# Sparse AOT multi-layer architecture

Status: implementation contract for the replacement of the dense Layer
225--228 backend. This document is normative for generated code. The schema
manifest and policy remain the normative wire inputs.

## 1. Goal and compatibility boundary

The multi-layer backend preserves external Telegram wire compatibility, not
the public Go API introduced by the first fork implementation. In particular:

- `tg` remains the canonical Layer 228 Go model and stays byte-for-byte equal
  to a single-schema canonical generation;
- `tlprofile` is the only public multi-layer package;
- Layer 225--228 request, result and object bytes remain exact, including
  flags, bare/boxed form, vectors, generic bindings and method result types;
- generation may break every existing `tg.Layer*` API and telesrv migrates in
  the same protocol line;
- no generated client facade or per-method server facade is retained.

The old backend generated a typed codec for every schema node and then exposed
the same catalog through TypeRef, wire, family, class, dynamic, client and
server surfaces. That made a four-layer delta look like a second complete TL
implementation. The replacement generates code by distinct execution plan.

## 2. Package topology

```text
github.com/iamxvbaba/td/tg
    canonical Layer 228 types and codecs only

github.com/iamxvbaba/td/tlprofile
    public Profile, Admission, Call and object/result encoding API
    generated compact route and metadata switches

github.com/iamxvbaba/td/internal/tlplan
    handwritten bounded runtime primitives; no schema catalog

github.com/iamxvbaba/td/internal/tlprofilegen
    generated sparse scanners, projections and historical codecs
```

The final package split may merge the two internal packages when that produces
a smaller import graph. Their visibility boundary is normative: consumers may
only import `tg` and `tlprofile`.

## 3. Generation-time IR

The complete manifest, semantic universe and reviewed conversion policy exist
only while gotdgen runs. For every `(profile, semantic family)` the generator
computes a transitive body state:

```text
direct       same wire ID and complete nested wire graph
retag        different wire ID, identical complete nested body graph
rewrite      body, projection, flags policy or nested graph differs
unavailable  absent in the target profile
policy       explicit adapter/reject/default/project decision
```

Body changes seed a reverse dependency closure. Dependencies include exact
bare constructors, every member of boxed abstract classes, recursively nested
vectors, and dynamic `Object`/generic parents. Method result graphs are frozen
independently from request bodies.

An emitted execution plan is identified by a stable digest over:

```text
operation kind
+ physical shape digest
+ transitive route digest
+ canonical projection digest
+ flags policy digest
+ complete result TypeRef digest (for result plans)
+ generic slot layout
+ resource/preflight policy digest
```

Wire IDs and Layer numbers route to a plan; they are not plan identities. Two
different wire IDs or profiles with the same digest share one emitted body.

## 4. Runtime model

Runtime routing is static and bounded:

```text
(profile, wire ID) --generated switch--> plan ID --static call--> code
```

There is no schema loading, reflection, dynamic `(Layer, CRC)` map, TypeRef
walker or bytes-to-bytes transcode. A canonical-direct plan calls the canonical
typed codec. A retag plan consumes/emits the historical ID and calls the
canonical bare codec. Only rewrite/policy plans contain generated field code.

Inbound RPC admission runs a non-materializing generated preflight plan before
the typed decode. It enforces wire-byte, depth, vector, aggregate-element and
field policy limits before canonical decoders can allocate client-controlled
collections. Preflight plans are also deduplicated by execution-plan digest.

`Admission` freezes:

- effective profile and whether it came from explicit evidence;
- semantic method identity and exact request wire ID;
- immutable result plan ID and wire-invariance proof;
- canonical request object;
- wrapper proof and frozen wrapper field values;
- canonical and wire request digests/sizes.

`Call.EncodeResult` is the only RPC result encoder. `EncodeObject` is the only
general proactive-update/object encoder. Both fail closed when the target
profile cannot represent the canonical value.

## 5. Public API direction

The intended small surface is:

```go
type Profile int
type Limits struct { /* bounded decode limits */ }
type Admission struct { /* immutable, opaque */ }
type Call struct { /* immutable, opaque */ }

func Admit(profile Profile, body *bin.Buffer, limits Limits) (Admission, error)
func AdmitDefault(profile Profile, body *bin.Buffer, limits Limits) (Admission, error)
func AdmitUnprofiled(body *bin.Buffer, limits Limits) (Admission, error)

func (a Admission) Request() bin.Object
func (a Admission) Call() Call
func (c Call) EncodeResult(value any, out *bin.Buffer) error

func EncodeObject(profile Profile, value bin.Object, out *bin.Buffer) error
func DecodeObject(profile Profile, in *bin.Buffer) (bin.Object, error)
```

Wrapper inspection, request identity and preflight hooks remain available as
small opaque capabilities required by telesrv. Semantic dispatch is one
handler keyed by generated semantic ID. The generator does not emit `OnX`,
`LayerClient`, public arbitrary TypeRef descriptors, or one facade per Layer.

## 6. Forbidden states

- clamping an unknown/future Layer to a generated profile;
- falling back to canonical bytes after historical encoding fails;
- reusing prepared bytes across profiles or across different result plans;
- declaring direct reuse from local CRC/body equality without transitive proof;
- materializing a request before generated resource preflight succeeds;
- mutating an admitted call when a connection later changes Layer;
- accepting a constructor absent from the exact target class/profile;
- retaining the old `tg.Layer*` API as a compatibility implementation.

## 7. Generated evidence and gates

Production source contains only runtime plans and compact route metadata.
Review evidence is emitted as deterministic JSON under `_schema/layers/audit/`
and consumed by tests. At minimum it records profile/family classification,
closure reason, plan digest, route memberships, policy decisions and result
plan identity.

Required gates:

1. canonical `tg` generation has byte-zero diff from canonical-only generation;
2. a second generation has zero diff;
3. all Layer 225--228 request/result/object goldens match the v1.0.0 oracle;
4. malformed, over-limit, truncated and trailing input fails transactionally;
5. source-size and plan-count budgets fail on dense-regeneration regressions;
6. repository scans reject runtime schema/walker/transcode/canonical-fallback
   paths;
7. telesrv contains no import-time or identifier dependency on `tg.Layer*`.

