# Multi-layer TL generation

`gotdgen` treats this directory as one versioned schema universe, not as a
collection of independent generators. `manifest.json` selects the canonical
Layer and records the upstream repository, commit, blob and SHA-256 for every
input. `policy.json` contains the reviewed decisions which cannot be inferred
from TL structure alone.

The generated `tg` package has one stable canonical Go model (the manifest's
canonical Layer) and static wire codecs for every unique constructor or method
ID present in the universe. Exact profiles map a semantic name to its wire ID
and body variant. RPC results, active updates and difference responses all use
the same `EncodeLayer` / `DecodeLayer` machinery; there is no push-specific
codec and no fallback to canonical bytes when a projection fails.

## Adding a Layer

1. Copy the exact upstream TL source into `layer-N.tl`.
2. Append its provenance and digest to `manifest.json`, and select it as
   `canonical_layer` when it is the new canonical model.
3. Run the policy audit without weakening an existing decision:

   ```powershell
   go run ./cmd/gotdgen --schema-manifest _schema/layers/manifest.json `
     --layer-policy _schema/layers/policy.json `
     --layer-policy-template _schema/layers/policy.next.json `
     --package tg --target tg
   ```

4. Review every new obligation. Mechanical ID/body reuse needs no policy.
   Removed fields, replacements, old-only definitions, changed RPC results and
   unavailable update constructors require an explicit `reject`, `drop`,
   `default`, `alias`, `project` or typed `adapter` decision. Copy only reviewed
   entries into `policy.json`; stale keys and unresolved obligations are hard
   generation errors.
5. Regenerate and verify:

   ```powershell
   go generate .
   go test ./gen ./cmd/gotdgen ./tg
   go vet ./gen ./cmd/gotdgen
   git diff --check
   ```

Adding an unchanged 228/229 profile therefore only extends generated profile
metadata and switch cases. A genuinely changed schema stops at generation time
until its semantic policy and typed hook are supplied.

## Runtime invariants

- A connection profile is resolved exactly and then frozen. An inner
  `invokeWithLayer` cannot change it.
- Request admission consumes the complete outer wire value and freezes the
  exact result `TypeRef`, wire ID and request digest.
- Wrapper metadata is preserved outer-to-inner. Wrappers with session,
  ordering or update-suppression meaning must be consumed explicitly.
- Flags are rebuilt by `(flags word, bit)` groups. Present-empty slices remain
  present; every value-bearing member of a set bit is encoded atomically.
- Encoding is transactional. Rejected adapters, partial projections, malformed
  flags and size limits leave the caller's buffer unchanged.
- Decode depth and vector lengths are bounded. TL strings and byte strings must
  fit the protocol's 24-bit length header.
- Frozen values may be prepared once per exact profile/call identity. Wire bytes
  are never reused across unequal profiles or result `TypeRef` identities.

The source emitter coalesces identical profile bodies but keeps one static
function family per unique wire ID. It does not use reflection, a runtime
schema walker or a dynamic schema map.
