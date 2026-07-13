package semantic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gotd/tl"
)

// Manifest locks all schema inputs and their upstream provenance.
type Manifest struct {
	CanonicalLayer int             `json:"canonical_layer"`
	Repository     string          `json:"repository"`
	SourcePath     string          `json:"source_path"`
	Overlays       []string        `json:"overlays"`
	Layers         []ManifestLayer `json:"layers"`
}

// ManifestLayer is one immutable TDesktop schema source.
type ManifestLayer struct {
	Layer  int    `json:"layer"`
	File   string `json:"file"`
	Commit string `json:"commit"`
	Blob   string `json:"blob"`
	SHA256 string `json:"sha256"`
}

// ReadManifest parses a manifest and rejects unknown or invalid fields.
func ReadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("semantic: read manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("semantic: decode manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("semantic: decode trailing manifest data: %w", err)
	}
	return fmt.Errorf("semantic: manifest has multiple JSON values")
}

func validateManifest(manifest Manifest) error {
	if manifest.CanonicalLayer <= 0 {
		return fmt.Errorf("semantic: invalid canonical layer %d", manifest.CanonicalLayer)
	}
	if strings.TrimSpace(manifest.Repository) == "" {
		return fmt.Errorf("semantic: manifest repository is empty")
	}
	if strings.TrimSpace(manifest.SourcePath) == "" {
		return fmt.Errorf("semantic: manifest source_path is empty")
	}
	if len(manifest.Layers) == 0 {
		return fmt.Errorf("semantic: manifest has no layers")
	}
	seen := make(map[int]struct{}, len(manifest.Layers))
	canonicalFound := false
	previous := 0
	for i, layer := range manifest.Layers {
		if layer.Layer <= 0 {
			return fmt.Errorf("semantic: manifest layer[%d] has invalid layer %d", i, layer.Layer)
		}
		if i > 0 && layer.Layer <= previous {
			return fmt.Errorf("semantic: manifest layers must be strictly increasing")
		}
		previous = layer.Layer
		if _, duplicate := seen[layer.Layer]; duplicate {
			return fmt.Errorf("semantic: manifest repeats layer %d", layer.Layer)
		}
		seen[layer.Layer] = struct{}{}
		canonicalFound = canonicalFound || layer.Layer == manifest.CanonicalLayer
		if strings.TrimSpace(layer.File) == "" {
			return fmt.Errorf("semantic: layer %d file is empty", layer.Layer)
		}
		if err := validateHex("commit", layer.Layer, layer.Commit, 20); err != nil {
			return err
		}
		if err := validateHex("blob", layer.Layer, layer.Blob, 20); err != nil {
			return err
		}
		if err := validateHex("sha256", layer.Layer, layer.SHA256, sha256.Size); err != nil {
			return err
		}
	}
	if !canonicalFound {
		return fmt.Errorf("semantic: canonical layer %d is absent from manifest", manifest.CanonicalLayer)
	}
	for i, overlay := range manifest.Overlays {
		if strings.TrimSpace(overlay) == "" {
			return fmt.Errorf("semantic: overlay[%d] is empty", i)
		}
	}
	return nil
}

func validateHex(field string, layer int, value string, size int) error {
	if value != strings.ToLower(value) {
		return fmt.Errorf("semantic: layer %d %s must be lowercase hex", layer, field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != size {
		return fmt.Errorf("semantic: layer %d %s must be %d-byte hex", layer, field, size)
	}
	return nil
}

// LoadUniverse reads, hashes, parses, overlays, and validates every schema in
// a manifest. Schema files are resolved relative to the manifest directory.
func LoadUniverse(manifestPath string) (*Universe, error) {
	manifest, err := ReadManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(manifestPath)
	overlays := make([]*tl.Schema, 0, len(manifest.Overlays))
	for _, name := range manifest.Overlays {
		overlay, err := parseSchemaFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return nil, fmt.Errorf("semantic: overlay %q: %w", name, err)
		}
		overlays = append(overlays, overlay)
	}

	schemas := make([]*SchemaModel, 0, len(manifest.Layers))
	for _, entry := range manifest.Layers {
		name := filepath.Join(root, filepath.FromSlash(entry.File))
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("semantic: layer %d read schema: %w", entry.Layer, err)
		}
		digest := sha256.Sum256(data)
		if got := hex.EncodeToString(digest[:]); got != entry.SHA256 {
			return nil, fmt.Errorf("semantic: layer %d SHA256 mismatch: got %s, want %s", entry.Layer, got, entry.SHA256)
		}
		parsed, err := tl.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("semantic: layer %d parse schema: %w", entry.Layer, err)
		}
		if parsed.Layer != entry.Layer {
			return nil, fmt.Errorf("semantic: layer %d file declares layer %d", entry.Layer, parsed.Layer)
		}
		for _, overlay := range overlays {
			mergeSchema(parsed, overlay)
		}
		model, err := BuildSchema(parsed, SourceRef{
			Layer:      entry.Layer,
			Repository: manifest.Repository,
			Commit:     entry.Commit,
			Blob:       entry.Blob,
			Path:       manifest.SourcePath,
			File:       entry.File,
			SHA256:     ShapeDigest(digest),
		})
		if err != nil {
			return nil, err
		}
		schemas = append(schemas, model)
	}
	return NewUniverse(manifest.CanonicalLayer, schemas...)
}

func parseSchemaFile(path string) (*tl.Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	parsed, err := tl.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

// SortedKeys returns family keys in deterministic category/name order.
func (u *Universe) SortedKeys() []DefinitionKey {
	keys := make([]DefinitionKey, 0, len(u.Families))
	for key := range u.Families {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Category != keys[j].Category {
			return keys[i].Category < keys[j].Category
		}
		return keys[i].QName < keys[j].QName
	})
	return keys
}
