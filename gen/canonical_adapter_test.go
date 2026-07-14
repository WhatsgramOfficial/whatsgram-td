package gen

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gotd/tl"

	"github.com/iamxvbaba/td/gen/semantic"
)

type sourceSnapshot map[string][]byte

func (s sourceSnapshot) WriteFile(name string, source []byte) error {
	if _, duplicate := s[name]; duplicate {
		return fmt.Errorf("duplicate generated file %q", name)
	}
	s[name] = append([]byte(nil), source...)
	return nil
}

func TestCanonicalAdapterGeneratedSourceZeroDiff(t *testing.T) {
	universe, err := semantic.LoadUniverse("../_schema/layers/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	originalData, err := os.ReadFile("../_schema/telegram.tl")
	if err != nil {
		t.Fatal(err)
	}
	originalSchema, err := tl.Parse(bytes.NewReader(originalData))
	if err != nil {
		t.Fatal(err)
	}

	original := generateSnapshot(t, originalSchema)
	adapted := generateSchemaSetSnapshot(t, universe)
	if got := len(adapted); got <= len(original)+2 {
		t.Fatalf("schema-set generated files = %d, want canonical files plus static layer backend", got)
	}
	layerSource, ok := adapted["tl_layer_metadata_gen.go"]
	if !ok {
		t.Fatal("schema-set generator did not emit layer metadata")
	}
	if _, err := format.Source(layerSource); err != nil {
		t.Fatalf("format layer metadata: %v", err)
	}
	codecSource, ok := adapted["tl_layer_codec_api_gen.go"]
	if !ok {
		t.Fatal("schema-set generator did not emit unified layer codec API")
	}
	if _, err := format.Source(codecSource); err != nil {
		t.Fatalf("format layer codec API: %v", err)
	}
	clientOverlaySource, ok := adapted["tl_layer_client_rpc_overlay_gen.go"]
	if !ok {
		t.Fatal("schema-set generator did not emit static client RPC overlays")
	}
	if _, err := format.Source(clientOverlaySource); err != nil {
		t.Fatalf("format client RPC overlay: %v", err)
	}
	for _, forbidden := range []string{"tl.Parse", "parseSchema", "reflect."} {
		if bytes.Contains(clientOverlaySource, []byte(forbidden)) {
			t.Fatalf("static client RPC overlay contains runtime interpreter marker %q", forbidden)
		}
	}
	if !bytes.Contains(clientOverlaySource, []byte("return 15")) {
		t.Fatal("static client RPC overlay does not contain all audited DrKLO methods")
	}
	names := make([]string, 0, len(original))
	for name := range original {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "tl_server_gen.go" {
			// The multi-layer dispatcher intentionally replaces the canonical-ID-
			// only server while preserving every OnX facade.
			continue
		}
		got, ok := adapted[name]
		if !ok {
			t.Errorf("adapter did not generate %s", name)
			continue
		}
		if !bytes.Equal(got, original[name]) {
			t.Errorf("adapter output differs for %s", name)
		}
	}
	for name := range adapted {
		if _, canonical := original[name]; canonical {
			continue
		}
		if !strings.HasPrefix(name, "tl_layer_") {
			t.Errorf("unexpected non-layer companion file %s", name)
		}
	}
}

func generateSnapshot(t *testing.T, schema *tl.Schema) sourceSnapshot {
	t.Helper()
	generator, err := NewGenerator(schema, canonicalTestGeneratorOptions())
	if err != nil {
		t.Fatal(err)
	}
	return generateGeneratorSnapshot(t, generator)
}

func generateSchemaSetSnapshot(t *testing.T, schemaSet *SchemaSet) sourceSnapshot {
	t.Helper()
	options := canonicalTestGeneratorOptions()
	options.LayerPolicy = layerTestPolicy(t, schemaSet)
	generator, err := NewSchemaSetGenerator(schemaSet, options)
	if err != nil {
		t.Fatal(err)
	}
	if generator.SchemaSet() != schemaSet {
		t.Fatal("generator did not retain the normalized schema set")
	}
	return generateGeneratorSnapshot(t, generator)
}

func canonicalTestGeneratorOptions() GeneratorOptions {
	return GeneratorOptions{
		DocBaseURL: "https://core.telegram.org/",
		GenerateFlags: GenerateFlags{
			Client:            true,
			Registry:          true,
			Server:            true,
			Handlers:          true,
			UpdatesClassifier: true,
			GetSet:            true,
			Mapping:           true,
			Slices:            true,
		},
	}
}

func generateGeneratorSnapshot(t *testing.T, generator *Generator) sourceSnapshot {
	t.Helper()
	result := sourceSnapshot{}
	if err := generator.WriteSource(result, "tg", Template()); err != nil {
		t.Fatal(err)
	}
	return result
}
