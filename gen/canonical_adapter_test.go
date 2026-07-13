package gen

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/gotd/tl"

	"github.com/gotd/td/gen/semantic"
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
	adapted := generateSnapshot(t, universe.CanonicalSchema())
	if len(original) != len(adapted) {
		t.Fatalf("generated files = %d, adapter files = %d", len(original), len(adapted))
	}
	names := make([]string, 0, len(original))
	for name := range original {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		got, ok := adapted[name]
		if !ok {
			t.Errorf("adapter did not generate %s", name)
			continue
		}
		if !bytes.Equal(got, original[name]) {
			t.Errorf("adapter output differs for %s", name)
		}
	}
}

func generateSnapshot(t *testing.T, schema *tl.Schema) sourceSnapshot {
	t.Helper()
	options := GeneratorOptions{
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
	generator, err := NewGenerator(schema, options)
	if err != nil {
		t.Fatal(err)
	}
	result := sourceSnapshot{}
	if err := generator.WriteSource(result, "tg", Template()); err != nil {
		t.Fatal(err)
	}
	return result
}
