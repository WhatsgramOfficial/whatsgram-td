// Binary gotdgen generates go source code from TL schema.
package main

import (
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gotd/tl"

	"github.com/gotd/td/gen"
	"github.com/gotd/td/gen/semantic"
)

type formattedSource struct {
	Format bool
	Root   string
	files  map[string][]byte
}

func (t *formattedSource) WriteFile(name string, content []byte) error {
	if _, duplicate := t.files[name]; duplicate {
		return fmt.Errorf("duplicate generated file %q", name)
	}
	out := content
	if t.Format {
		buf, err := format.Source(content)
		if err != nil {
			return err
		}
		out = buf
	}
	t.files[name] = append([]byte(nil), out...)
	return nil
}

// Commit writes only after every template has rendered and formatted
// successfully. Individual targets are atomically replaced in deterministic
// order, so a generation/format error can never leave a mixed package.
func (t *formattedSource) Commit() error {
	names := make([]string, 0, len(t.files))
	for name := range t.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writeFileAtomic(filepath.Join(t.Root, name), t.files[name], 0o600); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}
	return nil
}

func (t *formattedSource) Has(name string) bool {
	_, ok := t.files[name]
	return ok
}

func main() {
	schemaPath := flag.String("schema", "", "Path to .tl file")
	schemaManifest := flag.String("schema-manifest", "", "Path to locked multi-layer schema manifest")
	layerPolicy := flag.String("layer-policy", "", "Path to versioned multi-layer conversion policy")
	layerPolicyTemplate := flag.String("layer-policy-template", "", "Write unresolved multi-layer policy skeleton to path (or - for stdout) and exit")
	targetDir := flag.String("target", "td", "Path to target dir")
	packageName := flag.String("package", "td", "Target package name")
	performFormat := flag.Bool("format", true, "Perform code formatting")
	clean := flag.Bool("clean", false, "Clean generated files before generation")

	genOpts := gen.GeneratorOptions{}
	genOpts.RegisterFlags(flag.CommandLine)

	flag.Parse()
	if (*schemaPath == "") == (*schemaManifest == "") {
		panic("provide exactly one of -schema or -schema-manifest")
	}
	if *layerPolicy != "" && *schemaManifest == "" {
		panic("-layer-policy requires -schema-manifest")
	}
	if *layerPolicyTemplate != "" && *schemaManifest == "" {
		panic("-layer-policy-template requires -schema-manifest")
	}

	start := time.Now()
	var g *gen.Generator
	if *schemaManifest != "" {
		schemaSet, err := semantic.LoadUniverse(*schemaManifest)
		if err != nil {
			panic(fmt.Sprintf("load schema manifest: %+v", err))
		}
		if *layerPolicy != "" {
			policy, err := gen.LoadLayerPolicy(*layerPolicy)
			if err != nil {
				panic(fmt.Sprintf("load layer policy: %+v", err))
			}
			genOpts.LayerPolicy = policy
		}
		g, err = gen.NewSchemaSetGenerator(schemaSet, genOpts)
		if err != nil {
			panic(fmt.Sprintf("build schema set generator: %+v", err))
		}
	} else {
		f, err := os.Open(*schemaPath)
		if err != nil {
			panic(err)
		}
		defer func() { _ = f.Close() }()

		schema, err := tl.Parse(f)
		if err != nil {
			panic(err)
		}
		g, err = gen.NewGenerator(schema, genOpts)
		if err != nil {
			panic(fmt.Sprintf("%+v", err))
		}
	}
	collectInfoTime := time.Since(start)
	if *layerPolicyTemplate != "" {
		plan := g.LayerConversionPlan()
		if plan == nil {
			panic("layer policy template requires a schema-set conversion plan")
		}
		data, err := gen.MarshalLayerPolicyTemplate(plan.Report)
		if err != nil {
			panic(fmt.Sprintf("render layer policy template: %+v", err))
		}
		if *layerPolicyTemplate == "-" {
			if _, err := os.Stdout.Write(data); err != nil {
				panic(fmt.Sprintf("write layer policy template: %+v", err))
			}
			return
		}
		if err := writeFileAtomic(*layerPolicyTemplate, data, 0o600); err != nil {
			panic(fmt.Sprintf("write layer policy template: %+v", err))
		}
		fmt.Printf("Layer policy template written to %s (%d unresolved decisions)\n", *layerPolicyTemplate, len(plan.Report.Unresolved()))
		return
	}

	files, err := os.ReadDir(*targetDir)
	if err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	if os.IsNotExist(err) {
		if err := os.Mkdir(*targetDir, 0750); err != nil {
			panic(err)
		}
	}
	fs := &formattedSource{
		Root:   *targetDir,
		Format: *performFormat,
		files:  make(map[string][]byte),
	}
	start = time.Now()
	if err := g.WriteSource(fs, *packageName, gen.Template()); err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	if err := fs.Commit(); err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	if *clean {
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			if !strings.HasSuffix(name, "_gen.go") || !strings.HasPrefix(name, "tl_") || fs.Has(name) {
				continue
			}
			if err := os.Remove(filepath.Join(*targetDir, name)); err != nil {
				panic(err)
			}
		}
	}
	writeTime := time.Since(start)

	fmt.Printf("Generation %s complete, collect time: %s, write time: %s\n",
		*packageName,
		collectInfoTime,
		writeTime,
	)
}
