// Binary gotdgen generates go source code from TL schema.
package main

import (
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gotd/tl"

	"github.com/gotd/td/gen"
	"github.com/gotd/td/gen/semantic"
)

type formattedSource struct {
	Format bool
	Root   string
}

func (t formattedSource) WriteFile(name string, content []byte) error {
	out := content
	if t.Format {
		buf, err := format.Source(content)
		if err != nil {
			return err
		}
		out = buf
	}
	return os.WriteFile(filepath.Join(t.Root, name), out, 0600)
}

func main() {
	schemaPath := flag.String("schema", "", "Path to .tl file")
	schemaManifest := flag.String("schema-manifest", "", "Path to locked multi-layer schema manifest")
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

	start := time.Now()
	var g *gen.Generator
	if *schemaManifest != "" {
		schemaSet, err := semantic.LoadUniverse(*schemaManifest)
		if err != nil {
			panic(fmt.Sprintf("load schema manifest: %+v", err))
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

	files, err := os.ReadDir(*targetDir)
	if err != nil && !os.IsNotExist(err) {
		panic(err)
	}
	if os.IsNotExist(err) {
		if err := os.Mkdir(*targetDir, 0750); err != nil {
			panic(err)
		}
	}
	if *clean {
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			if !strings.HasSuffix(name, "_gen.go") {
				continue
			}
			if !strings.HasPrefix(name, "tl_") {
				continue
			}
			if err := os.Remove(filepath.Join(*targetDir, name)); err != nil {
				panic(err)
			}
		}
	}

	fs := formattedSource{
		Root:   *targetDir,
		Format: *performFormat,
	}
	start = time.Now()
	if err := g.WriteSource(fs, *packageName, gen.Template()); err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	writeTime := time.Since(start)

	fmt.Printf("Generation %s complete, collect time: %s, write time: %s\n",
		*packageName,
		collectInfoTime,
		writeTime,
	)
}
