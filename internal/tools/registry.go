package tools

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed manifests/*.yaml
var embeddedManifests embed.FS

// Registry is an immutable set of tool manifests.
type Registry struct {
	byName map[string]Manifest
	names  []string
}

// LoadEmbedded loads the manifests compiled into the binary.
func LoadEmbedded() (*Registry, error) {
	return LoadFS(embeddedManifests, "manifests")
}

// LoadFS loads every *.yaml manifest from a filesystem directory.
func LoadFS(fsys fs.FS, dir string) (*Registry, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read tool manifests: %w", err)
	}
	registry := &Registry{byName: make(map[string]Manifest)}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		filename := path.Join(dir, entry.Name())
		data, err := fs.ReadFile(fsys, filename)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filename, err)
		}
		var manifest Manifest
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&manifest); err != nil {
			return nil, fmt.Errorf("parse %s: %w", filename, err)
		}
		if err := manifest.Compile(); err != nil {
			return nil, fmt.Errorf("%s: %w", filename, err)
		}
		expected := strings.TrimSuffix(entry.Name(), ".yaml")
		if manifest.Name != expected {
			return nil, fmt.Errorf("%s: manifest name %q does not match filename", filename, manifest.Name)
		}
		if _, exists := registry.byName[manifest.Name]; exists {
			return nil, fmt.Errorf("%s: duplicate tool %q", filename, manifest.Name)
		}
		registry.byName[manifest.Name] = manifest
		registry.names = append(registry.names, manifest.Name)
	}
	if len(registry.names) == 0 {
		return nil, fmt.Errorf("no tool manifests found in %s", dir)
	}
	sort.Strings(registry.names)
	return registry, nil
}

// List returns all manifests sorted by name.
func (r *Registry) List() []Manifest {
	manifests := make([]Manifest, 0, len(r.names))
	for _, name := range r.names {
		manifests = append(manifests, r.byName[name])
	}
	return manifests
}

// Names returns manifest names sorted alphabetically.
func (r *Registry) Names() []string {
	return append([]string(nil), r.names...)
}

// Get returns a manifest by name.
func (r *Registry) Get(name string) (Manifest, bool) {
	manifest, ok := r.byName[strings.ToLower(strings.TrimSpace(name))]
	return manifest, ok
}
