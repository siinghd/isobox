// Package registry loads the declarative language catalogue (registry.yaml) and
// resolves a caller's language/version into a fully-specified, trusted launch
// recipe (image, compile/run argv, defaults). Everything the sandbox executes
// originates here, never from the caller, which is what makes it safe to pass
// the compile/run commands into an in-container shell.
package registry

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/siinghd/isobox/internal/executor"
	"gopkg.in/yaml.v3"
)

// RegistryLimits are the per-language default bounds (YAML-friendly types).
type RegistryLimits struct {
	MemoryBytes    int64  `yaml:"memory_bytes"`
	CPUs           string `yaml:"cpus"`
	PidsLimit      int    `yaml:"pids_limit"`
	WallTimeSec    int    `yaml:"wall_time_sec"`
	CompileTimeSec int    `yaml:"compile_time_sec"`
	OutputBytes    int64  `yaml:"output_bytes"`
}

// Language is one catalogue entry.
type Language struct {
	Name        string            `yaml:"name"`
	Version     string            `yaml:"version"`
	Aliases     []string          `yaml:"aliases"`
	Image       string            `yaml:"image"` // digest-pinned
	SourceFile  string            `yaml:"source_file"`
	Compile     []string          `yaml:"compile"` // nil => interpreted
	Run         []string          `yaml:"run"`
	Workdir     string            `yaml:"workdir"`
	Env         map[string]string `yaml:"env"`
	ScratchExec bool              `yaml:"scratch_exec"`
	ScratchMB   int               `yaml:"scratch_mb"`
	Limits      RegistryLimits    `yaml:"limits"`
}

type fileDoc struct {
	Languages []Language `yaml:"languages"`
}

// Registry is an immutable, concurrently-readable view of the catalogue.
type Registry struct {
	mu    sync.RWMutex
	byKey map[string]*Language
	all   []Language
}

// Load parses registry.yaml into a Registry, indexing every name and alias
// (both bare and name@version).
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read registry: %w", err)
	}
	var doc fileDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse registry: %w", err)
	}
	if len(doc.Languages) == 0 {
		return nil, fmt.Errorf("registry %s defines no languages", path)
	}
	r := &Registry{byKey: make(map[string]*Language)}
	r.all = make([]Language, len(doc.Languages))
	copy(r.all, doc.Languages)
	for i := range r.all {
		l := &r.all[i]
		if l.Workdir == "" {
			l.Workdir = "/box"
		}
		if l.Name == "" || l.Image == "" || len(l.Run) == 0 {
			return nil, fmt.Errorf("registry entry %d: name, image and run are required", i)
		}
		for _, k := range append([]string{l.Name}, l.Aliases...) {
			lk := strings.ToLower(k)
			r.byKey[lk] = l
			r.byKey[lk+"@"+l.Version] = l
		}
	}
	return r, nil
}

// Reload re-parses the registry file and atomically swaps the catalogue. Safe to
// call while requests are in flight (e.g. from a SIGHUP handler).
func (r *Registry) Reload(path string) error {
	nr, err := Load(path)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byKey = nr.byKey
	r.all = nr.all
	return nil
}

// Resolve finds a language by name/alias, optionally pinned to a version.
func (r *Registry) Resolve(name, version string) (*Language, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	name = strings.ToLower(strings.TrimSpace(name))
	if version != "" {
		if l, ok := r.byKey[name+"@"+strings.TrimSpace(version)]; ok {
			return l, true
		}
	}
	l, ok := r.byKey[name]
	return l, ok
}

// All returns the catalogue (for GET /runtimes).
func (r *Registry) All() []Language {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Language, len(r.all))
	copy(out, r.all)
	return out
}

// DefaultLimits maps a language's YAML defaults into executor.Limits.
func (l *Language) DefaultLimits() executor.Limits {
	cpus, _ := strconv.ParseFloat(l.Limits.CPUs, 64)
	if cpus <= 0 {
		cpus = 1.0
	}
	return executor.Limits{
		MemoryBytes:   nonzero64(l.Limits.MemoryBytes, 256<<20),
		CPUs:          cpus,
		Pids:          nonzero(l.Limits.PidsLimit, 128),
		OutputBytes:   nonzero64(l.Limits.OutputBytes, 64<<10),
		WallTimeMs:    nonzero(l.Limits.WallTimeSec, 10) * 1000,
		CompileTimeMs: l.Limits.CompileTimeSec * 1000,
	}
}

// BuildSpec assembles a trusted executor.Spec for this language plus the
// caller's files/stdin/argv and (already clamped) limits.
func (l *Language) BuildSpec(files []executor.File, stdin string, argv []string, limits executor.Limits, network bool) executor.Spec {
	return executor.Spec{
		Lang:        executor.Language{Name: l.Name, Version: l.Version},
		Image:       l.Image,
		Compile:     l.Compile,
		Run:         l.Run,
		Workdir:     l.Workdir,
		Env:         l.Env,
		ScratchExec: l.ScratchExec,
		ScratchMB:   l.ScratchMB,
		Files:       files,
		Stdin:       stdin,
		Argv:        argv,
		Limits:      limits,
		Network:     network,
	}
}

func nonzero(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func nonzero64(v, def int64) int64 {
	if v <= 0 {
		return def
	}
	return v
}
