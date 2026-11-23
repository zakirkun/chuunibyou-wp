// Package registry holds all compiled-in modules and provides lookup/filter.
package registry

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/lab/wpforge/internal/module"
)

var (
	mu      sync.RWMutex
	modules = map[string]module.Module{}
	order   []string // registration order for stable listing
)

// Register adds a module. Panics on duplicate ID — that's a build-time bug.
func Register(m module.Module) {
	id := m.Meta().ID
	mu.Lock()
	defer mu.Unlock()
	if _, dup := modules[id]; dup {
		panic(fmt.Sprintf("registry: duplicate module id %q", id))
	}
	modules[id] = m
	order = append(order, id)
}

// All returns every registered module sorted by ID.
func All() []module.Module {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]module.Module, 0, len(modules))
	for _, id := range order {
		out = append(out, modules[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Meta().ID < out[j].Meta().ID })
	return out
}

// Get looks a module up by ID.
func Get(id string) (module.Module, bool) {
	mu.RLock()
	defer mu.RUnlock()
	m, ok := modules[id]
	return m, ok
}

// Filter returns modules whose ID/name/CVE/component contains all terms
// (case-insensitive), matching the TUI browser's incremental search.
func Filter(terms string) []module.Module {
	terms = strings.ToLower(strings.TrimSpace(terms))
	all := All()
	if terms == "" {
		return all
	}
	var out []module.Module
	for _, m := range all {
		meta := m.Meta()
		hay := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %s",
			meta.ID, meta.Name, meta.CVE, meta.Component, meta.Primitive, meta.Notes))
		match := true
		for _, term := range strings.Fields(terms) {
			if !strings.Contains(hay, term) {
				match = false
				break
			}
		}
		if match {
			out = append(out, m)
		}
	}
	return out
}
