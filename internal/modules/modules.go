// Package modules imports every module package so init() side effects
// populate the registry. Add new module packages here.
package modules

import (
	_ "github.com/lab/wpforge/internal/modules/access"
	_ "github.com/lab/wpforge/internal/modules/backdoor"
	_ "github.com/lab/wpforge/internal/modules/exploit"
	_ "github.com/lab/wpforge/internal/modules/netdisc"
	_ "github.com/lab/wpforge/internal/modules/recon"
)
