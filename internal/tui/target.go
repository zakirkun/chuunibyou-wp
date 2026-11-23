// Package tui implements the wpforge console: a tview-based interface with
// a module browser (left), output console (right), and status bar (bottom).
package tui

import (
	"time"

	"github.com/lab/wpforge/internal/engine"
	"github.com/lab/wpforge/internal/module"
)

// newTarget builds a module.Target from form input.
func newTarget(baseURL, timeoutSecs string) (*module.Target, error) {
	timeout, err := time.ParseDuration(timeoutSecs + "s")
	if err != nil {
		return nil, err
	}
	client, err := engine.NewClient(baseURL, timeout)
	if err != nil {
		return viaErr(err)
	}
	return &module.Target{BaseURL: baseURL, Client: client}, nil
}

func viaErr(err error) (*module.Target, error) {
	return nil, err
}
