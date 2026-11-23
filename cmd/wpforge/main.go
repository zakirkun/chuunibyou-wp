// wpforge — modular WordPress exploitation research framework (lab use only).
package main

import (
	"flag"
	"fmt"
	"os"

	_ "github.com/lab/wpforge/internal/modules" // side-effect: register all modules
	"github.com/lab/wpforge/internal/tui"
)

func main() {
	var target, user, pass string
	flag.StringVar(&target, "target", "", "WordPress base URL (pre-seeds the TUI target)")
	flag.StringVar(&user, "user", "", "WordPress username (optional, for auth modules)")
	flag.StringVar(&pass, "pass", "", "WordPress password (optional, for auth modules)")
	flag.Parse()

	if target != "" {
		fmt.Printf("target pre-set: %s\n", target)
	}
	if err := tui.NewWithTarget(target, user, pass).Run(); err != nil {
		os.Exit(1)
	}
}
