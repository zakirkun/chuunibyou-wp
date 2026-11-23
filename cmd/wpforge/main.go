// wpforge — modular WordPress exploitation research framework (lab use only).
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	_ "github.com/lab/wpforge/internal/modules" // side-effect: register all modules
	"github.com/lab/wpforge/internal/tui"
)

func main() {
	var target, user, pass string
	var timeout int
	flag.StringVar(&target, "target", "", "WordPress base URL (pre-seeds the TUI target)")
	flag.StringVar(&user, "user", "", "WordPress username (optional, for auth modules)")
	flag.StringVar(&pass, "pass", "", "WordPress password (optional, for auth modules)")
	flag.IntVar(&timeout, "timeout", 15, "HTTP timeout in seconds")
	flag.Parse()

	if err := validateArgs(target, user, pass, timeout); err != nil {
		fmt.Fprintln(os.Stderr, "wpforge:", err)
		os.Exit(2)
	}
	if target != "" {
		fmt.Printf("target pre-set: %s\n", target)
	}
	if err := tui.NewWithTarget(target, user, pass, strconv.Itoa(timeout)).Run(); err != nil {
		os.Exit(1)
	}
}

func validateArgs(target, user, pass string, timeout int) error {
	if timeout <= 0 {
		return fmt.Errorf("-timeout must be greater than zero")
	}
	if target == "" {
		if user != "" || pass != "" {
			return fmt.Errorf("-user and -pass require -target")
		}
		return nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || (strings.ToLower(u.Scheme) != "http" && strings.ToLower(u.Scheme) != "https") {
		return fmt.Errorf("-target must be an absolute http:// or https:// URL")
	}
	return nil
}
