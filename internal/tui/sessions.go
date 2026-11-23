// Sessions console: interactive shell access for registered sessions.
package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/lab/wpforge/internal/shell"
)

// sessionsView owns the sessions page UI.
type sessionsView struct {
	app        *App
	list       *tview.List
	term       *tview.TextView
	input      *tview.InputField
	current    *shell.Session
	mu         sync.Mutex
	generation uint64
}

// buildSessions is called from App.New.
func (a *App) buildSessions() {
	a.sessionsUI = &sessionsView{app: a}
	sv := a.sessionsUI

	sv.list = tview.NewList().ShowSecondaryText(true)
	sv.list.SetBorder(true).SetTitle(" Sessions (Enter: connect, r: refresh, k: kill) ")
	sv.list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() != tcell.KeyRune {
			return ev
		}
		switch ev.Rune() {
		case 'r':
			sv.refresh()
			return nil
		case 'k':
			sv.kill()
			return nil
		default:
			return ev
		}
	})

	sv.term = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWordWrap(true).
		SetMaxLines(3000)
	sv.term.SetBorder(true).SetTitle(" Terminal (type command + Enter) ")

	sv.input = tview.NewInputField().SetLabel("$ ")
	sv.input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		text := sv.input.GetText()
		sv.input.SetText("")
		sv.exec(text)
	})

	termCol := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(sv.term, 0, 1, false).
		AddItem(sv.input, 1, 0, false)
	body := tview.NewFlex().
		AddItem(sv.list, 0, 1, true).
		AddItem(termCol, 0, 2, false)
	page := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(a.status, 1, 0, false)

	a.pages.AddPage("sessions", page, true, false)
}

// show switches to the sessions page and refreshes the list.
func (sv *sessionsView) show() {
	sv.refresh()
	sv.app.pages.SwitchToPage("sessions")
	sv.app.app.SetFocus(sv.list)
}

// refresh rebuilds the session list from the manager.
func (sv *sessionsView) refresh() {
	sv.list.Clear()
	for _, s := range shell.M().List() {
		ss := s
		sv.list.AddItem(fmt.Sprintf("%s  [%s]", s.ID, s.Kind), s.Target, 0, func() {
			sv.connect(ss)
		})
	}
	if sv.list.GetItemCount() == 0 {
		sv.list.AddItem("(no live sessions)", "set a target to start the automatic scan", 0, nil)
	}
}

// connect selects a session as the active terminal target.
func (sv *sessionsView) connect(s *shell.Session) {
	sv.mu.Lock()
	sv.current = s
	sv.generation++
	sv.mu.Unlock()
	sv.term.Clear()
	fmt.Fprintf(sv.term, "[green]connected: %s[white] (%s, %s)\n", s.ID, s.Kind, s.Target)
	if s.Kind == "webshell" {
		fmt.Fprintf(sv.term, "[gray]webshell: commands run via HTTP param %q[white]\n", s.Param)
	}
	sv.app.app.SetFocus(sv.input)
}

// exec runs a command on the active session.
func (sv *sessionsView) exec(cmdline string) {
	sv.mu.Lock()
	s := sv.current
	sv.mu.Unlock()
	if s == nil {
		fmt.Fprintf(sv.term, "[yellow]no session selected - Enter on a session first[white]\n")
		return
	}
	if strings.TrimSpace(cmdline) == "" {
		return
	}
	if cmdline == "exit" || cmdline == "quit" {
		fmt.Fprintf(sv.term, "[yellow]staying connected - use k in the list to kill the session[white]\n")
		return
	}
	sv.execAsync(s, cmdline)
}

// execAsync runs one command in the background and prints its output.
func (sv *sessionsView) execAsync(s *shell.Session, cmdline string) {
	fmt.Fprintf(sv.term, "[aqua]> %s[white]\n", tview.Escape(cmdline))
	sv.mu.Lock()
	generation := sv.generation
	sv.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(sv.app.ctx, 25*time.Second)
		defer cancel()
		out, err := s.Exec(ctx, cmdline)
		sv.app.app.QueueUpdateDraw(func() {
			sv.mu.Lock()
			active := sv.current == s && sv.generation == generation
			sv.mu.Unlock()
			if !active {
				return
			}
			if err != nil {
				fmt.Fprintf(sv.term, "[red]error: %v[white]\n", tview.Escape(err.Error()))
			}
			if out != "" {
				fmt.Fprintf(sv.term, "%s\n", tview.Escape(out))
			}
		})
	}()
}

// kill closes the active session.
func (sv *sessionsView) kill() {
	idx := sv.list.GetCurrentItem()
	sessions := shell.M().List()
	if idx < 0 || idx >= len(sessions) {
		return
	}
	selected := sessions[idx]
	sv.mu.Lock()
	if sv.current == selected {
		sv.current = nil
		sv.generation++
	}
	sv.mu.Unlock()
	shell.M().Close(selected.ID)
	sv.app.Logf("warn", "session %s closed", selected.ID)
	sv.refresh()
}
