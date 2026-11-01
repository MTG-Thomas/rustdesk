package transport

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

type Route uint8

const (
	Rendezvous Route = iota
	Relay
	maxMessage = 4 * 1024 * 1024
)

// Socket carries binary RustDesk messages, never receiver authorization.
type Socket struct {
	connection *websocket.Conn
	lifetime   context.Context
	cancel     context.CancelFunc
	leaseDone  <-chan struct{}
}

// Dial uses only the pinned origin, normal TLS verification, no proxy or
// redirects, and a ten-second handshake bound. It never prepares a lease.
func (l *Lease) Dial(ctx context.Context, route Route) (*Socket, error) {
	transport := &http.Transport{
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 16 * 1024,
		DisableKeepAlives:      true,
	}
	defer transport.CloseIdleConnections()
	return l.dial(ctx, route, transport)
}

func (l *Lease) dial(ctx context.Context, route Route, transport http.RoundTripper) (*Socket, error) {
	path := ""
	switch route {
	case Rendezvous:
		path = "/ws/id"
	case Relay:
		path = "/ws/relay"
	default:
		return nil, ErrRejected
	}
	if ctx == nil {
		return nil, ErrRejected
	}
	request, err := http.NewRequest("GET", origin+path, nil)
	if err != nil {
		return nil, ErrRejected
	}
	request.Header.Set("Upgrade", "websocket")
	if l.AuthorizeUpgrade(request, time.Now()) != nil {
		return nil, ErrRejected
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrRejected
	}
	if l.done == nil {
		l.done = make(chan struct{})
	}
	done, expires := l.done, l.expires
	l.mu.Unlock()
	lifetime, cancel := context.WithDeadline(ctx, expires)
	go func() {
		select {
		case <-done:
		case <-lifetime.Done():
		}
		cancel()
	}()
	handshake, finish := context.WithTimeout(lifetime, 10*time.Second)
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	connection, _, err := websocket.Dial(handshake, request.URL.String(), &websocket.DialOptions{
		HTTPClient: client, HTTPHeader: request.Header, CompressionMode: websocket.CompressionDisabled,
	})
	finish()
	request.Header.Del("Authorization")
	if err != nil {
		cancel()
		return nil, ErrRejected
	}
	connection.SetReadLimit(maxMessage)
	context.AfterFunc(lifetime, func() { connection.CloseNow() })
	if lifetime.Err() != nil {
		connection.CloseNow()
		cancel()
		return nil, ErrRejected
	}
	return &Socket{connection: connection, lifetime: lifetime, cancel: cancel, leaseDone: done}, nil
}

func (s *Socket) active() bool {
	if s.lifetime.Err() != nil {
		return false
	}
	select {
	case <-s.leaseDone:
		return false
	default:
		return true
	}
}

func (s *Socket) Read() ([]byte, error) {
	if !s.active() {
		s.Close()
		return nil, ErrRejected
	}
	typeID, message, err := s.connection.Read(s.lifetime)
	if err != nil || typeID != websocket.MessageBinary || !s.active() {
		s.Close()
		return nil, ErrRejected
	}
	return message, nil
}

func (s *Socket) Write(message []byte) error {
	if !s.active() || len(message) > maxMessage || s.connection.Write(s.lifetime, websocket.MessageBinary, message) != nil {
		s.Close()
		return ErrRejected
	}
	return nil
}

// Close is local teardown. The caller must still end/revoke the remote lease.
func (s *Socket) Close() {
	s.cancel()
	s.connection.CloseNow()
}

func (s *Socket) String() string   { return "QuickSupportSocket(redacted)" }
func (s *Socket) GoString() string { return s.String() }
