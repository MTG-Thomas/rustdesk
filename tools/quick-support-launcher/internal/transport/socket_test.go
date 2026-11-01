package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func socketLease(duration time.Duration) *Lease {
	l := &Lease{created: time.Now(), expires: time.Now().Add(duration)}
	for index := range l.token {
		l.token[index] = 0xab
	}
	return l
}

func pinnedLocalTransport(t *testing.T, server *httptest.Server) *http.Transport {
	t.Helper()
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = address.Hostname()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

func TestBinarySocketsSurviveHandshakeAndLeaseCloseEndsBothRoutes(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "quick-support-api.midtowntg.com" || (r.URL.Path != "/ws/id" && r.URL.Path != "/ws/relay") ||
			r.Header.Get("Authorization") != "Bearer "+syntheticTicket || r.Header.Get("Sec-WebSocket-Extensions") != "" {
			http.Error(w, "rejected", 401)
			return
		}
		requests.Add(1)
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		for {
			typeID, data, err := connection.Read(r.Context())
			if err != nil || connection.Write(r.Context(), typeID, data) != nil {
				return
			}
		}
	}))
	defer server.Close()
	l := socketLease(time.Minute)
	defer l.Close()
	transport := pinnedLocalTransport(t, server)
	var sockets []*Socket
	for _, route := range []Route{Rendezvous, Relay} {
		socket, err := l.dial(context.Background(), route, transport)
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		sockets = append(sockets, socket)
		for _, payload := range [][]byte{{}, {0, 127, 128, 255}} {
			if err := socket.Write(payload); err != nil {
				t.Fatal("socket closed after successful handshake", err)
			}
			data, err := socket.Read()
			if err != nil || !bytes.Equal(data, payload) {
				t.Fatal("binary payload changed", err)
			}
		}
	}
	l.Close()
	l.Close()
	for _, socket := range sockets {
		if socket.Write([]byte("after close")) == nil {
			t.Fatal("closed lease still writes")
		}
		select {
		case <-socket.lifetime.Done():
		case <-time.After(time.Second):
			t.Fatal("lease close did not cancel socket")
		}
	}
	if requests.Load() != 2 {
		t.Fatal("unexpected request count")
	}
}

func TestSocketExpiryClosesBlockedReadAndRedirectIsNeverFollowed(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		var requests atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if redirect {
				http.Redirect(w, r, origin+"/unapproved", http.StatusTemporaryRedirect)
				return
			}
			connection, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer connection.CloseNow()
			connection.Read(r.Context())
		}))
		l := socketLease(300 * time.Millisecond)
		socket, err := l.dial(context.Background(), Rendezvous, pinnedLocalTransport(t, server))
		if redirect {
			if err != ErrRejected || socket != nil || requests.Load() != 1 {
				t.Fatal("redirect followed or exposed")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() { _, err := socket.Read(); finished <- err }()
			select {
			case err := <-finished:
				if err != ErrRejected {
					t.Fatal("expired read accepted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("expiry left blocked read open")
			}
			socket.Close()
		}
		l.Close()
		server.Close()
	}
}

func TestSocketRejectsUnknownRouteAndUntrustedTLS(t *testing.T) {
	l := socketLease(time.Minute)
	defer l.Close()
	if _, err := l.Dial(context.Background(), Route(255)); err != ErrRejected {
		t.Fatal("unknown route accepted")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted TLS reached HTTP handler")
	}))
	defer server.Close()
	transport := pinnedLocalTransport(t, server)
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if _, err := l.dial(context.Background(), Relay, transport); err != ErrRejected {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestSocketRejectsTextAndOversizeIncomingMessages(t *testing.T) {
	for _, message := range []struct {
		typeID websocket.MessageType
		data   []byte
	}{{websocket.MessageText, []byte("unexpected")}, {websocket.MessageBinary, make([]byte, maxMessage+1)}} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			connection, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer connection.CloseNow()
			connection.Write(r.Context(), message.typeID, message.data)
			connection.Read(r.Context())
		}))
		l := socketLease(time.Minute)
		socket, err := l.dial(context.Background(), Rendezvous, pinnedLocalTransport(t, server))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := socket.Read(); err != ErrRejected {
			t.Fatal("unexpected message accepted")
		}
		socket.Close()
		l.Close()
		server.Close()
	}
}
