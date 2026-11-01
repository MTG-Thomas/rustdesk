package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/iotest"
	"time"

	"github.com/coder/websocket"
)

// These are the wire headers emitted by hbb_common's BytesCodec, rather than
// round-trip assertions between two copies of the helper's own implementation.
func TestRustDeskWireHeadersAndFragmentedPrivateStream(t *testing.T) {
	for _, fixture := range []struct {
		length int
		header []byte
	}{
		{0, []byte{0}}, {63, []byte{0xfc}}, {64, []byte{1, 1}},
		{16383, []byte{0xfd, 0xff}}, {16384, []byte{2, 0, 1}},
		{4194303, []byte{0xfe, 0xff, 0xff}}, {4194304, []byte{3, 0, 0, 1}},
	} {
		payload := bytes.Repeat([]byte{0x81}, fixture.length)
		expected := append(append([]byte{}, fixture.header...), payload...)
		var actual bytes.Buffer
		if err := writeFrame(&actual, payload); err != nil || !bytes.Equal(actual.Bytes(), expected) {
			t.Fatalf("wrong RustDesk frame for %d bytes", fixture.length)
		}
		decoded, err := readFrame(iotest.OneByteReader(bytes.NewReader(expected)))
		if err != nil || !bytes.Equal(decoded, payload) {
			t.Fatalf("fragmented frame rejected for %d bytes", fixture.length)
		}
	}
	for _, frame := range [][]byte{{1}, {8, 0}, {7, 0, 0, 1}} {
		if _, err := readFrame(bytes.NewReader(frame)); err != ErrRejected {
			t.Fatal("truncated or oversized private frame accepted")
		}
	}
}

func TestPrivateStreamBridgeCarriesExactFramesAndTeardownUnblocksBothDirections(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			connection, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer connection.CloseNow()
			typeID, payload, err := connection.Read(r.Context())
			if err != nil || typeID != websocket.MessageBinary || !bytes.Equal(payload, []byte{0, 127, 128, 255}) {
				t.Error("WebSocket received framing bytes or changed payload")
				return
			}
			if connection.Write(r.Context(), websocket.MessageBinary, nil) != nil ||
				connection.Write(r.Context(), websocket.MessageBinary, payload) != nil {
				return
			}
			connection.Read(r.Context())
		}))
		defer server.Close()
		duration := time.Minute
		if expiry {
			duration = time.Second
		}
		l := socketLease(duration)
		defer l.Close()
		socket, err := l.dial(context.Background(), Relay, pinnedLocalTransport(t, server))
		if err != nil {
			t.Fatal(err)
		}
		helper, client := net.Pipe()
		defer client.Close()
		result := make(chan error, 1)
		go func() { result <- socket.Bridge(helper) }()
		if _, err := client.Write([]byte{16, 0, 127, 128, 255}); err != nil {
			t.Fatal(err)
		}
		var reply [6]byte
		if _, err := io.ReadFull(client, reply[:]); err != nil || !bytes.Equal(reply[:], []byte{0, 16, 0, 127, 128, 255}) {
			t.Fatal("private client did not receive empty and binary RustDesk frames", err)
		}
		if !expiry {
			l.Close()
		}
		select {
		case <-result:
		case <-time.After(2 * time.Second):
			t.Fatal("bridge copying goroutines survived lease close")
		}
		if _, err := client.Read(reply[:]); err == nil {
			t.Fatal("private stream survived lease close")
		}
	}
}

type shortFrameWriter struct{ bytes.Buffer }

func (w *shortFrameWriter) Write(part []byte) (int, error) {
	if len(part) > 2 {
		part = part[:2]
	}
	return w.Buffer.Write(part)
}

func TestPrivateFrameWriterHandlesShortWrites(t *testing.T) {
	var writer shortFrameWriter
	if err := writeFrame(&writer, []byte{0, 127, 128, 255}); err != nil ||
		!bytes.Equal(writer.Bytes(), []byte{16, 0, 127, 128, 255}) {
		t.Fatal("short writes changed frame")
	}
}

// The transport is deliberately opaque. A child must not treat its first frame
// as trusted launcher bootstrap or as authorization, even on authenticated IPC.
func TestUnsolicitedPeerFrameIsNotLauncherBootstrap(t *testing.T) {
	payload := []byte("synthetic-premature-control-not-a-signed-bootstrap")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		if connection.Write(r.Context(), websocket.MessageBinary, payload) != nil {
			return
		}
		connection.Read(r.Context())
	}))
	defer server.Close()
	lease := socketLease(time.Minute)
	defer lease.Close()
	socket, err := lease.dial(context.Background(), Relay, pinnedLocalTransport(t, server))
	if err != nil {
		t.Fatal(err)
	}
	helper, child := net.Pipe()
	defer child.Close()
	done := make(chan error, 1)
	go func() { done <- socket.Bridge(helper) }()
	if err := child.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	first, err := readFrame(child)
	if err != nil || !bytes.Equal(first, payload) {
		t.Fatal("transport inserted or authorized a bootstrap", err)
	}
	lease.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("untrusted pre-bootstrap transport did not tear down")
	}
}
