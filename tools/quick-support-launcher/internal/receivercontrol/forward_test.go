package receivercontrol

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFramingAndSourceClosureAreTerminal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	writer, reader := net.Pipe()
	defer reader.Close()
	source := make(chan string, 2)
	expected := []string{"synthetic-control", strings.Repeat("x", 16384)}
	for _, token := range expected {
		source <- token
	}
	done := make(chan error, 1)
	go func() { done <- Forward(ctx, writer, source) }()
	var header [4]byte
	for _, token := range expected {
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			t.Fatal(err)
		}
		length := binary.BigEndian.Uint32(header[:])
		if length != uint32(len(token)) {
			t.Fatal("wrong bounded frame length", length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil || string(payload) != token {
			t.Fatal("wrong control frame", err)
		}
	}
	close(source)
	if err := <-done; err != ErrStopped {
		t.Fatal("source EOF accepted", err)
	}
	if n, err := reader.Read(header[:]); n != 0 || err == nil {
		t.Fatal("control connection retained")
	}
}

func TestMalformedControlsNeverWriteAHeader(t *testing.T) {
	for _, test := range []struct{ name, token string }{{"empty", ""}, {"oversized", strings.Repeat("x", 16385)}, {"invalid-utf8", string([]byte{255})}} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			writer, reader := net.Pipe()
			defer reader.Close()
			source := make(chan string, 1)
			source <- test.token
			done := make(chan error, 1)
			go func() { done <- Forward(ctx, writer, source) }()
			var header [4]byte
			if n, err := reader.Read(header[:]); n != 0 || err == nil {
				t.Fatal("malformed control wrote bytes")
			}
			if err := <-done; err != ErrStopped {
				t.Fatal(err)
			}
		})
	}
}

func TestCancellationUnblocksAPartialControlWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	writer, reader := net.Pipe()
	defer reader.Close()
	deadline, _ := ctx.Deadline()
	if err := reader.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	source := make(chan string, 1)
	source <- "synthetic-control"
	done := make(chan error, 1)
	go func() { done <- Forward(ctx, writer, source) }()
	var partial [2]byte
	if _, err := io.ReadFull(reader, partial[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != ErrStopped {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled partial writer retained")
	}
	if n, err := reader.Read(partial[:]); n != 0 || err == nil {
		t.Fatal("cancelled frame resumed")
	}
}

func TestUnboundedControlSourceClosesWithoutWriting(t *testing.T) {
	writer, reader := net.Pipe()
	defer reader.Close()
	source := make(chan string, 1)
	source <- "synthetic-control"
	if err := Forward(context.Background(), writer, source); err != ErrStopped {
		t.Fatal(err)
	}
	var header [4]byte
	if n, err := reader.Read(header[:]); n != 0 || err == nil {
		t.Fatal("unbounded source retained")
	}
}
