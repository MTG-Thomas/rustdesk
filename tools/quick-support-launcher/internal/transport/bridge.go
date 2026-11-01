package transport

import (
	"encoding/binary"
	"io"
	"net"
)

// Bridge consumes an already authenticated private IPC connection. It translates
// RustDesk BytesCodec frames, including empty heartbeats, to binary WebSocket
// messages. It creates no listener and grants no receiver permissions. Close on
// the supplied connection must unblock pending reads and writes, as net.Conn requires.
func (s *Socket) Bridge(pipe net.Conn) error {
	defer s.Close()
	if pipe == nil {
		return ErrRejected
	}
	defer pipe.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-s.lifetime.Done():
		case <-s.leaseDone:
		case <-finished:
			return
		}
		pipe.Close()
		s.Close()
	}()
	results := make(chan error, 2)
	go func() {
		for {
			message, err := readFrame(pipe)
			if err != nil {
				results <- err
				return
			}
			if err := s.Write(message); err != nil {
				results <- err
				return
			}
		}
	}()
	go func() {
		for {
			message, err := s.Read()
			if err == nil {
				err = writeFrame(pipe, message)
			}
			if err != nil {
				results <- err
				return
			}
		}
	}()
	err := <-results
	s.Close()
	pipe.Close()
	<-results // Teardown must not leave either copying goroutine behind.
	if err == io.EOF {
		return nil
	}
	return ErrRejected
}

func readFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:1]); err != nil {
		return nil, err
	}
	count := int(header[0]&3) + 1
	if _, err := io.ReadFull(reader, header[1:count]); err != nil {
		return nil, ErrRejected
	}
	length := binary.LittleEndian.Uint32(header[:]) >> 2
	if length > maxMessage {
		return nil, ErrRejected
	}
	message := make([]byte, int(length))
	if _, err := io.ReadFull(reader, message); err != nil {
		return nil, ErrRejected
	}
	return message, nil
}

func writeFrame(writer io.Writer, message []byte) error {
	if len(message) > maxMessage {
		return ErrRejected
	}
	count := 1
	switch {
	case len(message) > 0x3fffff:
		count = 4
	case len(message) > 0x3fff:
		count = 3
	case len(message) > 0x3f:
		count = 2
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(message))<<2|uint32(count-1))
	for _, part := range [][]byte{header[:count], message} {
		for len(part) > 0 {
			n, err := writer.Write(part)
			if err != nil || n <= 0 || n > len(part) {
				return ErrRejected
			}
			part = part[n:]
		}
	}
	return nil
}
