package fragment

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type captureConn struct {
	bytes.Buffer
	closed bool
}

func (c *captureConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *captureConn) Close() error { c.closed = true; return nil }
func (c *captureConn) LocalAddr() net.Addr { return testAddr("local") }
func (c *captureConn) RemoteAddr() net.Addr { return testAddr("remote") }
func (c *captureConn) SetDeadline(time.Time) error { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string
func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string { return string(a) }

func clientHelloRecord(payload []byte, tail []byte) []byte {
	wire := []byte{22, 3, 1, byte(len(payload) >> 8), byte(len(payload))}
	wire = append(wire, payload...)
	return append(wire, tail...)
}

func TestTLSRecordFragmentPreservesHandshakeBytes(t *testing.T) {
	handshake := []byte{1, 0, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7}
	tail := []byte{20, 3, 3, 0, 1, 1}
	input := clientHelloRecord(handshake, tail)
	raw := new(captureConn)
	conn, err := NewConnClient(&Config{PacketsFrom: -1, PacketsTo: 2}, raw, false)
	if err != nil { t.Fatal(err) }

	n, err := conn.Write(input)
	if err != nil { t.Fatal(err) }
	if n != len(input) { t.Fatalf("Write returned %d, want %d", n, len(input)) }

	wire := raw.Bytes()
	if len(wire) < 10 || wire[0] != 22 || wire[5] != 22 {
		t.Fatalf("expected two handshake records, got %x", wire)
	}
	firstLen := int(wire[3])<<8 | int(wire[4])
	if firstLen != 2 { t.Fatalf("first record payload length = %d, want 2", firstLen) }
	secondOffset := 5 + firstLen
	secondLen := int(wire[secondOffset+3])<<8 | int(wire[secondOffset+4])
	secondStart := secondOffset + 5
	if !bytes.Equal(append(append([]byte{}, wire[5:secondOffset]...), wire[secondStart:secondStart+secondLen]...), handshake) {
		t.Fatal("fragmented records did not preserve the original handshake bytes")
	}
	if !bytes.Equal(wire[secondStart+secondLen:], tail) {
		t.Fatal("bytes following the first TLS record were changed")
	}
}

func TestTLSRecordFragmentFailsOpenForIncompleteRecord(t *testing.T) {
	input := []byte{22, 3, 1, 0, 20, 1, 0}
	raw := new(captureConn)
	conn, err := NewConnClient(&Config{PacketsFrom: -1, PacketsTo: 2}, raw, false)
	if err != nil { t.Fatal(err) }
	n, err := conn.Write(input)
	if err != nil { t.Fatal(err) }
	if n != len(input) || !bytes.Equal(raw.Bytes(), input) {
		t.Fatal("incomplete ClientHello must pass through unchanged")
	}
}

func TestTLSRecordFragmentOnlyChangesFirstWrite(t *testing.T) {
	handshake := []byte{1, 0, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7}
	input := clientHelloRecord(handshake, nil)
	raw := new(captureConn)
	conn, err := NewConnClient(&Config{PacketsFrom: -1, PacketsTo: 2}, raw, false)
	if err != nil { t.Fatal(err) }
	if _, err := conn.Write(input); err != nil { t.Fatal(err) }
	second := []byte("application data")
	if n, err := conn.Write(second); err != nil || n != len(second) { t.Fatalf("second write: n=%d err=%v", n, err) }
	if !bytes.HasSuffix(raw.Bytes(), second) { t.Fatal("subsequent application data was modified") }
}

func TestTLSRecordFragmentIsClientOnly(t *testing.T) {
	handshake := []byte{1, 0, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7}
	input := clientHelloRecord(handshake, nil)
	raw := new(captureConn)
	conn, err := NewConnServer(&Config{PacketsFrom: -1, PacketsTo: 2}, raw, true)
	if err != nil { t.Fatal(err) }
	if _, err := conn.Write(input); err != nil { t.Fatal(err) }
	if !bytes.Equal(raw.Bytes(), input) { t.Fatal("server-side writes must remain unchanged") }
}

var _ = errors.Is
