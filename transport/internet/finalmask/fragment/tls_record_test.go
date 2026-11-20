package fragment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func clientHelloRecord(payload, tail []byte) []byte {
	wire := []byte{22, 3, 1, byte(len(payload) >> 8), byte(len(payload))}
	wire = append(wire, payload...)
	return append(wire, tail...)
}

func readExactly(conn net.Conn, size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := io.ReadFull(conn, data)
	return data, err
}

func clientHelloWithSNI(host string) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)

	otherExtension := []byte{0, 16, 0, 1, 0}
	serverName := []byte{0}
	serverName = append(serverName, byte(len(host)>>8), byte(len(host)))
	serverName = append(serverName, []byte(host)...)
	sniData := []byte{byte(len(serverName) >> 8), byte(len(serverName))}
	sniData = append(sniData, serverName...)
	sniExtension := []byte{0, 0, byte(len(sniData) >> 8), byte(len(sniData))}
	sniExtension = append(sniExtension, sniData...)

	trailingExtension := []byte{0x12, 0x34, 0, 1, 0}
	extensions := append(append(otherExtension, sniExtension...), trailingExtension...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(handshake, body...)
}

func TestTLSClientHelloSNISplitOffsets(t *testing.T) {
	handshake := clientHelloWithSNI("example.com")
	sniExtensionStart := 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 5
	hostStart := sniExtensionStart + 4 + 2 + 1 + 2

	sniExtensionEnd := sniExtensionStart + 20
	if got := tlsClientHelloSNISplit(handshake, 1); got != sniExtensionStart {
		t.Fatalf("before-extension split = %d, want %d", got, sniExtensionStart)
	}
	if got := tlsClientHelloSNISplit(handshake, 2); got != sniExtensionStart+2 {
		t.Fatalf("extension-header split = %d, want %d", got, sniExtensionStart+2)
	}
	if got := tlsClientHelloSNISplit(handshake, 3); got != hostStart+len("example.com")/2 {
		t.Fatalf("mid-hostname split = %d, want %d", got, hostStart+len("example.com")/2)
	}
	if got := tlsClientHelloSNISplit(handshake, 4); got != sniExtensionEnd {
		t.Fatalf("after-extension split = %d, want %d", got, sniExtensionEnd)
	}
	if got := tlsClientHelloSNISplit(handshake, 99); got != -1 {
		t.Fatalf("unknown mode split = %d, want -1", got)
	}
}

func TestTLSClientHelloSNISplitRejectsMalformedInput(t *testing.T) {
	for _, payload := range [][]byte{
		nil,
		{1, 0, 0, 1},
		{2, 0, 0, 0},
	} {
		if got := tlsClientHelloSNISplit(payload, 1); got != -1 {
			t.Fatalf("malformed payload split = %d, want -1", got)
		}
	}
}

func TestTLSRecordSNISplitAtExtensionHeaderAndAfterExtensionPreservesHandshake(t *testing.T) {
	handshake := clientHelloWithSNI("example.com")
	input := clientHelloRecord(handshake, []byte{20, 3, 3, 0, 1, 1})

	for _, mode := range []int64{2, 4} {
		clientPipe, serverPipe := net.Pipe()
		conn, err := NewConnClient(&Config{PacketsFrom: -3, PacketsTo: mode}, clientPipe, false)
		if err != nil {
			t.Fatal(err)
		}
		type readResult struct {
			data []byte
			err  error
		}
		read := make(chan readResult, 1)
		go func() {
			data, err := readExactly(serverPipe, len(input)+5)
			read <- readResult{data: data, err: err}
		}()

		if n, err := conn.Write(input); err != nil || n != len(input) {
			t.Fatalf("mode %d: write n=%d err=%v", mode, n, err)
		}
		result := <-read
		if result.err != nil {
			t.Fatalf("mode %d: read: %v", mode, result.err)
		}
		wire := result.data
		firstLen := int(binary.BigEndian.Uint16(wire[3:5]))
		secondOffset := 5 + firstLen
		secondLen := int(binary.BigEndian.Uint16(wire[secondOffset+3 : secondOffset+5]))
		secondStart := secondOffset + 5
		reassembled := append(append([]byte{}, wire[5:secondOffset]...), wire[secondStart:secondStart+secondLen]...)
		if !bytes.Equal(reassembled, handshake) {
			t.Fatalf("mode %d changed the ClientHello handshake bytes", mode)
		}
		_ = conn.Close()
		_ = serverPipe.Close()
	}
}

func TestTLSRecordSNIFragmentPreservesHandshakeBytes(t *testing.T) {
	handshake := clientHelloWithSNI("example.com")
	input := clientHelloRecord(handshake, []byte{20, 3, 3, 0, 1, 1})
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	conn, err := NewConnClient(&Config{PacketsFrom: -3, PacketsTo: 3}, clientPipe, false)
	if err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		data, err := readExactly(serverPipe, len(input)+5)
		read <- readResult{data: data, err: err}
	}()
	n, err := conn.Write(input)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(input) {
		t.Fatalf("Write returned %d, want %d", n, len(input))
	}
	result := <-read
	if result.err != nil {
		t.Fatal(result.err)
	}
	wire := result.data
	firstLen := int(binary.BigEndian.Uint16(wire[3:5]))
	secondOffset := 5 + firstLen
	if wire[0] != 22 || wire[secondOffset] != 22 {
		t.Fatal("SNI-aware split did not produce two TLS handshake records")
	}
	secondLen := int(binary.BigEndian.Uint16(wire[secondOffset+3 : secondOffset+5]))
	secondStart := secondOffset + 5
	reassembled := append(append([]byte{}, wire[5:secondOffset]...), wire[secondStart:secondStart+secondLen]...)
	if !bytes.Equal(reassembled, handshake) {
		t.Fatal("SNI-aware split changed the ClientHello handshake bytes")
	}
	if !bytes.Equal(wire[secondStart+secondLen:], input[len(input)-6:]) {
		t.Fatal("bytes after the ClientHello record changed")
	}
	if conn.(interface{ Splice() bool }).Splice() {
		t.Fatal("SNI-aware TLS record mode must not be unwrapped for splice")
	}
}

func TestTLSRecordFragmentPreservesHandshakeBytes(t *testing.T) {
	handshake := []byte{1, 0, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7}
	tail := []byte{20, 3, 3, 0, 1, 1}
	input := clientHelloRecord(handshake, tail)
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	conn, err := NewConnClient(&Config{PacketsFrom: -1, PacketsTo: 2}, clientPipe, false)
	if err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		data, err := readExactly(serverPipe, len(input)+5)
		read <- readResult{data: data, err: err}
	}()
	n, err := conn.Write(input)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(input) {
		t.Fatalf("Write returned %d, want %d", n, len(input))
	}
	result := <-read
	if result.err != nil {
		t.Fatal(result.err)
	}
	wire := result.data
	firstLen := int(wire[3])<<8 | int(wire[4])
	if wire[0] != 22 || firstLen != 2 {
		t.Fatalf("unexpected first TLS record: %x", wire[:7])
	}
	secondOffset := 5 + firstLen
	if wire[secondOffset] != 22 {
		t.Fatalf("second record missing at offset %d: %x", secondOffset, wire)
	}
	secondLen := int(wire[secondOffset+3])<<8 | int(wire[secondOffset+4])
	secondStart := secondOffset + 5
	reassembled := append(append([]byte{}, wire[5:secondOffset]...), wire[secondStart:secondStart+secondLen]...)
	if !bytes.Equal(reassembled, handshake) {
		t.Fatal("fragmented records did not preserve the original handshake bytes")
	}
	if !bytes.Equal(wire[secondStart+secondLen:], tail) {
		t.Fatal("bytes following the first TLS record were changed")
	}
	if conn.(interface{ Splice() bool }).Splice() {
		t.Fatal("TLS record mode must not be unwrapped for splice")
	}
}

func TestTLSRecordVersionOverrideChangesOnlyRecordHeader(t *testing.T) {
	handshake := []byte{1, 0, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7}
	tail := []byte{20, 3, 3, 0, 1, 1}
	input := clientHelloRecord(handshake, tail)
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	conn, err := NewConnClient(&Config{PacketsFrom: -2, PacketsTo: 0x0303}, clientPipe, false)
	if err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		data, err := readExactly(serverPipe, len(input))
		read <- readResult{data: data, err: err}
	}()
	n, err := conn.Write(input)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(input) {
		t.Fatalf("Write returned %d, want %d", n, len(input))
	}
	result := <-read
	if result.err != nil {
		t.Fatal(result.err)
	}
	want := append([]byte(nil), input...)
	want[1], want[2] = 3, 3
	if !bytes.Equal(result.data, want) {
		t.Fatalf("record version override changed unexpected bytes\\n got: %x\\nwant: %x", result.data, want)
	}
	if conn.(interface{ Splice() bool }).Splice() {
		t.Fatal("TLS record version mode must not be unwrapped for splice")
	}
}

func TestTLSRecordVersionOverrideBuffersSplitApplicationWrites(t *testing.T) {
	handshake := []byte{1, 0, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7}
	input := clientHelloRecord(handshake, []byte{20, 3, 3, 0, 1, 1})
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	conn, err := NewConnClient(&Config{PacketsFrom: -2, PacketsTo: 0x0303}, clientPipe, false)
	if err != nil {
		t.Fatal(err)
	}

	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		data, err := readExactly(serverPipe, len(input))
		read <- readResult{data: data, err: err}
	}()

	if n, err := conn.Write(input[:2]); err != nil || n != 2 {
		t.Fatalf("first partial write: n=%d err=%v", n, err)
	}
	if n, err := conn.Write(input[2:]); err != nil || n != len(input)-2 {
		t.Fatalf("second partial write: n=%d err=%v", n, err)
	}

	result := <-read
	if result.err != nil {
		t.Fatal(result.err)
	}
	want := append([]byte(nil), input...)
	want[1], want[2] = 3, 3
	if !bytes.Equal(result.data, want) {
		t.Fatalf("buffered record version override changed unexpected bytes\n got: %x\nwant: %x", result.data, want)
	}
}

func TestTLSRecordSNIFragmentBuffersSplitApplicationWrites(t *testing.T) {
	handshake := clientHelloWithSNI("example.com")
	input := clientHelloRecord(handshake, []byte{20, 3, 3, 0, 1, 1})
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	conn, err := NewConnClient(&Config{PacketsFrom: -3, PacketsTo: 3}, clientPipe, false)
	if err != nil {
		t.Fatal(err)
	}

	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		data, err := readExactly(serverPipe, len(input)+5)
		read <- readResult{data: data, err: err}
	}()

	if n, err := conn.Write(input[:3]); err != nil || n != 3 {
		t.Fatalf("first partial write: n=%d err=%v", n, err)
	}
	if n, err := conn.Write(input[3:]); err != nil || n != len(input)-3 {
		t.Fatalf("second partial write: n=%d err=%v", n, err)
	}

	result := <-read
	if result.err != nil {
		t.Fatal(result.err)
	}
	wire := result.data
	firstLen := int(binary.BigEndian.Uint16(wire[3:5]))
	secondOffset := 5 + firstLen
	secondLen := int(binary.BigEndian.Uint16(wire[secondOffset+3 : secondOffset+5]))
	secondStart := secondOffset + 5
	reassembled := append(append([]byte{}, wire[5:secondOffset]...), wire[secondStart:secondStart+secondLen]...)
	if !bytes.Equal(reassembled, handshake) {
		t.Fatal("buffered SNI fragmentation changed the ClientHello handshake bytes")
	}
}

func TestTLSRecordIncompleteHeaderIsFlushedOnClose(t *testing.T) {
	pending := []byte{22, 3}
	clientPipe, serverPipe := net.Pipe()
	defer serverPipe.Close()

	conn, err := NewConnClient(&Config{PacketsFrom: -2, PacketsTo: 0x0303}, clientPipe, false)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(pending); err != nil || n != len(pending) {
		t.Fatalf("partial write: n=%d err=%v", n, err)
	}

	read := make(chan []byte, 1)
	go func() {
		data, _ := readExactly(serverPipe, len(pending))
		read <- data
	}()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-read; !bytes.Equal(got, pending) {
		t.Fatalf("incomplete TLS prefix = %x, want %x", got, pending)
	}
}

func TestTLSRecordVersionOverrideIsClientOnly(t *testing.T) {
	input := clientHelloRecord([]byte{1, 0, 0, 4, 0, 0, 0, 0}, nil)
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	conn, err := NewConnServer(&Config{PacketsFrom: -2, PacketsTo: 0x0303}, clientPipe, true)
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan []byte, 1)
	go func() {
		data, _ := readExactly(serverPipe, len(input))
		read <- data
	}()
	if n, err := conn.Write(input); err != nil || n != len(input) {
		t.Fatalf("server-side write: n=%d err=%v", n, err)
	}
	if got := <-read; !bytes.Equal(got, input) {
		t.Fatal("server-side record version must remain unchanged")
	}
}

func TestTLSRecordFragmentBuffersIncompleteRecordUntilClose(t *testing.T) {
	input := []byte{22, 3, 1, 0, 20, 1, 0}
	clientPipe, serverPipe := net.Pipe()
	defer serverPipe.Close()

	conn, err := NewConnClient(&Config{PacketsFrom: -1, PacketsTo: 2}, clientPipe, false)
	if err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		data, err := readExactly(serverPipe, len(input))
		read <- readResult{data: data, err: err}
	}()

	if n, err := conn.Write(input); err != nil || n != len(input) {
		t.Fatalf("incomplete record write: n=%d err=%v", n, err)
	}
	// The declared record is incomplete, so it is flushed unchanged only when
	// the caller closes the connection instead of being transformed or lost.
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	result := <-read
	if result.err != nil {
		t.Fatal(result.err)
	}
	if !bytes.Equal(result.data, input) {
		t.Fatal("incomplete ClientHello record must be flushed unchanged on close")
	}
}

func TestTLSRecordFragmentIsClientOnly(t *testing.T) {
	handshake := []byte{1, 0, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7}
	input := clientHelloRecord(handshake, nil)
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	conn, err := NewConnServer(&Config{PacketsFrom: -1, PacketsTo: 2}, clientPipe, true)
	if err != nil {
		t.Fatal(err)
	}
	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		data, err := readExactly(serverPipe, len(input))
		read <- readResult{data: data, err: err}
	}()
	if n, err := conn.Write(input); err != nil || n != len(input) {
		t.Fatalf("server-side write: n=%d err=%v", n, err)
	}
	result := <-read
	if result.err != nil {
		t.Fatal(result.err)
	}
	if !bytes.Equal(result.data, input) {
		t.Fatal("server-side writes must remain unchanged")
	}
}

func TestTLSRecordFragmentCompletesTLSHandshake(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	parsedCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsedCert)

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()
	if err := clientPipe.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := serverPipe.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	maskedClient, err := NewConnClient(&Config{PacketsFrom: -1, PacketsTo: 2}, clientPipe, false)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(maskedClient, &tls.Config{
		ServerName: "example.test",
		RootCAs:    roots,
	})
	server := tls.Server(serverPipe, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	})
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- server.Handshake()
	}()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server handshake failed: %v", err)
	}
}
