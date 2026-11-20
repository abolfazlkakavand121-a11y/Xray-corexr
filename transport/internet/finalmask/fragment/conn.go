package fragment

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/crypto"
)

type fragmentConn struct {
	net.Conn
	config *Config
	count  uint64

	server bool

	tlsRecordMu      sync.Mutex
	tlsRecordDone    bool
	tlsRecordPending []byte
}

func NewConnClient(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	conn := &fragmentConn{
		Conn:   raw,
		config: c,

		server: server,
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	return NewConnClient(c, raw, server)
}

func (c *fragmentConn) TcpMaskConn() {}

func (c *fragmentConn) RawConn() net.Conn {
	return c.Conn
}

func (c *fragmentConn) Splice() bool {
	if c.server || c.config.PacketsFrom == -1 || c.config.PacketsFrom == -2 || c.config.PacketsFrom == -3 {
		return false
	}
	return true
}

// lengthForSegment returns the length range (min, max) for the given segment index (0-based).
// Clamps to the last entry when the index exceeds the list length.
func (c *fragmentConn) lengthForSegment(segIdx int) (int64, int64) {
	if segIdx >= len(c.config.LengthsMin) {
		segIdx = len(c.config.LengthsMin) - 1
	}
	return c.config.LengthsMin[segIdx], c.config.LengthsMax[segIdx]
}

// delayForSegment returns the delay range (min, max) for the given segment index (0-based).
// Clamps to the last entry when the index exceeds the list length.
func (c *fragmentConn) delayForSegment(segIdx int) (int64, int64) {
	if segIdx >= len(c.config.DelaysMin) {
		segIdx = len(c.config.DelaysMin) - 1
	}
	return c.config.DelaysMin[segIdx], c.config.DelaysMax[segIdx]
}

// mergeTlsHelloSegments returns true only when delays has exactly one zero entry.
func (c *fragmentConn) mergeTlsHelloSegments() bool {
	return len(c.config.DelaysMax) == 1 && c.config.DelaysMax[0] == 0
}

// tlsRecordFirstMessageReady reports whether p is safe to inspect as a complete
// first TLS record. A short record header or payload is buffered across writes;
// invalid, oversized, and non-TLS prefixes are passed through unchanged.
func tlsRecordFirstMessageReady(p []byte) bool {
	if len(p) == 0 || p[0] != 22 {
		return true
	}
	if len(p) < 5 {
		return false
	}
	if p[1] != 3 || p[2] > 4 {
		return true
	}
	recordLen := int(binary.BigEndian.Uint16(p[3:5]))
	const maxTLSRecordSize = (1 << 14) + 2048
	if recordLen < 4 || recordLen > maxTLSRecordSize {
		return true
	}
	return len(p) >= 5+recordLen
}

func (c *fragmentConn) writeTLSRecordVersion(p []byte) (int, error) {
	// Change only the legacy_version bytes of the first TLS ClientHello record.
	// The handshake payload and transcript are left byte-for-byte unchanged.
	if len(p) < 9 || p[0] != 22 {
		return writeUnmodified(c.Conn, p)
	}
	recordLen := int(binary.BigEndian.Uint16(p[3:5]))
	if recordLen < 4 || 5+recordLen > len(p) || p[5] != 1 {
		return writeUnmodified(c.Conn, p)
	}
	handshakeLen := int(p[6])<<16 | int(p[7])<<8 | int(p[8])
	if handshakeLen+4 > recordLen {
		return writeUnmodified(c.Conn, p)
	}
	version := uint16(c.config.PacketsTo)
	if version < 0x0301 || version > 0x0303 {
		return 0, io.ErrUnexpectedEOF
	}
	wire := append([]byte(nil), p...)
	wire[1] = byte(version >> 8)
	wire[2] = byte(version)
	if err := writeFull(c.Conn, wire); err != nil {
		return 0, err
	}
	return len(p), nil
}

// tlsClientHelloSNISplit returns a split offset within the handshake payload.
// Mode 1 splits before the SNI extension, mode 2 inside its two-byte length
// header, mode 3 in the first host_name value, and mode 4 after the extension.
// Invalid or absent SNI returns -1.
func tlsClientHelloSNISplit(payload []byte, mode int64) int {
	if len(payload) < 4 || payload[0] != 1 {
		return -1
	}
	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	end := 4 + handshakeLen
	if end > len(payload) {
		return -1
	}
	pos := 4
	if pos+34 > end {
		return -1
	}
	pos += 34
	if pos+1 > end {
		return -1
	}
	sessionIDLen := int(payload[pos])
	pos++
	if pos+sessionIDLen+2 > end {
		return -1
	}
	pos += sessionIDLen
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	if pos+cipherSuitesLen+1 > end {
		return -1
	}
	pos += cipherSuitesLen
	compressionMethodsLen := int(payload[pos])
	pos++
	if pos+compressionMethodsLen+2 > end {
		return -1
	}
	pos += compressionMethodsLen
	extensionsLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > end {
		return -1
	}
	for pos+4 <= extensionsEnd {
		extensionStart := pos
		extensionType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extensionLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4
		if pos+extensionLen > extensionsEnd {
			return -1
		}
		if extensionType == 0 {
			extensionEnd := pos + extensionLen
			if pos+5 > extensionEnd {
				return -1
			}
			serverNameListLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
			listStart := pos + 2
			listEnd := listStart + serverNameListLen
			if listEnd > extensionEnd || listStart+3 > listEnd {
				return -1
			}
			nameType := payload[listStart]
			nameLen := int(binary.BigEndian.Uint16(payload[listStart+1 : listStart+3]))
			hostStart := listStart + 3
			if nameType != 0 || hostStart+nameLen > listEnd || nameLen < 2 {
				return -1
			}
			switch mode {
			case 1:
				return extensionStart
			case 2:
				return extensionStart + 2
			case 3:
				return hostStart + nameLen/2
			case 4:
				return extensionEnd
			default:
				return -1
			}
		}
		pos += extensionLen
	}
	return -1
}

func (c *fragmentConn) writeTLSRecordSNIFragment(p []byte) (int, error) {
	if len(p) < 9 || p[0] != 22 {
		return writeUnmodified(c.Conn, p)
	}
	recordLen := int(binary.BigEndian.Uint16(p[3:5]))
	recordEnd := 5 + recordLen
	if recordLen < 4 || recordEnd > len(p) {
		return writeUnmodified(c.Conn, p)
	}
	payload := p[5:recordEnd]
	splitAt := tlsClientHelloSNISplit(payload, c.config.PacketsTo)
	if splitAt <= 0 || splitAt >= len(payload) {
		return writeUnmodified(c.Conn, p)
	}
	wire := make([]byte, 0, len(p)+5)
	wire = appendTLSRecord(wire, p[:3], payload[:splitAt])
	wire = appendTLSRecord(wire, p[:3], payload[splitAt:])
	wire = append(wire, p[recordEnd:]...)
	if err := writeFull(c.Conn, wire); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *fragmentConn) writeTLSRecordFragment(p []byte) (int, error) {
	// Fail open for non-TLS, incomplete, or non-ClientHello first writes.
	if len(p) < 9 || p[0] != 22 {
		return writeUnmodified(c.Conn, p)
	}
	recordLen := int(binary.BigEndian.Uint16(p[3:5]))
	recordEnd := 5 + recordLen
	if recordLen < 4 || recordEnd > len(p) {
		return writeUnmodified(c.Conn, p)
	}
	payload := p[5:recordEnd]
	if payload[0] != 1 {
		return writeUnmodified(c.Conn, p)
	}
	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if handshakeLen+4 > len(payload) {
		return writeUnmodified(c.Conn, p)
	}
	splitAt := int(c.config.PacketsTo)
	if splitAt <= 0 || splitAt >= len(payload) {
		return writeUnmodified(c.Conn, p)
	}

	// TLS permits a handshake message to span multiple records. Reusing the
	// original record version and preserving every handshake byte keeps the
	// TLS transcript unchanged; only record boundaries differ.
	wire := make([]byte, 0, len(p)+5)
	wire = appendTLSRecord(wire, p[:3], payload[:splitAt])
	wire = appendTLSRecord(wire, p[:3], payload[splitAt:])
	wire = append(wire, p[recordEnd:]...)

	if err := writeFull(c.Conn, wire); err != nil {
		return 0, err
	}
	return len(p), nil
}

func writeUnmodified(conn net.Conn, data []byte) (int, error) {
	if err := writeFull(conn, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

func appendTLSRecord(dst, header, payload []byte) []byte {
	dst = append(dst, header[:3]...)
	dst = append(dst, byte(len(payload)>>8), byte(len(payload)))
	return append(dst, payload...)
}

func writeFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (c *fragmentConn) Close() error {
	c.tlsRecordMu.Lock()
	pending := c.tlsRecordPending
	c.tlsRecordPending = nil
	c.tlsRecordDone = true
	var writeErr error
	if len(pending) > 0 {
		writeErr = writeFull(c.Conn, pending)
	}
	c.tlsRecordMu.Unlock()

	closeErr := c.Conn.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func (c *fragmentConn) Write(p []byte) (n int, err error) {
	// Serialize first-flight TLS transforms so concurrent writes cannot overtake them.
	if c.config.PacketsFrom == -1 || c.config.PacketsFrom == -2 || c.config.PacketsFrom == -3 {
		if c.server {
			return c.Conn.Write(p)
		}
		c.tlsRecordMu.Lock()
		defer c.tlsRecordMu.Unlock()

		if c.tlsRecordDone || len(p) == 0 {
			return c.Conn.Write(p)
		}

		// Some TLS clients write the record header and payload in separate calls.
		// Hold at most one bounded TLS record until its declared payload arrives,
		// then transform it once. Close flushes an unfinished prefix unchanged.
		firstWrite := make([]byte, 0, len(c.tlsRecordPending)+len(p))
		firstWrite = append(firstWrite, c.tlsRecordPending...)
		firstWrite = append(firstWrite, p...)
		if !tlsRecordFirstMessageReady(firstWrite) {
			c.tlsRecordPending = firstWrite
			return len(p), nil
		}

		c.tlsRecordDone = true
		c.tlsRecordPending = nil
		switch c.config.PacketsFrom {
		case -1:
			_, err = c.writeTLSRecordFragment(firstWrite)
		case -2:
			_, err = c.writeTLSRecordVersion(firstWrite)
		case -3:
			_, err = c.writeTLSRecordSNIFragment(firstWrite)
		}
		if err != nil {
			return 0, err
		}
		// The buffered prefix was acknowledged by the earlier Write call. Report
		// only the bytes accepted from this call, not the aggregate first record.
		return len(p), nil
	}

	c.count++

	if c.config.PacketsFrom == 0 && c.config.PacketsTo == 1 {
		if c.count != 1 || len(p) <= 5 || p[0] != 22 {
			return c.Conn.Write(p)
		}
		recordLen := 5 + ((int(p[3]) << 8) | int(p[4]))
		if len(p) < recordLen {
			return c.Conn.Write(p)
		}
		data := p[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		mergeHello := c.mergeTlsHelloSegments()
		maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
		var splitNum int64
		for from := 0; ; {
			lengthMin, lengthMax := c.lengthForSegment(int(splitNum))
			to := from + int(crypto.RandBetween(lengthMin, lengthMax))
			if to > len(data) || (maxSplit > 0 && splitNum+1 >= maxSplit) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], p)
			copy(buff[5:], data[from:to])
			from = to
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)
			if mergeHello {
				hello = append(hello, buff[:5+l]...)
			} else {
				delayMin, delayMax := c.delayForSegment(int(splitNum))
				_, err := c.Conn.Write(buff[:5+l])
				if delayMax > 0 {
					time.Sleep(time.Duration(crypto.RandBetween(delayMin, delayMax)) * time.Millisecond)
				}
				if err != nil {
					return 0, err
				}
			}
			splitNum++
			if from == len(data) {
				if len(hello) > 0 {
					_, err := c.Conn.Write(hello)
					if err != nil {
						return 0, err
					}
				}
				if len(p) > recordLen {
					n, err := c.Conn.Write(p[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(p), nil
			}
		}
	}

	if c.config.PacketsFrom != 0 && (c.count < uint64(c.config.PacketsFrom) || c.count > uint64(c.config.PacketsTo)) {
		return c.Conn.Write(p)
	}
	maxSplit := crypto.RandBetween(c.config.MaxSplitMin, c.config.MaxSplitMax)
	var splitNum int64
	for from := 0; ; {
		lengthMin, lengthMax := c.lengthForSegment(int(splitNum))
		to := from + int(crypto.RandBetween(lengthMin, lengthMax))
		if to > len(p) || (maxSplit > 0 && splitNum+1 >= maxSplit) {
			to = len(p)
		}
		n, err := c.Conn.Write(p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		delayMin, delayMax := c.delayForSegment(int(splitNum))
		if delayMax > 0 {
			time.Sleep(time.Duration(crypto.RandBetween(delayMin, delayMax)) * time.Millisecond)
		}
		splitNum++
		if from >= len(p) {
			return from, nil
		}
	}
}
