package fragment

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common/crypto"
)

type fragmentConn struct {
	net.Conn
	config *Config
	count  uint64

	server bool
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
	if c.server || c.config.PacketsFrom == -1 {
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

func (c *fragmentConn) writeTLSRecordFragment(p []byte) (int, error) {
	// Fail open for non-TLS, incomplete, or non-ClientHello first writes.
	if len(p) < 9 || p[0] != 22 {
		return c.Conn.Write(p)
	}
	recordLen := int(binary.BigEndian.Uint16(p[3:5]))
	recordEnd := 5 + recordLen
	if recordLen < 4 || recordEnd > len(p) {
		return c.Conn.Write(p)
	}
	payload := p[5:recordEnd]
	if payload[0] != 1 {
		return c.Conn.Write(p)
	}
	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if handshakeLen+4 > len(payload) {
		return c.Conn.Write(p)
	}
	splitAt := int(c.config.PacketsTo)
	if splitAt <= 0 || splitAt >= len(payload) {
		return c.Conn.Write(p)
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

func (c *fragmentConn) Write(p []byte) (n int, err error) {
	c.count++

	// TLS record mode is opt-in via the dedicated "tls-record" finalmask type.
	// It transforms only the first complete outbound ClientHello record.
	if c.config.PacketsFrom == -1 {
		if c.server || c.count != 1 {
			return c.Conn.Write(p)
		}
		return c.writeTLSRecordFragment(p)
	}

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
