package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const maxFrameSize = 1 << 20 // 1 MiB is enough for this mini TP outputs.

// ReadFrame reads a length-prefixed payload (big-endian uint32 + bytes).
func ReadFrame(r io.Reader) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", err
	}

	size := binary.BigEndian.Uint32(header)
	if size > maxFrameSize {
		return "", fmt.Errorf("frame too large: %d bytes", size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", err
	}

	return string(payload), nil
}

// WriteFrame writes a length-prefixed payload (big-endian uint32 + bytes).
func WriteFrame(w io.Writer, payload string) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("payload too large: %d bytes", len(payload))
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write([]byte(payload)); err != nil {
		return err
	}
	return nil
}
