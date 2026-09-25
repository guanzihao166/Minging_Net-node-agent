package sniguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// The ClientHello we are willing to inspect. Anything larger is treated as
// malformed; real handshakes are far below this bound.
const maxHandshakeBytes = 18 * 1024

// A single TLS record body is capped at 16KB plus padding; records claiming
// more than this are malformed or hostile.
const maxRecordBytes = 16384 + 512

var (
	errNotTLS          = errors.New("sniguard: first byte is not a TLS handshake record")
	errMalformedHello  = errors.New("sniguard: malformed client hello")
	errOversizedHello  = errors.New("sniguard: client hello exceeds size limit")
	errHandshakeType   = errors.New("sniguard: first handshake message is not a client hello")
	errServerNameEntry = errors.New("sniguard: server_name extension has no host entry")
)

// ReadClientHelloSNI reads the TLS ClientHello from conn and returns the SNI
// host name exactly as the client sent it (case preserved), together with every
// byte read so the caller can replay the handshake to a backend.
//
// The REALITY server inside Xray matches SNI case-sensitively against its
// configured server_names map (xtls/reality tls.go: `config.ServerNames[...]`),
// so the guard must compare the raw name, never a normalized one.
func ReadClientHelloSNI(conn net.Conn) (string, []byte, error) {
	var replay, handshake []byte
	for {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return "", replay, err
		}
		if len(replay) == 0 && header[0] != 0x16 {
			return "", replay, errNotTLS
		}
		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLen == 0 || recordLen > maxRecordBytes {
			return "", replay, errMalformedHello
		}
		body := make([]byte, recordLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return "", replay, err
		}
		replay = append(replay, header...)
		replay = append(replay, body...)
		handshake = append(handshake, body...)

		if len(handshake) >= 4 {
			if handshake[0] != 0x01 {
				return "", replay, errHandshakeType
			}
			messageLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if messageLen > maxHandshakeBytes {
				return "", replay, errOversizedHello
			}
			if len(handshake) >= 4+messageLen {
				sni, err := parseServerName(handshake[4 : 4+messageLen])
				if err != nil {
					return "", replay, err
				}
				return sni, replay, nil
			}
		}
		if len(replay) > maxHandshakeBytes*2 {
			return "", replay, errOversizedHello
		}
	}
}

// parseServerName extracts the host_name entry of the SNI extension from a
// ClientHello body. It returns an empty string when the hello carries no SNI.
func parseServerName(hello []byte) (string, error) {
	readLen := func(offset int) (int, error) {
		if len(hello) < offset+2 {
			return 0, errMalformedHello
		}
		return int(hello[offset])<<8 | int(hello[offset+1]), nil
	}
	// legacy_version(2) + random(32)
	i := 34
	if len(hello) < i+1 {
		return "", errMalformedHello
	}
	i += 1 + int(hello[i]) // session_id
	cipherLen, err := readLen(i)
	if err != nil {
		return "", err
	}
	i += 2 + cipherLen
	if len(hello) < i+1 {
		return "", errMalformedHello
	}
	i += 1 + int(hello[i]) // compression methods
	extensionsLen, err := readLen(i)
	if err != nil {
		return "", err
	}
	i += 2
	end := i + extensionsLen
	if end > len(hello) {
		end = len(hello)
	}
	for i+4 <= end {
		extensionType := int(hello[i])<<8 | int(hello[i+1])
		extensionLen := int(hello[i+2])<<8 | int(hello[i+3])
		i += 4
		if i+extensionLen > len(hello) {
			return "", errMalformedHello
		}
		if extensionType == 0x0000 {
			name, err := parseServerNameExtension(hello[i : i+extensionLen])
			if errors.Is(err, errServerNameEntry) {
				return "", fmt.Errorf("sniguard: %w", err)
			}
			return name, err
		}
		i += extensionLen
	}
	return "", nil
}

func parseServerNameExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errMalformedHello
	}
	listLen := int(data[0])<<8 | int(data[1])
	i := 2
	end := i + listLen
	if end > len(data) {
		end = len(data)
	}
	for i+3 <= end {
		nameType := data[i]
		nameLen := int(data[i+1])<<8 | int(data[i+2])
		i += 3
		if i+nameLen > len(data) {
			return "", errMalformedHello
		}
		if nameType == 0x00 {
			return string(data[i : i+nameLen]), nil
		}
		i += nameLen
	}
	return "", errServerNameEntry
}
