//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// enableVT: на unix ANSI-последовательности работают из коробки.
func enableVT() {}

// detachAttrs отвязывает дочерний процесс от терминала (новая сессия),
// чтобы демон переживал закрытие SSH-сессии.
func detachAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func sockPath(dir string) string { return filepath.Join(dir, "sbox.sock") }

func listenIPC(dir string) (net.Listener, error) {
	os.Remove(sockPath(dir))
	return net.Listen("unix", sockPath(dir))
}

func dialIPC(dir string) (net.Conn, error) {
	return net.Dial("unix", sockPath(dir))
}

func serviceManagerName() string { return "systemd" }

// serviceKind: как именно крутится демон — под systemd или как обычный процесс.
func serviceKind() string {
	if err := exec.Command("systemctl", "is-active", "--quiet", "sbox-daemon").Run(); err == nil {
		return "systemd"
	}
	return "local"
}

const unitTemplate = `[Unit]
Description=sbox daemon (sing-box supervisor)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s --daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`

func installService() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemd not found on this system")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	unit := fmt.Sprintf(unitTemplate, self)
	if err := os.WriteFile("/etc/systemd/system/sbox-daemon.service", []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit (need root?): %w", err)
	}
	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", "--now", "sbox-daemon"},
	} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
		}
	}
	return nil
}
