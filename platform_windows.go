//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// ipcAddr: на Windows вместо unix-сокета используется loopback TCP —
// работает на любой версии Windows без прав администратора.
const ipcAddr = "127.0.0.1:2085"

// enableVT включает обработку ANSI escape-последовательностей в консоли
// (Windows 10+). Без этого вместо цветов печатались бы «кракозябры».
func enableVT() {
	for _, h := range []windows.Handle{windows.Handle(os.Stdout.Fd()), windows.Handle(os.Stderr.Fd())} {
		var mode uint32
		if err := windows.GetConsoleMode(h, &mode); err == nil {
			windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
		}
	}
}

// detachAttrs запускает дочерний процесс без окна консоли и в отдельной
// группе, чтобы демон пережил закрытие терминала.
func detachAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
}

func listenIPC(dir string) (net.Listener, error) {
	return net.Listen("tcp", ipcAddr)
}

func dialIPC(dir string) (net.Conn, error) {
	return net.Dial("tcp", ipcAddr)
}

func serviceManagerName() string { return "Task Scheduler" }

const taskName = "sbox-daemon"

func serviceKind() string {
	if err := exec.Command("schtasks", "/Query", "/TN", taskName).Run(); err == nil {
		return "schtasks"
	}
	return "local"
}

// installService регистрирует демон в Планировщике задач Windows:
// автозапуск при входе в систему + немедленный старт.
func installService() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	tr := fmt.Sprintf(`"%s" --daemon`, self)
	if out, err := exec.Command("schtasks", "/Create", "/F", "/TN", taskName,
		"/TR", tr, "/SC", "ONLOGON", "/RL", "HIGHEST").CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks create: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("schtasks", "/Run", "/TN", taskName).CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks run: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
