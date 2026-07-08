package mobilecore

import (
	"syscall"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
)

// SocketProtector реализуется на стороне Kotlin (VpnService.protect).
// gomobile превращает интерфейс в Java-интерфейс.
type SocketProtector interface {
	Protect(fd int) bool
}

// SetProtect ставит хук: каждый исходящий сокет ядра защищается через VpnService,
// иначе трафик к серверу уходит обратно в TUN → петля.
func SetProtect(p SocketProtector) {
	if p == nil {
		dialer.DefaultSocketHook = nil
		return
	}
	dialer.DefaultSocketHook = func(network, address string, conn syscall.RawConn) error {
		return conn.Control(func(fd uintptr) {
			p.Protect(int(fd))
		})
	}
}

// Start применяет YAML-конфиг подписки и заводит TUN на переданном fd
// (fd — от Android VpnService.establish()). Возвращает "" при успехе или текст ошибки.
func Start(homeDir, configYAML string, fd int) string {
	C.SetHomeDir(homeDir)
	cfg, err := executor.ParseWithBytes([]byte(configYAML))
	if err != nil {
		return err.Error()
	}
	// Форсим корректные Android-настройки TUN поверх конфига подписки.
	cfg.General.Tun.Enable = true
	cfg.General.Tun.FileDescriptor = fd
	cfg.General.Tun.Stack = C.TunGvisor
	cfg.General.Tun.AutoRoute = false
	cfg.General.Tun.AutoDetectInterface = false
	if len(cfg.General.Tun.DNSHijack) == 0 {
		cfg.General.Tun.DNSHijack = []string{"any:53"}
	}
	executor.ApplyConfig(cfg, true)
	return ""
}

// Stop останавливает ядро.
func Stop() {
	executor.Shutdown()
}
