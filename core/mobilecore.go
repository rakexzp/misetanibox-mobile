package mobilecore

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	tun "github.com/metacubex/sing-tun"
)

// Кольцевой буфер последних предупреждений/ошибок ядра.
// hub.ApplyConfig ошибок не возвращает — всё, что ломается внутри (TUN, подписка),
// только пишется в лог. Без этого причина сбоя на устройстве недоступна.
var (
	logMu    sync.Mutex
	logLines []string
	logOnce  sync.Once
)

func startLogCapture() {
	logOnce.Do(func() {
		go func() {
			for ev := range log.Subscribe() {
				switch ev.LogLevel {
				case log.ERROR, log.WARNING:
					logMu.Lock()
					logLines = append(logLines, ev.Type()+": "+ev.Payload)
					if len(logLines) > 15 {
						logLines = logLines[len(logLines)-15:]
					}
					logMu.Unlock()
				}
			}
		}()
	})
}

func recentLogs() []string {
	logMu.Lock()
	defer logMu.Unlock()
	out := make([]string, len(logLines))
	copy(out, logLines)
	return out
}

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
	// Стек gvisor компилируется только с -tags with_gvisor. Без тега sing-tun подставляет
	// заглушку: TUN не поднимается, а hub.ApplyConfig ошибку не возвращает — приложение
	// думает, что подключилось, при этом трафик уходит в никуда. Проверяем явно.
	if !tun.WithGVisor {
		return "ядро собрано без поддержки TUN (нужен -tags with_gvisor)"
	}

	startLogCapture()

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
	// Адрес tun-интерфейса ядра ОБЯЗАН совпадать с VpnService.addAddress("172.19.0.1", 30).
	// Без этого gVisor-нетстек ядра поднимается на дефолтном 198.18.0.1/30 и не считает
	// 172.19.0.2 (addDnsServer в Kotlin) своим локальным адресом → hijacknутый DNS-запрос
	// приложения некуда ответить → DNS_PROBE_STARTED («подключено, но DNS не резолвит»).
	// Плюс дефолт 198.18.0.1 лежит ВНУТРИ fake-ip-range 198.18.0.0/16 (коллизия адресов).
	cfg.General.Tun.Inet4Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")}
	if len(cfg.General.Tun.DNSHijack) == 0 {
		cfg.General.Tun.DNSHijack = []string{"any:53"}
	}
	// hub.ApplyConfig = applyRoute (поднимает external-controller/API) + executor.ApplyConfig (ядро).
	hub.ApplyConfig(cfg)
	return ""
}

// Diagnose — краткий отчёт о состоянии ядра. Нужен, потому что hub.ApplyConfig не
// возвращает ошибок: если TUN не поднялся или подписка не загрузилась, приложение
// иначе показывает «подключено» при мёртвом туннеле.
func Diagnose() string {
	var b strings.Builder

	tunConf := listener.GetTunConf()
	fmt.Fprintf(&b, "TUN: включён=%v стек=%v\n", tunConf.Enable, tunConf.Stack)

	fmt.Fprintf(&b, "узлов всего: %d\n", len(tunnel.Proxies()))

	providers := tunnel.Providers()
	if len(providers) == 0 {
		b.WriteString("провайдеров подписки нет\n")
	}
	for name, p := range providers {
		fmt.Fprintf(&b, "подписка %s: %d узлов\n", name, len(p.Proxies()))
	}

	if lines := recentLogs(); len(lines) > 0 {
		b.WriteString("ошибки ядра:\n")
		for _, l := range lines {
			b.WriteString("  " + l + "\n")
		}
	} else {
		b.WriteString("ошибок ядра нет\n")
	}
	return b.String()
}

// Stop останавливает ядро.
func Stop() {
	executor.Shutdown()
}
