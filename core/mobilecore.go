package mobilecore

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	LC "github.com/metacubex/mihomo/listener/config"
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
func Start(homeDir, configYAML string, fd int) (ret string) {
	defer func() {
		if r := recover(); r != nil {
			ret = fmt.Sprintf("ядро упало при старте: %v", r)
		}
	}()
	// Стек gvisor компилируется только с -tags with_gvisor. Без тега sing-tun подставляет
	// заглушку: TUN не поднимается, а hub.ApplyConfig ошибку не возвращает — приложение
	// думает, что подключилось, при этом трафик уходит в никуда. Проверяем явно.
	if !tun.WithGVisor {
		return "ядро собрано без поддержки TUN (нужен -tags with_gvisor)"
	}

	startLogCapture()

	C.SetHomeDir(homeDir)
	cfg, err := executor.ParseWithBytes([]byte(prepareConfig(configYAML)))
	if err != nil {
		return err.Error()
	}
	// TUN собираем сами, tun-блок подписки НЕ наследуем: чужие strict-route/auto-redirect/
	// route-address на Android без рута роняют sing_tun.New, а его cleanup паникует
	// (nil Listener.Close) → падает весь процесс.
	cfg.General.Tun = LC.Tun{
		Enable:              true,
		FileDescriptor:      fd,
		Stack:               C.TunGvisor,
		AutoRoute:           false,
		AutoDetectInterface: false,
		DNSHijack:           []string{"any:53"},
		// адрес ОБЯЗАН совпадать с VpnService.addAddress("172.19.0.1", 30): иначе gVisor
		// не считает 172.19.0.2 (addDnsServer) своим → DNS_PROBE_STARTED; дефолт 198.18.0.1
		// к тому же лежит внутри fake-ip-range
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		MTU:          9000,
		UDPTimeout:   300,
	}
	// поиск процесса-владельца соединения на Android = парсинг /proc на каждый коннект впустую (батарея);
	// роутинг по приложениям делает VpnService
	cfg.General.FindProcessMode = process.FindProcessOff
	// redir/tproxy-листенеры на Android без рута не поднимаются («operation not permitted»)
	cfg.General.RedirPort = 0
	cfg.General.TProxyPort = 0
	// Классический режим: запускаем КОНФИГ подписки как есть (со всеми proxy-group'ами
	// автора). Форсим только адрес API, чтобы coreRequest из приложения всегда достучался
	// (в подписке external-controller может быть любым или с секретом).
	if cfg.Controller != nil {
		cfg.Controller.ExternalController = "127.0.0.1:9090"
		cfg.Controller.Secret = ""
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
