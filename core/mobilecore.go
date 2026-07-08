package mobilecore

import (
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
)

// Start применяет конфиг из homeDir/config.yaml (там уже прописан tun.file-descriptor).
func Start(homeDir string) string {
	constant.SetHomeDir(homeDir)
	cfg, err := executor.Parse()
	if err != nil {
		return err.Error()
	}
	executor.ApplyConfig(cfg, true)
	return ""
}

// Stop останавливает ядро.
func Stop() {
	executor.Shutdown()
}
