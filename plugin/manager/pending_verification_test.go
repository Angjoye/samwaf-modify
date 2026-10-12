package manager

import (
	"strings"
	"testing"

	pluginconfig "SamWaf/plugin/config"
)

// 待验证总闸的护栏用例：只在闸门开启（PendingVerification=true）时生效。
// 将来 L0+L1 落地把常量置为 false 后，这些用例自动跳过，不会成为绊脚石。

func TestPendingVerification_LoadPluginRefused(t *testing.T) {
	if !PendingVerification {
		t.Skip("总闸已放开，跳过")
	}

	pm := NewPluginManager(&pluginconfig.PluginSystemConfig{Enabled: true})
	err := pm.LoadPlugin(&pluginconfig.PluginConfig{
		ID:         "any_plugin",
		BinaryPath: "./data/plugins/binaries/whatever.exe",
		Enabled:    true,
	})
	if err == nil {
		t.Fatal("待验证期间 LoadPlugin 必须拒绝，实际放行了")
	}
	if !strings.Contains(err.Error(), "待验证") {
		t.Fatalf("拒绝原因应指明待验证，实际: %v", err)
	}
	if len(pm.GetAllPlugins()) != 0 {
		t.Fatal("拒绝后不应留下任何插件实例")
	}
}

func TestPendingVerification_ConfigEnabledIsOverridden(t *testing.T) {
	if !PendingVerification {
		t.Skip("总闸已放开，跳过")
	}

	// 配置文件写 enabled: true 也必须被强制关掉
	pm := NewPluginManager(&pluginconfig.PluginSystemConfig{
		Enabled:             true,
		AutoRestart:         true,
		HealthCheckInterval: 1,
	})
	if pm.IsEnabled() {
		t.Fatal("待验证期间即便配置 enabled:true，管理器也必须处于关闭状态")
	}

	// SetEnabled 只允许关，不允许开
	pm.SetEnabled(true)
	if pm.IsEnabled() {
		t.Fatal("待验证期间 SetEnabled(true) 不应生效")
	}
}

func TestPendingVerification_CheckRequestPassThrough(t *testing.T) {
	if !PendingVerification {
		t.Skip("总闸已放开，跳过")
	}

	// 引擎热路径调用点：必须直接放行，不得拦截、不得 panic
	pm := NewPluginManager(&pluginconfig.PluginSystemConfig{Enabled: true})
	isBlock, reason := pm.CheckRequest(nil, "pre_check", "1.2.3.4", "/", "ua", "GET", "example.com")
	if isBlock {
		t.Fatalf("待验证期间插件检查必须放行，实际拦截: %s", reason)
	}
}
