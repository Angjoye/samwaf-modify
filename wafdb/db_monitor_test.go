package wafdb

import (
	"encoding/json"
	"os"
	"testing"

	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/wafdb/dialect"
)

// TestMain 为本包用例准备真开库所需的两个前提：
//
//  1. 注册 SQLite dialect。生产里这步在 wafconfig.LoadAndInitConfig() 末尾做，
//     测试不走那条路径，不注册的话 InitCoreDb 里的 dialect.Get() 会直接 panic。
//  2. 把工作目录切到临时目录，并置 SamWafIDE 让 utils.GetCurrentDir() 返回 "."。
//     InitCoreDb 与 MonitorAllDatabases 都用 GetCurrentDir 拼 data/ 路径，
//     不统一的话建库和读文件大小会落到两个地方；切到临时目录也顺带避免把
//     data/*.db 及其备份写进仓库或 go build 的缓存目录。
func TestMain(m *testing.M) {
	dialect.Register(&dialect.SQLiteDialect{})
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")

	tmpDir, err := os.MkdirTemp("", "samwaf-wafdb-test-")
	if err != nil {
		panic("创建临时目录失败: " + err.Error())
	}
	oldDir, _ := os.Getwd()
	oldEnv, hadEnv := os.LookupEnv("SamWafIDE")
	_ = os.Setenv("SamWafIDE", "1")
	if err := os.Chdir(tmpDir); err != nil {
		panic("切换到临时目录失败: " + err.Error())
	}

	code := m.Run()

	_ = os.Chdir(oldDir)
	if hadEnv {
		_ = os.Setenv("SamWafIDE", oldEnv)
	} else {
		_ = os.Unsetenv("SamWafIDE")
	}
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}

// initTestDatabases 建三个库。三者都写 global 单例，且 InitXxxDb 内部按
// "单例为 nil 才建" 判断，所以本包用例不能并行跑，只能共用同一套库。
func initTestDatabases(t *testing.T) {
	t.Helper()
	if _, err := InitCoreDb(""); err != nil {
		t.Fatalf("初始化主数据库失败: %v", err)
	}
	if _, err := InitLogDb(""); err != nil {
		t.Fatalf("初始化日志数据库失败: %v", err)
	}
	if _, err := InitStatsDb(""); err != nil {
		t.Fatalf("初始化统计数据库失败: %v", err)
	}
}

// TestDatabaseMonitoring 建库后采集一次指标，验证三个库都被采到且字段有意义。
func TestDatabaseMonitoring(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过：需要真实建库并跑全量迁移")
	}
	initTestDatabases(t)

	metrics, err := MonitorAllDatabases()
	if err != nil {
		t.Fatalf("采集数据库指标失败: %v", err)
	}
	if len(metrics) < 3 {
		t.Fatalf("期望至少采到 core/log/stats 三个库的指标，实际 %d 个", len(metrics))
	}
	for _, m := range metrics {
		if m.DatabaseName == "" {
			t.Errorf("指标缺少数据库名: %+v", m)
		}
		// 建库并迁移完必然有页，PageCount 为 0 说明采集读到的不是真实库
		if m.PageCount <= 0 {
			t.Errorf("%s 的 PageCount 应大于 0，实际 %d", m.DatabaseName, m.PageCount)
		}
		// 本项目所有库都带 _db_key 且开 WAL，这两项是回归点：
		// 之前有过 mmap 导致读出密文的坑，journal_mode 变了要能被发现
		if m.JournalMode == "" {
			t.Errorf("%s 未读到 journal_mode", m.DatabaseName)
		}
	}

	// PrintDatabaseMetrics 只写日志，这里确认它不会 panic
	PrintDatabaseMetrics()
}

// TestDatabaseMetricsJSON 验证指标能被正确序列化——监控接口对外就是吐这个 JSON。
func TestDatabaseMetricsJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过：需要真实建库并跑全量迁移")
	}
	initTestDatabases(t)

	jsonMetrics, err := GetDatabaseMetricsJSON()
	if err != nil {
		t.Fatalf("获取 JSON 格式指标失败: %v", err)
	}
	var decoded []*DatabaseMetrics
	if err := json.Unmarshal([]byte(jsonMetrics), &decoded); err != nil {
		t.Fatalf("指标 JSON 无法反序列化: %v，原文: %s", err, jsonMetrics)
	}
	if len(decoded) < 3 {
		t.Fatalf("JSON 里期望至少三个库，实际 %d 个", len(decoded))
	}
}

// TestStartDatabaseMonitoring 验证启动定时监控不会 panic。
//
// 刻意不等它跑出一个周期：StartDatabaseMonitoring 的最小间隔是 1 分钟，且没有
// 停止通道（起的 goroutine 会活到进程结束），等待既拖慢用例又停不掉。周期内真正
// 执行的是 PrintDatabaseMetrics，已由 TestDatabaseMonitoring 直接覆盖。
func TestStartDatabaseMonitoring(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过：需要真实建库并跑全量迁移")
	}
	initTestDatabases(t)
	StartDatabaseMonitoring(1)
}

// BenchmarkDatabaseMetrics 指标采集的性能基准。
func BenchmarkDatabaseMetrics(b *testing.B) {
	if _, err := InitCoreDb(""); err != nil {
		b.Fatalf("初始化主数据库失败: %v", err)
	}
	if _, err := InitLogDb(""); err != nil {
		b.Fatalf("初始化日志数据库失败: %v", err)
	}
	if _, err := InitStatsDb(""); err != nil {
		b.Fatalf("初始化统计数据库失败: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := MonitorAllDatabases(); err != nil {
			b.Fatalf("监控数据库失败: %v", err)
		}
	}
}
