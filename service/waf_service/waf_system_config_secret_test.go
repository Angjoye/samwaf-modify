package waf_service

import (
	"path/filepath"
	"testing"

	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafsec"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newSecretTestDB 起一个只含 system_configs 表的临时 SQLite 库，并接到 global 单例。
// 不跑全量迁移：本用例只关心配置项的读写加解密。
func newSecretTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	zlog.InitZLog(false, "console")
	dialect.Register(&dialect.SQLiteDialect{})
	db, err := gorm.Open(
		sqlitedriver.Open(filepath.Join(t.TempDir(), "core.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatalf("打开 sqlite 失败: %v", err)
	}
	if err := db.AutoMigrate(&model.SystemConfig{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() {
		if s, e := db.DB(); e == nil {
			s.Close()
		}
		global.GWAF_LOCAL_DB = nil
	})
	if err := wafsec.InitDataKey(t.TempDir(), ""); err != nil {
		t.Fatalf("初始化 DEK: %v", err)
	}
	if !wafsec.DataKeyReady() {
		t.Fatalf("DEK 未就绪")
	}
	return db
}

// 密钥类配置项的落库加密（T31）：写入加密、读取解密、页面回显脱敏、编辑保值。
// 自带轻量 SQLite 环境，默认构建即运行（cross_engine 系列在 crossdb tag 后面）。
func TestSensitiveConfigEncryptAtRest(t *testing.T) {
	global.GWAF_USER_CODE = "t"
	global.GWAF_TENANT_ID = "t"
	db := newSecretTestDB(t)

	const item = "gpt_token"
	const secret = "sk-test-abcdef-0123456789"
	svc := WafSystemConfigServiceApp

	// 写入：service 层应加密后落库。
	if err := svc.AddApi(request.WafSystemConfigAddReq{
		ItemClass: "gpt", Item: item, Value: secret, ItemType: "string",
	}); err != nil {
		t.Fatalf("AddApi: %v", err)
	}

	// 库里必须是 swk1 密文，不能是明文。
	var raw string
	if err := db.Raw("SELECT value FROM system_configs WHERE item = ?", item).Scan(&raw).Error; err != nil {
		t.Fatalf("读原始值: %v", err)
	}
	if raw == secret {
		t.Fatalf("密钥类配置不应明文落库")
	}
	if !wafsec.IsDataKeyCiphertext(raw) {
		t.Fatalf("落库值应为 swk1 密文，实际: %q", raw)
	}

	// 读取：所有 service getter 都应还原明文，供内部逻辑直接使用。
	if got := svc.GetDetailByItem(item).Value; got != secret {
		t.Fatalf("GetDetailByItem 应返回明文: got %q want %q", got, secret)
	}
	if got := svc.GetDetailByItemApi(request.WafSystemConfigDetailByItemReq{Item: item}).Value; got != secret {
		t.Fatalf("GetDetailByItemApi 应返回明文: got %q", got)
	}
	// 配置加载走 GetAllConfigs，必须拿到明文，否则全局变量会被写进密文。
	if got := svc.GetAllConfigs()[item].Value; got != secret {
		t.Fatalf("GetAllConfigs 应返回明文: got %q want %q", got, secret)
	}

	// 非密钥项不受影响：仍明文落库、原样读出。
	const plainItem = "gpt_model"
	const plainVal = "deepseek-chat"
	if err := svc.AddApi(request.WafSystemConfigAddReq{
		ItemClass: "gpt", Item: plainItem, Value: plainVal, ItemType: "string",
	}); err != nil {
		t.Fatalf("AddApi 非密钥项: %v", err)
	}
	var plainRaw string
	db.Raw("SELECT value FROM system_configs WHERE item = ?", plainItem).Scan(&plainRaw)
	if plainRaw != plainVal {
		t.Fatalf("非密钥项应明文落库: got %q want %q", plainRaw, plainVal)
	}

	// 页面回显：抹空 Value，给出 is_sensitive / has_value。
	bean := svc.GetDetailByItem(item)
	MaskSensitiveConfig(&bean)
	if bean.Value != "" || !bean.HasValue || !bean.IsSensitive {
		t.Fatalf("脱敏后应 Value 空且 HasValue/IsSensitive 为真: %+v", bean)
	}
	plainBean := svc.GetDetailByItem(plainItem)
	MaskSensitiveConfig(&plainBean)
	if plainBean.Value != plainVal || plainBean.IsSensitive {
		t.Fatalf("非密钥项不应被脱敏: %+v", plainBean)
	}

	// 更新为新密钥：仍加密落库、读出为新值。
	const secret2 = "sk-rotated-999"
	if err := svc.ModifyByItemApi(request.WafSystemConfigEditByItemReq{Item: item, Value: secret2}); err != nil {
		t.Fatalf("ModifyByItemApi: %v", err)
	}
	db.Raw("SELECT value FROM system_configs WHERE item = ?", item).Scan(&raw)
	if !wafsec.IsDataKeyCiphertext(raw) || raw == secret2 {
		t.Fatalf("更新后应仍为密文: %q", raw)
	}
	if got := svc.GetDetailByItem(item).Value; got != secret2 {
		t.Fatalf("更新后应读出新密钥: got %q want %q", got, secret2)
	}

	// 哨兵值防御：任何路径提交哨兵都表示清空，不能把哨兵本身当密钥加密存起来。
	if err := svc.ModifyByItemApi(request.WafSystemConfigEditByItemReq{
		Item: item, Value: ConfigClearSentinel,
	}); err != nil {
		t.Fatalf("ModifyByItemApi 哨兵: %v", err)
	}
	if got := svc.GetDetailByItem(item).Value; got != "" {
		t.Fatalf("提交哨兵后应清空: got %q", got)
	}
}

// 存量明文行的兼容：升级前写入的明文值，在迁移完成前也必须能正常读出。
func TestSensitiveConfigLegacyPlaintextReadable(t *testing.T) {
	db := newSecretTestDB(t)

	// 绕过 service 直接写明文，模拟升级前的存量行。
	const legacy = "legacy-plain-token"
	if err := db.Exec(
		"INSERT INTO system_configs(id,item,item_class,value) VALUES(?,?,?,?)",
		"cfg-legacy", "debug_pwd", "debug", legacy).Error; err != nil {
		t.Fatalf("插入存量明文行: %v", err)
	}

	if got := WafSystemConfigServiceApp.GetDetailByItem("debug_pwd").Value; got != legacy {
		t.Fatalf("存量明文应原样读出: got %q want %q", got, legacy)
	}
	if got := WafSystemConfigServiceApp.GetAllConfigs()["debug_pwd"].Value; got != legacy {
		t.Fatalf("GetAllConfigs 对存量明文应原样读出: got %q", got)
	}
	if !model.IsSensitiveConfigItem("debug_pwd") {
		t.Fatalf("debug_pwd 应在敏感清单内")
	}
}
