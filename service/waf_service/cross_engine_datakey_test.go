//go:build crossdb

// 静态数据加密（每实例 DEK）的跨引擎回归：SQLite / MySQL / PostgreSQL 各跑一遍。
//
// 为什么必须跨库测：
//   - 迁移用 Raw SELECT + Rows() 逐行扫描，三种驱动对 TEXT 列的返回类型不一致
//     （SQLite 给 []byte，MySQL/PG 可能给 string），类型断言写错会静默跳过所有行；
//   - value / item 这类列名在部分方言里是关键字，标识符不加引用会报语法错；
//   - Updates() 的主键匹配在 []byte 与 TEXT 之间会失配，导致「读到了但没更新」。
//
// 这些都不是 SQLite 单库能暴露的问题。

package waf_service

import (
	"testing"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafsec"

	"gorm.io/gorm"
)

func runDataKeyCases(t *testing.T, db *gorm.DB) {
	if !wafsec.DataKeyReady() {
		t.Fatalf("DEK 未就绪，跨库用例无法验证加密路径")
	}

	// —— 1. 密钥类配置项：加密落库 / 解密读出 / 非密钥项不受影响 ——
	t.Run("SystemConfigSecret", func(t *testing.T) {
		item := "gpt_token" // 敏感项
		secret := "sk-cross-" + sfx()
		svc := WafSystemConfigServiceApp

		// 清掉可能存在的同名行，保证 AddApi 不被幂等保护跳过
		db.Exec("DELETE FROM system_configs WHERE item = ?", item)
		fatalIf(t, svc.AddApi(request.WafSystemConfigAddReq{
			ItemClass: "gpt", Item: item, Value: secret, ItemType: "string",
		}))

		var raw string
		fatalIf(t, db.Raw("SELECT "+qc("value")+" FROM system_configs WHERE item = ?", item).Scan(&raw).Error)
		if raw == secret {
			t.Fatalf("密钥类配置不应明文落库")
		}
		if !wafsec.IsDataKeyCiphertext(raw) {
			t.Fatalf("落库值应为 swk1 密文，实际 %q", raw)
		}
		if got := svc.GetDetailByItem(item).Value; got != secret {
			t.Fatalf("读出应为明文: got %q want %q", got, secret)
		}
		if got := svc.GetAllConfigs()[item].Value; got != secret {
			t.Fatalf("GetAllConfigs 应为明文: got %q want %q", got, secret)
		}

		// 非密钥项保持明文，行为不变
		plainItem := "gpt_model"
		plainVal := "model-" + sfx()
		db.Exec("DELETE FROM system_configs WHERE item = ?", plainItem)
		fatalIf(t, svc.AddApi(request.WafSystemConfigAddReq{
			ItemClass: "gpt", Item: plainItem, Value: plainVal, ItemType: "string",
		}))
		var plainRaw string
		db.Raw("SELECT "+qc("value")+" FROM system_configs WHERE item = ?", plainItem).Scan(&plainRaw)
		if plainRaw != plainVal {
			t.Fatalf("非密钥项应明文落库: got %q want %q", plainRaw, plainVal)
		}
	})

	// —— 2. 存量迁移：明文 → swk1，幂等，再回退 → 明文 ——
	// otps.secret 是「升级前明文」这一类列的代表。
	t.Run("MigrateOtpPlaintext", func(t *testing.T) {
		id := "dk_" + sfx()
		plain := "JBSWY3DPEHPK3PXP"
		fatalIf(t, db.Exec("INSERT INTO otps(id,user_name,secret) VALUES(?,?,?)",
			id, "u_"+sfx(), plain).Error)

		wafdb.MigrateDataKeyEncryption(db)
		got := readSecretCol(t, db, "otps", "secret", id)
		if !wafsec.IsDataKeyCiphertext(got) {
			t.Fatalf("迁移后应为 swk1 密文，实际 %q", got)
		}
		if dec, _ := wafsec.DataDecrypt(got, global.GWAF_COMMUNICATION_KEY); dec != plain {
			t.Fatalf("迁移后解密应还原: got %q want %q", dec, plain)
		}

		// 幂等
		before := got
		wafdb.MigrateDataKeyEncryption(db)
		if after := readSecretCol(t, db, "otps", "secret", id); after != before {
			t.Fatalf("迁移应幂等: before %q after %q", before, after)
		}

		// 回退到旧格式（该列旧格式是明文）
		wafdb.RekeyToLegacy(db)
		if back := readSecretCol(t, db, "otps", "secret", id); back != plain {
			t.Fatalf("回退后应还原明文: got %q want %q", back, plain)
		}
	})

	// —— 3. 存量迁移：旧 CBC 密文 → swk1 → 回退 CBC ——
	t.Run("MigrateLegacyCBC", func(t *testing.T) {
		id := "dk_" + sfx()
		plain := "cross-cbc-secret"
		legacyEnc, err := wafsec.AesEncrypt([]byte(plain), global.GWAF_COMMUNICATION_KEY)
		fatalIf(t, err)
		fatalIf(t, db.Exec("INSERT INTO access_account(id,otp_secret) VALUES(?,?)", id, legacyEnc).Error)

		wafdb.MigrateDataKeyEncryption(db)
		got := readSecretCol(t, db, "access_account", "otp_secret", id)
		if !wafsec.IsDataKeyCiphertext(got) {
			t.Fatalf("迁移后应为 swk1: %q", got)
		}
		if dec, _ := wafsec.DataDecrypt(got, global.GWAF_COMMUNICATION_KEY); dec != plain {
			t.Fatalf("迁移后解密应还原: got %q want %q", dec, plain)
		}

		wafdb.RekeyToLegacy(db)
		back := readSecretCol(t, db, "access_account", "otp_secret", id)
		if wafsec.IsDataKeyCiphertext(back) {
			t.Fatalf("回退后不应带 swk1 前缀: %q", back)
		}
		b, err := wafsec.AesDecrypt(back, global.GWAF_COMMUNICATION_KEY)
		if err != nil || string(b) != plain {
			t.Fatalf("旧版应能解回退后的 CBC: got %q err %v", string(b), err)
		}
	})

	// —— 4. system_configs 的行过滤迁移：只动敏感 item，其它配置一律不碰 ——
	t.Run("MigrateSystemConfigRowFilter", func(t *testing.T) {
		secretItem := "zerossl_access_key"
		otherItem := "cross_plain_" + sfx()
		secretPlain := "zs-" + sfx()
		otherPlain := "just-a-normal-value"

		db.Exec("DELETE FROM system_configs WHERE item = ?", secretItem)
		fatalIf(t, db.Exec("INSERT INTO system_configs(id,item,item_class,"+qc("value")+") VALUES(?,?,?,?)",
			"cfg_"+sfx(), secretItem, "ssl", secretPlain).Error)
		fatalIf(t, db.Exec("INSERT INTO system_configs(id,item,item_class,"+qc("value")+") VALUES(?,?,?,?)",
			"cfg_"+sfx(), otherItem, "system", otherPlain).Error)

		wafdb.MigrateDataKeyEncryption(db)

		var secretRaw, otherRaw string
		db.Raw("SELECT "+qc("value")+" FROM system_configs WHERE item = ?", secretItem).Scan(&secretRaw)
		db.Raw("SELECT "+qc("value")+" FROM system_configs WHERE item = ?", otherItem).Scan(&otherRaw)

		if !wafsec.IsDataKeyCiphertext(secretRaw) {
			t.Fatalf("敏感配置项应被迁移为密文: %q", secretRaw)
		}
		if dec, _ := wafsec.DataDecrypt(secretRaw, global.GWAF_COMMUNICATION_KEY); dec != secretPlain {
			t.Fatalf("敏感项解密应还原: got %q want %q", dec, secretPlain)
		}
		if otherRaw != otherPlain {
			t.Fatalf("非敏感配置项不应被改动: got %q want %q", otherRaw, otherPlain)
		}
		if !model.IsSensitiveConfigItem(secretItem) || model.IsSensitiveConfigItem(otherItem) {
			t.Fatalf("敏感项判定不符预期")
		}
	})
}

// qc 按当前方言引用标识符（value / item 等在部分方言里是关键字）。
func qc(ident string) string { return dialect.Q(ident) }

// readSecretCol 读单个密文列（列名过方言引用，避开关键字问题）。
func readSecretCol(t *testing.T, db *gorm.DB, table, col, id string) string {
	t.Helper()
	var v string
	if err := db.Raw("SELECT "+qc(col)+" FROM "+qc(table)+" WHERE id = ?", id).Scan(&v).Error; err != nil {
		t.Fatalf("读取 %s.%s: %v", table, col, err)
	}
	return v
}
