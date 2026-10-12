package wafdb

import (
	"testing"

	"SamWaf/global"
	"SamWaf/wafsec"

	"gorm.io/gorm"
)

// ensureTestDataKey 用真实的 InitDataKey 在临时目录准备一把 DEK。
// InitDataKey 内部 sync.Once：整个测试进程只生效一次，之后调用是空操作，DEK 保持就绪。
func ensureTestDataKey(t *testing.T) {
	t.Helper()
	if err := wafsec.InitDataKey(t.TempDir(), ""); err != nil {
		t.Fatalf("初始化 DEK: %v", err)
	}
	if !wafsec.DataKeyReady() {
		t.Fatalf("DEK 未就绪")
	}
}

func readCol(t *testing.T, db *gorm.DB, table, col, id string) string {
	t.Helper()
	var v string
	if err := db.Raw("SELECT "+col+" FROM "+table+" WHERE id = ?", id).Scan(&v).Error; err != nil {
		t.Fatalf("读取 %s.%s: %v", table, col, err)
	}
	return v
}

// 管理端 2FA 密钥升级前是【明文】，是最特殊的一列：迁移=加密明文，回退=还原明文。
func TestDataKeyMigrateOTPPlaintext(t *testing.T) {
	initTestDatabases(t)
	ensureTestDataKey(t)

	db := global.GWAF_LOCAL_DB
	if !db.Migrator().HasTable("otps") {
		t.Skip("otps 表不存在，跳过")
	}
	db.Exec("DELETE FROM otps")
	const plain = "JBSWY3DPEHPK3PXP"
	if err := db.Exec("INSERT INTO otps(id,user_name,secret) VALUES(?,?,?)", "t1", "admin", plain).Error; err != nil {
		t.Fatalf("插入明文行: %v", err)
	}

	// 迁移：明文 → swk1。
	MigrateDataKeyEncryption(db)
	got := readCol(t, db, "otps", "secret", "t1")
	if !wafsec.IsDataKeyCiphertext(got) {
		t.Fatalf("迁移后应为 swk1 密文，实际: %q", got)
	}
	if dec, _ := wafsec.DataDecrypt(got, global.GWAF_COMMUNICATION_KEY); dec != plain {
		t.Fatalf("迁移后解密应还原明文: got %q want %q", dec, plain)
	}

	// 幂等：第二次迁移不应改变。
	before := got
	MigrateDataKeyEncryption(db)
	if after := readCol(t, db, "otps", "secret", "t1"); after != before {
		t.Fatalf("迁移应幂等: before %q after %q", before, after)
	}

	// 回退：swk1 → 明文(旧版按明文读 otps.secret)。
	if n := RekeyToLegacy(db); n == 0 {
		t.Fatalf("回退应至少重写 1 行")
	}
	if back := readCol(t, db, "otps", "secret", "t1"); back != plain {
		t.Fatalf("回退后应还原为明文: got %q want %q", back, plain)
	}
}

// CBC 密文列(如 access_account.otp_secret)的重写变换：迁移=CBC→swk1、回退=swk1→CBC。
// 直接测 rewrapValue，不依赖具体表结构(表级读写已由 OTP 用例端到端覆盖)。
func TestRewrapValueLegacyCBC(t *testing.T) {
	ensureTestDataKey(t)
	legacy := global.GWAF_COMMUNICATION_KEY
	const plain = "totp-secret-cbc"
	cbc, err := wafsec.AesEncrypt([]byte(plain), legacy)
	if err != nil {
		t.Fatalf("造旧 CBC 密文: %v", err)
	}

	// 迁移：CBC → swk1。
	migrated, ok := rewrapValue(cbc, modeMigrate, legacy, false)
	if !ok || !wafsec.IsDataKeyCiphertext(migrated) {
		t.Fatalf("迁移应产出 swk1: ok=%v val=%q", ok, migrated)
	}
	if dec, _ := wafsec.DataDecrypt(migrated, legacy); dec != plain {
		t.Fatalf("迁移后解密应还原: got %q want %q", dec, plain)
	}

	// 已是 swk1，再迁移应幂等跳过。
	if _, ok := rewrapValue(migrated, modeMigrate, legacy, false); ok {
		t.Fatalf("swk1 值在迁移模式下应跳过")
	}

	// 回退：swk1 → CBC，且旧密钥能解回原文。
	back, ok := rewrapValue(migrated, modeRekeyToOld, legacy, false)
	if !ok || wafsec.IsDataKeyCiphertext(back) {
		t.Fatalf("回退应产出无前缀 CBC: ok=%v val=%q", ok, back)
	}
	b, err := wafsec.AesDecrypt(back, legacy)
	if err != nil || string(b) != plain {
		t.Fatalf("旧版应能解回退后的 CBC: got %q err %v", string(b), err)
	}
}

// 明文列(otps.secret)的重写变换：迁移=明文→swk1、回退=swk1→明文。
func TestRewrapValuePlaintext(t *testing.T) {
	ensureTestDataKey(t)
	legacy := global.GWAF_COMMUNICATION_KEY
	const plain = "JBSWY3DPEHPK3PXP"

	migrated, ok := rewrapValue(plain, modeMigrate, legacy, true)
	if !ok || !wafsec.IsDataKeyCiphertext(migrated) {
		t.Fatalf("明文迁移应产出 swk1: ok=%v val=%q", ok, migrated)
	}
	back, ok := rewrapValue(migrated, modeRekeyToOld, legacy, true)
	if !ok || back != plain {
		t.Fatalf("回退应还原明文: ok=%v got %q want %q", ok, back, plain)
	}
}
