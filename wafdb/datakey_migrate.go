package wafdb

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafsec"

	"gorm.io/gorm"
)

// 静态数据加密密钥（DEK）的存量密文重写。覆盖所有把敏感字段加密落库的表/列：
// 这些列升级前用通讯密钥 CBC 加密（无前缀），迁移后改为每实例 DEK 的 swk1: 密文。
//
// 三种模式共用同一套 (表,主键列,密文列) 清单：
//   - migrateToDataKey：启动时一次性把无前缀旧密文重写为 swk1（已是 swk1 的跳过，幂等）
//   - RekeyDataKey     ：--rekey，强制把遗留（旧 CBC / 明文）字段升级为当前 DEK 的 swk1 密文，
//                        供“启动迁移被跳过/中断后手动补跑”。注意：它用当前 DEK 解 swk1 行，
//                        不是“旧钥解、新钥加”的真轮换——真轮换需先保留旧钥，不在本命令职责内。
//                        因此切勿先替换 data_key 文件再跑本命令（旧 swk1 行会因 GCM 校验失败被跳过）。
//   - RekeyToLegacy    ：--rekey-legacy，把 swk1 密文重写回旧通讯密钥 CBC（降级到旧版前执行）
//
// 单行失败只记日志跳过、绝不中断：该行保持原样，仍可被原逻辑读取，重启后可再次尝试。

const logNameDataKey = "DataKeyMigrate"

// secretColumnSpec 描述一张表里需要重写的密文列。
// legacyPlaintext=true 表示该列在启用 DEK 之前是【明文】存储（如管理端 2FA 的 otps.secret），
// 迁移=直接加密明文、回退=还原为明文；false 表示之前是旧通讯密钥 CBC 密文（其余列），
// 迁移=CBC 解密后再用 DEK 加密、回退=还原为 CBC 密文。
// whereSQL 非空时只处理命中该条件的行（用于 system_configs 这类 KV 表：
// 整表只有敏感 item 那几行需要加密，其余配置必须保持明文可读）。
type secretColumnSpec struct {
	table           string
	idCol           string
	valCols         []string
	legacyPlaintext bool
	whereSQL        string
	whereArgs       []interface{}
}

// secretColumnSpecs 是全部“落库敏感字段”的权威清单。新增此类字段务必在此登记，
// 否则换密钥/迁移/回退会漏掉它。
func secretColumnSpecs() []secretColumnSpec {
	return []secretColumnSpec{
		{table: "access_account", idCol: "id", valCols: []string{"otp_secret"}},
		{table: "access_config", idCol: "id", valCols: []string{"hmac_secret"}},
		{table: "cdn_provider", idCol: "id", valCols: []string{"secret_id", "secret_key"}},
		{table: "otps", idCol: "id", valCols: []string{"secret"}, legacyPlaintext: true},
		// system_configs 是 KV 表：只加密密钥类 item 那几行，其余配置保持明文。
		// item 清单与 model.SensitiveConfigItemList() 同源，避免两处漂移。
		newSystemConfigSpec(),
	}
}

// newSystemConfigSpec 构造 system_configs 的行过滤规格：WHERE item IN (敏感项…)。
func newSystemConfigSpec() secretColumnSpec {
	items := model.SensitiveConfigItemList()
	placeholders := ""
	args := make([]interface{}, 0, len(items))
	for i, it := range items {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args = append(args, it)
	}
	return secretColumnSpec{
		table:           "system_configs",
		idCol:           "id",
		valCols:         []string{"value"},
		legacyPlaintext: true, // 升级前这些配置值是明文
		whereSQL:        dialect.Q("item") + " IN (" + placeholders + ")",
		whereArgs:       args,
	}
}

type rekeyMode int

const (
	modeMigrate    rekeyMode = iota // 无前缀 → swk1（幂等，跳过已 swk1）
	modeRekey                       // 任意 → swk1（当前 DEK）
	modeRekeyToOld                  // swk1 → 旧 CBC（跳过无前缀）
)

// MigrateDataKeyEncryption 启动时调用：把存量的旧格式密文一次性迁移为 swk1。
// DEK 未就绪时直接返回（不应发生，InitDataKey 在此之前已调用）。
func MigrateDataKeyEncryption(db *gorm.DB) {
	if db == nil || !wafsec.DataKeyReady() {
		return
	}
	total := rekeyAll(db, modeMigrate)
	if total > 0 {
		zlog.Info(logNameDataKey, "敏感字段静态加密迁移完成", "重写行数", total)
	}
}

// RekeyDataKey 供 CLI --rekey：强制把遗留字段升级为当前 DEK 的 swk1（补跑迁移用，非密钥轮换）。
func RekeyDataKey(db *gorm.DB) int {
	if db == nil || !wafsec.DataKeyReady() {
		return 0
	}
	return rekeyAll(db, modeRekey)
}

// RekeyToLegacy 供 CLI --rekey-legacy：把 swk1 密文重写回旧通讯密钥 CBC 格式，
// 供降级到旧版二进制前执行（旧版只认无前缀 CBC）。
func RekeyToLegacy(db *gorm.DB) int {
	if db == nil {
		return 0
	}
	return rekeyAll(db, modeRekeyToOld)
}

func rekeyAll(db *gorm.DB, mode rekeyMode) int {
	legacy := global.GWAF_COMMUNICATION_KEY
	changed := 0
	for _, spec := range secretColumnSpecs() {
		if !db.Migrator().HasTable(spec.table) {
			continue
		}
		changed += rekeyTable(db, spec, mode, legacy)
	}
	return changed
}

// rekeyTable 处理一张表：显式 SELECT id + 密文列后逐行按目标格式重写。
// 用 Raw+Rows 而非 Find(&[]map)，避免不同驱动对 map 扫描的行为差异。
func rekeyTable(db *gorm.DB, spec secretColumnSpec, mode rekeyMode, legacy []byte) int {
	cols := append([]string{spec.idCol}, spec.valCols...)
	// 列名/表名过 dialect.Q 引用：value 等标识符在部分方言里是关键字。
	query := "SELECT " + joinCols(cols) + " FROM " + dialect.Q(spec.table)
	if spec.whereSQL != "" {
		query += " WHERE " + spec.whereSQL
	}
	rows, err := db.Raw(query, spec.whereArgs...).Rows()
	if err != nil {
		zlog.Warn(logNameDataKey, "读取表失败，跳过", "表", spec.table, "错误", err.Error())
		return 0
	}
	// 先把要改的行收集出来，再统一更新：避免边遍历结果集边执行 UPDATE(某些驱动不允许)。
	type pendingUpdate struct {
		id      string
		updates map[string]interface{}
	}
	var pending []pendingUpdate
	for rows.Next() {
		scanTargets := make([]interface{}, len(cols))
		holders := make([]interface{}, len(cols))
		for i := range holders {
			holders[i] = &scanTargets[i]
		}
		if err := rows.Scan(holders...); err != nil {
			zlog.Warn(logNameDataKey, "扫描行失败，跳过", "表", spec.table, "错误", err.Error())
			continue
		}
		id := toStringValue(scanTargets[0])
		if id == "" {
			continue
		}
		updates := map[string]interface{}{}
		for i, col := range spec.valCols {
			enc := toStringValue(scanTargets[i+1])
			if enc == "" {
				continue
			}
			newEnc, ok := rewrapValue(enc, mode, legacy, spec.legacyPlaintext)
			if !ok || newEnc == enc {
				continue
			}
			updates[col] = newEnc
		}
		if len(updates) > 0 {
			pending = append(pending, pendingUpdate{id: id, updates: updates})
		}
	}
	rows.Close()

	changed := 0
	for _, p := range pending {
		if err := db.Table(spec.table).Where(spec.idCol+" = ?", p.id).Updates(p.updates).Error; err != nil {
			zlog.Warn(logNameDataKey, "重写行失败，保持原样",
				"表", spec.table, spec.idCol, p.id, "错误", err.Error())
			continue
		}
		changed++
	}
	return changed
}

// joinCols 以逗号拼接列名并按方言引用(列名来自代码内白名单，非外部输入)。
func joinCols(cols []string) string {
	out := ""
	for i, c := range cols {
		if i > 0 {
			out += ", "
		}
		out += dialect.Q(c)
	}
	return out
}

// toStringValue 把 map 扫描出来的列值统一成字符串：不同驱动可能返回 string 或 []byte。
func toStringValue(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	default:
		return ""
	}
}

// rewrapValue 按模式把单个字段值重写为目标格式。返回 (新值, 是否需要更新)。
// 任一步失败返回 (原值,false)，让调用方跳过该字段而不是写坏数据。
// legacyPlaintext 决定“启用 DEK 之前”的格式是明文还是 CBC 密文。
func rewrapValue(enc string, mode rekeyMode, legacy []byte, legacyPlaintext bool) (string, bool) {
	isNew := wafsec.IsDataKeyCiphertext(enc)
	switch mode {
	case modeMigrate:
		if isNew {
			return enc, false // 已是 swk1，幂等跳过
		}
	case modeRekeyToOld:
		if !isNew {
			return enc, false // 已是旧格式，跳过
		}
	}

	// 解出明文：swk1 走 DataDecrypt；否则按该列的旧格式解（明文列=原样，密文列=CBC）。
	var plain string
	if isNew {
		p, err := wafsec.DataDecrypt(enc, legacy)
		if err != nil || p == "" {
			return enc, false
		}
		plain = p
	} else if legacyPlaintext {
		plain = enc // 旧值本就是明文
	} else {
		b, err := wafsec.AesDecrypt(enc, legacy)
		if err != nil || len(b) == 0 {
			return enc, false
		}
		plain = string(b)
	}

	// 编码为目标格式。
	var out string
	var err error
	if mode == modeRekeyToOld {
		if legacyPlaintext {
			out = plain // 回退到明文（旧版按明文读该列）
		} else {
			out, err = wafsec.LegacyEncrypt(plain, legacy) // 回退到旧 CBC 密文
		}
	} else {
		out, err = wafsec.DataEncrypt(plain) // 迁移/轮换到 swk1
	}
	if err != nil || out == "" {
		return enc, false
	}
	return out, true
}
