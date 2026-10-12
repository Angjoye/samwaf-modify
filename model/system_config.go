package model

import (
	"SamWaf/model/baseorm"
)

/*
*
系统配置
*/
type SystemConfig struct {
	baseorm.BaseOrm
	IsSystem  string `gorm:"size:10" json:"is_system"`   //是否是系统值
	ItemClass string `gorm:"size:100" json:"item_class"` //所属分类
	Item      string `gorm:"size:255" json:"item"`
	Value     string `gorm:"type:text" json:"value"`
	ItemType  string `gorm:"size:50" json:"item_type"` //配置类型 普通字符串，可选项
	Options   string `gorm:"type:text" json:"options"` //如果ItemType == 可选项 这个地方有数据
	HashInfo  string `gorm:"size:255" json:"hash_info"`
	Remarks   string `gorm:"size:500" json:"remarks"` //备注

	//瞬态字段(不落库)：密钥类配置在列表/详情接口里 Value 会被抹空。
	//IsSensitive 告知前端“这一项是密钥类”(据此渲染密码框/已配置态/清空按钮，前端无需维护重复清单)，
	//HasValue 告知“是否已配置”。非密钥项两者都是 false，行为不变。
	IsSensitive bool `gorm:"-" json:"is_sensitive"`
	HasValue    bool `gorm:"-" json:"has_value"`
}

// sensitiveConfigItems 密钥类配置项的权威清单。这类 item 的 Value：
// 落库加密(swk1)、列表/详情接口不回显原文、编辑时留空=保持原值。
// 放在 model 层是为了让 service(读写加解密) 与 wafdb(存量迁移) 共用同一份清单而不产生循环依赖。
// 新增密钥类配置项务必在此登记，否则它会以明文落库且被页面原样回显。
var sensitiveConfigItems = map[string]bool{
	"gpt_token":            true,
	"debug_pwd":            true,
	"zerossl_access_key":   true,
	"zerossl_eab_kid":      true,
	"zerossl_eab_hmac_key": true,
}

// IsSensitiveConfigItem 判断某配置项是否为密钥类。
func IsSensitiveConfigItem(item string) bool {
	return sensitiveConfigItems[item]
}

// SensitiveConfigItemList 返回密钥类配置项清单（供存量迁移按 item 过滤行）。
func SensitiveConfigItemList() []string {
	items := make([]string, 0, len(sensitiveConfigItems))
	for k := range sensitiveConfigItems {
		items = append(items, k)
	}
	return items
}
