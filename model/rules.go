package model

import (
	"SamWaf/model/baseorm"
)

type Rules struct {
	baseorm.BaseOrm
	HostCode        string `gorm:"size:64" json:"host_code"`           //主机唯一码
	RuleCode        string `gorm:"size:64" json:"rule_code"`           //规则的唯一码
	RuleName        string `gorm:"size:255" json:"rule_name"`          //规则名称
	RuleContent     string `gorm:"type:text" json:"rule_content"`      //规则内容
	RuleContentJSON string `gorm:"type:text" json:"rule_content_json"` //规则JSON内容
	RuleVersionName string `gorm:"size:100" json:"rule_version_name"`  //规则版本名
	RuleVersion     int    `json:"rule_version"`                       //规则版本号
	IsPublicRule    int    `json:"is_public_rule"`                     //是否为公共规则
	IsManualRule    int    `json:"is_manual_rule"`                     //是否为手工写规则  1：手工编写 0 ：UI界面形式
	RuleStatus      int    `json:"rule_status"`                        //规则是否开启 1，开启 0，关闭不生效 999 删除

	//BatchCode 一次「多选网站」提交产生的同组规则共享同一批次码。
	//引擎依然按 host_code 逐站点加载规则（每个站点各有一条独立记录），
	//批次码只用于列表展示与「改一处、同步整组」的批量编辑/删除。
	//历史单站点规则该列为空，视为独立规则。
	BatchCode string `gorm:"size:64;index" json:"batch_code"`

	//Salience 规则优先级，不落库：从 RuleContent 里解析出来供列表展示
	//优先级本身写在规则文本(GRL)里，手工模式和界面模式都有，所以统一从文本解析，无需加数据库列
	Salience int `gorm:"-" json:"salience"`

	//以下字段不落库，仅用于接口回显，方便前端把同批次规则当作一条规则展示与编辑
	BatchHostCodes []string `gorm:"-" json:"batch_host_codes,omitempty"` //同批次覆盖的网站唯一码
	BatchSize      int      `gorm:"-" json:"batch_size"`                 //同批次规则条数，独立规则为 1
}
