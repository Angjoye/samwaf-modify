package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/utils"
	"errors"
	"time"

	"gorm.io/gorm"
)

type WafRuleService struct{}

var WafRuleServiceApp = new(WafRuleService)

func (receiver *WafRuleService) AddApi(wafRuleAddReq request.WafRuleAddReq, ruleCode string, chsName string, hostCode string, ruleContent string) error {
	return receiver.AddRuleApi(wafRuleAddReq, ruleCode, chsName, hostCode, ruleContent, "")
}

// AddRuleApi 落一条规则记录。
//batchCode 非空表示这条记录属于一次「多选网站」提交的同一批次：
//引擎依旧按 host_code 逐站点加载，所以每个站点各存一条，批次码只用于把它们串成一组。
func (receiver *WafRuleService) AddRuleApi(wafRuleAddReq request.WafRuleAddReq, ruleCode string, chsName string, hostCode string, ruleContent string, batchCode string) error {
	return global.GWAF_LOCAL_DB.Create(receiver.BuildRuleBean(wafRuleAddReq, ruleCode, chsName, hostCode, ruleContent, batchCode)).Error
}

// BuildRuleBean 组装一条规则记录（只组装不落库），供单条新增与多站点批量新增共用
func (receiver *WafRuleService) BuildRuleBean(wafRuleAddReq request.WafRuleAddReq, ruleCode string, chsName string, hostCode string, ruleContent string, batchCode string) *model.Rules {
	// 如果没有传入规则状态，默认为开启（1）
	ruleStatus := wafRuleAddReq.RuleStatus
	if ruleStatus != 0 && ruleStatus != 1 {
		ruleStatus = 1
	}

	return &model.Rules{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:        hostCode, //网站CODE
		RuleCode:        ruleCode,
		RuleName:        chsName,
		RuleContent:     ruleContent,
		RuleContentJSON: wafRuleAddReq.RuleJson, //TODO 后续考虑是否应该再从结构转一次
		RuleVersionName: "初版",
		RuleVersion:     1,
		IsPublicRule:    0,
		IsManualRule:    wafRuleAddReq.IsManualRule,
		RuleStatus:      ruleStatus,
		BatchCode:       batchCode,
	}
}

// AddRulesApi 一次落多条规则记录（多站点一次提交），放在同一个事务里保证要么全成要么全不成，
//避免中途失败留下"只加了一半站点"的规则。
func (receiver *WafRuleService) AddRulesApi(rules []*model.Rules) error {
	if len(rules) == 0 {
		return errors.New("规则内容为空")
	}
	return global.GWAF_LOCAL_DB.Transaction(func(tx *gorm.DB) error {
		for _, rule := range rules {
			if err := tx.Create(rule).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// SetBatchCodeApi 给一组规则打上同一个批次码（编辑时把原本独立的规则扩成多站点规则）
func (receiver *WafRuleService) SetBatchCodeApi(ruleCodes []string, batchCode string) error {
	if len(ruleCodes) == 0 || batchCode == "" {
		return nil
	}
	return global.GWAF_LOCAL_DB.Model(model.Rules{}).Where("rule_code IN ?", ruleCodes).
		Updates(map[string]interface{}{
			"BatchCode":  batchCode,
			"UPDATE_TIME": customtype.JsonTime(time.Now()),
		}).Error
}

// GetRulesByBatchCode 取同一批次下的全部有效规则，按创建时间排序保证顺序稳定
func (receiver *WafRuleService) GetRulesByBatchCode(batchCode string) []model.Rules {
	var rules []model.Rules
	if batchCode == "" {
		return rules
	}
	global.GWAF_LOCAL_DB.Where("batch_code = ? and rule_status <> 999", batchCode).
		Order("create_time asc").Find(&rules)
	return rules
}

// ExpandBatchCodes 把传入的规则码扩展为「这些规则所属批次的全部规则码」。
// 多站点规则是按网站拆成多行的，删掉/停用其中任意一行都要带上同批次的其他行，
// 否则会留下只认自己一个站点的半条规则。批量删除、切换状态都走这里。
func (receiver *WafRuleService) ExpandBatchCodes(ruleCodes []string) []string {
	if len(ruleCodes) == 0 {
		return ruleCodes
	}
	var rules []model.Rules
	global.GWAF_LOCAL_DB.Where("rule_code IN ?", ruleCodes).Find(&rules)

	allCodes := map[string]bool{}
	for _, ruleCode := range ruleCodes {
		allCodes[ruleCode] = true
	}
	var batchCodes []string
	seen := map[string]bool{}
	for i := range rules {
		if rules[i].BatchCode == "" || seen[rules[i].BatchCode] {
			continue
		}
		seen[rules[i].BatchCode] = true
		batchCodes = append(batchCodes, rules[i].BatchCode)
	}
	if len(batchCodes) == 0 {
		return ruleCodes
	}

	var siblings []model.Rules
	global.GWAF_LOCAL_DB.Where("batch_code IN ? and rule_status <> 999", batchCodes).Find(&siblings)
	for i := range siblings {
		allCodes[siblings[i].RuleCode] = true
	}

	result := make([]string, 0, len(allCodes))
	for ruleCode := range allCodes {
		result = append(result, ruleCode)
	}
	return result
}

// DelRuleCodes 按规则码软删除（批次编辑时用于剔除被取消的站点）
func (receiver *WafRuleService) DelRuleCodes(ruleCodes []string) error {
	if len(ruleCodes) == 0 {
		return nil
	}
	ruleMap := map[string]interface{}{
		"RuleStatus":  "999",
		"RuleVersion": 999999,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	return global.GWAF_LOCAL_DB.Model(model.Rules{}).Where("rule_code IN ?", ruleCodes).Updates(ruleMap).Error
}

// UpdateRuleApi 按规则码更新单条规则，用于多站点批次的逐条同步
func (receiver *WafRuleService) UpdateRuleApi(ruleCode string, chsName string, hostCode string, ruleContent string, ruleContentJSON string, isManualRule int, ruleStatus int) error {
	var rule model.Rules
	global.GWAF_LOCAL_DB.Where("rule_code=?", ruleCode).Find(&rule)
	if rule.Id == "" {
		return errors.New("要更新的规则不存在")
	}
	if ruleStatus != 0 && ruleStatus != 1 {
		ruleStatus = rule.RuleStatus
	}
	ruleMap := map[string]interface{}{
		"HostCode":        hostCode,
		"RuleName":        chsName,
		"RuleContent":     ruleContent,
		"RuleContentJSON": ruleContentJSON,
		"RuleVersionName": "初版",
		"RuleVersion":     rule.RuleVersion + 1,
		"user_code":       global.GWAF_USER_CODE,
		"IsPublicRule":    0,
		"IsManualRule":    isManualRule,
		"RuleStatus":      ruleStatus,
		"UPDATE_TIME":     customtype.JsonTime(time.Now()),
	}
	return global.GWAF_LOCAL_DB.Model(model.Rules{}).Where("rule_code=?", ruleCode).Updates(ruleMap).Error
}

// FillBatchInfo 给规则列表补上批次信息（本批次覆盖了哪些站点、共几条），供前端把一组规则
//当作一条规则展示与编辑。用一次 IN 查询补齐所有规则，避免逐条查询造成 N+1。
func (receiver *WafRuleService) FillBatchInfo(rules []model.Rules) []model.Rules {
	if len(rules) == 0 {
		return rules
	}
	batchSeen := map[string]bool{}
	var batchCodes []string
	for i := range rules {
		bc := rules[i].BatchCode
		if bc != "" && !batchSeen[bc] {
			batchSeen[bc] = true
			batchCodes = append(batchCodes, bc)
		}
	}
	hostMap := map[string][]string{}
	if len(batchCodes) > 0 {
		var siblings []model.Rules
		global.GWAF_LOCAL_DB.Model(&model.Rules{}).
			Select("batch_code", "host_code").
			Where("batch_code IN ? and rule_status <> 999", batchCodes).
			Order("create_time asc").Find(&siblings)
		for _, s := range siblings {
			hostMap[s.BatchCode] = append(hostMap[s.BatchCode], s.HostCode)
		}
	}
	for i := range rules {
		hosts := hostMap[rules[i].BatchCode]
		if len(hosts) == 0 {
			//独立规则（含历史数据）：批次信息回退为自己的站点，前端逻辑可统一处理
			rules[i].BatchHostCodes = []string{rules[i].HostCode}
			rules[i].BatchSize = 1
			continue
		}
		rules[i].BatchHostCodes = hosts
		rules[i].BatchSize = len(hosts)
	}
	return rules
}

/*
*

	false表明 不存在
*/
func (receiver *WafRuleService) CheckIsExistApi(ruleName string, hostCode string) int64 {
	var count int64 = 0
	err := global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where("rule_name = ? and host_code = ? and rule_status<> 999", ruleName, hostCode).Count(&count).Error
	if err != nil {
		zlog.Error("检查是否存在错误", err)
	}
	return count
}

func (receiver *WafRuleService) ModifyApi(wafRuleEditReq request.WafRuleEditReq, chsName string, hostCode string, ruleContent string) error {
	var rule model.Rules

	global.GWAF_LOCAL_DB.Where("rule_name = ? and host_code= ?",
		chsName, hostCode).Find(&rule)

	if rule.Id != "" && rule.RuleCode != wafRuleEditReq.CODE {

		return errors.New("当前规则名称已经存在")
	}

	global.GWAF_LOCAL_DB.Where("rule_code=?", wafRuleEditReq.CODE).Find(&rule)

	// 如果没有传入规则状态，保持原有状态
	ruleStatus := wafRuleEditReq.RuleStatus
	if ruleStatus != 0 && ruleStatus != 1 {
		ruleStatus = rule.RuleStatus
	}

	ruleMap := map[string]interface{}{
		"HostCode":        hostCode,
		"RuleName":        chsName,
		"RuleContent":     ruleContent,
		"RuleContentJSON": wafRuleEditReq.RuleJson,
		"RuleVersionName": "初版",
		"RuleVersion":     rule.RuleVersion + 1,
		"user_code":       global.GWAF_USER_CODE,
		"IsPublicRule":    0,
		"IsManualRule":    wafRuleEditReq.IsManualRule,
		"RuleStatus":      ruleStatus,
		"UPDATE_TIME":     customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Rules{}).Where("rule_code=?", wafRuleEditReq.CODE).Updates(ruleMap).Error

	return err
}
func (receiver *WafRuleService) GetDetailApi(wafRuleDetailReq request.WafRuleDetailReq) model.Rules {
	var rules model.Rules
	global.GWAF_LOCAL_DB.Where("RULE_CODE=?  and rule_status<> 999", wafRuleDetailReq.CODE).Find(&rules)
	return rules
}
func (receiver *WafRuleService) GetDetailByCodeApi(ruleCode string) model.Rules {
	var webRule model.Rules
	global.GWAF_LOCAL_DB.Where("rule_code=?  and rule_status<> 999 ", ruleCode).Find(&webRule)
	return webRule
}
func (receiver *WafRuleService) GetListApi(wafRuleSearchReq request.WafRuleSearchReq) ([]model.Rules, int64, error) {
	var total int64 = 0
	var rules []model.Rules
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = "rule_status<>? "
	if len(wafRuleSearchReq.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}
	if len(wafRuleSearchReq.RuleName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " rule_name=? "
	}
	if len(wafRuleSearchReq.RuleCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " rule_code=? "
	}
	//where字段赋值
	whereValues = append(whereValues, 999)
	if len(wafRuleSearchReq.HostCode) > 0 {
		whereValues = append(whereValues, wafRuleSearchReq.HostCode)
	}
	if len(wafRuleSearchReq.RuleName) > 0 {
		whereValues = append(whereValues, wafRuleSearchReq.RuleName)
	}
	if len(wafRuleSearchReq.RuleCode) > 0 {
		whereValues = append(whereValues, wafRuleSearchReq.RuleCode)
	}

	global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where(whereField, whereValues...).Limit(wafRuleSearchReq.PageSize).Offset(wafRuleSearchReq.PageSize * (wafRuleSearchReq.PageIndex - 1)).Find(&rules)
	global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where(whereField, whereValues...).Count(&total)

	fillRuleSalience(rules)
	return rules, total, nil
}

// fillRuleSalience 给列表数据补上优先级
// 优先级只存在于规则文本(GRL)里，没有数据库列；手工模式和界面模式的规则文本都带 salience，
// 所以统一从文本解析，避免为了展示一个字段去加列 + 写迁移 + 回填存量数据
func fillRuleSalience(rules []model.Rules) {
	for i := range rules {
		rules[i].Salience = utils.ExtractRuleSalience(rules[i].RuleContent)
	}
}

func (receiver *WafRuleService) GetListByHostCodeApi(wafRuleSearchReq request.WafRuleSearchReq) ([]model.Rules, int64, error) {
	var total int64 = 0
	var rules []model.Rules
	// tenant/user 由 before_query 自动追加，这里只传 host_code（占位符与参数数须一致，避免参数顺移）
	global.GWAF_LOCAL_DB.Where("host_code = ? and rule_status <> 999 ",
		wafRuleSearchReq.HostCode).Limit(wafRuleSearchReq.PageSize).Offset(wafRuleSearchReq.PageSize * (wafRuleSearchReq.PageIndex - 1)).Find(&rules)
	global.GWAF_LOCAL_DB.Where("host_code = ? and rule_status <> 999",
		wafRuleSearchReq.HostCode).Model(&model.Rules{}).Count(&total)

	fillRuleSalience(rules)
	return rules, total, nil
}

func (receiver *WafRuleService) DelRuleApi(req request.WafRuleDelReq) error {
	var rule model.Rules
	err := global.GWAF_LOCAL_DB.Where("rule_code = ?", req.CODE).First(&rule).Error
	if err != nil {

		return errors.New("要删除的规则信息未找到")
	}
	ruleMap := map[string]interface{}{
		"RuleStatus":  "999",
		"RuleVersion": 999999,
	}
	err = global.GWAF_LOCAL_DB.Model(model.Rules{}).Where("rule_code = ?", req.CODE).Updates(ruleMap).Error
	if err != nil {

		return errors.New("删除失败")
	}
	return nil
}

// BatchDelApi 批量删除指定编码的规则
func (receiver *WafRuleService) BatchDelApi(req request.WafRuleBatchDelReq) error {
	if len(req.Codes) == 0 {
		return errors.New("删除编码列表不能为空")
	}

	// 先检查所有编码是否存在
	var count int64
	err := global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where("rule_code IN ? AND user_code = ? AND tenant_id = ? AND rule_status <> 999", req.Codes, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Count(&count).Error
	if err != nil {
		return err
	}

	if count != int64(len(req.Codes)) {
		return errors.New("部分规则编码不存在")
	}

	// 执行批量删除（软删除）
	ruleMap := map[string]interface{}{
		"RuleStatus":  "999",
		"RuleVersion": 999999,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err = global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where("rule_code IN ? AND user_code = ? AND tenant_id = ?", req.Codes, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Updates(ruleMap).Error
	return err
}

// DelAllApi 删除指定网站的所有规则
func (receiver *WafRuleService) DelAllApi(req request.WafRuleDelAllReq) error {
	var whereCondition string
	var whereValues []interface{}

	if len(req.HostCode) > 0 {
		whereCondition = "host_code = ? AND user_code = ? AND tenant_id = ? AND rule_status <> 999"
		whereValues = append(whereValues, req.HostCode, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	} else {
		whereCondition = "user_code = ? AND tenant_id = ? AND rule_status <> 999"
		whereValues = append(whereValues, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	}

	// 先检查是否存在记录
	var count int64
	err := global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where(whereCondition, whereValues...).Count(&count).Error
	if err != nil {
		return err
	}

	if count == 0 {
		return errors.New("没有规则记录")
	}

	// 执行删除（软删除）
	ruleMap := map[string]interface{}{
		"RuleStatus":  "999",
		"RuleVersion": 999999,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err = global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where(whereCondition, whereValues...).Updates(ruleMap).Error
	return err
}

// GetHostCodesByCodes 根据规则编码列表获取HostCode列表
func (receiver *WafRuleService) GetHostCodesByCodes(codes []string) ([]string, error) {
	var hostCodes []string
	err := global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where("rule_code IN ? AND rule_status <> 999", codes).Pluck("host_code", &hostCodes).Error
	return hostCodes, err
}

// GetHostCodes 获取所有HostCode列表
func (receiver *WafRuleService) GetHostCodes() ([]string, error) {
	var hostCodes []string
	err := global.GWAF_LOCAL_DB.Model(&model.Rules{}).Where("rule_status <> 999").Pluck("host_code", &hostCodes).Error
	return hostCodes, err
}

// ModifyRuleStatusApi 修改规则状态
func (receiver *WafRuleService) ModifyRuleStatusApi(req request.WafRuleStatusReq) error {
	ruleMap := map[string]interface{}{
		"RuleStatus":  req.RULE_STATUS,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}

	//多站点规则整组一起改，避免同一条规则在部分站点生效、部分站点不生效
	ruleCodes := receiver.ExpandBatchCodes([]string{req.CODE})
	return global.GWAF_LOCAL_DB.Model(model.Rules{}).Where("rule_code IN ?", ruleCodes).Updates(ruleMap).Error
}
