package api

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"SamWaf/utils"
	"SamWaf/wafenginecore/wafhttpcore"
	"errors"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

type WafRuleAPi struct {
}

// 手工规则文本长度上限，防止超大规则拖垮编译
const maxManualRuleContentLen = 64 * 1024

// checkManualRuleContent 手工模式规则的安全校验
// 除了让 grule 真正编译一遍，还要保证"保存时看到的动作"和"运行时执行的动作"是同一个：
//   - 一段规则内容里只能有一条规则（防止在一条规则后面再塞一条放行规则）
//   - 规则名必须和规则码对得上（防止覆盖到别的规则）
//   - 动作标记只能有一个，Allow 的参数必须是已知的检测模块
func checkManualRuleContent(ruleHelper *utils.RuleHelper, ruleContent string, expectRuleCode string) error {
	if len(ruleContent) > maxManualRuleContentLen {
		return errors.New("规则内容过长")
	}
	//语法校验
	if err := ruleHelper.CheckRuleAvailable(ruleContent); err != nil {
		return errors.New("规则校验失败")
	}
	//一条规则内容只允许定义一条规则
	names := utils.ExtractRuleNamesFromText(ruleContent)
	if len(names) == 0 {
		return errors.New("未找到规则定义")
	}
	if len(names) > 1 {
		return errors.New("一条规则内容里只能定义一条规则")
	}
	//规则名必须与规则码一致
	if expectRuleCode != "" {
		expectName := "R" + strings.Replace(expectRuleCode, "-", "", -1)
		if !strings.EqualFold(names[0], expectName) {
			return fmt.Errorf("规则标识与规则码不一致，应为 %s", expectName)
		}
	}
	//动作校验
	if _, err := utils.ExtractRuleActionForCheck(ruleContent); err != nil {
		return err
	}
	return nil
}

// ruleBatchMaxHosts 一次多选网站的站点数上限，挡住"误选全部站点"把规则表撑爆
const ruleBatchMaxHosts = 200

// resolveRuleHostCodes 归一化前端传来的目标站点列表：
//去空、去重、剔除占位文案，并在为空时回退到规则JSON里的单站点，保证老前端与老接口调用方行为不变。
func resolveRuleHostCodes(reqHostCodes []string, fallback string) ([]string, error) {
	seen := map[string]bool{}
	hosts := make([]string, 0, len(reqHostCodes))
	for _, h := range reqHostCodes {
		h = strings.TrimSpace(h)
		if h == "" || h == "请选择网站" || seen[h] {
			continue
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	if len(hosts) == 0 {
		fb := strings.TrimSpace(fallback)
		if fb == "" || fb == "请选择网站" {
			return nil, errors.New("请选择网站")
		}
		hosts = append(hosts, fb)
	}
	if len(hosts) > ruleBatchMaxHosts {
		return nil, fmt.Errorf("一次最多选择 %d 个网站", ruleBatchMaxHosts)
	}
	return hosts, nil
}

// rewriteManualRuleName 把手工规则文本里的规则名换成目标规则码对应的名字。
//多站点扇出时每个站点必须有各自唯一的规则名，否则规则之间会互相覆盖。
func rewriteManualRuleName(ruleContent string, oldName string, newRuleCode string) string {
	oldName = strings.TrimSpace(oldName)
	if oldName == "" {
		return ruleContent
	}
	newName := strings.Replace(newRuleCode, "-", "", -1)
	if oldName == newName {
		return ruleContent
	}
	return strings.Replace(ruleContent, "R"+oldName, "R"+newName, 1)
}

// uniqueHostCodes 保序去重，通知引擎时避免同一个站点被重复推送
func uniqueHostCodes(hostCodes []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(hostCodes))
	for _, h := range hostCodes {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		result = append(result, h)
	}
	return result
}

// AddApi 新增WAF规则
// @Summary      新增WAF规则
// @Description  新增一条WAF防护规则
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafRuleAddReq  true  "规则配置"
// @Success      200   {object}  response.Response{data=string}  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/add [post]
func (w *WafRuleAPi) AddApi(c *gin.Context) {
	ruleHelper := &utils.RuleHelper{}
	var req request.WafRuleAddReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	var ruleTool = model.RuleTool{}
	ruleInfo, err := ruleTool.LoadRule(req.RuleJson)
	if err != nil {
		response.FailWithMessage("规则解析错误", c)
		return
	}

	//目标站点：优先取多选结果（host_codes），为空时回退到规则JSON里的单站点，兼容老前端
	hostCodes, err := resolveRuleHostCodes(req.HostCodes, ruleInfo.RuleBase.RuleDomainCode)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}

	chsName := ruleInfo.RuleBase.RuleName

	//基准规则码：界面模式用前端准备好的；手工模式的规则码写在规则文本里，从中提取
	baseRuleCode := uuid.GenUUID()
	manualRuleName := ""
	if req.IsManualRule == 1 {
		manualRuleName, err = ruleHelper.ExtractRuleName(req.RuleJson)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
		if manualRuleName != "{SamWafUUID}" {
			baseRuleCode = manualRuleName
			existBean := wafRuleService.GetDetailByCodeApi(baseRuleCode)
			if existBean.RuleCode != "" {
				response.FailWithMessage("当前编码已存在，请刷新页面重新尝试", c)
				return
			}
		}
	} else if strings.TrimSpace(req.RuleCode) != "" {
		//手工编码情况下 前端准备好的
		baseRuleCode = req.RuleCode
	}

	//先做完整校验再落库：任一站点不通过就整批拒绝，避免出现"只加了一半站点"
	for _, hostCode := range hostCodes {
		if count := wafRuleService.CheckIsExistApi(chsName, hostCode); count > 0 {
			response.FailWithMessage("当前规则已存在", c)
			return
		}
	}

	//多站点规则：每个站点各存一条记录并共享同一个批次码。
	//引擎依旧按 host_code 逐站点加载，所以这里不需要改引擎，站点之间的规则天然互不影响。
	batchCode := uuid.GenUUID()
	beans := make([]*model.Rules, 0, len(hostCodes))
	for i, hostCode := range hostCodes {
		ruleCode := baseRuleCode
		if i > 0 {
			//一个规则码不能挂在两条记录上，第二个站点起各自生成
			ruleCode = uuid.GenUUID()
		}
		var ruleContent string
		if req.IsManualRule == 1 {
			//手工模式的规则名必须和规则码一致，逐站点改写规则名
			ruleContent = rewriteManualRuleName(ruleInfo.RuleContent, manualRuleName, ruleCode)
			if err = checkManualRuleContent(ruleHelper, ruleContent, ruleCode); err != nil {
				response.FailWithMessage(err.Error(), c)
				return
			}
		} else {
			ruleInfo.RuleBase.RuleName = strings.Replace(ruleCode, "-", "", -1)
			ruleContent, err = ruleTool.GenRuleInfo(ruleInfo, chsName)
			if err != nil {
				response.FailWithMessage(err.Error(), c)
				return
			}
		}
		beans = append(beans, wafRuleService.BuildRuleBean(req, ruleCode, chsName, hostCode, ruleContent, batchCode))
	}

	if err = wafRuleService.AddRulesApi(beans); err != nil {
		response.FailWithMessage("添加失败", c)
		return
	}
	for _, hostCode := range uniqueHostCodes(hostCodes) {
		w.NotifyWaf(hostCode)
	}
	if len(hostCodes) > 1 {
		response.OkWithMessage(fmt.Sprintf("添加成功，已应用到 %d 个网站", len(hostCodes)), c)
	} else {
		response.OkWithMessage("添加成功", c)
	}
}

// GetDetailApi 获取WAF规则详情
// @Summary      获取WAF规则详情
// @Description  根据 code 获取单条WAF规则详情
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "规则唯一编码"
// @Success      200   {object}  response.Response{data=model.Rules}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/detail [get]
func (w *WafRuleAPi) GetDetailApi(c *gin.Context) {
	var req request.WafRuleDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafHost := wafRuleService.GetDetailApi(req)
		//回显该规则所在批次的全部站点，前端据此把"多选网站"还原出来便于继续编辑
		filled := wafRuleService.FillBatchInfo([]model.Rules{wafHost})
		if len(filled) > 0 {
			wafHost = filled[0]
		}
		response.OkWithDetailed(wafHost, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取WAF规则列表
// @Summary      获取WAF规则列表
// @Description  分页查询WAF防护规则列表
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafRuleSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/list [post]
func (w *WafRuleAPi) GetListApi(c *gin.Context) {
	var req request.WafRuleSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		wafRules, total, _ := wafRuleService.GetListApi(req)
		//补上批次信息，列表里能看出哪些规则是"一条规则套多个网站"（一次 IN 查询，无 N+1）
		wafRules = wafRuleService.FillBatchInfo(wafRules)
		response.OkWithDetailed(response.PageResult{
			List:      wafRules,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafRuleAPi) GetListByHostCodeApi(c *gin.Context) {
	var req request.WafRuleSearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafRules, total, _ := wafRuleService.GetListByHostCodeApi(req)
		wafRules = wafRuleService.FillBatchInfo(wafRules)
		response.OkWithDetailed(response.PageResult{
			List:      wafRules,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelRuleApi 删除WAF规则
// @Summary      删除WAF规则
// @Description  根据 code 删除WAF防护规则
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        code  query     string  true  "规则唯一编码"
// @Success      200   {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/del [get]
func (w *WafRuleAPi) DelRuleApi(c *gin.Context) {
	var req request.WafRuleDelReq
	err := c.ShouldBind(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	wafRule := wafRuleService.GetDetailByCodeApi(req.CODE)
	if wafRule.Id == "" {
		response.FailWithMessage("请检测参数", c)
		return
	}

	//多站点规则删一条即删一组：整批一起清理，避免留下"孤儿"规则继续占着其他站点
	ruleCodes := []string{wafRule.RuleCode}
	hostCodes := []string{wafRule.HostCode}
	if wafRule.BatchCode != "" {
		siblings := wafRuleService.GetRulesByBatchCode(wafRule.BatchCode)
		if len(siblings) > 0 {
			ruleCodes = make([]string, 0, len(siblings))
			hostCodes = make([]string, 0, len(siblings))
			for _, sibling := range siblings {
				ruleCodes = append(ruleCodes, sibling.RuleCode)
				hostCodes = append(hostCodes, sibling.HostCode)
			}
		}
	}

	err = wafRuleService.DelRuleCodes(ruleCodes)
	if err != nil {
		response.FailWithMessage("发生错误", c)
		return
	}
	//TODO 通知引擎重新加载某个网站的规则信息
	for _, hostCode := range uniqueHostCodes(hostCodes) {
		w.NotifyWaf(hostCode)
	}
	if len(ruleCodes) > 1 {
		response.OkWithMessage(fmt.Sprintf("删除成功，已从 %d 个网站移除", len(ruleCodes)), c)
	} else {
		response.OkWithMessage("删除成功", c)
	}
}

// ModifyRuleApi 编辑WAF规则
// @Summary      编辑WAF规则
// @Description  修改已有WAF防护规则配置
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafRuleEditReq  true  "规则配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/edit [post]
func (w *WafRuleAPi) ModifyRuleApi(c *gin.Context) {
	ruleHelper := &utils.RuleHelper{}
	var req request.WafRuleEditReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	var ruleTool = model.RuleTool{}
	rule := wafRuleService.GetDetailByCodeApi(req.CODE)
	if rule.Id == "" {
		response.FailWithMessage("请检测参数", c)
		return
	}

	//目标站点集合暂时留到规则JSON解析之后再定：
	//老前端是单站点，站点写在 rule_json 的 rule_domain_code 里，优先级必须高于库里的当前站点
	if req.IsManualRule == 1 {
		ruleCodeFormDRL, err := ruleHelper.ExtractRuleName(req.RuleJson)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
		if rule.RuleCode != ruleCodeFormDRL {
			zlog.Debug(fmt.Sprintf("原始的规则码 %v， 需要替换的规则码 %v", rule.RuleCode, ruleCodeFormDRL))
			beforeJson := req.RuleJson
			req.RuleJson = strings.Replace(req.RuleJson, ruleCodeFormDRL, strings.Replace(rule.RuleCode, "-", "", -1), -1)
			zlog.Debug(fmt.Sprintf("原始信息 %v 替换后信息 %v ", beforeJson, req.RuleJson))

		}
	}
	ruleInfo, err := ruleTool.LoadRule(req.RuleJson)
	if err != nil {
		response.FailWithMessage("解析错误", c)
		return
	}

	//目标站点：优先取多选结果（host_codes）；没有就退回规则JSON里的单站点（老前端），
	//再没有才用库里这条记录当前的站点
	fallbackHost := strings.TrimSpace(ruleInfo.RuleBase.RuleDomainCode)
	if fallbackHost == "" || fallbackHost == "请选择网站" {
		fallbackHost = rule.HostCode
	}
	targetHosts, err := resolveRuleHostCodes(req.HostCodes, fallbackHost)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}

	var ruleName = ruleInfo.RuleBase.RuleName //中文名

	//批次内已有站点：历史独立规则批次码为空，视为只有它自己
	siblings := []model.Rules{rule}
	if rule.BatchCode != "" {
		if batchRules := wafRuleService.GetRulesByBatchCode(rule.BatchCode); len(batchRules) > 0 {
			siblings = batchRules
		}
	}
	existing := make(map[string]model.Rules, len(siblings))
	siblingCodes := make([]string, 0, len(siblings))
	for _, sibling := range siblings {
		existing[sibling.HostCode] = sibling
		siblingCodes = append(siblingCodes, sibling.RuleCode)
	}

	//单个站点之间搬家时保持原来的规则码（老行为），否则"编辑换个网站"会变成换了一条规则
	movedRuleCode := ""
	if len(siblings) == 1 && len(targetHosts) == 1 && siblings[0].HostCode != targetHosts[0] {
		movedRuleCode = siblings[0].RuleCode
		existing[targetHosts[0]] = siblings[0]
	}

	//同名冲突检查：同一站点下不能有两条不同规则重名。
	//同批次的多站点规则天然同名，必须排除自己和同批次其他站点，否则会误报。
	var dupCount int64
	err = global.GWAF_LOCAL_DB.Model(&model.Rules{}).
		Where("rule_name = ? and host_code IN ? and rule_status <> 999", ruleName, targetHosts).
		Where("rule_code NOT IN ?", siblingCodes).
		Count(&dupCount).Error
	if err != nil {
		response.FailWithMessage("编辑发生错误", c)
		return
	}
	if dupCount > 0 {
		response.FailWithMessage("当前规则名称已经存在", c)
		return
	}

	//目标超过一个站点才需要批次码；原本独立的规则一旦扩成多站点就补上
	batchCode := rule.BatchCode
	if batchCode == "" && len(targetHosts) > 1 {
		batchCode = uuid.GenUUID()
	}

	//按目标集合做差异同步：留着的更新内容、新增的插入、取消的软删除
	keep := make(map[string]bool, len(targetHosts))
	for _, hostCode := range targetHosts {
		keep[hostCode] = true
	}
	var removeCodes []string
	for _, sibling := range siblings {
		if !keep[sibling.HostCode] && sibling.RuleCode != movedRuleCode {
			removeCodes = append(removeCodes, sibling.RuleCode)
		}
	}

	//有效状态沿用旧值，前端没传就保持原样
	status := req.RuleStatus
	if status != 0 && status != 1 {
		status = rule.RuleStatus
	}

	//手工模式提交内容里的规则名对应本条记录的规则码，同步到别的站点时要逐一改写规则名
	manualBaseName := ""
	if req.IsManualRule == 1 {
		manualBaseName = strings.Replace(rule.RuleCode, "-", "", -1)
	}

	var addBeans []*model.Rules
	for _, hostCode := range targetHosts {
		sibling, ok := existing[hostCode]
		hostRuleCode := uuid.GenUUID()
		if ok {
			hostRuleCode = sibling.RuleCode
		}

		var hostContent string
		if req.IsManualRule == 1 {
			hostContent = rewriteManualRuleName(ruleInfo.RuleContent, manualBaseName, hostRuleCode)
			if err = checkManualRuleContent(ruleHelper, hostContent, hostRuleCode); err != nil {
				response.FailWithMessage(err.Error(), c)
				return
			}
		} else {
			ruleInfo.RuleBase.RuleName = strings.Replace(hostRuleCode, "-", "", -1)
			hostContent, err = ruleTool.GenRuleInfo(ruleInfo, ruleName)
			if err != nil {
				response.FailWithMessage(err.Error(), c)
				return
			}
		}

		if ok {
			if err = wafRuleService.UpdateRuleApi(hostRuleCode, ruleName, hostCode, hostContent, req.RuleJson, req.IsManualRule, status); err != nil {
				response.FailWithMessage("编辑发生错误", c)
				return
			}
		} else {
			addBeans = append(addBeans, wafRuleService.BuildRuleBean(request.WafRuleAddReq{
				RuleJson:     req.RuleJson,
				IsManualRule: req.IsManualRule,
				RuleStatus:   status,
			}, hostRuleCode, ruleName, hostCode, hostContent, batchCode))
		}
	}

	if len(addBeans) > 0 {
		if err = wafRuleService.AddRulesApi(addBeans); err != nil {
			response.FailWithMessage("编辑发生错误", c)
			return
		}
	}
	if len(removeCodes) > 0 {
		if err = wafRuleService.DelRuleCodes(removeCodes); err != nil {
			response.FailWithMessage("编辑发生错误", c)
			return
		}
	}
	//把批次码补给"刚刚从单站点扩成多站点"的原记录
	if batchCode != "" && rule.BatchCode == "" {
		if err = wafRuleService.SetBatchCodeApi(siblingCodes, batchCode); err != nil {
			response.FailWithMessage("编辑发生错误", c)
			return
		}
	}

	//新老站点都要刷新：被取消的站点也要重新加载一次，否则旧规则会在引擎里留着(issue #898)
	notifyHosts := append([]string{}, targetHosts...)
	for _, sibling := range siblings {
		notifyHosts = append(notifyHosts, sibling.HostCode)
	}
	for _, hostCode := range uniqueHostCodes(notifyHosts) {
		w.NotifyWaf(hostCode)
	}
	if len(targetHosts) > 1 {
		response.OkWithMessage(fmt.Sprintf("编辑成功，已同步到 %d 个网站", len(targetHosts)), c)
	} else {
		response.OkWithMessage("编辑成功", c)
	}
}

/*
*
通知到waf引擎实时生效
*/
func (w *WafRuleAPi) NotifyWaf(host_code string) {
	var ruleconfig []model.Rules
	global.GWAF_LOCAL_DB.Where("host_code = ?  and rule_status=1", host_code).Find(&ruleconfig)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeRule,
		Content:  ruleconfig,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

// BatchDelRuleApi 批量删除规则
func (w *WafRuleAPi) BatchDelRuleApi(c *gin.Context) {
	var req request.WafRuleBatchDelReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 多站点规则是按网站拆成多行的，选中任意一行都要连带删除同批次的其他行，
		// 否则会留下只认自己一个站点的半条规则
		req.Codes = wafRuleService.ExpandBatchCodes(req.Codes)

		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafRuleService.GetHostCodesByCodes(req.Codes)
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		// 执行批量删除
		err = wafRuleService.BatchDelApi(req)
		if err != nil {
			response.FailWithMessage("批量删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range uniqueHostCodes(hostCodes) {
				if hostCode != "" {
					w.NotifyWaf(hostCode)
				}
			}
			response.OkWithMessage(fmt.Sprintf("成功删除 %d 条记录", len(req.Codes)), c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelAllRuleApi 删除指定网站的所有规则
func (w *WafRuleAPi) DelAllRuleApi(c *gin.Context) {
	var req request.WafRuleDelAllReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafRuleService.GetHostCodes()
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		err = wafRuleService.DelAllApi(req)
		if err != nil {
			response.FailWithMessage("全部删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			if len(req.HostCode) > 0 {
				response.OkWithMessage("成功删除该网站的所有规则", c)
			} else {
				response.OkWithMessage("成功删除所有规则", c)
			}
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// WafRulePreViewReq 规则格式预览
func (w *WafRuleAPi) FormatRuleApi(c *gin.Context) {
	ruleHelper := &utils.RuleHelper{}
	var req request.WafRulePreViewReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	var ruleTool = model.RuleTool{}
	ruleInfo, err := ruleTool.LoadRule(req.RuleJson)
	if err != nil {
		response.FailWithMessage("规则解析错误", c)
		return
	}

	// 与新增/编辑保持一致，先校验网站选择
	if ruleInfo.RuleBase.RuleDomainCode == "请选择网站" && req.FormSource != "builder" {
		response.FailWithMessage("请选择网站", c)
		return
	}

	chsName := ruleInfo.RuleBase.RuleName
	ruleInfo.RuleBase.RuleName = strings.Replace(req.RuleCode, "-", "", -1)

	var ruleContent string
	if req.IsManualRule == 1 {
		// 手工模式走合法性校验
		ruleContent = ruleInfo.RuleContent
		if err = checkManualRuleContent(ruleHelper, ruleContent, req.RuleCode); err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
	} else {
		ruleContent, err = ruleTool.GenRuleInfo(ruleInfo, chsName)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
	}

	// 返回格式化内容，供前端展示
	response.OkWithDetailed(gin.H{
		"rule_content": ruleContent,
	}, "获取成功", c)
}

// ModifyRuleStatusApi 修改WAF规则状态
// @Summary      修改WAF规则状态
// @Description  启用或禁用WAF防护规则
// @Tags         网站防护-规则管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafRuleStatusReq  true  "状态参数"
// @Success      200   {object}  response.Response  "状态更新成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/rule/rulestatus [get]
func (w *WafRuleAPi) ModifyRuleStatusApi(c *gin.Context) {
	var req request.WafRuleStatusReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafRuleService.ModifyRuleStatusApi(req)
		if err != nil {
			response.FailWithMessage("更新状态发生错误", c)
		} else {
			//多站点规则整组同步了状态，本批次涉及的网站都要通知引擎重新加载
			ruleCodes := wafRuleService.ExpandBatchCodes([]string{req.CODE})
			hostCodes, _ := wafRuleService.GetHostCodesByCodes(ruleCodes)
			for _, hostCode := range uniqueHostCodes(hostCodes) {
				if hostCode != "" {
					w.NotifyWaf(hostCode)
				}
			}
			response.OkWithMessage("状态更新成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// TestRuleApi 测试规则是否匹配模拟请求
// 处理逻辑与 wafengine.go ServeHTTP 中的 WebLog 构建保持一致
func (w *WafRuleAPi) TestRuleApi(c *gin.Context) {
	var req request.WafRuleTestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数解析失败", c)
		return
	}

	// 1. 生成规则内容（与 AddApi/ModifyRuleApi 逻辑一致）
	var ruleContent string
	if req.IsManualRule == 1 {
		ruleContent = req.RuleContent
	} else {
		var ruleTool = model.RuleTool{}
		ruleInfo, err := ruleTool.LoadRule(req.RuleJson)
		if err != nil {
			response.FailWithMessage("规则解析错误", c)
			return
		}
		chsName := ruleInfo.RuleBase.RuleName
		ruleInfo.RuleBase.RuleName = strings.Replace(req.RuleCode, "-", "", -1)
		ruleContent, err = ruleTool.GenRuleInfo(ruleInfo, chsName)
		if err != nil {
			response.FailWithMessage(err.Error(), c)
			return
		}
	}

	// 2. 初始化规则引擎并加载规则
	ruleHelper := &utils.RuleHelper{}
	ruleHelper.InitRuleEngine()
	err := ruleHelper.LoadRuleString(ruleContent)
	if err != nil {
		response.FailWithMessage("规则加载失败: "+err.Error(), c)
		return
	}

	// 3. 通过IP解析地理位置（与 wafengine.go 第353行一致）
	region := utils.GetCountry(req.TestSrcIP)
	// region 返回格式: [国家, ISP, 省份, 城市, ...]
	country := ""
	province := ""
	city := ""
	if len(region) > 0 {
		country = region[0]
	}
	if len(region) > 2 {
		province = region[2]
	}
	if len(region) > 3 {
		city = region[3]
	}

	// 4. URL解码处理（与 wafengine.go 第358行一致）
	decodedRawQuery := ""
	decodedURL := req.TestURL
	if strings.Contains(req.TestURL, "?") {
		parts := strings.SplitN(req.TestURL, "?", 2)
		if len(parts) == 2 {
			decodedRawQuery = wafhttpcore.WafHttpCoreUrlEncode(parts[1], 10)
			decodedURL = parts[0] + "?" + decodedRawQuery
		}
	}

	// 5. 构建 WebLog（字段与 wafengine.go 第360-395行保持一致）
	weblog := &innerbean.WebLog{
		SRC_IP:     req.TestSrcIP,
		HOST:       req.TestHost,
		URL:        decodedURL,
		RawQuery:   decodedRawQuery,
		METHOD:     req.TestMethod,
		USER_AGENT: req.TestUserAgent,
		REFERER:    req.TestReferer,
		HEADER:     req.TestHeader,
		COOKIES:    req.TestCookies,
		BODY:       req.TestBody,
		COUNTRY:    country,
		PROVINCE:   province,
		CITY:       city,
	}

	// 6. 执行规则匹配
	ruleMatches, err := ruleHelper.Match("MF", weblog)
	if err != nil {
		response.FailWithMessage("规则匹配失败: "+err.Error(), c)
		return
	}

	// 7. 构建响应
	var matchedRules []string
	var matchedRuleDetails []gin.H
	for _, r := range ruleMatches {
		matchedRules = append(matchedRules, r.RuleDescription)

		//把每条命中规则真正生效的动作返回给前端。规则内容里可能混着用户/攻击者可控的文本，
		//这里展示的是引擎实际认定的动作，保存前点一下测试就能看出规则有没有被写歪。
		action := ruleHelper.GetRuleAction(r.RuleName)
		matchedRuleDetails = append(matchedRuleDetails, gin.H{
			"rule_name":        r.RuleName,
			"rule_description": r.RuleDescription,
			"salience":         r.Salience,
			"action":           action.Action,
			"skip_modules":     action.SkipModules,
		})
	}

	//多条规则命中时，最终生效的动作
	effectiveAction := ""
	var effectiveSkipModules []string
	if len(ruleMatches) > 0 {
		info := ruleHelper.GetRuleAction(ruleMatches[0].RuleName)
		effectiveAction = info.Action
		effectiveSkipModules = info.SkipModules
	}

	response.OkWithDetailed(gin.H{
		"is_match":               len(ruleMatches) > 0,
		"matched_rules":          matchedRules,
		"matched_rule_details":   matchedRuleDetails,
		"effective_action":       effectiveAction,
		"effective_skip_modules": effectiveSkipModules,
		"parsed_country":         country,
		"parsed_province":        province,
		"parsed_city":            city,
	}, "测试完成", c)
}

// AiGenRuleApi 用后台配置的 AI 生成一条自定义规则
// 生成后在服务端做校验（单条规则 + 语法编译 + 动作合法），不通过就把错误喂回模型重试，
// 返回时尽量保证规则可直接编译落地，且不会被注入成放行规则。
// RuleAiPromptApi 返回"复制给AI"的提示词（唯一来源在后端 api/waf_gpt.go，前端直接取用）
func (w *WafRuleAPi) RuleAiPromptApi(c *gin.Context) {
	response.OkWithDetailed(GetRuleAiPrompt(c.Query("lang")), "获取成功", c)
}

func (w *WafRuleAPi) AiGenRuleApi(c *gin.Context) {
	var req request.WafGptRuleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数解析失败", c)
		return
	}
	intent := strings.TrimSpace(req.Intent)
	if intent == "" {
		response.FailWithMessage("请填写你想要的防护需求", c)
		return
	}
	if !IsGPTConfigured() {
		response.FailWithMessage("尚未配置AI密钥，请到【系统配置】填写 gpt_url / gpt_token / gpt_model", c)
		return
	}

	sysPrompt := ruleGenSystemPromptZH
	if strings.HasPrefix(strings.ToLower(req.Lang), "en") {
		sysPrompt = ruleGenSystemPromptEN
	}
	messages := []model.GptMessage{
		{Role: "system", Content: sysPrompt},
		{Role: "user", Content: intent},
	}

	ruleHelper := &utils.RuleHelper{}
	const maxAttempts = 3
	var ruleContent string
	var lastErr string
	valid := false
	attempts := 0

	for attempts < maxAttempts {
		attempts++
		out, err := callGPTOnce(messages)
		if err != nil {
			response.FailWithMessage("AI 请求失败: "+err.Error(), c)
			return
		}
		// 归一化（补动作分号等），再校验
		ruleContent = normalizeGeneratedRule(out)

		// 服务端校验闭环
		if n := utils.CountRuleBlocks(ruleContent); n != 1 {
			lastErr = "必须且只能生成一条规则"
		} else if err := ruleHelper.CheckRuleAvailable(ruleContent); err != nil {
			lastErr = "规则语法有误: " + err.Error()
		} else if _, err := utils.ExtractRuleActionForCheck(ruleContent); err != nil {
			lastErr = err.Error()
		} else {
			valid = true
			lastErr = ""
			break
		}

		// 修复重试：把上次输出和具体错误喂回模型，并强调常见坑
		messages = append(messages,
			model.GptMessage{Role: "assistant", Content: out},
			model.GptMessage{Role: "user", Content: "上面的规则有问题：" + lastErr + "。请修正后只输出规则文本，不要解释。注意：then 里的动作必须以分号结尾(如 RF.Deny(); )，只能有一条规则。"},
		)
	}

	action := utils.RuleActionDeny
	if valid {
		if info, err := utils.ExtractRuleActionForCheck(ruleContent); err == nil && info.Action != "" {
			action = info.Action
		}
	}

	response.OkWithDetailed(gin.H{
		"rule_content": ruleContent, // 生成的规则文本
		"valid":        valid,       // 是否通过服务端校验
		"action":       action,      // 生效动作
		"error":        lastErr,     // 未通过时的原因
		"attempts":     attempts,    // 实际尝试次数
	}, "生成完成", c)
}
