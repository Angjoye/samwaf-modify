package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafsec"
	"errors"
	"fmt"
	"strings"
	"time"
)

type WafSystemConfigService struct{}

var WafSystemConfigServiceApp = new(WafSystemConfigService)

// ConfigClearSentinel 前端要显式清空某个密钥类配置时提交的特殊值。
// 因为“留空=保持原值不变”（防止只改备注把密钥冲掉），清空必须走独立标记。
const ConfigClearSentinel = "__SAMWAF_CLEAR__"

// IsSensitiveConfigItem 判断某配置项是否为密钥类（需加密落库、脱敏回显、写保护）。
// 权威清单在 model 层（service 与 wafdb 迁移共用，避免两处漂移）。
func IsSensitiveConfigItem(item string) bool {
	return model.IsSensitiveConfigItem(item)
}

// encConfigValue / decConfigValue 密钥类配置值的落库加解密（每实例 DEK，swk1 前缀）。
// 非密钥项原样返回，行为不变。
//
// 加密失败时退回明文并告警，而不是让保存失败：配置页是运维自救入口，不能因加密不可用锁死；
// 下次启动的存量迁移会把这类明文行重新加密，可自愈。
func encConfigValue(item, plain string) string {
	if plain == "" || !model.IsSensitiveConfigItem(item) {
		return plain
	}
	// 防御：哨兵值代表“清空”，任何路径都不该把它当密钥本身加密落库。
	if plain == ConfigClearSentinel {
		return ""
	}
	enc, err := wafsec.DataEncrypt(plain)
	if err != nil || enc == "" {
		zlog.Error("配置项加密失败，暂以原值落库", "item", item, "err", err)
		return plain
	}
	return enc
}

// decConfigValue 读出明文：swk1 走 DEK 解；无前缀视为升级前的明文，原样返回（存量兜底）。
func decConfigValue(item, stored string) string {
	if stored == "" || !model.IsSensitiveConfigItem(item) {
		return stored
	}
	if !wafsec.IsDataKeyCiphertext(stored) {
		return stored
	}
	plain, err := wafsec.DataDecrypt(stored, global.GWAF_COMMUNICATION_KEY)
	if err != nil {
		zlog.Error("配置项解密失败", "item", item, "err", err)
		return ""
	}
	return plain
}

// decryptConfigBean 就地把 bean 的 Value 还原为明文（读取路径统一入口）。
func decryptConfigBean(bean *model.SystemConfig) {
	if bean == nil {
		return
	}
	bean.Value = decConfigValue(bean.Item, bean.Value)
}

// MaskSensitiveConfig 对密钥类配置项抹空 Value 并置 HasValue，供页面列表/详情接口使用。
// 只处理页面回显，绝不改动库内数据；内部读取真实值走 GetDetailByItemApi 等 getter，不经此。
func MaskSensitiveConfig(bean *model.SystemConfig) {
	if bean == nil || !IsSensitiveConfigItem(bean.Item) {
		return
	}
	bean.IsSensitive = true
	bean.HasValue = strings.TrimSpace(bean.Value) != ""
	bean.Value = ""
}

func (receiver *WafSystemConfigService) AddApi(wafSystemConfigAddReq request.WafSystemConfigAddReq) error {
	// 幂等保护：先检查 item 是否已存在，存在则跳过，防止重复插入
	var existing model.SystemConfig
	result := global.GWAF_LOCAL_DB.Where("item = ?", wafSystemConfigAddReq.Item).First(&existing)
	if result.Error == nil && existing.Id != "" {
		// 已存在，跳过插入
		return nil
	}
	var bean = &model.SystemConfig{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		ItemClass: wafSystemConfigAddReq.ItemClass,
		Item:      wafSystemConfigAddReq.Item,
		Value:     encConfigValue(wafSystemConfigAddReq.Item, wafSystemConfigAddReq.Value),
		IsSystem:  "0",
		Remarks:   wafSystemConfigAddReq.Remarks,
		HashInfo:  "",
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafSystemConfigService) CheckIsExistApi(wafSystemConfigAddReq request.WafSystemConfigAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.SystemConfig{}, "item = ? ", wafSystemConfigAddReq.Item).Error
}
func (receiver *WafSystemConfigService) ModifyApi(req request.WafSystemConfigEditReq) error {
	var sysConfig model.SystemConfig
	global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Find(&sysConfig)
	if req.Id != "" && req.Item != req.Item {
		return errors.New("当前配置已经存在")
	}
	editMap := map[string]interface{}{
		"Item":        req.Item,
		"ItemClass":   req.ItemClass,
		"Value":       encConfigValue(req.Item, req.Value),
		"Remarks":     req.Remarks,
		"ItemType":    req.ItemType,
		"Options":     req.Options,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}

	err := global.GWAF_LOCAL_DB.Model(model.SystemConfig{}).Where("id = ?", req.Id).Updates(editMap).Error

	return err
}

// ModifyByItemApi 通过 item 修改系统配置的 value
func (receiver *WafSystemConfigService) ModifyByItemApi(req request.WafSystemConfigEditByItemReq) error {
	var sysConfig model.SystemConfig
	err := global.GWAF_LOCAL_DB.Where("item = ?", req.Item).First(&sysConfig).Error
	if err != nil {
		return errors.New("配置项不存在")
	}

	editMap := map[string]interface{}{
		"Value":       encConfigValue(req.Item, req.Value),
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}

	err = global.GWAF_LOCAL_DB.Model(model.SystemConfig{}).Where("item = ?", req.Item).Updates(editMap).Error

	return err
}

// SyncMetaByItemApi 只同步配置项的说明性字段（分类/类型/可选项/备注），不动 Value。
// 用途：配置项的说明文案会随版本演进，而存量库里的行是首次写入时的老文案，
// 页面上一直显示过时说明（例如令牌有效期的"默认5分钟"）。这里让描述跟着代码走，
// 用户设置过的值不受影响。
func (receiver *WafSystemConfigService) SyncMetaByItemApi(item string, itemClass string, itemType string, options string, remarks string) error {
	editMap := map[string]interface{}{
		"item_class":  itemClass,
		"item_type":   itemType,
		"options":     options,
		"remarks":     remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	return global.GWAF_LOCAL_DB.Model(model.SystemConfig{}).Where("item = ?", item).Updates(editMap).Error
}

// 以下 Get* 一律返回【明文】Value：密钥类配置在库里是 swk1 密文，读取时统一解密，
// 让所有调用方（内部逻辑与 API 层）拿到的都是可直接使用的值。
// 页面回显的脱敏由 API handler 的 MaskSensitiveConfig 单独负责，不在这里做。
func (receiver *WafSystemConfigService) GetDetailApi(req request.WafSystemConfigDetailReq) model.SystemConfig {
	var bean model.SystemConfig
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	decryptConfigBean(&bean)
	return bean
}
func (receiver *WafSystemConfigService) GetDetailByItemApi(req request.WafSystemConfigDetailByItemReq) model.SystemConfig {
	var bean model.SystemConfig
	global.GWAF_LOCAL_DB.Where("Item=?", req.Item).Find(&bean)
	decryptConfigBean(&bean)
	return bean
}
func (receiver *WafSystemConfigService) GetDetailByIdApi(id string) model.SystemConfig {
	var bean model.SystemConfig
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	decryptConfigBean(&bean)
	return bean
}
func (receiver *WafSystemConfigService) GetDetailByItem(item string) model.SystemConfig {
	var bean model.SystemConfig
	global.GWAF_LOCAL_DB.Where("Item=?", item).Find(&bean)
	decryptConfigBean(&bean)
	return bean
}
func (receiver *WafSystemConfigService) GetListApi(req request.WafSystemConfigSearchReq) ([]model.SystemConfig, int64, error) {
	var list []model.SystemConfig
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""
	if len(req.Item) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " item=? "
	}
	if len(req.Remarks) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " remarks like ? "
	}
	//where字段赋值
	if len(req.Item) > 0 {
		whereValues = append(whereValues, req.Item)
	}
	if len(req.Remarks) > 0 {
		whereValues = append(whereValues, "%"+req.Remarks+"%")
	}
	global.GWAF_LOCAL_DB.Model(&model.SystemConfig{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.SystemConfig{}).Where(whereField, whereValues...).Count(&total)
	for i := range list {
		decryptConfigBean(&list[i])
	}

	return list, total, nil
}
func (receiver *WafSystemConfigService) DelApi(req request.WafSystemConfigDelReq) error {
	var bean model.SystemConfig
	err := global.GWAF_LOCAL_DB.Where("id = ? and is_system='0'", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ? and is_system='0'", req.Id).Delete(model.SystemConfig{}).Error
	return err
}

// GetAllConfigs 批量获取所有配置项，返回以item为key的map
// 同时会对历史数据中同一 item 存在多条记录的情况进行预处理：保留最新一条，删除其余重复数据
func (receiver *WafSystemConfigService) GetAllConfigs() map[string]model.SystemConfig {
	var configs []model.SystemConfig
	configMap := make(map[string]model.SystemConfig)

	// 一次性查询所有配置
	global.GWAF_LOCAL_DB.Find(&configs)

	// 预处理：检测并清理同一 item 的重复记录（兼容历史版本脏数据）
	// 按 item 分组，如果同一 item 有多条记录，保留 UPDATE_TIME 最新的一条，删除其余
	itemGroup := make(map[string][]model.SystemConfig)
	for _, config := range configs {
		itemGroup[config.Item] = append(itemGroup[config.Item], config)
	}
	for item, group := range itemGroup {
		if len(group) <= 1 {
			continue
		}
		// 找出 UPDATE_TIME 最新的记录作为保留项
		keepIdx := 0
		for i := 1; i < len(group); i++ {
			if time.Time(group[i].UPDATE_TIME).After(time.Time(group[keepIdx].UPDATE_TIME)) {
				keepIdx = i
			}
		}
		// 收集需要删除的记录 ID（排除保留项，且仅删除有 Id 的记录）
		var deleteIds []string
		for i, g := range group {
			if i != keepIdx && g.Id != "" {
				deleteIds = append(deleteIds, g.Id)
			}
		}
		if len(deleteIds) > 0 {
			zlog.Warn(fmt.Sprintf(
				"[配置去重] item=%s 发现 %d 条重复记录，保留 id=%s (UPDATE_TIME=%s)，即将删除 %d 条: %v",
				item,
				len(group),
				group[keepIdx].Id,
				time.Time(group[keepIdx].UPDATE_TIME).Format("2006-01-02 15:04:05"),
				len(deleteIds),
				deleteIds,
			))
			global.GWAF_LOCAL_DB.Where("id IN ?", deleteIds).Delete(&model.SystemConfig{})
		}
		// 将保留项放入 map
		configMap[item] = group[keepIdx]
	}
	// 对于没有重复的 item，直接放入 map
	for _, config := range configs {
		if _, exists := configMap[config.Item]; !exists {
			configMap[config.Item] = config
		}
	}

	// 密钥类配置在库里是密文，这里统一还原为明文再交给调用方。
	// 必须在返回前完成：配置加载会拿 Value 与默认值比较并写入全局变量，
	// 若带着密文出去，全局变量拿到的就是密文而非真正的密钥。
	for item, config := range configMap {
		if model.IsSensitiveConfigItem(item) {
			config.Value = decConfigValue(item, config.Value)
			configMap[item] = config
		}
	}

	return configMap
}
