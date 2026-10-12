package api

import (
	"testing"

	"SamWaf/service/waf_service"
)

// 密钥字段编辑三态（T34 依赖的后端语义）：
//
//	留空   → 保持原值（后端不回显原文，空提交不能当成清空，否则"只改备注"就会把密钥冲掉）
//	哨兵值 → 显式清空（前端换渠道类型时用它清掉本类型用不到的密钥）
//	新值   → 覆盖
func TestResolveMaskedSecret(t *testing.T) {
	const current = "stored-secret"

	cases := []struct {
		name      string
		submitted string
		current   string
		want      string
	}{
		{"留空保持原值", "", current, current},
		{"留空且原本就没有", "", "", ""},
		{"哨兵显式清空", waf_service.ConfigClearSentinel, current, ""},
		{"哨兵清空空值也安全", waf_service.ConfigClearSentinel, "", ""},
		{"填新值即覆盖", "new-secret", current, "new-secret"},
		{"新值覆盖空值", "new-secret", "", "new-secret"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveMaskedSecret(c.submitted, c.current); got != c.want {
				t.Fatalf("resolveMaskedSecret(%q, %q) = %q，期望 %q",
					c.submitted, c.current, got, c.want)
			}
		})
	}
}

// 系统配置的密钥项同款三态；非密钥项一律原样透传，行为不变。
func TestResolveSensitiveConfigValue(t *testing.T) {
	const sensitiveItem = "gpt_token" // 在敏感清单内
	const plainItem = "gpt_model"     // 普通配置项
	const current = "sk-stored"

	load := func() string { return current }

	if got := resolveSensitiveConfigValue(sensitiveItem, "", load); got != current {
		t.Fatalf("密钥项留空应保持原值: got %q want %q", got, current)
	}
	if got := resolveSensitiveConfigValue(sensitiveItem, waf_service.ConfigClearSentinel, load); got != "" {
		t.Fatalf("密钥项哨兵应清空: got %q", got)
	}
	if got := resolveSensitiveConfigValue(sensitiveItem, "sk-new", load); got != "sk-new" {
		t.Fatalf("密钥项新值应覆盖: got %q", got)
	}

	// 非密钥项：空值就是空值，不能被"保持原值"逻辑改写
	if got := resolveSensitiveConfigValue(plainItem, "", load); got != "" {
		t.Fatalf("非密钥项留空应原样传空: got %q", got)
	}
	if got := resolveSensitiveConfigValue(plainItem, "v2", load); got != "v2" {
		t.Fatalf("非密钥项应原样透传: got %q", got)
	}
}
