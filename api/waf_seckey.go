package api

import (
	"SamWaf/model/common/response"
	"SamWaf/wafsec"

	"github.com/gin-gonic/gin"
)

// 传输层 v2（swt2）的握手接口，一次往返完成。
//
// X25519 是双方各出一个公钥、各自算出同一把共享密钥，谁先谁后都行——客户端发的是
// 自己的一次性公钥，而不是"用服务端公钥加密的东西"，所以不必先取服务端公钥。
// （原设计按 RSA 画的时序要先取公钥再包会话密钥，那种顺序才是硬的。）
//
// 端点在登录前开放，因此：响应必须明文（此时双方还没有共享密钥），且只回必要内容，
// 不带版本、构建号等任何额外信息。公钥只在"确实要建会话"时才回，被动扫描拿不到——
// 每实例公钥是稳定的实例标识，能少给一条追踪线索就少给一条。
// 防探测的真手段仍是端口不暴露公网 + IP 白名单，由 Public 路由组的中间件统一保证。
type WafSecKeyApi struct {
}

// maxClientPubLen 是客户端公钥字段的长度上限：32 字节 base64 后 44 字符，
// 留出余量即可，超长直接拒绝，不进解码。
const maxClientPubLen = 64

// SecKeyApi 用客户端一次性公钥协商本次会话密钥，
// 返回服务端公钥（客户端据此算出同一把共享密钥）、keyid 与存活秒数。
func (w *WafSecKeyApi) SecKeyApi(c *gin.Context) {
	var req struct {
		Epk string `json:"epk"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithPlainMessage("参数不正确", c)
		return
	}
	if len(req.Epk) == 0 || len(req.Epk) > maxClientPubLen {
		response.FailWithPlainMessage("参数不正确", c)
		return
	}
	pub, err := wafsec.CommPublicKey()
	if err != nil {
		response.FailWithPlainMessage("传输密钥不可用", c)
		return
	}
	keyid, ttl, err := wafsec.RegisterCommSession(req.Epk)
	if err != nil {
		response.FailWithPlainMessage("握手失败", c)
		return
	}
	response.OkWithPlainData(gin.H{"pub": pub, "keyid": keyid, "ttl": ttl}, c)
}
