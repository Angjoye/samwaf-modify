package wafenginecore

import (
	"SamWaf/common/diagstat"
)

// RegisterDiagProvider 把引擎内部对象计量注册到运行诊断（main 创建引擎后调用一次）。
// 全部是内存读取：路由快照走无锁 rt()，Transport 池/证书表拿各自的读锁。
func (waf *WafEngine) RegisterDiagProvider() {
	diagstat.Register("engine", func() map[string]int64 {
		table := waf.rt()
		items := map[string]int64{
			"hosts":            int64(len(table.HostTarget)),
			"host_more_domain": int64(len(table.HostTargetMoreDomain)),
			"online_ports":     int64(waf.ServerOnline.Len()),
			"sensitive_words":  int64(len(waf.Sensitive)),
			"engine_status":    int64(waf.EngineCurrentStatus),
		}
		waf.TransportMux.RLock()
		items["transport_pool"] = int64(len(waf.TransportPool))
		waf.TransportMux.RUnlock()
		waf.AllCertificate.Mux.Lock()
		items["certificates"] = int64(len(waf.AllCertificate.Map))
		waf.AllCertificate.Mux.Unlock()
		return items
	})
}
