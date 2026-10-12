package libinjection

import (
	"SamWaf/innerbean"
	"strings"
)

// 独特工具指纹：在 URL 或 User-Agent 命中即判定。
var scannerSigsAny = []string{
	"sqlmap", "nikto", "nessus", "acunetix", "appscan",
	"masscan", "wpscan", "gobuster", "dirbuster", "feroxbuster",
	"ffuf", "wfuzz", "zgrab", "openvas", "w3af",
	"skipfish", "whatweb", "netsparker",
}

// 像普通英文/科学词的工具名(nuclei/nmap/arachni)：只在 UA 里判，避免正常 URL/内容误伤。
var scannerSigsUA = []string{"nuclei", "nmap", "arachni"}

// D2-6：扫描器注入的特定头名/标记(对标 CRS 913110 scanners-headers)。均为扫描器特有、正常
// 流量不出现，命中即判。acunetix/netsparker 等厂商名已由 scannerSigsAny 覆盖(查全部头)。
var scannerHeaderMarkers = []string{
	"x-scan-memo", "x-scanner", "x-wipp", "x-ratproxy-loop", "wvstest", "x-wf-scanner",
}

// D2-7：扫描器探测路径/文件名指纹(对标 CRS 913120 scanners-urls)。不含工具名、但为已知扫描
// 探测串。含工具名的探测路径(acunetix-wvs-test 等)已由 scannerSigsAny 覆盖。
var scannerUrlProbes = []string{
	"w00tw00t", "muieblackcat", "thereisnowaythat-you-canbe-a-search-engine", "cybercop",
}

// IsScan 检测已知扫描/攻击工具。工具名查 URL+全部请求头(含 UA、自定义头)、大小写不敏感；
// 另叠扫描器头名标记(D2-6)与探测路径指纹(D2-7)。未纳入 curl/python-requests/Go-http-client
// 等常见客户端，避免误伤。
func IsScan(log *innerbean.WebLog) bool {
	url := strings.ToLower(log.URL)
	hdr := strings.ToLower(log.HEADER) // joinHeader 结果，含 UA 与自定义头(扫描器工具名常塞头里)
	// 工具名：URL + 全部请求头(D2-6 闭合 header 位缺口)
	hay := url + "\n" + hdr + "\n" + strings.ToLower(log.USER_AGENT)
	for _, s := range scannerSigsAny {
		if strings.Contains(hay, s) {
			return true
		}
	}
	// 易误伤的短工具名(nmap/nuclei/arachni)：仅 UA
	ua := strings.ToLower(log.USER_AGENT)
	for _, s := range scannerSigsUA {
		if strings.Contains(ua, s) {
			return true
		}
	}
	// D2-6 扫描器头名标记
	for _, s := range scannerHeaderMarkers {
		if strings.Contains(hdr, s) {
			return true
		}
	}
	// D2-7 扫描器探测路径指纹
	for _, s := range scannerUrlProbes {
		if strings.Contains(url, s) {
			return true
		}
	}
	return false
}
