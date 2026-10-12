package localca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testPaths(t *testing.T) Paths {
	t.Helper()
	return DefaultPaths(t.TempDir())
}

// 最要紧的一条：签出来的东西必须能真的被 TLS 用起来，
// 而不是"看起来像证书"。这里直接走 tls.X509KeyPair + 校验链。
func TestIssuedCertIsUsableAndChainsToCA(t *testing.T) {
	p := testPaths(t)

	summary, err := IssueServerCert(p, []string{"waf.example.com", "192.168.1.10", "127.0.0.1"}, 0)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	certPEM, err := os.ReadFile(p.SrvCert)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(p.SrvKey)
	if err != nil {
		t.Fatal(err)
	}
	// 证书与私钥必须配对，否则管理端启动时加载会直接失败
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("证书与私钥不配对: %v", err)
	}

	caPEM, err := ReadCACert(p)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA 证书无法解析")
	}
	leaf, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	// 导入根证书后，浏览器就是这样校验的：链能验通 + 访问名在 SAN 里
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "waf.example.com"}); err != nil {
		t.Fatalf("按域名校验失败: %v", err)
	}
	if err := leaf.VerifyHostname("192.168.1.10"); err != nil {
		t.Fatalf("按IP校验失败: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("按回环IP校验失败: %v", err)
	}

	// 摘要要如实反映 SAN 分类
	if len(summary.DNSNames) != 1 || summary.DNSNames[0] != "waf.example.com" {
		t.Fatalf("DNS SAN 不对: %v", summary.DNSNames)
	}
	if len(summary.IPs) != 2 {
		t.Fatalf("IP SAN 数量不对: %v", summary.IPs)
	}
}

// 漏掉访问方式是这类证书最常见的坑：只写域名的话用 IP 访问必报错。
func TestHostnameNotInSANIsRejected(t *testing.T) {
	p := testPaths(t)
	if _, err := IssueServerCert(p, []string{"waf.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(p.SrvCert)
	leaf, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("192.168.1.10"); err == nil {
		t.Fatal("没写进 SAN 的 IP 竟然校验通过了")
	}
}

// 重签只换服务器证书，CA 必须原样不动——否则用户导入过的信任会作废
func TestReissueKeepsSameCA(t *testing.T) {
	p := testPaths(t)

	if _, err := IssueServerCert(p, []string{"a.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	caFirst, err := ReadCACert(p)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := IssueServerCert(p, []string{"b.example.com", "10.0.0.5"}, 0); err != nil {
		t.Fatal(err)
	}
	caSecond, err := ReadCACert(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(caFirst) != string(caSecond) {
		t.Fatal("重签之后 CA 变了——用户导入过的根证书会失效")
	}

	// 新证书要能用新的 SAN 校验，且仍挂在同一个 CA 下
	certPEM, _ := os.ReadFile(p.SrvCert)
	leaf, err := parseCertPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("b.example.com"); err != nil {
		t.Fatalf("新 SAN 校验失败: %v", err)
	}
	if !IsIssuedByLocalCA(p) {
		t.Fatal("重签后没被认成本地 CA 签发")
	}
}

// 825 天是 Apple 平台的硬上限，必须在签发前就挡住
func TestValidDaysUpperBound(t *testing.T) {
	p := testPaths(t)
	if _, err := IssueServerCert(p, []string{"a.example.com"}, 826); err == nil {
		t.Fatal("超过 825 天的有效期竟然被接受")
	}
	if _, err := IssueServerCert(p, []string{"a.example.com"}, maxServerCertValidDays); err != nil {
		t.Fatalf("恰好 %d 天应当允许: %v", maxServerCertValidDays, err)
	}
}

// 默认有效期要落在上限内，且 CA 必须显著长于服务器证书
func TestDefaultValidity(t *testing.T) {
	p := testPaths(t)
	summary, err := IssueServerCert(p, []string{"a.example.com"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	days := summary.NotAfter.Sub(summary.NotBefore).Hours() / 24
	if days > maxServerCertValidDays {
		t.Fatalf("默认有效期 %.0f 天超过上限", days)
	}
	ca := CASummary(p)
	if ca == nil {
		t.Fatal("CA 摘要为空")
	}
	if !ca.NotAfter.After(summary.NotAfter.AddDate(1, 0, 0)) {
		t.Fatal("CA 有效期没有显著长于服务器证书，会导致续期时链先过期")
	}
}

func TestSANParsing(t *testing.T) {
	dns, ips, err := splitSANs([]string{
		" waf.example.com ",      // 前后空格
		"https://a.example.com/", // 带协议与斜杠
		"192.168.1.10:26666",     // 带端口
		"[::1]",                  // IPv6 字面量
		"waf.example.com",        // 重复
		"",                       // 空项
	})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(dns) != 2 {
		t.Fatalf("期望 2 个域名，实际 %v", dns)
	}
	if len(ips) != 2 {
		t.Fatalf("期望 2 个IP，实际 %v", ips)
	}
}

func TestSANRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"a b.com", "-bad.com", "bad-.com", "有中文.com"} {
		if _, _, err := splitSANs([]string{bad}); err == nil {
			t.Fatalf("非法访问地址被接受: %q", bad)
		}
	}
	if _, err := IssueServerCert(testPaths(t), []string{"  ", ""}, 0); err == nil {
		t.Fatal("空 SAN 列表竟然签发成功")
	}
}

// 手工上传/ACME 的证书不能被误判成本地 CA 签的，否则续期任务会去重签别人的证书
func TestIsIssuedByLocalCARejectsForeignCert(t *testing.T) {
	p := testPaths(t)
	if _, err := IssueServerCert(p, []string{"a.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	if !IsIssuedByLocalCA(p) {
		t.Fatal("自己签的没被认出来")
	}

	// 另起一套 CA 签一张，冒充放到管理端证书位置
	other := testPaths(t)
	if _, err := IssueServerCert(other, []string{"a.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	foreign, err := os.ReadFile(other.SrvCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SrvCert, foreign, 0644); err != nil {
		t.Fatal(err)
	}
	if IsIssuedByLocalCA(p) {
		t.Fatal("别的 CA 签的证书被误判为本地 CA 签发（只比名字就会这样）")
	}
}

// CA 私钥必须 0600，且证书是公开的可以放宽
func TestKeyFilePermission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 的文件模式位不反映真实 ACL，跳过")
	}
	p := testPaths(t)
	if _, err := IssueServerCert(p, []string{"a.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p.CAKey, p.SrvKey} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s 权限应为 0600，实际 %o", path, info.Mode().Perm())
		}
	}
}

// 没有证书时各查询接口要安静地返回空，不能报错或 panic
func TestSummariesWhenAbsent(t *testing.T) {
	p := testPaths(t)
	if CASummary(p) != nil {
		t.Fatal("不存在的 CA 应返回 nil")
	}
	if CurrentServerCert(p) != nil {
		t.Fatal("不存在的服务器证书应返回 nil")
	}
	if IsIssuedByLocalCA(p) {
		t.Fatal("什么都没有时不该判为本地 CA 签发")
	}
	if got := SANsOf(nil); got != nil {
		t.Fatalf("nil 摘要应返回 nil，实际 %v", got)
	}
}

// 时钟略有偏差时刚签的证书也应立即可用
func TestNotBeforeToleratesClockSkew(t *testing.T) {
	p := testPaths(t)
	summary, err := IssueServerCert(p, []string{"a.example.com"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.NotBefore.Before(time.Now()) {
		t.Fatal("NotBefore 不早于当前时间，时钟稍有偏差就会\"证书尚未生效\"")
	}
}

// 轮换必须真的换掉 CA——否则"吊销"就是假的
func TestRotateCAReplacesCA(t *testing.T) {
	p := testPaths(t)
	if _, err := IssueServerCert(p, []string{"a.example.com", "10.0.0.5"}, 0); err != nil {
		t.Fatal(err)
	}
	caOld, _ := ReadCACert(p)
	certOld, _ := os.ReadFile(p.SrvCert)

	// 不传 SAN：应沿用当前证书护住的地址，避免换完 CA 反而漏了访问方式
	summary, err := RotateCA(p, nil, 0)
	if err != nil {
		t.Fatalf("轮换失败: %v", err)
	}
	caNew, _ := ReadCACert(p)
	if string(caOld) == string(caNew) {
		t.Fatal("轮换后 CA 没变——旧根证书仍然有效，等于没吊销")
	}
	certNew, _ := os.ReadFile(p.SrvCert)
	if string(certOld) == string(certNew) {
		t.Fatal("轮换后服务器证书没变")
	}
	if len(summary.DNSNames) != 1 || len(summary.IPs) != 1 {
		t.Fatalf("没沿用原有的访问地址: dns=%v ips=%v", summary.DNSNames, summary.IPs)
	}

	// 新证书必须挂在新 CA 下，且用旧 CA 验不过
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caOld) {
		t.Fatal("旧 CA 解析失败")
	}
	leaf, err := parseCertPEM(certNew)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "a.example.com"}); err == nil {
		t.Fatal("新证书竟然能用旧 CA 验通过")
	}
	if !IsIssuedByLocalCA(p) {
		t.Fatal("轮换后没被认成本地 CA 签发")
	}
}

// 清除要把 CA 与它签的证书一并删掉，且可重复执行不报错
func TestClearLocalRemovesEverything(t *testing.T) {
	p := testPaths(t)
	if _, err := IssueServerCert(p, []string{"a.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := ClearLocal(p); err != nil {
		t.Fatalf("清除失败: %v", err)
	}
	for _, f := range []string{p.CAKey, p.CACert, p.SrvCert, p.SrvKey} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("%s 没被删掉", f)
		}
	}
	// 幂等：再清一次不应报错
	if err := ClearLocal(p); err != nil {
		t.Fatalf("重复清除应当无害: %v", err)
	}
}

// 手工上传/ACME 的证书不归本地 CA 管，清除时绝不能连它一起删
func TestClearLocalKeepsForeignServerCert(t *testing.T) {
	p := testPaths(t)
	if _, err := IssueServerCert(p, []string{"a.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	// 用另一套 CA 签一张放到管理端证书位置，模拟"用户改用了手工上传的证书"
	other := testPaths(t)
	if _, err := IssueServerCert(other, []string{"a.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	foreign, _ := os.ReadFile(other.SrvCert)
	if err := os.WriteFile(p.SrvCert, foreign, 0644); err != nil {
		t.Fatal(err)
	}

	if err := ClearLocal(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.SrvCert); os.IsNotExist(err) {
		t.Fatal("把不属于本地 CA 的管理端证书也删掉了")
	}
	if _, err := os.Stat(p.CACert); !os.IsNotExist(err) {
		t.Fatal("本地 CA 没被删掉")
	}
}

// CheckServerCert 是"重启会不会把人关在门外"的判定依据，几条失败路径都要认得出来
func TestCheckServerCertDetectsUnusable(t *testing.T) {
	dir := t.TempDir()
	p := DefaultPaths(dir)

	// 1) 什么都没有
	if err := CheckServerCert(p); err == nil {
		t.Fatal("证书文件不存在时应当报错")
	}

	// 2) 正常签发的证书应当通过
	if _, err := IssueServerCert(p, []string{"localhost", "127.0.0.1"}, 0); err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if err := CheckServerCert(p); err != nil {
		t.Fatalf("刚签发的证书应当可用，却报: %v", err)
	}

	// 3) 私钥换成另一张证书的——最典型的"上传时贴错文件"
	other := DefaultPaths(t.TempDir())
	if _, err := IssueServerCert(other, []string{"localhost"}, 0); err != nil {
		t.Fatalf("签发对照证书失败: %v", err)
	}
	otherKey, err := os.ReadFile(other.SrvKey)
	if err != nil {
		t.Fatalf("读取对照私钥失败: %v", err)
	}
	if err := os.WriteFile(p.SrvKey, otherKey, 0600); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if err := CheckServerCert(p); err == nil {
		t.Fatal("证书与私钥不配对时应当报错")
	}

	// 4) 证书内容损坏
	if err := os.WriteFile(p.SrvCert, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if err := CheckServerCert(p); err == nil {
		t.Fatal("证书损坏时应当报错")
	}
}

// 过期证书必须被判为不可用：它是"管理端重启后打不开"最常见的原因
func TestCheckServerCertRejectsExpired(t *testing.T) {
	dir := t.TempDir()
	p := DefaultPaths(dir)

	caCert, caKey, err := EnsureCA(p)
	if err != nil {
		t.Fatalf("建CA失败: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	serial, err := randomSerial()
	if err != nil {
		t.Fatalf("生成序列号失败: %v", err)
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.AddDate(0, 0, -10),
		NotAfter:     now.AddDate(0, 0, -1), // 昨天就过期了
		DNSNames:     []string{"localhost"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if err := writeFileAtomic(p.SrvCert, pemBlock("CERTIFICATE", der), 0644); err != nil {
		t.Fatalf("写证书失败: %v", err)
	}
	if err := writeKeyFile(p.SrvKey, key); err != nil {
		t.Fatalf("写私钥失败: %v", err)
	}

	err = CheckServerCert(p)
	if err == nil {
		t.Fatal("已过期的证书应当被判为不可用")
	}
	if !strings.Contains(err.Error(), "过期") {
		t.Fatalf("错误信息要说清是过期，实际: %v", err)
	}
}
