package localca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 管理端本地证书签发。
//
// 面向"没有域名、或有域名但不走 ACME"的部署：本机生成一个长效 CA，用它签发管理端
// 服务器证书。管理员把 CA 根证书导入自己电脑一次，之后换 SAN、续期都只重签服务器证书，
// 信任关系不用重新建立——这也是不用单张裸自签的原因。
//
// 为什么自己用标准库签而不是集成 mkcert 之类的工具：签证书本身 crypto/x509 就够了，
// 而那类工具真正值钱的是"自动把根证书装进系统信任库"——SamWaf 跑在服务器上、管理员
// 用自己的电脑访问，在服务器上装信任库对访问方毫无用处，那部分能力在这个部署形态下拿不到。
//
// 密钥落盘口径与 wafsec 的 DEK 一致：CA 私钥 0600、不进数据库、不经 API 回显。

const (
	// caValidYears CA 自身长效：换 SAN / 续期都不动它，用户只需导入一次
	caValidYears = 10
	// serverCertValidDays 服务器证书有效期。**不得超过 825 天**——
	// Apple 平台对任意 CA 签发的 TLS 证书都卡这个上限，超了 Safari/iOS 直接拒绝。
	serverCertValidDays = 397
	// maxServerCertValidDays 硬上限，防止调用方传入更大的值
	maxServerCertValidDays = 825
)

// Paths 描述本地 CA 与管理端证书涉及的文件位置
type Paths struct {
	CAKey   string // CA 私钥（0600，不下发）
	CACert  string // CA 根证书（可下载给管理员导入）
	SrvCert string // 管理端服务器证书
	SrvKey  string // 管理端服务器私钥
}

// DefaultPaths 按安装目录给出默认路径。
// CA 私钥与 wafsec 的密钥同放 data/.keys；证书是公开信息，放 data/ssl/manager。
func DefaultPaths(baseDir string) Paths {
	return Paths{
		CAKey:   filepath.Join(baseDir, "data", ".keys", "manager_ca_key"),
		CACert:  filepath.Join(baseDir, "data", "ssl", "manager", "ca.crt"),
		SrvCert: filepath.Join(baseDir, "data", "ssl", "manager", "domain.crt"),
		SrvKey:  filepath.Join(baseDir, "data", "ssl", "manager", "domain.key"),
	}
}

// CertSummary 证书摘要，供接口回显（不含任何私钥内容）
type CertSummary struct {
	Subject   string    `json:"subject"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names"`
	IPs       []string  `json:"ips"`
	// Fingerprint 是证书 DER 的 SHA-256，冒号分隔大写十六进制——与 Windows 证书管理器、
	// macOS 钥匙串、Firefox 里显示的格式一致。换过 CA 之后信任库里会存在多张同名的
	// "SamWaf Local CA"，只有指纹能区分该删哪张、留哪张，所以必须回显。
	Fingerprint string `json:"fingerprint"`
	// Serial 十六进制序列号，Windows 证书管理器按它排序查找更快
	Serial string `json:"serial"`
}

// EnsureCA 加载本地 CA；不存在则生成一个新的（10 年有效期）。
func EnsureCA(p Paths) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, key, err := loadCA(p)
	if err == nil {
		return cert, key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	return createCA(p)
}

func loadCA(p Paths) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(p.CACert)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(p.CAKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("解析本地CA证书失败: %w", err)
	}
	key, err := parseECKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("解析本地CA私钥失败: %w", err)
	}
	return cert, key, nil
}

func createCA(p Paths) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成本地CA密钥失败: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			// 名字里带上"本地"字样，管理员在系统信任库里一眼能认出这是哪来的
			CommonName:   "SamWaf Local CA",
			Organization: []string{"SamWaf"},
		},
		NotBefore:             now.Add(-5 * time.Minute), // 容忍轻微时钟偏差
		NotAfter:              now.AddDate(caValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // 只签叶子证书，不再签下级 CA
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("签发本地CA证书失败: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	if err := writeKeyFile(p.CAKey, key); err != nil {
		return nil, nil, err
	}
	if err := writePEMFile(p.CACert, "CERTIFICATE", der, 0644); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// IssueServerCert 用本地 CA 给管理端签一张服务器证书，写入 SrvCert / SrvKey。
// sans 是用户实际会用来访问管理端的名字：域名走 DNS SAN、IP 走 IP SAN。
// 现代浏览器只认 SAN 不认 CN，所以漏掉任何一个访问方式都会直接报错。
func IssueServerCert(p Paths, sans []string, validDays int) (*CertSummary, error) {
	dnsNames, ips, err := splitSANs(sans)
	if err != nil {
		return nil, err
	}
	if len(dnsNames) == 0 && len(ips) == 0 {
		return nil, errors.New("至少需要一个访问地址（域名或IP）")
	}
	if validDays <= 0 {
		validDays = serverCertValidDays
	}
	if validDays > maxServerCertValidDays {
		return nil, fmt.Errorf("服务器证书有效期不得超过 %d 天（Apple 平台的硬性上限，超出会被 Safari/iOS 拒绝）", maxServerCertValidDays)
	}

	caCert, caKey, err := EnsureCA(p)
	if err != nil {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成服务器证书密钥失败: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	// CommonName 只是给人看的：现代浏览器完全不看它，校验全靠 SAN
	commonName := "SamWaf Manager"
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	} else if len(ips) > 0 {
		commonName = ips[0].String()
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"SamWaf"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("签发管理端证书失败: %w", err)
	}

	// 证书链里带上 CA：有些客户端不会主动去找签发者
	chain := append(pemBlock("CERTIFICATE", der), pemBlock("CERTIFICATE", caCert.Raw)...)
	if err := writeFileAtomic(p.SrvCert, chain, 0644); err != nil {
		return nil, err
	}
	if err := writeKeyFile(p.SrvKey, key); err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return summarize(cert), nil
}

// RotateCA 作废当前本地 CA 并用新 CA 重新签发管理端证书。
//
// 用途：CA 私钥疑似泄露、或就是想换一把。**这是破坏性操作**——新 CA 与旧的没有任何关系，
// 所有导入过旧根证书的电脑都会立刻对管理端报不安全，必须删旧的、导新的。
// 自建 CA 没有 CRL/OCSP，所谓吊销实际就是这两步：服务端换 CA + 客户端删旧根证书。
func RotateCA(p Paths, sans []string, validDays int) (*CertSummary, error) {
	if len(sans) == 0 {
		// 没显式给就沿用当前证书护住的那些地址，避免换完 CA 反而漏了访问方式
		sans = SANsOf(CurrentServerCert(p))
	}
	if len(sans) == 0 {
		return nil, errors.New("至少需要一个访问地址（域名或IP）")
	}
	// 先删旧 CA，IssueServerCert 里的 EnsureCA 就会生成新的
	if err := removeIfExists(p.CAKey); err != nil {
		return nil, err
	}
	if err := removeIfExists(p.CACert); err != nil {
		return nil, err
	}
	return IssueServerCert(p, sans, validDays)
}

// ClearLocal 删除本地 CA 与它签发的管理端证书。
//
// 调用方必须先确认管理端没在用这张证书（SSL 已关或已切到别的来源），
// 否则重启后加载不到证书文件，HTTPS 直接起不来。
func ClearLocal(p Paths) error {
	// 只在确实是本地 CA 签的时候才动服务器证书——手工上传/ACME 的证书不归这里管
	if IsIssuedByLocalCA(p) {
		if err := removeIfExists(p.SrvCert); err != nil {
			return err
		}
		if err := removeIfExists(p.SrvKey); err != nil {
			return err
		}
	}
	if err := removeIfExists(p.CAKey); err != nil {
		return err
	}
	return removeIfExists(p.CACert)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除 %s 失败: %w", filepath.Base(path), err)
	}
	return nil
}

// CASummary 返回本地 CA 的摘要；CA 不存在返回 nil（不视为错误——用户可能压根没用这条路）
func CASummary(p Paths) *CertSummary {
	certPEM, err := os.ReadFile(p.CACert)
	if err != nil {
		return nil
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil
	}
	return summarize(cert)
}

// ReadCACert 读取 CA 根证书 PEM，供下载给管理员导入
func ReadCACert(p Paths) ([]byte, error) {
	return os.ReadFile(p.CACert)
}

// IsIssuedByLocalCA 判断当前管理端证书是不是本地 CA 签的——
// 续期任务据此决定要不要接管：手工上传的证书和 ACME 证书都不该被我们重签。
func IsIssuedByLocalCA(p Paths) bool {
	caCertPEM, err := os.ReadFile(p.CACert)
	if err != nil {
		return false
	}
	caCert, err := parseCertPEM(caCertPEM)
	if err != nil {
		return false
	}
	srvPEM, err := os.ReadFile(p.SrvCert)
	if err != nil {
		return false
	}
	srvCert, err := parseCertPEM(srvPEM)
	if err != nil {
		return false
	}
	// 比签发者与签名，避免只比名字被同名证书糊弄
	if srvCert.Issuer.CommonName != caCert.Subject.CommonName {
		return false
	}
	return srvCert.CheckSignatureFrom(caCert) == nil
}

// CurrentServerCert 返回当前管理端证书的摘要（不存在返回 nil）
func CurrentServerCert(p Paths) *CertSummary {
	pemBytes, err := os.ReadFile(p.SrvCert)
	if err != nil {
		return nil
	}
	cert, err := parseCertPEM(pemBytes)
	if err != nil {
		return nil
	}
	return summarize(cert)
}

// CheckServerCert 判断当前管理端证书能不能真的把 HTTPS 用起来。
//
// 前三项是 tls 监听自己会踩的：文件在不在、能不能解析、证书与私钥是不是一对——
// 任何一项不成立，tls.LoadX509KeyPair 就直接失败，HTTPS 起不来。
//
// 第四项**有效期是刻意多查的**：LoadX509KeyPair 根本不看有效期，一张过期证书能加载成功、
// HTTPS 也能正常监听，可浏览器一律拒连。那是最难排查的一种失败——服务看着起来了，却没人进得去。
//
// 不限定来源：手工上传的、证书夹绑定的、本地 CA 签的都走这里。
//
// 用在重启之前：启用了 SSL 却拿着一张不可用的证书重启，轻则 HTTPS 起不来，
// 重则叠加"仅允许HTTPS"后管理端只回 503，人就被关在门外了。
func CheckServerCert(p Paths) error {
	certPEM, err := os.ReadFile(p.SrvCert)
	if err != nil {
		return fmt.Errorf("读取证书文件失败(%s): %v", filepath.Base(p.SrvCert), err)
	}
	keyPEM, err := os.ReadFile(p.SrvKey)
	if err != nil {
		return fmt.Errorf("读取私钥文件失败(%s): %v", filepath.Base(p.SrvKey), err)
	}
	// 这一步同时覆盖了"能否解析"和"证书与私钥是否配对"
	if _, err = tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("证书与私钥不可用: %v", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return fmt.Errorf("证书解析失败: %v", err)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("证书尚未生效（生效时间 %s），请检查服务器时间", cert.NotBefore.Format("2006-01-02 15:04:05"))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("证书已于 %s 过期", cert.NotAfter.Format("2006-01-02 15:04:05"))
	}
	return nil
}

// SANsOf 取出证书里的全部访问名，续期时原样沿用
func SANsOf(s *CertSummary) []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.DNSNames)+len(s.IPs))
	out = append(out, s.DNSNames...)
	out = append(out, s.IPs...)
	return out
}

// fingerprintOf 返回 SHA-256 指纹，格式与各平台证书管理器一致（冒号分隔大写十六进制）
func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, 0, len(sum))
	for _, b := range sum {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(parts, ":")
}

func summarize(cert *x509.Certificate) *CertSummary {
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return &CertSummary{
		Subject:     cert.Subject.CommonName,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		DNSNames:    cert.DNSNames,
		IPs:         ips,
		Fingerprint: fingerprintOf(cert),
		Serial:      strings.ToUpper(cert.SerialNumber.Text(16)),
	}
}

// splitSANs 把用户填的一串访问地址分成 DNS 名与 IP 两类
func splitSANs(sans []string) ([]string, []net.IP, error) {
	var dnsNames []string
	var ips []net.IP
	seen := map[string]bool{}

	for _, raw := range sans {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		// 容忍用户填 [::1] 或 https://host 这类形式
		item = strings.TrimPrefix(strings.TrimPrefix(item, "https://"), "http://")
		item = strings.TrimSuffix(item, "/")
		if h, _, err := net.SplitHostPort(item); err == nil && h != "" {
			item = h
		}
		item = strings.Trim(item, "[]")
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true

		if ip := net.ParseIP(item); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if !isValidDNSName(item) {
			return nil, nil, fmt.Errorf("访问地址格式不正确: %s", raw)
		}
		dnsNames = append(dnsNames, item)
	}
	return dnsNames, ips, nil
}

// isValidDNSName 只做基本形态校验：证书 SAN 里塞进奇怪字符没有意义，
// 而且这串内容来自管理端输入，先收一道口。允许通配符前缀。
func isValidDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			if !isAlnum && c != '-' && c != '_' {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("生成证书序列号失败: %w", err)
	}
	return serial, nil
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, errors.New("没有找到证书 PEM 块")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		data = rest
	}
}

func parseECKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("没有找到私钥 PEM 块")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	// 兼容 PKCS#8 封装
	anyKey, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err8 != nil {
		return nil, err
	}
	ecKey, ok := anyKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("私钥不是 ECDSA 类型")
	}
	return ecKey, nil
}

func pemBlock(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func writePEMFile(path, blockType string, der []byte, mode os.FileMode) error {
	return writeFileAtomic(path, pemBlock(blockType, der), mode)
}

func writeKeyFile(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("序列化私钥失败: %w", err)
	}
	return writePEMFile(path, "EC PRIVATE KEY", der, 0600)
}

// writeFileAtomic 先写临时文件再改名：证书与私钥是成对使用的，
// 写到一半被读走会让管理端加载出一个残缺的证书直接起不来。
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
