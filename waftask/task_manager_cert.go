package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/utils"
	"SamWaf/utils/localca"
	"fmt"
	"time"
)

// 管理端证书的到期处理。
//
// 为什么单独一个任务：既有的 SSLExpireCheck 面向"被防护站点的域名列表"，
// 管理端自己的证书（data/ssl/manager/domain.crt）根本不在那张表里，
// 到期了不会有任何人提醒——管理员往往是某天打不开后台才发现。
//
// 三类来源，处理方式各不相同：
//   - 本地 CA 签发：能自己重签，剩余天数不足时**自动续期**，CA 不变故已导入的信任不受影响
//   - 证书夹绑定(ACME)：既有链路已自动续期并刷新，这里不插手，只在日志里留一句
//   - 手工上传：代不了劳，只能按阈值提醒
const (
	// managerCertRenewDays 本地证书剩余天数低于此值即自动重签
	managerCertRenewDays = 30
)

// ManagerCertCheck 检查管理端证书：本地 CA 签的自动续期，其余按阈值提醒。
func ManagerCertCheck() {
	innerLogName := "ManagerCertCheck"
	paths := localca.DefaultPaths(utils.GetCurrentDir())

	current := localca.CurrentServerCert(paths)
	if current == nil {
		// 没配管理端证书是正常状态（默认就是 HTTP），不该刷日志
		return
	}

	daysLeft := int(time.Until(current.NotAfter).Hours() / 24)

	if localca.IsIssuedByLocalCA(paths) {
		if daysLeft > managerCertRenewDays {
			return
		}
		// 沿用原证书的访问地址重签：用户当初填了哪些名字就继续保哪些
		sans := localca.SANsOf(current)
		if len(sans) == 0 {
			zlog.Error(innerLogName, "管理端本地证书没有可用的访问地址，无法自动续期，请到系统配置页重新生成")
			return
		}
		summary, err := localca.IssueServerCert(paths, sans, 0)
		if err != nil {
			zlog.Error(innerLogName, fmt.Sprintf("管理端本地证书自动续期失败: %v", err))
			notifyManagerCertExpire(current.Subject, current.NotAfter, daysLeft, "自动续期失败，请手动处理")
			return
		}
		zlog.Info(innerLogName, fmt.Sprintf("管理端本地证书已自动续期，新到期时间 %s；需要重启管理端后生效",
			summary.NotAfter.Format("2006-01-02 15:04:05")))
		global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.OperatorMessageInfo{
			BaseMessageInfo: innerbean.BaseMessageInfo{
				OperaType: "管理端证书续期",
				Server:    global.GWAF_CUSTOM_SERVER_NAME,
			},
			OperaCnt: fmt.Sprintf("管理端本地证书已自动续期至 %s，重启管理端后生效",
				summary.NotAfter.Format("2006-01-02")),
		})
		return
	}

	// 绑定证书夹的证书由既有 ACME 链路续期并刷新，这里不重复提醒，避免和站点证书的提醒撞车
	if global.GWAF_SSL_BIND_CERT_ID != "" {
		if daysLeft <= 7 {
			zlog.Info(innerLogName, fmt.Sprintf("管理端绑定的证书夹证书剩余 %d 天，等待证书夹自动续期后刷新", daysLeft))
		}
		return
	}

	// 手工上传：只能提醒
	for _, threshold := range []int{30, 7, 1} {
		if daysLeft == threshold {
			notifyManagerCertExpire(current.Subject, current.NotAfter, daysLeft, "请及时更换管理端证书")
			return
		}
	}
	if daysLeft <= 0 {
		notifyManagerCertExpire(current.Subject, current.NotAfter, daysLeft, "管理端证书已过期")
	}
}

func notifyManagerCertExpire(subject string, expireAt time.Time, daysLeft int, hint string) {
	zlog.Info("ManagerCertCheck", fmt.Sprintf("管理端证书 %s 剩余 %d 天（%s）：%s",
		subject, daysLeft, expireAt.Format("2006-01-02"), hint))
	global.GQEQUE_MESSAGE_DB.Enqueue(innerbean.SSLExpireMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{
			OperaType: "管理端证书过期提醒",
			Server:    global.GWAF_CUSTOM_SERVER_NAME,
		},
		Domain:     subject,
		ExpireTime: expireAt.Format("2006-01-02 15:04:05"),
		DaysLeft:   daysLeft,
	})
}
