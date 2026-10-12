package wsmsg

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafsec"
	"encoding/json"
)

// WebSocket 推送报文的统一组装出口。
//
// 广播不能再像以前那样"加密一次发给所有人"：v2 通道下每条连接的会话密钥不同，
// 必须按连接现组装。调用方把本函数塞进 gwebsocket.BroadcastBuild 的 build 回调即可。
//
// keyID 为空（旧客户端）或其会话已失效时回落 legacy 通道，行为与改造前逐字节一致。

// Build 按目标连接的会话密钥标识组装一条 WebSocket 推送报文。
func Build(keyID string, dataPacket model.MsgDataPacket, cmdType string) ([]byte, error) {
	msgBody, err := json.Marshal(dataPacket)
	if err != nil {
		return nil, err
	}

	var payload string
	if keyID != "" {
		if enc, encErr := wafsec.TransportEncrypt(keyID, msgBody); encErr == nil {
			payload = enc
		}
	}
	if payload == "" {
		payload, _ = wafsec.AesEncrypt(msgBody, global.GWAF_COMMUNICATION_KEY)
	}

	return json.Marshal(model.MsgPacket{
		MsgCode:       "200",
		MsgDataPacket: payload,
		MsgCmdType:    cmdType,
	})
}
