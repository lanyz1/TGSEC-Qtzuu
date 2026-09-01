// Package main — c2d: Stopen 高性能 C2 监听器守护进程（Go 数据面）
//
// 与 Python 控制面 (FastAPI) 的分工：
//   - c2d 只负责网络监听（TCP 反向 / HTTP Beacon / WebSocket）与加解密
//   - 会话与任务状态全部保存在 Python 端 SQLite，通过内部 bridge API 读写
//   - 线上协议与旧版 Python 实现逐字节兼容（AES-256-CTR: b64(iv||ct)；XOR: b64）
package main

import "fmt"

const (
	// 与 Python 端约定的消息类型
	msgExec      = "exec"
	msgHeartbeat = "heartbeat"
	msgRegister  = "register"
	msgResult    = "result"
)

// version 随协议/行为变更手动递增
const version = "1.0.0"

func mustDecryptOrEmpty(cipher, key, enc string) (string, bool) {
	pt, err := Decrypt(cipher, key, enc)
	if err != nil {
		return "", false
	}
	return pt, true
}

func debugf(format string, args ...interface{}) {
	if debugMode {
		fmt.Printf("[c2d debug] "+format+"\n", args...)
	}
}
