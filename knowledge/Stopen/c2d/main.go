package main

// c2d — Stopen C2 监听器守护进程（Go 数据面）
//
// 用法:
//   c2d --addr 127.0.0.1:8477 --ctl-token <token>
//
// 控制面 API（仅本机）:
//   GET    /ctl/health               -> {"status":"ok",...}
//   POST   /ctl/config               -> {backend_url, backend_token}
//   POST   /ctl/listeners            -> 启动 {id,type,host,port,secret,encryption}
//   DELETE /ctl/listeners/{id}       -> 停止
//   GET    /ctl/listeners            -> 运行中列表
import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"context"
	"time"
)

var (
	debugMode bool
)

type manager struct {
	mu        sync.Mutex
	listeners map[string]*listenerMeta
	cancels   map[string]context.CancelFunc
	bridge    *Bridge
}

func newManager() *manager {
	return &manager{
		listeners: map[string]*listenerMeta{},
		cancels:   map[string]context.CancelFunc{},
	}
}

var supportedTypes = map[string]bool{"tcp": true, "http": true, "ws": true}

func (m *manager) start(l *listenerMeta) error {
	if !supportedTypes[l.Type] {
		return fmt.Errorf("不支持的监听器类型: %s", l.Type)
	}
	if l.Encrypt == "" {
		l.Encrypt = encAES
	}
	m.mu.Lock()
	if _, exists := m.listeners[l.ID]; exists {
		m.mu.Unlock()
		return fmt.Errorf("监听器已在运行: %s", l.ID)
	}
	m.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	var err error
	switch l.Type {
	case "tcp":
		err = startTCP(ctx, l, m.bridge)
	case "http":
		err = startHTTP(ctx, l, m.bridge)
	case "ws":
		err = startWS(ctx, l, m.bridge)
	}
	if err != nil {
		cancel()
		return err
	}
	m.mu.Lock()
	m.listeners[l.ID] = l
	m.cancels[l.ID] = cancel
	m.mu.Unlock()
	logf("监听器已启动: %s (%s://%s:%d, %s)", l.ID, l.Type, l.Host, l.Port, l.Encrypt)
	return nil
}

func (m *manager) stop(id string) bool {
	m.mu.Lock()
	cancel, ok := m.cancels[id]
	if ok {
		delete(m.cancels, id)
		delete(m.listeners, id)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	cancel()
	logf("监听器已停止: %s", id)
	return true
}

func (m *manager) running() []map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []map[string]string{}
	for id, l := range m.listeners {
		out = append(out, map[string]string{"id": id, "type": l.Type, "host": l.Host, "port": itoa(l.Port)})
	}
	return out
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8477", "控制面监听地址（仅本机）")
	ctlToken := flag.String("ctl-token", "", "控制面认证 token（必填）")
	backendURL := flag.String("backend-url", "", "Python 控制面地址（如 http://127.0.0.1:8080）")
	backendToken := flag.String("backend-token", "", "Python 控制面 Bearer Token")
	standalone := flag.Bool("standalone", false, "独立模式：不做后端探活（开发调试）")
	flag.BoolVar(&debugMode, "debug", false, "调试输出")
	flag.Parse()
	if *ctlToken == "" {
		fmt.Fprintln(os.Stderr, "[c2d] 必须提供 --ctl-token")
		os.Exit(1)
	}

	mgr := newManager()
	if *backendURL != "" {
		mgr.bridge = NewBridge(*backendURL, *backendToken)
	}

	// 看门狗：后端持续不可达 60s 自动退出，避免孤儿守护进程占用端口
	if !*standalone && mgr.bridge != nil {
		go func() {
			backendDownSince := time.Time{}
			for {
				time.Sleep(15 * time.Second)
				client := &http.Client{Timeout: 3 * time.Second}
				resp, err := client.Get(mgr.bridge.baseURL + "/api/health")
				if err == nil {
					resp.Body.Close()
					backendDownSince = time.Time{}
					continue
				}
				if backendDownSince.IsZero() {
					backendDownSince = time.Now()
					continue
				}
				if time.Since(backendDownSince) > 60*time.Second {
					logf("后端持续不可达超过 60s，c2d 自动退出")
					os.Exit(0)
				}
			}
		}()
	}

	mux := http.NewServeMux()
	// 统一 token 校验
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-CTL-Token") != *ctlToken {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("/ctl/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok", "version": version, "listeners": len(mgr.running()),
		})
	})

	mux.HandleFunc("/ctl/config", auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			BackendURL   string `json:"backend_url"`
			BackendToken string `json:"backend_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.BackendURL == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mgr.bridge = NewBridge(body.BackendURL, body.BackendToken)
		logf("已连接控制面: %s", body.BackendURL)
		w.Write([]byte(`{"ok":true}`))
	}))

	mux.HandleFunc("/ctl/listeners", auth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"listeners": mgr.running()})
		case http.MethodPost:
			var l listenerMeta
			if err := json.NewDecoder(r.Body).Decode(&l); err != nil || l.ID == "" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if err := mgr.start(&l); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true}`))
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/ctl/listeners/", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/ctl/listeners/")
		if !mgr.stop(id) {
			http.Error(w, "监听器不存在或未运行", http.StatusNotFound)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	logf("c2d v%s 控制面就绪: http://%s", version, *addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[c2d] 控制面启动失败: %v", err)
	}
}
