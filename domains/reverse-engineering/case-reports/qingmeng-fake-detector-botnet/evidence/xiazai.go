package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	// 获取端口参数，默认80
	port := "80"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	// 打印公网地址
	fmt.Print("🌐 公网地址: ")
	publicIP := getPublicIP()
	fmt.Printf("http://%s:%s/\n", publicIP, port)

	// 支持当前目录文件访问
	http.Handle("/", logRequest(http.StripPrefix("/", http.FileServer(http.Dir("./")))))

	// 支持 ./web 目录文件访问
	http.Handle("/web/", logRequest(http.StripPrefix("/web/", http.FileServer(http.Dir("./web")))))

	fmt.Println("📡 文件服务已启动，访问上方地址查看和下载文件。")

	// 启动服务器并输出错误
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		fmt.Println("启动服务器失败:", err)
	}
}

// 获取公网IP并缓存到 /tmp/public_ip.txt
func getPublicIP() string {
	ipBytes, err := os.ReadFile("/tmp/public_ip.txt")
	if err == nil {
		return strings.TrimSpace(string(ipBytes))
	}
	out, err := exec.Command("curl", "-s", "ifconfig.me").Output()
	if err != nil {
		fmt.Println("无法获取公网IP，使用0.0.0.0")
		return "0.0.0.0"
	}
	publicIP := strings.TrimSpace(string(out))
	_ = os.WriteFile("/tmp/public_ip.txt", []byte(publicIP), 0644)
	return publicIP
}

// HTTP请求日志中间件
func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 记录响应状态码
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: 200}
		handler.ServeHTTP(lrw, r)

		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Printf("[%s] %s %s %d (%v)\n", start.Format("2006-01-02 15:04:05"), clientIP, r.URL.Path, lrw.statusCode, time.Since(start))
	})
}

// 自定义 ResponseWriter 用于记录状态码
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}