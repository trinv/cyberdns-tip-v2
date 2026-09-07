// Command healthcheck kiểm tra một endpoint HTTP rồi thoát với mã 0 hoặc 1.
//
// Cần một binary riêng vì image chạy trên distroless: không có shell, không có curl,
// không có wget. Thiếu nó thì docker compose không dùng được healthcheck, và
// "depends_on: service_healthy" — thứ khiến kịch bản khởi động đáng tin — mất tác dụng.
//
//	healthcheck http://127.0.0.1:9101/healthz
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "dùng: healthcheck <url>")
		os.Exit(2)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}
}
