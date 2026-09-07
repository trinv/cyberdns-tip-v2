// Package web nhúng giao diện quản trị vào binary.
//
// Nhúng thay vì phục vụ từ thư mục ngoài: triển khai chỉ còn một container duy nhất,
// không có bước build Node trong CI, và không có tình huống binary với tài nguyên tĩnh
// lệch phiên bản nhau.
package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed index.html app.css app.js
var files embed.FS

// asset là một file đã nạp sẵn kèm ETag.
type asset struct {
	body        []byte
	contentType string
	etag        string
}

// assets nạp một lần lúc khởi động. Ba file này chỉ vài chục KB, và giữ trong bộ nhớ
// tránh được một lượt đọc FS cho mỗi request.
var assets = map[string]asset{
	"/app.css":    load("app.css", "text/css; charset=utf-8"),
	"/app.js":     load("app.js", "text/javascript; charset=utf-8"),
	"/index.html": load("index.html", "text/html; charset=utf-8"),
}

// buildTime là mốc thời gian dùng cho Last-Modified.
var buildTime = time.Now()

func load(name, contentType string) asset {
	body, err := files.ReadFile(name)
	if err != nil {
		panic("web: không đọc được tài nguyên nhúng " + name + ": " + err.Error())
	}
	sum := sha256.Sum256(body)
	return asset{
		body:        body,
		contentType: contentType,
		// ETag là hash nội dung, nên nó chỉ đổi khi file thật sự đổi.
		etag: strconv.Quote(hex.EncodeToString(sum[:16])),
	}
}

// Handler phục vụ giao diện.
//
// Mọi đường dẫn không phải file tĩnh đều trả về index.html: giao diện định tuyến bằng
// hash ở phía client, nên tải lại trang ở bất kỳ màn hình nào cũng phải ra được vỏ ứng
// dụng chứ không phải 404.
//
// Không dùng http.FileServer: nó tự chuyển hướng ".../index.html" về ".../", nên
// đường fallback sẽ trả 301 thay vì nội dung.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if a, ok := assets[path]; ok && path != "/index.html" {
			// Tài nguyên tĩnh nhúng trong binary đổi cùng lúc với binary, nên cache
			// ngắn là đủ và tránh việc người dùng phải xóa cache sau mỗi lần deploy.
			w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
			serve(w, r, a)
			return
		}

		// Bảng quản trị không bao giờ được cache: nó hiển thị trạng thái vận hành hiện
		// tại, và một bản cũ trong cache có thể khiến người vận hành ra quyết định sai.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Giao diện không nhúng gì từ nơi khác và không được đặt trong iframe.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; "+
				"style-src 'self'; img-src 'self' data:; connect-src 'self'; "+
				"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

		serve(w, r, assets["/index.html"])
	})
}

func serve(w http.ResponseWriter, r *http.Request, a asset) {
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("ETag", a.etag)
	http.ServeContent(w, r, "", buildTime, bytes.NewReader(a.body))
}

// AssetNames trả về tên các file được nhúng, dùng cho test và chẩn đoán.
func AssetNames() []string {
	names := make([]string, 0, len(assets))
	for name := range assets {
		names = append(names, strings.TrimPrefix(name, "/"))
	}
	return names
}
