// Package migrations nhúng các file SQL migration vào binary để mọi service chạy
// migration mà không cần mang theo thư mục nguồn.
package migrations

import "embed"

// FS chứa toàn bộ file .sql theo thứ tự từ vựng của tên file.
//
//go:embed *.sql
var FS embed.FS
