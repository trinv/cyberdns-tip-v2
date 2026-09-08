package opencti

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Loại sự kiện mà Live Stream phát ra.
const (
	EventCreate = "create"
	EventUpdate = "update"
	EventDelete = "delete"
	EventMerge  = "merge"
	// EventMessage là loại của các sự kiện phát lại khi bắt kịp từ đầu; xử lý như create.
	EventMessage = "message"
	// Hai loại dưới đây chỉ để giữ kết nối, không mang dữ liệu.
	EventHeartbeat = "heartbeat"
	EventConnected = "connected"
)

// Event là một sự kiện đã giải mã.
type Event struct {
	// ID dùng để tiếp tục sau khi mất kết nối.
	ID   string
	Type string

	// Object là đối tượng STIX trong trường "data" của envelope.
	Object map[string]any

	// MergedFrom là các định danh đã bị gộp vào Object, chỉ có ở sự kiện merge.
	//
	// Đây là phần mà connector mẫu của OpenCTI bỏ qua. Không xử lý nó thì sau mỗi lần
	// analyst gộp hai indicator, hàng của định danh cũ nằm lại trong CSDL mà không sự
	// kiện nào còn nhắc tới nó nữa — domain bị chặn vĩnh viễn, không ai truy được vì sao.
	MergedFrom []string
}

// envelope là gói dữ liệu bọc ngoài đối tượng STIX trong trường data của SSE.
type envelope struct {
	Data    map[string]any `json:"data"`
	Message string         `json:"message"`
	Origin  map[string]any `json:"origin"`
	Context struct {
		// Sources là danh sách entity bị gộp đi ở sự kiện merge.
		Sources []map[string]any `json:"sources"`
	} `json:"context"`
	Version string `json:"version"`
}

// ParseEvent giải mã phần data của một khung SSE.
func ParseEvent(id, eventType, data string) (Event, error) {
	ev := Event{ID: id, Type: eventType}

	if eventType == EventHeartbeat || eventType == EventConnected {
		return ev, nil
	}

	var env envelope
	if err := json.Unmarshal([]byte(data), &env); err != nil {
		return ev, fmt.Errorf("opencti: giải mã envelope: %w", err)
	}
	if env.Data == nil {
		return ev, fmt.Errorf("opencti: envelope không có trường data")
	}
	ev.Object = env.Data

	// Với merge, context.sources liệt kê những entity vừa bị gộp đi. Định danh của
	// chúng phải được ánh xạ sang entity còn lại, nếu không sẽ để lại hàng mồ côi.
	for _, src := range env.Context.Sources {
		if id := stringField(src, "id"); id != "" {
			ev.MergedFrom = append(ev.MergedFrom, id)
			continue
		}
		if id := stringField(src, "x_opencti_id"); id != "" {
			ev.MergedFrom = append(ev.MergedFrom, id)
		}
	}

	return ev, nil
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// HasData báo sự kiện có mang đối tượng để xử lý hay không.
func (e Event) HasData() bool {
	return e.Object != nil &&
		e.Type != EventHeartbeat && e.Type != EventConnected
}

// Normalized quy loại sự kiện về một trong bốn loại ta xử lý.
func (e Event) Normalized() string {
	switch e.Type {
	case EventMessage, "":
		// Sự kiện phát lại lúc bắt kịp không có loại; coi như create.
		return EventCreate
	default:
		return e.Type
	}
}

// StreamConfig là cấu hình kết nối Live Stream.
type StreamConfig struct {
	// URL trỏ tới một live stream cụ thể, ví dụ https://opencti/stream/live-abc.
	URL   string
	Token string

	// StartFrom là id sự kiện để tiếp tục. Rỗng nghĩa là bắt đầu từ hiện tại.
	StartFrom string

	// ListenDelete phải BẬT. Tắt nó thì việc analyst xóa một indicator không bao giờ
	// tới được đây, và domain đó bị chặn mãi.
	ListenDelete bool

	// Recover yêu cầu OpenCTI phát lại từ một mốc thời gian, dùng khi consumer đã
	// ngừng lâu hơn thời gian lưu của stream.
	Recover *time.Time

	HTTPClient *http.Client
}

// Handler xử lý một sự kiện. Trả lỗi sẽ dừng vòng lặp stream.
type Handler func(ctx context.Context, ev Event) error

// Listen mở kết nối Live Stream và gọi handler cho từng sự kiện có dữ liệu.
//
// Hàm chặn tới khi ctx bị hủy hoặc kết nối đứt. Bên gọi chịu trách nhiệm thử lại — ở
// đây cố tình không tự kết nối lại để việc ghi lại checkpoint và đo độ trễ nằm gọn một
// chỗ thay vì rải ra hai nơi.
func Listen(ctx context.Context, cfg StreamConfig, h Handler) error {
	if cfg.URL == "" {
		return fmt.Errorf("opencti: thiếu URL stream")
	}

	url := cfg.URL
	if cfg.Recover != nil {
		url += "?recover=" + cfg.Recover.UTC().Format(time.RFC3339)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("opencti: dựng request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("listen-delete", boolHeader(cfg.ListenDelete))
	req.Header.Set("no-dependencies", "true")
	req.Header.Set("with-inferences", "false")
	if cfg.StartFrom != "" {
		req.Header.Set("Last-Event-ID", cfg.StartFrom)
	}

	client := cfg.HTTPClient
	if client == nil {
		// Không đặt Timeout: đây là kết nối chạy dài, và một timeout ở tầng client sẽ
		// cắt ngang stream đang khỏe mạnh.
		client = &http.Client{}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("opencti: kết nối stream: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("opencti: stream trả về HTTP %d", resp.StatusCode)
	}

	return scanSSE(ctx, resp.Body, h)
}

func boolHeader(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// maxEventBytes chặn một khung SSE khổng lồ làm cạn bộ nhớ.
const maxEventBytes = 8 << 20

// scanSSE đọc luồng text/event-stream và gọi handler cho từng khung hoàn chỉnh.
func scanSSE(ctx context.Context, r io.Reader, h Handler) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxEventBytes)

	var id, eventType string
	var data strings.Builder

	flush := func() error {
		if data.Len() == 0 {
			id, eventType = "", ""
			data.Reset()
			return nil
		}

		ev, err := ParseEvent(id, eventType, data.String())
		id, eventType = "", ""
		data.Reset()

		if err != nil {
			// Một khung hỏng không được làm chết cả stream: bỏ qua rồi đi tiếp, còn hơn
			// mất toàn bộ luồng cập nhật vì một sự kiện dị dạng.
			return nil
		}
		if !ev.HasData() {
			return nil
		}
		return h(ctx, ev)
	}

	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}

		line := sc.Text()

		// Dòng trống kết thúc một khung.
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		// Dòng bắt đầu bằng ":" là chú thích giữ kết nối.
		if strings.HasPrefix(line, ":") {
			continue
		}

		field, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimPrefix(value, " ")

		switch field {
		case "id":
			id = value
		case "event":
			eventType = value
		case "data":
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(value)
		}
	}

	if err := sc.Err(); err != nil {
		return fmt.Errorf("opencti: đọc stream: %w", err)
	}
	// Luồng đóng bình thường: coi khung dang dở cuối cùng là hoàn chỉnh.
	return flush()
}
