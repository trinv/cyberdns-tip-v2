package opencti

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// collect chạy scanSSE trên một luồng dựng sẵn và gom lại các sự kiện mà handler nhận.
func collect(t *testing.T, stream string) []Event {
	t.Helper()
	var got []Event
	err := scanSSE(context.Background(), strings.NewReader(stream), func(_ context.Context, ev Event) error {
		got = append(got, ev)
		return nil
	})
	if err != nil {
		t.Fatalf("scanSSE: %v", err)
	}
	return got
}

func TestScanSSEBasic(t *testing.T) {
	stream := "" +
		"event: create\n" +
		"id: 1757000000000-0\n" +
		`data: {"data":{"type":"indicator","id":"indicator--1","pattern":"[domain-name:value = 'evil.com']"}}` + "\n" +
		"\n"

	got := collect(t, stream)
	if len(got) != 1 {
		t.Fatalf("số sự kiện = %d, mong đợi 1", len(got))
	}
	if got[0].Type != EventCreate {
		t.Errorf("Type = %q", got[0].Type)
	}
	if got[0].ID != "1757000000000-0" {
		t.Errorf("ID = %q", got[0].ID)
	}
	if got[0].Object["id"] != "indicator--1" {
		t.Errorf("Object = %v", got[0].Object)
	}
}

// heartbeat và connected tới liên tục để giữ kết nối. Đẩy chúng xuống handler sẽ khiến
// consumer ghi checkpoint và đụng CSDL vài giây một lần mà không có gì thay đổi.
func TestScanSSESkipsKeepalive(t *testing.T) {
	stream := "" +
		"event: connected\n" +
		`data: {"message":"stream ready"}` + "\n" +
		"\n" +
		"event: heartbeat\n" +
		`data: {"message":"2026-09-08T10:00:00.000Z"}` + "\n" +
		"\n" +
		": comment giữ kết nối\n" +
		"\n" +
		"event: update\n" +
		"id: 2\n" +
		`data: {"data":{"type":"domain-name","id":"domain-name--2","value":"a.com"}}` + "\n" +
		"\n"

	got := collect(t, stream)
	if len(got) != 1 {
		t.Fatalf("số sự kiện = %d, mong đợi 1 (chỉ update)", len(got))
	}
	if got[0].Type != EventUpdate {
		t.Errorf("Type = %q", got[0].Type)
	}
}

// Chuẩn SSE cho phép chia phần data thành nhiều dòng, nối lại bằng "\n". OpenCTI phát
// JSON một dòng, nhưng proxy ở giữa được phép chia lại — nối sai thì JSON hỏng và toàn
// bộ sự kiện lớn biến mất trong im lặng.
func TestScanSSEMultilineData(t *testing.T) {
	stream := "" +
		"event: create\n" +
		"id: 3\n" +
		"data: {\"data\":{\"type\":\"indicator\",\n" +
		"data: \"id\":\"indicator--3\",\n" +
		"data: \"pattern\":\"[domain-name:value = 'x.com']\"}}\n" +
		"\n"

	got := collect(t, stream)
	if len(got) != 1 {
		t.Fatalf("số sự kiện = %d, mong đợi 1", len(got))
	}
	if got[0].Object["id"] != "indicator--3" {
		t.Errorf("Object = %v", got[0].Object)
	}
}

// Sự kiện merge: OpenCTI giữ lại một entity và gộp các entity khác vào nó. Định danh của
// những entity bị gộp nằm ở context.sources, và nếu không ánh xạ lại thì hàng của chúng
// nằm mồ côi trong CSDL — domain bị chặn vĩnh viễn mà không sự kiện nào còn nhắc tới.
// Connector stream mẫu của OpenCTI bỏ qua trường hợp này.
func TestScanSSEMerge(t *testing.T) {
	stream := "" +
		"event: merge\n" +
		"id: 4\n" +
		`data: {"data":{"type":"indicator","id":"indicator--keep","pattern":"[domain-name:value = 'evil.com']"},` +
		`"context":{"sources":[{"id":"indicator--gone-1"},{"x_opencti_id":"gone-2"}]}}` + "\n" +
		"\n"

	got := collect(t, stream)
	if len(got) != 1 {
		t.Fatalf("số sự kiện = %d, mong đợi 1", len(got))
	}
	ev := got[0]
	if ev.Type != EventMerge {
		t.Errorf("Type = %q", ev.Type)
	}
	if ev.Object["id"] != "indicator--keep" {
		t.Errorf("entity còn lại = %v", ev.Object["id"])
	}
	want := []string{"indicator--gone-1", "gone-2"}
	if len(ev.MergedFrom) != len(want) {
		t.Fatalf("MergedFrom = %v, mong đợi %v", ev.MergedFrom, want)
	}
	for i := range want {
		if ev.MergedFrom[i] != want[i] {
			t.Errorf("MergedFrom[%d] = %q, mong đợi %q", i, ev.MergedFrom[i], want[i])
		}
	}
}

// Một khung hỏng không được làm chết cả luồng: mất một sự kiện dị dạng còn hơn mất toàn
// bộ cập nhật cho tới lần khởi động lại tiếp theo.
func TestScanSSESkipsMalformed(t *testing.T) {
	stream := "" +
		"event: create\n" +
		"data: {khong-phai-json\n" +
		"\n" +
		"event: create\n" +
		`data: {"khong_co_truong_data": true}` + "\n" +
		"\n" +
		"event: create\n" +
		"id: 5\n" +
		`data: {"data":{"type":"domain-name","id":"domain-name--5","value":"ok.com"}}` + "\n" +
		"\n"

	got := collect(t, stream)
	if len(got) != 1 {
		t.Fatalf("số sự kiện = %d, mong đợi 1 (hai khung đầu phải bị bỏ)", len(got))
	}
	if got[0].ID != "5" {
		t.Errorf("ID = %q", got[0].ID)
	}
}

// Luồng đóng mà khung cuối chưa có dòng trống kết thúc: vẫn phải xử lý, nếu không sự
// kiện cuối cùng trước mỗi lần đứt kết nối sẽ bị mất một cách có hệ thống.
func TestScanSSEFlushesFinalFrame(t *testing.T) {
	stream := "" +
		"event: create\n" +
		"id: 6\n" +
		`data: {"data":{"type":"domain-name","id":"domain-name--6","value":"last.com"}}` + "\n"

	got := collect(t, stream)
	if len(got) != 1 {
		t.Fatalf("số sự kiện = %d, mong đợi 1", len(got))
	}
}

// Sự kiện phát lại lúc bắt kịp mang loại "message" chứ không phải "create". Không quy
// chúng về create thì toàn bộ dữ liệu lịch sử bị bỏ qua và consumer chỉ thấy phần mới.
func TestEventNormalized(t *testing.T) {
	cases := map[string]string{
		EventMessage: EventCreate,
		"":           EventCreate,
		EventCreate:  EventCreate,
		EventUpdate:  EventUpdate,
		EventDelete:  EventDelete,
		EventMerge:   EventMerge,
	}
	for in, want := range cases {
		if got := (Event{Type: in}).Normalized(); got != want {
			t.Errorf("Normalized(%q) = %q, mong đợi %q", in, got, want)
		}
	}
}

func TestListenSendsRequiredHeaders(t *testing.T) {
	var gotHeaders http.Header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: create\nid: 9\n" +
			`data: {"data":{"type":"domain-name","id":"domain-name--9","value":"h.com"}}` + "\n\n"))
	}))
	defer srv.Close()

	var got []Event
	err := Listen(context.Background(), StreamConfig{
		URL:          srv.URL + "/stream/live-test",
		Token:        "secret-token",
		StartFrom:    "1757000000000-0",
		ListenDelete: true,
		HTTPClient:   srv.Client(),
	}, func(_ context.Context, ev Event) error {
		got = append(got, ev)
		return nil
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("số sự kiện = %d, mong đợi 1", len(got))
	}

	// listen-delete phải BẬT: thiếu nó thì việc analyst xóa một indicator không bao giờ
	// tới được đây và domain bị chặn mãi.
	want := map[string]string{
		"Authorization":   "Bearer secret-token",
		"Listen-Delete":   "true",
		"No-Dependencies": "true",
		"Last-Event-Id":   "1757000000000-0",
	}
	for k, v := range want {
		if gotHeaders.Get(k) != v {
			t.Errorf("header %s = %q, mong đợi %q", k, gotHeaders.Get(k), v)
		}
	}
}

// Token sai trả 401. Phải báo lỗi rõ ràng chứ không im lặng coi như luồng rỗng, nếu
// không consumer sẽ chạy mãi mà không bao giờ nhận được gì và không ai biết vì sao.
func TestListenRejectsNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := Listen(context.Background(), StreamConfig{
		URL:        srv.URL + "/stream/live-test",
		Token:      "sai",
		HTTPClient: srv.Client(),
	}, func(context.Context, Event) error { return nil })

	if err == nil {
		t.Fatal("Listen trả nil dù server từ chối")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("lỗi = %v, mong đợi có mã 401", err)
	}
}

func TestListenRequiresURL(t *testing.T) {
	err := Listen(context.Background(), StreamConfig{}, func(context.Context, Event) error { return nil })
	if err == nil {
		t.Fatal("Listen trả nil dù thiếu URL")
	}
}
