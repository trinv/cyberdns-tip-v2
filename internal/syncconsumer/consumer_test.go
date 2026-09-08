package syncconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/opencti"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

var at = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// fakeStore ghi lại lời gọi để kiểm chứng phần điều phối mà không cần PostgreSQL.
//
// Thứ tự trong callOrder là thứ quan trọng nhất mà nó ghi lại: xử lý merge sai thứ tự
// vẫn cho ra dữ liệu trông đúng ở trạng thái cuối trong hầu hết trường hợp, và chỉ lộ
// ra thành hàng mồ côi khi hai entity cùng trỏ về một domain.
type fakeStore struct {
	upserts   []store.OpenCTIRecord
	deletes   []string
	merges    [][]string
	mergeTo   []string
	saves     []string
	savedAt   []time.Time
	processed []int64
	callOrder []string

	upsertErr error
	deleteN   int64
	mergeN    int64
}

func (f *fakeStore) UpsertOpenCTI(_ context.Context, _ store.Source, rec store.OpenCTIRecord, _ time.Time) error {
	f.callOrder = append(f.callOrder, "upsert")
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.upserts = append(f.upserts, rec)
	return nil
}

func (f *fakeStore) DeleteOpenCTI(_ context.Context, _ int64, stixID string) (int64, error) {
	f.callOrder = append(f.callOrder, "delete")
	f.deletes = append(f.deletes, stixID)
	return f.deleteN, nil
}

func (f *fakeStore) MergeOpenCTI(_ context.Context, _ int64, from []string, to string) (int64, error) {
	f.callOrder = append(f.callOrder, "merge")
	f.merges = append(f.merges, from)
	f.mergeTo = append(f.mergeTo, to)
	return f.mergeN, nil
}

func (f *fakeStore) SaveStreamState(_ context.Context, _ int64, _, eventID string, eventAt time.Time, processed int64) error {
	f.callOrder = append(f.callOrder, "checkpoint")
	f.saves = append(f.saves, eventID)
	f.savedAt = append(f.savedAt, eventAt)
	f.processed = append(f.processed, processed)
	return nil
}

func newConsumer(t *testing.T, f *fakeStore, opts Options) *Consumer {
	t.Helper()
	opts.Source = store.Source{ID: 7, Name: "opencti", TrustScore: 90}
	opts.StreamID = "live-test"
	opts.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	opts.Now = func() time.Time { return at }
	return New(f, opts)
}

// event dựng một sự kiện đã giải mã từ JSON thô, đi đúng đường mà stream thật đi.
func event(t *testing.T, id, kind, raw string) opencti.Event {
	t.Helper()
	ev, err := opencti.ParseEvent(id, kind, raw)
	if err != nil {
		t.Fatalf("dựng sự kiện: %v", err)
	}
	return ev
}

func TestHandleCreate(t *testing.T) {
	f := &fakeStore{}
	c := newConsumer(t, f, Options{})

	ev := event(t, "1", opencti.EventCreate, `{"data":{
		"type":"indicator","id":"indicator--1",
		"pattern":"[domain-name:value = 'evil.com']",
		"confidence":80,"modified":"2026-09-08T10:00:00.000Z"}}`)

	if err := c.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(f.upserts) != 1 {
		t.Fatalf("số upsert = %d, muốn 1", len(f.upserts))
	}
	got := f.upserts[0]
	if got.STIXID != "indicator--1" {
		t.Errorf("STIXID = %q", got.STIXID)
	}
	if len(got.Rules) != 1 || got.Rules[0].Domain != "evil.com" {
		t.Errorf("Rules = %v", got.Rules)
	}
	// RawLine phải là pattern gốc: L0 tồn tại để trả lời "vì sao domain này có ở đây".
	if got.RawLine != "[domain-name:value = 'evil.com']" {
		t.Errorf("RawLine = %q", got.RawLine)
	}
}

// Luồng CTI thật chở đủ thứ không phải tên miền. Chúng phải bị bỏ qua chứ không được
// làm dừng stream — nếu không, consumer sẽ chết ngay indicator IP đầu tiên.
func TestHandleSkipsNonDomain(t *testing.T) {
	f := &fakeStore{}
	c := newConsumer(t, f, Options{})

	for _, raw := range []string{
		`{"data":{"type":"indicator","id":"i--1","pattern":"[ipv4-addr:value = '198.51.100.1']"}}`,
		`{"data":{"type":"malware","id":"malware--1","name":"Emotet"}}`,
		`{"data":{"type":"relationship","id":"rel--1"}}`,
	} {
		if err := c.Handle(context.Background(), event(t, "1", opencti.EventCreate, raw)); err != nil {
			t.Fatalf("Handle(%s): %v", raw, err)
		}
	}
	if len(f.upserts) != 0 {
		t.Errorf("số upsert = %d, muốn 0", len(f.upserts))
	}
}

// detection=false nghĩa là indicator chỉ để phân tích. Chặn theo nó là làm trái ý
// analyst đã ghi rõ.
func TestHandleSkipsDetectionFalse(t *testing.T) {
	f := &fakeStore{}
	c := newConsumer(t, f, Options{})

	ev := event(t, "1", opencti.EventCreate, `{"data":{
		"type":"indicator","id":"indicator--2",
		"pattern":"[domain-name:value = 'research.example']",
		"x_opencti_detection":false}}`)

	if err := c.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(f.upserts) != 0 {
		t.Errorf("số upsert = %d, muốn 0", len(f.upserts))
	}
}

// Phát lại sau khi kết nối lại là đường đi bình thường của SSE, không phải lỗi.
func TestHandleTreatsStaleAsNormal(t *testing.T) {
	f := &fakeStore{upsertErr: store.ErrStale}
	c := newConsumer(t, f, Options{})

	ev := event(t, "1", opencti.EventUpdate, `{"data":{
		"type":"indicator","id":"indicator--3",
		"pattern":"[domain-name:value = 'old.example.com']"}}`)

	if err := c.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle = %v, muốn nil: phát lại không phải lỗi", err)
	}
}

// Lỗi CSDL thật thì phải nổi lên: tiếp tục chạy khi không ghi được gì sẽ biến consumer
// thành thứ chạy mãi mà im lặng bỏ mất toàn bộ dữ liệu.
func TestHandlePropagatesRealError(t *testing.T) {
	boom := errors.New("mất kết nối")
	f := &fakeStore{upsertErr: boom}
	c := newConsumer(t, f, Options{})

	ev := event(t, "1", opencti.EventCreate, `{"data":{
		"type":"indicator","id":"indicator--4",
		"pattern":"[domain-name:value = 'x.example.com']"}}`)

	if err := c.Handle(context.Background(), ev); !errors.Is(err, boom) {
		t.Fatalf("Handle = %v, muốn %v", err, boom)
	}
}

func TestHandleDelete(t *testing.T) {
	f := &fakeStore{deleteN: 1}
	c := newConsumer(t, f, Options{})

	ev := event(t, "1", opencti.EventDelete, `{"data":{
		"type":"indicator","id":"indicator--5",
		"pattern":"[domain-name:value = 'gone.example.com']"}}`)

	if err := c.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(f.deletes) != 1 || f.deletes[0] != "indicator--5" {
		t.Errorf("deletes = %v", f.deletes)
	}
	if len(f.upserts) != 0 {
		t.Errorf("delete không được ghi thêm gì: upserts = %v", f.upserts)
	}
}

// Merge phải ánh xạ định danh TRƯỚC rồi mới ghi entity còn lại.
//
// Làm ngược lại sẽ tạo hàng thứ hai cho cùng một domain trước khi bước ánh xạ chạy, tức
// là chính những hàng mồ côi mà bước này sinh ra để dọn.
func TestHandleMergeOrdersOperations(t *testing.T) {
	f := &fakeStore{mergeN: 1}
	c := newConsumer(t, f, Options{})

	ev := event(t, "1", opencti.EventMerge, `{"data":{
		"type":"indicator","id":"indicator--keep",
		"pattern":"[domain-name:value = 'merged.example.com']"},
		"context":{"sources":[{"id":"indicator--gone"}]}}`)

	if err := c.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(f.merges) != 1 || len(f.merges[0]) != 1 || f.merges[0][0] != "indicator--gone" {
		t.Fatalf("merges = %v", f.merges)
	}
	if f.mergeTo[0] != "indicator--keep" {
		t.Errorf("mergeTo = %q", f.mergeTo[0])
	}
	if len(f.callOrder) < 2 || f.callOrder[0] != "merge" || f.callOrder[1] != "upsert" {
		t.Errorf("thứ tự = %v, muốn merge trước rồi mới upsert", f.callOrder)
	}
}

// Sự kiện phát lại lúc bắt kịp mang loại "message". Bỏ qua chúng sẽ vứt toàn bộ dữ liệu
// lịch sử và consumer chỉ thấy phần mới sinh sau khi nó khởi động.
func TestHandleCatchUpMessage(t *testing.T) {
	f := &fakeStore{}
	c := newConsumer(t, f, Options{})

	ev := event(t, "1", opencti.EventMessage, `{"data":{
		"type":"domain-name","id":"domain-name--6","value":"catchup.example.com"}}`)

	if err := c.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(f.upserts) != 1 {
		t.Fatalf("số upsert = %d, muốn 1", len(f.upserts))
	}
}

func TestLabelMapping(t *testing.T) {
	f := &fakeStore{}
	c := newConsumer(t, f, Options{
		LabelCategories: map[string][]int16{
			"malware":  {1},
			"phishing": {2},
		},
	})

	tests := []struct {
		name   string
		labels string
		want   []int16
	}{
		{"một nhãn khớp", `["malware"]`, []int16{1}},
		{"nhiều nhãn khớp, kết quả đã sắp xếp", `["phishing","malware"]`, []int16{1, 2}},
		{"nhãn trùng chỉ tính một lần", `["malware","MALWARE"]`, []int16{1}},
		// Nhãn lạ không được làm indicator biến mất: một cài đặt OpenCTI mới dựng gần
		// như chưa có nhãn nào, và bỏ hết sẽ khiến tích hợp trông như hỏng.
		{"nhãn không khớp thì để nguồn tự quyết", `["apt29"]`, nil},
		{"không có nhãn", `[]`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.upserts = nil
			raw := `{"data":{"type":"indicator","id":"indicator--l",` +
				`"pattern":"[domain-name:value = 'label.example.com']",` +
				`"labels":` + tt.labels + `}}`
			if err := c.Handle(context.Background(), event(t, "1", opencti.EventCreate, raw)); err != nil {
				t.Fatalf("Handle: %v", err)
			}
			got := f.upserts[0].CategoryIDs
			if len(got) != len(tt.want) {
				t.Fatalf("CategoryIDs = %v, muốn %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("CategoryIDs = %v, muốn %v", got, tt.want)
				}
			}
		})
	}
}

// Checkpoint ghi theo lô, không phải mỗi sự kiện một transaction.
func TestCheckpointBatching(t *testing.T) {
	f := &fakeStore{}
	c := newConsumer(t, f, Options{CheckpointEvery: 3, CheckpointAfter: time.Hour})

	for i := 0; i < 5; i++ {
		raw := `{"data":{"type":"domain-name","id":"domain-name--b","value":"b.example.com"}}`
		if err := c.Handle(context.Background(), event(t, "e"+string(rune('0'+i)), opencti.EventCreate, raw)); err != nil {
			t.Fatalf("Handle: %v", err)
		}
	}

	if len(f.saves) != 1 {
		t.Fatalf("số lần ghi checkpoint = %d, muốn 1 sau 5 sự kiện với ngưỡng 3", len(f.saves))
	}
	if f.saves[0] != "e2" {
		t.Errorf("checkpoint = %q, muốn e2", f.saves[0])
	}
	if f.processed[0] != 3 {
		t.Errorf("số sự kiện đã xử lý = %d, muốn 3", f.processed[0])
	}

	// Flush lúc đóng stream phải đẩy nốt phần còn lại, nếu không hai sự kiện cuối sẽ
	// bị xử lý lại sau mỗi lần khởi động lại.
	if err := c.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(f.saves) != 2 || f.saves[1] != "e4" {
		t.Fatalf("saves = %v", f.saves)
	}
	if f.processed[1] != 2 {
		t.Errorf("phần còn lại = %d, muốn 2", f.processed[1])
	}
}

// Flush khi không có gì chờ không được đụng CSDL.
func TestFlushNoopWhenEmpty(t *testing.T) {
	f := &fakeStore{}
	c := newConsumer(t, f, Options{})

	if err := c.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(f.saves) != 0 {
		t.Errorf("saves = %v, muốn rỗng", f.saves)
	}
}

func TestEventTime(t *testing.T) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(`{"updated_at":"2026-09-08T10:00:00Z"}`), &obj); err != nil {
		t.Fatal(err)
	}
	got := eventTime(opencti.Event{Object: obj})
	if got.IsZero() || got.Hour() != 10 {
		t.Errorf("eventTime = %v", got)
	}

	if !eventTime(opencti.Event{}).IsZero() {
		t.Error("sự kiện không có đối tượng phải cho thời gian rỗng")
	}
}
