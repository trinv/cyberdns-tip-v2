// Package metrics dựng registry Prometheus dùng chung cho mọi service.
//
// Tập metric ở đây bám theo bảng observability của báo cáo phương án (§8.3): mỗi nhóm
// trong bảng đó phải có metric tương ứng ngay từ P0 để không phải gắn thêm về sau.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics gom registry và các collector dùng chung. Service chỉ dùng phần nó cần.
type Metrics struct {
	Registry *prometheus.Registry

	// --- Feed Ingestor ---
	FeedUp            *prometheus.GaugeVec
	FeedDurationSec   *prometheus.HistogramVec
	FeedDownloadBytes *prometheus.CounterVec
	FeedParseErrors   *prometheus.CounterVec
	FeedRecords       *prometheus.CounterVec
	FeedLastSuccessTS *prometheus.GaugeVec

	// --- Policy Engine ---
	PolicyDecisions      *prometheus.CounterVec
	PolicyRunDurationSec prometheus.Histogram

	// --- Blocklist Generator ---
	SnapshotBuildSec  *prometheus.HistogramVec
	SnapshotBytes     *prometheus.GaugeVec
	SnapshotEntries   *prometheus.GaugeVec
	SnapshotAgeSec    *prometheus.GaugeVec
	SnapshotPublishes *prometheus.CounterVec

	// --- HTTP (exporter + admin API) ---
	HTTPRequests    *prometheus.CounterVec
	HTTPDurationSec *prometheus.HistogramVec

	// --- OpenCTI sync-consumer ---
	// StreamLagSec là độ trễ Live Stream. Vì OpenCTI nằm trong đường sinh blocklist,
	// đây là chỉ số vận hành chứ không chỉ là chỉ số phân tích (kế hoạch §7.3).
	StreamLagSec prometheus.Gauge
	StreamEvents *prometheus.CounterVec
	StreamDrift  prometheus.Gauge
}

// New tạo registry kèm collector runtime của Go và process.
func New(service, version string) *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cyberdns_build_info",
		Help: "Thông tin build; giá trị luôn bằng 1.",
	}, []string{"service", "version"})
	buildInfo.WithLabelValues(service, version).Set(1)
	reg.MustRegister(buildInfo)

	m := &Metrics{
		Registry: reg,

		FeedUp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cyberdns_feed_up",
			Help: "1 nếu lần fetch gần nhất của nguồn thành công, 0 nếu không.",
		}, []string{"source"}),

		FeedDurationSec: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cyberdns_feed_duration_seconds",
			Help:    "Thời gian một lần import feed, tính theo giai đoạn.",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 12),
		}, []string{"source", "stage"}),

		FeedDownloadBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cyberdns_feed_download_bytes_total",
			Help: "Tổng số byte tải về theo nguồn.",
		}, []string{"source"}),

		FeedParseErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cyberdns_feed_parse_errors_total",
			Help: "Số dòng không parse được, theo nguồn và lý do.",
		}, []string{"source", "reason"}),

		FeedRecords: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cyberdns_feed_records_total",
			Help: "Số bản ghi theo nguồn và kết cục (accepted/rejected/added/updated/removed).",
		}, []string{"source", "outcome"}),

		FeedLastSuccessTS: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cyberdns_feed_last_success_timestamp_seconds",
			Help: "Unix timestamp của lần import thành công gần nhất; dùng để cảnh báo feed stale.",
		}, []string{"source"}),

		PolicyDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cyberdns_policy_decisions_total",
			Help: "Số quyết định theo category, action và nấc ưu tiên đã kích hoạt.",
		}, []string{"category", "action", "reason_code"}),

		PolicyRunDurationSec: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "cyberdns_policy_run_duration_seconds",
			Help:    "Thời gian chạy trọn một lượt policy.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 12),
		}),

		SnapshotBuildSec: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cyberdns_snapshot_build_duration_seconds",
			Help:    "Thời gian dựng một file snapshot.",
			Buckets: prometheus.ExponentialBuckets(0.5, 2, 12),
		}, []string{"tenant", "category"}),

		SnapshotBytes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cyberdns_snapshot_bytes",
			Help: "Kích thước file snapshot đang phát hành.",
		}, []string{"tenant", "category"}),

		SnapshotEntries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cyberdns_snapshot_entries",
			Help: "Số dòng trong file snapshot đang phát hành.",
		}, []string{"tenant", "category"}),

		SnapshotAgeSec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cyberdns_snapshot_age_seconds",
			Help: "Tuổi của bộ snapshot đang phát hành; dùng để cảnh báo snapshot cũ.",
		}, []string{"tenant"}),

		SnapshotPublishes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cyberdns_snapshot_publishes_total",
			Help: "Số lần publish theo bộ, kèm kết cục (published/failed/unchanged/rolled_back).",
		}, []string{"outcome"}),

		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cyberdns_http_requests_total",
			Help: "Số request HTTP theo route và mã trạng thái; 304 tách riêng để đo hiệu quả cache.",
		}, []string{"route", "code"}),

		HTTPDurationSec: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cyberdns_http_request_duration_seconds",
			Help:    "Thời gian phục vụ request HTTP.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route"}),

		StreamLagSec: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cyberdns_opencti_stream_lag_seconds",
			Help: "Khoảng cách giữa thời điểm sự kiện OpenCTI và lúc áp dụng xong.",
		}),

		StreamEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cyberdns_opencti_stream_events_total",
			Help: "Số sự kiện Live Stream theo loại (create/update/delete/merge) và kết cục.",
		}, []string{"type", "outcome"}),

		StreamDrift: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cyberdns_opencti_reconcile_drift",
			Help: "Số bản ghi lệch mà lần đối soát GraphQL gần nhất phát hiện; kỳ vọng bằng 0.",
		}),
	}

	reg.MustRegister(
		m.FeedUp, m.FeedDurationSec, m.FeedDownloadBytes, m.FeedParseErrors,
		m.FeedRecords, m.FeedLastSuccessTS,
		m.PolicyDecisions, m.PolicyRunDurationSec,
		m.SnapshotBuildSec, m.SnapshotBytes, m.SnapshotEntries, m.SnapshotAgeSec,
		m.SnapshotPublishes,
		m.HTTPRequests, m.HTTPDurationSec,
		m.StreamLagSec, m.StreamEvents, m.StreamDrift,
	)

	return m
}

// InitSource khởi tạo sẵn các nhãn cho một nguồn feed.
//
// Prometheus không xuất một metric vector khi nó chưa có label value nào. Không gọi
// hàm này thì cảnh báo dạng "cyberdns_feed_up == 0" sẽ không bao giờ kích hoạt cho
// nguồn chưa từng chạy thành công lần nào — đúng trường hợp cần cảnh báo nhất.
// Gọi khi nạp danh sách nguồn lúc khởi động.
func (m *Metrics) InitSource(source string) {
	m.FeedUp.WithLabelValues(source).Set(0)
	m.FeedLastSuccessTS.WithLabelValues(source).Set(0)
	m.FeedDownloadBytes.WithLabelValues(source).Add(0)
	for _, outcome := range []string{"accepted", "rejected", "added", "updated", "removed"} {
		m.FeedRecords.WithLabelValues(source, outcome).Add(0)
	}
}
