/*
 * CyberDNS TIP — logic giao diện quản trị.
 *
 * Không dùng framework và không có bước build: giao diện được nhúng thẳng vào binary
 * Go, nên triển khai chỉ là một container duy nhất và CI không cần thêm toolchain
 * Node. Với số màn hình ở đây thì một bundler chưa mang lại gì ngoài phụ thuộc.
 */

const $ = (sel, root = document) => root.querySelector(sel);

// ------------------------------------------------------------------ tiện ích

/** Chèn văn bản do người dùng hoặc CSDL cung cấp. Không bao giờ nối chuỗi vào innerHTML. */
function text(value) {
  return document.createTextNode(value == null ? "" : String(value));
}

/** el dựng phần tử; con là chuỗi (thành text node) hoặc phần tử. */
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.appendChild(typeof c === "string" || typeof c === "number" ? text(c) : c);
  }
  return node;
}

/** svgEl dựng phần tử SVG — cần namespace riêng, document.createElement không dùng được. */
function svgEl(tag, attrs = {}, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.appendChild(typeof c === "string" || typeof c === "number" ? text(c) : c);
  }
  return node;
}

function toast(message, kind = "") {
  const t = el("div", { class: `toast ${kind}` }, message);
  $("#toasts").appendChild(t);
  setTimeout(() => t.remove(), 5000);
}

function fmtNum(n) {
  return new Intl.NumberFormat("vi-VN").format(n ?? 0);
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("vi-VN", { dateStyle: "short", timeStyle: "short" });
}

function relTime(iso) {
  if (!iso) return "chưa bao giờ";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "vừa xong";
  if (diff < 3600) return `${Math.floor(diff / 60)} phút trước`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} giờ trước`;
  return `${Math.floor(diff / 86400)} ngày trước`;
}

// ------------------------------------------------------------------ gọi API

class HTTPError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: options.body ? { "Content-Type": "application/json" } : {},
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (res.status === 401) {
    showLogin();
    throw new HTTPError(401, "chưa đăng nhập");
  }
  if (res.status === 204) return null;

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new HTTPError(res.status, data.error || `lỗi HTTP ${res.status}`);
  return data;
}

/**
 * pollTrigger hỏi thăm một yêu cầu "chạy ngay" cho tới khi nó xong hoặc thất bại.
 *
 * feed-ingestor/policy-engine/blocklist-generator xử lý yêu cầu qua bảng CSDL, không
 * có kết nối trực tiếp nào để đẩy tiến độ về trình duyệt — nên phải hỏi lại. 1.5s một
 * lần là đủ nhanh để cảm giác "ngay", và đủ thưa để không đáng kể so với chu kỳ
 * poll 3s của service.
 */
async function pollTrigger(id, onTick) {
  for (;;) {
    const t = await api(`/api/triggers/${id}`);
    onTick?.(t);
    if (t.status === "done" || t.status === "failed") return t;
    await new Promise((r) => setTimeout(r, 1500));
  }
}

// ------------------------------------------------------------------ đồ thị donut

const CHART_COLORS = 8; // khớp .chart-color-1..8 trong app.css

/** donutChart dựng SVG donut từ [ [nhãn, số lượng], ... ]. Không dùng thư viện: bảng
 *  quản trị nội bộ không tải gì từ bên ngoài (xem TestNoExternalResourceLoads). */
function donutChart(entries, { size = 168, thickness = 24 } = {}) {
  const total = entries.reduce((sum, [, n]) => sum + n, 0);
  const r = (size - thickness) / 2;
  const c = size / 2;
  const circumference = 2 * Math.PI * r;

  const bg = svgEl("circle", {
    cx: c, cy: c, r, fill: "none",
    stroke: "var(--border)", "stroke-width": thickness,
  });

  const segments = [];
  let offset = 0;
  entries.forEach(([name, n], i) => {
    if (n <= 0 || total <= 0) return;
    const frac = n / total;
    const len = frac * circumference;
    segments.push(svgEl("circle", {
      class: `chart-color-${(i % CHART_COLORS) + 1}`,
      cx: c, cy: c, r, fill: "none",
      "stroke-width": thickness,
      "stroke-dasharray": `${len} ${circumference - len}`,
      "stroke-dashoffset": String(-offset),
      // Xoay để lát đầu tiên bắt đầu từ đỉnh 12 giờ thay vì 3 giờ (mặc định của SVG).
      transform: `rotate(-90 ${c} ${c})`,
    }, svgEl("title", {}, `${name}: ${fmtNum(n)} (${(frac * 100).toFixed(1)}%)`)));
    offset += len;
  });

  return svgEl("svg", { viewBox: `0 0 ${size} ${size}`, width: size, height: size },
    bg, segments);
}

/** donutLegend là chú giải màu đi kèm donutChart, cùng dữ liệu đầu vào. */
function donutLegend(entries) {
  const total = entries.reduce((sum, [, n]) => sum + n, 0);
  return el("ul", { class: "legend" },
    entries.map(([name, n], i) =>
      el("li", {},
        el("span", { class: `legend-dot chart-color-${(i % CHART_COLORS) + 1}` }),
        el("span", { class: "legend-name" }, name),
        el("span", { class: "legend-value" },
          `${fmtNum(n)}${total ? ` (${((n / total) * 100).toFixed(1)}%)` : ""}`))));
}

// ------------------------------------------------------------------ icon

const ICONS = {
  overview: "M3 12h4l3 8 4-16 3 8h4",
  sources: "M4 7h16M4 12h16M4 17h10",
  imports: "M12 3v12m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2",
  lookup: "M11 19a8 8 0 100-16 8 8 0 000 16zm10 2l-4.35-4.35",
  allowlist: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
  block: "M18.36 5.64L5.64 18.36M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
  clock: "M12 8v4l3 2m6-2a9 9 0 11-18 0 9 9 0 0118 0z",
  alert: "M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z",
};

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", ICONS[name] || ICONS.overview);
  path.setAttribute("stroke-linecap", "round");
  path.setAttribute("stroke-linejoin", "round");
  svg.appendChild(path);
  return svg;
}

// ------------------------------------------------------------------ trạng thái

let me = null;

const PAGES = [
  { id: "overview", title: "Tổng quan", icon: "overview", perm: "domain:read" },
  { id: "sources", title: "Nguồn feed", icon: "sources", perm: "source:read" },
  { id: "imports", title: "Lịch sử import", icon: "imports", perm: "import:read" },
  { id: "lookup", title: "Tra cứu domain", icon: "lookup", perm: "domain:read" },
  { id: "allowlist", title: "Allowlist", icon: "allowlist", perm: "allowlist:read" },
];

/** can kiểm tra quyền ở phía giao diện để ẩn nút. Đây KHÔNG phải hàng rào —
 *  hàng rào thật nằm ở tầng handler của API. */
function can(perm) {
  if (!me) return false;
  return me.permissions.some(
    (p) => p === "*" || p === perm || (p.endsWith(":*") && perm.startsWith(p.slice(0, -1))),
  );
}

// ------------------------------------------------------------------ màn hình

async function renderOverview(view) {
  const o = await api("/api/overview");

  const kpis = [
    { label: "Domain đang hiệu lực", value: fmtNum(o.domains_active), icon: "block", tone: "primary" },
    { label: "Nguồn đang bật", value: fmtNum(o.sources_enabled), icon: "sources", tone: "success" },
    { label: "Nguồn dữ liệu cũ", value: fmtNum(o.sources_stale), icon: "clock", tone: o.sources_stale ? "warning" : "success" },
    { label: "Nguồn đang lỗi", value: fmtNum(o.sources_failing), icon: "alert", tone: o.sources_failing ? "danger" : "success" },
  ];

  view.appendChild(
    el("div", { class: "kpi-grid" },
      kpis.map((k) =>
        el("div", { class: "kpi-card" },
          el("div", { class: "kpi-top" },
            el("div", { class: `kpi-icon ${k.tone}` }, icon(k.icon)),
            el("div", { class: "kpi-label" }, k.label)),
          el("div", { class: "kpi-value" }, k.value))),
    ),
  );

  if (o.sources_failing > 0) {
    view.appendChild(el("div", { class: "banner bad" },
      `${o.sources_failing} nguồn đang lỗi. Snapshot vẫn phục vụ bằng dữ liệu cũ — ` +
      `xem Lịch sử import để biết lý do.`));
  }

  if (can("policy:write") && can("snapshot:write")) {
    view.appendChild(renderPublishCard(o));
  }

  const cats = Object.entries(o.blocked_by_category).sort((a, b) => b[1] - a[1]);
  const nonZeroCats = cats.filter(([, n]) => n > 0);
  view.appendChild(
    el("div", { class: "card" },
      el("div", { class: "card-head" }, el("h2", {}, "Domain bị chặn theo category")),
      el("div", { class: "cat-layout" },
        nonZeroCats.length
          ? el("div", { class: "donut-block" }, donutChart(nonZeroCats), donutLegend(nonZeroCats))
          : el("div", { class: "empty" }, "Chưa có domain nào bị chặn.")),
      el("div", { class: "table-wrap" },
        el("table", {},
          el("thead", {}, el("tr", {},
            el("th", {}, "Category"),
            el("th", { class: "num" }, "Số domain"),
            el("th", {}, "URL công khai"))),
          el("tbody", {},
            cats.map(([name, n]) =>
              el("tr", {},
                el("td", {}, el("strong", {}, name)),
                el("td", { class: "num" }, fmtNum(n)),
                el("td", {}, el("code", {}, `/blocklist/${name}.txt`)))))))),
  );
}

/**
 * renderPublishCard là nút "cập nhật blocklist": chấm điểm lại rồi dựng & phát hành,
 * hai bước nối tiếp vì blocklist-generator chỉ dựng từ lượt policy đã hoàn tất gần
 * nhất — dựng ngay mà chưa chấm điểm lại thường chỉ tái tạo đúng bộ cũ.
 */
function renderPublishCard(o) {
  const status = el("div", { class: "op-status" });
  const btn = el("button", { class: "btn primary sm", type: "button" }, "Cập nhật & phát hành ngay");

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    status.className = "op-status busy";
    try {
      status.textContent = "Đang chấm điểm lại…";
      const { trigger_id: policyID } = await api("/api/policy/run", { method: "POST" });
      const policyDone = await pollTrigger(policyID);
      if (policyDone.status === "failed") {
        throw new Error(policyDone.error_message || "chấm điểm lại thất bại");
      }

      status.textContent = "Đang dựng & phát hành blocklist…";
      const { trigger_id: buildID } = await api("/api/blocklist/build", { method: "POST" });
      const buildDone = await pollTrigger(buildID);
      if (buildDone.status === "failed") {
        throw new Error(buildDone.error_message || "dựng blocklist thất bại");
      }

      const r = buildDone.result || {};
      toast(
        r.Skipped
          ? "Đã chấm điểm lại — dữ liệu không đổi, không có bản blocklist mới."
          : `Đã phát hành bản blocklist mới: ${fmtNum(r.Entries)} domain (${r.Tenants} tenant).`,
        "ok",
      );
      route();
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      btn.disabled = false;
      status.className = "op-status";
      status.textContent = "";
    }
  });

  return el("div", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, "Blocklist"), btn),
    el("div", { class: "card-body" },
      el("div", { style: "font-size:13px; color:var(--t-muted)" },
        "Lượt chấm điểm gần nhất: ",
        el("strong", { style: "color:var(--t-base)" }, fmtTime(o.last_policy_run)),
        o.last_policy_run ? ` (${relTime(o.last_policy_run)})` : ""),
      status));
}

/** syncButton là nút "Đồng bộ ngay" dùng chung cho một nguồn hoặc cho toàn bộ (id=null). */
function syncButton(id, label) {
  const btn = el("button", { class: "btn sm", type: "button" }, label);
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = "Đang đồng bộ…";
    try {
      const path = id == null ? "/api/sync" : `/api/sources/${id}/sync`;
      const { trigger_id } = await api(path, { method: "POST" });
      const t = await pollTrigger(trigger_id);
      if (t.status === "failed") throw new Error(t.error_message || "đồng bộ thất bại");
      toast(id == null ? "Đã đồng bộ xong toàn bộ nguồn." : "Đã đồng bộ xong.", "ok");
      route();
    } catch (err) {
      toast(err.message, "bad");
      btn.disabled = false;
      btn.textContent = original;
    }
  });
  return btn;
}

async function renderSources(view) {
  const { sources } = await api("/api/sources");
  const showActions = can("source:write") || can("source:sync");

  const head = el("div", { class: "card-head" },
    el("h2", {}, "Nguồn feed"),
    el("div", { class: "actions" },
      can("source:sync") && syncButton(null, "Đồng bộ tất cả"),
      can("source:write") && el("button", { class: "btn primary sm", onclick: () => sourceForm() }, "Thêm nguồn")));

  const rows = (sources || []).map((s) => {
    const statusChip =
      s.last_status === "completed" ? el("span", { class: "chip ok" }, "thành công")
      : s.last_status === "unchanged" ? el("span", { class: "chip neutral" }, "không đổi")
      : s.last_status === "rejected" ? el("span", { class: "chip bad" }, "bị từ chối")
      : s.last_status === "failed" ? el("span", { class: "chip bad" }, "lỗi")
      : el("span", { class: "chip neutral" }, "chưa chạy");

    // "Dừng/Bật đồng bộ" đặt lại enabled qua endpoint sửa nguồn đã có sẵn — không cần
    // handler riêng, chỉ là một cách nhanh để bấm ngay từ bảng thay vì mở form sửa.
    const toggleBtn = can("source:write") && el("button", {
      class: "btn sm",
      type: "button",
      onclick: async (ev) => {
        const b = ev.currentTarget;
        b.disabled = true;
        try {
          await api(`/api/sources/${s.ID}`, { method: "PATCH", body: { enabled: !s.Enabled } });
          toast(s.Enabled ? `Đã dừng đồng bộ ${s.Name}.` : `Đã bật đồng bộ ${s.Name}.`, "ok");
          route();
        } catch (err) {
          toast(err.message, "bad");
          b.disabled = false;
        }
      },
    }, s.Enabled ? "Dừng đồng bộ" : "Bật đồng bộ");

    return el("tr", {},
      el("td", {},
        el("div", {}, el("strong", {}, s.Name)),
        el("div", { style: "font-size:11.5px; color:var(--t-light); word-break:break-all" }, s.URL)),
      el("td", {},
        s.Enabled ? el("span", { class: "chip ok" }, "bật") : el("span", { class: "chip neutral" }, "tắt")),
      el("td", {}, el("span", { class: "chip brand" }, s.Origin)),
      el("td", { class: "num" }, String(s.TrustScore)),
      el("td", {},
        s.License ? el("span", { class: "chip info" }, s.License)
                  : el("span", { class: "chip warn" }, "chưa khai báo")),
      el("td", {},
        statusChip,
        s.last_error && el("div", { class: "reason", style: "margin-top:5px" }, s.last_error)),
      el("td", { style: "white-space:nowrap; font-size:12px; color:var(--t-muted)" },
        relTime(s.last_run_at)),
      el("td", { class: "num" }, fmtNum(s.last_accepted)),
      showActions && el("td", {},
        el("div", { class: "actions" },
          // 'opencti' đồng bộ qua sync-consumer nghe Live Stream, không qua nút này —
          // xem CLAUDE.md quy tắc chống vòng lặp phản hồi.
          can("source:sync") && s.Enabled && s.Origin === "direct" && syncButton(s.ID, "Đồng bộ"),
          toggleBtn,
          can("source:write") && el("button", { class: "btn sm", onclick: () => sourceForm(s) }, "Sửa"))));
  });

  view.appendChild(
    el("div", { class: "card" }, head,
      el("div", { class: "table-wrap" },
        el("table", {},
          el("thead", {}, el("tr", {},
            el("th", {}, "Nguồn"), el("th", {}, "Trạng thái"), el("th", {}, "Loại"),
            el("th", { class: "num" }, "Trust"), el("th", {}, "License"),
            el("th", {}, "Lần chạy gần nhất"), el("th", {}, "Khi nào"),
            el("th", { class: "num" }, "Bản ghi"),
            showActions && el("th", {}, ""))),
          rows.length
            ? el("tbody", {}, rows)
            : el("tbody", {}, el("tr", {}, el("td", { colspan: "9" },
                el("div", { class: "empty" }, "Chưa có nguồn nào."))))))),
  );
}

/** sourceForm hiện form thêm/sửa ngay trong trang. */
function sourceForm(source = null) {
  const view = $("#view");
  const editing = source !== null;

  const f = {
    name: el("input", { type: "text", value: source?.Name || "", required: true }),
    url: el("input", { type: "url", value: source?.URL || "" }),
    trust: el("input", { type: "number", min: "0", max: "100", value: String(source?.TrustScore ?? 50) }),
    license: el("input", { type: "text", value: source?.License || "" }),
    categories: el("input", { type: "text", value: "" }),
    enabled: el("input", { type: "checkbox" }),
  };
  if (source?.Enabled) f.enabled.checked = true;
  if (editing) f.name.disabled = true;

  const form = el("form", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, editing ? `Sửa nguồn: ${source.Name}` : "Thêm nguồn")),
    el("div", { class: "card-body" },
      el("div", { class: "row" },
        el("div", { class: "field" }, el("label", {}, "Tên"), f.name),
        el("div", { class: "field" }, el("label", {}, "Trust score (0–100)"), f.trust)),
      el("div", { class: "field" }, el("label", {}, "URL"), f.url),
      el("div", { class: "field" },
        el("label", {}, "License"), f.license,
        el("div", { class: "help" },
          "Bắt buộc trước khi bật. Hệ tái phát hành list dẫn xuất qua endpoint công khai, " +
          "nên bật một nguồn chưa rà license là quyết định có hệ quả pháp lý.")),
      el("div", { class: "field" },
        el("label", {}, "Category"), f.categories,
        el("div", { class: "help" },
          "Cách nhau bằng dấu phẩy, ví dụ: malware, phishing. Để trống nếu giữ nguyên.")),
      el("div", { class: "field" },
        el("label", { class: "switch" }, f.enabled, el("span", {}, "Bật nguồn này"))),
      el("div", { class: "row", style: "margin-top:6px" },
        el("button", { class: "btn primary", type: "submit" }, editing ? "Lưu" : "Tạo"),
        el("button", { class: "btn", type: "button", onclick: () => route() }, "Hủy"))),
  );

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const cats = f.categories.value.split(",").map((s) => s.trim()).filter(Boolean);

    const body = {
      trust_score: Number(f.trust.value),
      enabled: f.enabled.checked,
      license: f.license.value,
    };
    if (cats.length) body.categories = cats;
    if (f.url.value) body.url = f.url.value;
    if (!editing) body.name = f.name.value;

    try {
      if (editing) await api(`/api/sources/${source.ID}`, { method: "PATCH", body });
      else await api("/api/sources", { method: "POST", body });
      toast(editing ? "Đã lưu nguồn." : "Đã tạo nguồn.", "ok");
      location.hash = "#sources";
      route();
    } catch (err) {
      toast(err.message, "bad");
    }
  });

  view.replaceChildren(form);
}

async function renderImports(view) {
  const { imports } = await api("/api/imports?limit=100");

  const rows = (imports || []).map((i) => {
    const chip =
      i.status === "completed" ? el("span", { class: "chip ok" }, "thành công")
      : i.status === "unchanged" ? el("span", { class: "chip neutral" }, "không đổi")
      : i.status === "running" ? el("span", { class: "chip info" }, "đang chạy")
      : el("span", { class: "chip bad" }, i.status === "rejected" ? "bị từ chối" : "lỗi");

    return el("tr", {},
      el("td", { style: "white-space:nowrap" }, fmtTime(i.started_at)),
      el("td", {}, el("strong", {}, i.source)),
      el("td", {}, chip),
      el("td", { class: "num" }, fmtNum(i.accepted)),
      el("td", { class: "num" }, fmtNum(i.rejected)),
      el("td", { class: "num" }, fmtNum(i.added)),
      el("td", { class: "num" }, fmtNum(i.removed)),
      el("td", {}, i.error ? el("div", { class: "reason" }, i.error) : "—"));
  });

  view.appendChild(
    el("div", { class: "card" },
      el("div", { class: "card-head" }, el("h2", {}, "Lịch sử import")),
      el("div", { class: "table-wrap" },
        el("table", {},
          el("thead", {}, el("tr", {},
            el("th", {}, "Thời điểm"), el("th", {}, "Nguồn"), el("th", {}, "Kết quả"),
            el("th", { class: "num" }, "Nhận"), el("th", { class: "num" }, "Loại"),
            el("th", { class: "num" }, "Thêm"), el("th", { class: "num" }, "Gỡ"),
            el("th", {}, "Lý do"))),
          rows.length
            ? el("tbody", {}, rows)
            : el("tbody", {}, el("tr", {}, el("td", { colspan: "8" },
                el("div", { class: "empty" }, "Chưa có lần import nào."))))))),
  );
}

function renderLookup(view) {
  const input = el("input", { type: "text", placeholder: "evil.example.com", autofocus: true });
  const result = el("div", {});

  const form = el("form", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, "Tra cứu domain")),
    el("div", { class: "card-body" },
      el("div", { class: "field" },
        el("label", {}, "Domain"), input,
        el("div", { class: "help" },
          "Đầu vào được chuẩn hóa đúng như đường thu thập: chữ hoa, dấu chấm cuối và " +
          "tên miền tiếng Việt đều tra được.")),
      el("button", { class: "btn primary", type: "submit" }, "Tra cứu")));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    result.replaceChildren();
    try {
      const rep = await api(`/api/domains/lookup?domain=${encodeURIComponent(input.value)}`);
      renderReport(result, rep);
    } catch (err) {
      toast(err.message, "bad");
    }
  });

  view.replaceChildren(form, result);
}

function renderReport(root, rep) {
  if (!rep.found) {
    root.appendChild(el("div", { class: "card" },
      el("div", { class: "empty" }, `Không có dữ liệu nào về ${rep.domain}.`)));
    return;
  }

  const decisions = (rep.decisions || []).map((d) =>
    el("tr", {},
      el("td", {}, el("strong", {}, d.category)),
      el("td", {}, el("span", {
        class: `chip ${d.action === "BLOCK" ? "bad" : d.action === "ALLOW" ? "ok" : "neutral"}`,
      }, d.action)),
      el("td", { class: "num" }, String(d.score)),
      el("td", { class: "num" }, String(d.independent_sources)),
      el("td", {}, el("span", { class: "reason" }, d.reason_code)),
      el("td", { style: "white-space:nowrap" }, fmtTime(d.decided_at))));

  root.appendChild(el("div", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, `Quyết định — ${rep.domain}`)),
    el("div", { class: "table-wrap" },
      el("table", {},
        el("thead", {}, el("tr", {},
          el("th", {}, "Category"), el("th", {}, "Kết quả"),
          el("th", { class: "num" }, "Điểm"), el("th", { class: "num" }, "Nguồn độc lập"),
          el("th", {}, "Lý do"), el("th", {}, "Lúc"))),
        el("tbody", {}, decisions.length ? decisions
          : el("tr", {}, el("td", { colspan: "6" },
              el("div", { class: "empty" }, "Chưa có quyết định nào."))))))));

  const sources = (rep.sources || []).map((s) =>
    el("tr", {},
      el("td", {}, el("strong", {}, s.source)),
      el("td", {}, el("span", { class: "chip brand" }, s.origin)),
      el("td", { class: "num" }, String(s.trust_score)),
      el("td", { class: "num" }, s.confidence == null ? "—" : String(s.confidence)),
      el("td", {}, (s.categories || []).join(", ") || "—"),
      el("td", {}, s.active ? el("span", { class: "chip ok" }, "đang hiệu lực")
                            : el("span", { class: "chip neutral" }, "đã ngừng")),
      el("td", {}, s.revoked_at ? el("span", { class: "chip bad" }, "đã thu hồi") : "—"),
      el("td", { style: "white-space:nowrap" }, fmtTime(s.last_seen))));

  root.appendChild(el("div", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, "Nguồn khẳng định")),
    el("div", { class: "table-wrap" },
      el("table", {},
        el("thead", {}, el("tr", {},
          el("th", {}, "Nguồn"), el("th", {}, "Loại"), el("th", { class: "num" }, "Trust"),
          el("th", { class: "num" }, "Confidence"), el("th", {}, "Category"),
          el("th", {}, "Trạng thái"), el("th", {}, "Thu hồi"), el("th", {}, "Thấy lần cuối"))),
        el("tbody", {}, sources)))));

  // Bằng chứng thô là thứ thực sự trả lời "vì sao domain này bị chặn". Kết luận đã suy
  // dẫn thì ai cũng cãi được; dòng nguyên văn mà nguồn công bố thì không.
  const evidence = (rep.evidence || []).map((e) =>
    el("tr", {},
      el("td", { style: "white-space:nowrap" }, fmtTime(e.seen_at)),
      el("td", {}, el("strong", {}, e.source)),
      el("td", {}, el("div", { class: "evidence" }, e.raw_line))));

  root.appendChild(el("div", { class: "card" },
    el("div", { class: "card-head" },
      el("h2", {}, "Bằng chứng thô"),
      el("span", { class: "chip neutral" }, `${evidence.length} dòng gần nhất`)),
    el("div", { class: "table-wrap" },
      el("table", {},
        el("thead", {}, el("tr", {},
          el("th", {}, "Thời điểm"), el("th", {}, "Nguồn"), el("th", {}, "Dòng nguyên văn"))),
        el("tbody", {}, evidence.length ? evidence
          : el("tr", {}, el("td", { colspan: "3" },
              el("div", { class: "empty" }, "Không có bằng chứng nào."))))))));
}

async function renderAllowlist(view) {
  const { entries } = await api("/api/allowlist");

  const rows = (entries || []).map((e) =>
    el("tr", {},
      el("td", {}, el("code", {}, e.domain)),
      el("td", {}, e.match_type === 1 ? "wildcard" : "exact"),
      el("td", {}, el("span", { class: `chip ${e.tier === "protected" ? "bad" : "neutral"}` }, e.tier)),
      el("td", {}, e.reason || "—"),
      el("td", {}, e.created_by || "—"),
      el("td", { style: "white-space:nowrap" }, fmtTime(e.created_at)),
      can("allowlist:write") && el("td", {},
        el("button", {
          class: "btn sm danger",
          onclick: async () => {
            if (!confirm(`Gỡ ${e.domain} khỏi allowlist?`)) return;
            try {
              await api(`/api/allowlist/${e.id}`, { method: "DELETE" });
              toast("Đã gỡ khỏi allowlist.", "ok");
              route();
            } catch (err) { toast(err.message, "bad"); }
          },
        }, "Gỡ"))));

  const domain = el("input", { type: "text", placeholder: "example.com" });
  const mt = el("select", {}, el("option", { value: "0" }, "exact"), el("option", { value: "1" }, "wildcard"));
  const tier = el("select", {}, el("option", { value: "soft" }, "soft"), el("option", { value: "protected" }, "protected"));
  const reason = el("input", { type: "text", placeholder: "Lý do" });

  const form = el("form", { class: "card-body" },
    el("div", { class: "row" },
      el("div", { class: "field" }, el("label", {}, "Domain"), domain),
      el("div", { class: "field" }, el("label", {}, "Kiểu khớp"), mt),
      el("div", { class: "field" }, el("label", {}, "Mức"), tier),
      el("div", { class: "field" }, el("label", {}, "Lý do"), reason)),
    el("div", { class: "help", style: "margin-bottom:12px" },
      "Mức protected là lớp chống thảm họa: không tenant nào và không policy nào gỡ được. " +
      "Nó cần quyền riêng."),
    el("button", { class: "btn primary", type: "submit" }, "Thêm"));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/api/allowlist", {
        method: "POST",
        body: {
          domain: domain.value,
          match_type: Number(mt.value),
          tier: tier.value,
          reason: reason.value,
        },
      });
      toast("Đã thêm vào allowlist.", "ok");
      route();
    } catch (err) { toast(err.message, "bad"); }
  });

  view.appendChild(el("div", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, "Allowlist toàn cục")),
    can("allowlist:write") ? form : null,
    el("div", { class: "table-wrap" },
      el("table", {},
        el("thead", {}, el("tr", {},
          el("th", {}, "Domain"), el("th", {}, "Kiểu khớp"), el("th", {}, "Mức"),
          el("th", {}, "Lý do"), el("th", {}, "Người thêm"), el("th", {}, "Lúc"),
          can("allowlist:write") && el("th", {}, ""))),
        rows.length ? el("tbody", {}, rows)
          : el("tbody", {}, el("tr", {}, el("td", { colspan: "7" },
              el("div", { class: "empty" }, "Allowlist đang trống."))))))));
}

const RENDERERS = {
  overview: renderOverview,
  sources: renderSources,
  imports: renderImports,
  lookup: renderLookup,
  allowlist: renderAllowlist,
};

// ------------------------------------------------------------------ điều hướng

function buildNav() {
  const nav = $("#nav");
  nav.replaceChildren();
  for (const p of PAGES) {
    if (!can(p.perm)) continue;
    const a = el("a", { class: "nav-link", href: `#${p.id}`, "data-page": p.id },
      icon(p.icon), el("span", {}, p.title));
    nav.appendChild(a);
  }
}

async function route() {
  const id = (location.hash || "#overview").slice(1);
  const page = PAGES.find((p) => p.id === id) || PAGES[0];

  document.body.classList.remove("nav-open");
  $("#page-title").textContent = page.title;
  for (const a of document.querySelectorAll(".nav-link[data-page]")) {
    a.classList.toggle("active", a.dataset.page === page.id);
  }

  const view = $("#view");
  view.replaceChildren(el("div", { class: "empty" }, "Đang tải…"));

  try {
    const fresh = el("div", {});
    await RENDERERS[page.id](fresh);
    view.replaceChildren(...fresh.childNodes);
  } catch (err) {
    if (err.status === 401) return; // showLogin đã chạy
    view.replaceChildren(el("div", { class: "banner bad" }, err.message));
  }
}

// ------------------------------------------------------------------ phiên

function showLogin() {
  me = null;
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
}

function showApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#whoami").textContent = `${me.email} · ${me.role}`;
  buildNav();
  route();
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("#login-error");
  err.classList.add("hidden");

  try {
    me = await api("/api/auth/login", {
      method: "POST",
      body: { email: $("#email").value, password: $("#password").value },
    });
    $("#password").value = "";
    showApp();
  } catch (e2) {
    err.textContent = e2.message;
    err.classList.remove("hidden");
  }
});

$("#logout").addEventListener("click", async () => {
  try { await api("/api/auth/logout", { method: "POST" }); } catch { /* đằng nào cũng thoát */ }
  showLogin();
});

$("#theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("tip-theme", next); } catch { /* storage bị chặn */ }
});

$("#nav-toggle").addEventListener("click", () => document.body.classList.toggle("nav-open"));

window.addEventListener("hashchange", route);

// Khởi động: hỏi phiên hiện tại. api() tự chuyển sang màn đăng nhập nếu 401.
(async () => {
  try {
    me = await api("/api/auth/me");
    showApp();
  } catch { /* showLogin đã chạy trong api() */ }
})();
