/**
 * 节点测速 — Quantumult X
 *
 * 走指定节点测 Cloudflare：延迟 / 抖动 / 下载 / 上传。
 *
 * [rewrite_local]
 * ^http://httpjs\.local/speed url script-echo-response speed-test.js
 *
 * [task_local]
 * event-interaction speed-test.js, tag=节点测速, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Speedtest.png, enabled=true
 *
 * 查询参数：
 *   ?policy=节点名
 *   ?size=2          下载 MB，默认 2，最大 5
 *   ?pings=5         延迟次数，默认 5
 *   ?noup=1          跳过上传
 *   ?format=json
 */

const TITLE = "节点测速";
const UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
const TRACE_URL = "https://speed.cloudflare.com/cdn-cgi/trace";
const DOWN_URL = "https://speed.cloudflare.com/__down?bytes=";
const UP_URL = "https://speed.cloudflare.com/__up";
const PING_FALLBACK = "https://cp.cloudflare.com/generate_204";

(async () => {
  const policy = policyName();
  const q = query();
  const nodeLabel = await policyChain(policy);
  const downBytes = parseSizeMB(q.size) * 1000 * 1000;
  const pingCount = clampInt(q.pings, 5, 3, 8);
  const skipUp = q.noup === "1" || q.noup === "true";
  const upBytes = 256 * 1000;

  const warmup = await timedFetch(TRACE_URL, { policy: policy, timeout: 8000 });
  const pingUrl = warmup.ok ? TRACE_URL : PING_FALLBACK;
  const trace = warmup.ok ? parseTrace(warmup.body) : {};

  const pingMs = [];
  const pingErrors = [];
  for (var i = 0; i < pingCount; i++) {
    const p = await timedFetch(pingUrl, { policy: policy, timeout: 6000 });
    if (p.ok) pingMs.push(p.ms);
    else pingErrors.push(p.error || "fail");
  }
  if (!pingMs.length) throw new Error("延迟测试失败" + (pingErrors[0] ? "：" + pingErrors[0] : ""));
  const st = stats(pingMs);

  const downTimeout = Math.min(25000, Math.max(12000, Math.round(downBytes / 1000) + 8000));
  const down = await timedFetch(DOWN_URL + downBytes, { policy: policy, timeout: downTimeout });
  const downSize = down.ok ? downBytes : 0;
  const downMbps = down.ok ? toMbps(downSize, down.ms) : 0;

  var up = null;
  var upMbps = 0;
  if (!skipUp) {
    up = await timedFetch(UP_URL, {
      policy: policy,
      timeout: 12000,
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: padBytes(upBytes),
    });
    upMbps = up.ok ? toMbps(upBytes, up.ms) : 0;
  }

  if (!trace.ip && down.ok) {
    const t2 = await timedFetch(TRACE_URL, { policy: policy, timeout: 6000 });
    if (t2.ok) Object.assign(trace, parseTrace(t2.body));
  }

  const items = [
    {
      key: "延迟",
      value: Math.round(st.avg) + " ms",
      html: pingHtml(st.avg),
    },
    {
      key: "最低 / 抖动",
      value: Math.round(st.min) + " / " + Math.round(st.jitter) + " ms",
    },
    {
      key: "下载",
      value: down.ok ? fmtMbps(downMbps) : "失败 " + (down.error || ""),
      html: down.ok
        ? speedHtml(downMbps)
        : '<font color="#dc3545">' + escapeHtml("失败 " + (down.error || "")) + "</font>",
    },
  ];
  if (!skipUp) {
    items.push({
      key: "上传",
      value: up && up.ok ? fmtMbps(upMbps) : "失败 " + ((up && up.error) || ""),
      html:
        up && up.ok
          ? speedHtml(upMbps)
          : '<font color="#dc3545">' + escapeHtml("失败 " + ((up && up.error) || "")) + "</font>",
    });
  }
  items.push({
    key: "下载详情",
    value: down.ok ? fmtBytes(downSize) + " · " + (down.ms / 1000).toFixed(2) + " s" : "",
  });
  if (trace.colo || trace.loc) {
    items.push({
      key: "Cloudflare",
      value: [trace.colo, trace.loc ? flagEmoji(trace.loc) + " " + trace.loc : ""].filter(Boolean).join(" · "),
    });
  }
  if (trace.ip) items.push({ key: "落地 IP", value: trace.ip });
  items.push({
    key: "样本",
    value: pingMs.map(function (ms) {
      return Math.round(ms);
    }).join(" / ") + " ms",
  });

  doneOK(TITLE, items, {
    node: nodeLabel || policy || "当前策略",
    json: {
      policy: policy,
      ping: st,
      pingMs: pingMs,
      download: { ok: down.ok, bytes: downSize, ms: down.ms, mbps: round2(downMbps), error: down.error || "" },
      upload: skipUp ? null : { ok: !!(up && up.ok), bytes: upBytes, ms: up ? up.ms : 0, mbps: round2(upMbps), error: (up && up.error) || "" },
      cloudflare: trace,
    },
  });
})().catch((err) => {
  console.log("speed-test error: " + err);
  doneErr(TITLE, String(err && err.message ? err.message : err));
});

function parseSizeMB(raw) {
  const n = parseFloat(raw);
  if (!isFinite(n) || n <= 0) return 2;
  return Math.max(1, Math.min(5, Math.round(n)));
}

function clampInt(raw, fallback, min, max) {
  const n = parseInt(raw, 10);
  if (!isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function parseTrace(text) {
  const o = {};
  String(text || "")
    .split("\n")
    .forEach(function (line) {
      const i = line.indexOf("=");
      if (i > 0) o[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    });
  return o;
}

function stats(list) {
  const a = list.slice().sort(function (x, y) {
    return x - y;
  });
  var sum = 0;
  for (var i = 0; i < a.length; i++) sum += a[i];
  var jit = 0;
  for (var j = 1; j < list.length; j++) jit += Math.abs(list[j] - list[j - 1]);
  return {
    min: a[0],
    max: a[a.length - 1],
    avg: sum / a.length,
    jitter: list.length > 1 ? jit / (list.length - 1) : 0,
  };
}

function toMbps(bytes, ms) {
  if (!ms || ms <= 0 || !bytes) return 0;
  return (bytes * 8) / ms / 1000;
}

function fmtMbps(n) {
  if (!isFinite(n) || n <= 0) return "0 Mbps";
  const s = n >= 10 ? n.toFixed(1) : n.toFixed(2);
  return s + " Mbps";
}

function fmtBytes(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + " MB";
  if (n >= 1000) return Math.round(n / 1000) + " KB";
  return n + " B";
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

function padBytes(n) {
  var s = "0123456789abcdef0123456789abcdef";
  while (s.length < n) s += s;
  return s.slice(0, n);
}

function speedHtml(mbps) {
  var color = "#dc3545";
  if (mbps >= 30) color = "#28a745";
  else if (mbps >= 10) color = "#ca8a04";
  else if (mbps >= 3) color = "#ff8c00";
  return '<font color="' + color + '">' + escapeHtml(fmtMbps(mbps)) + "</font>";
}

function pingHtml(ms) {
  var color = "#dc3545";
  if (ms <= 80) color = "#28a745";
  else if (ms <= 150) color = "#ca8a04";
  else if (ms <= 250) color = "#ff8c00";
  return '<font color="' + color + '">' + escapeHtml(Math.round(ms) + " ms") + "</font>";
}

async function timedFetch(url, opt) {
  const t0 = Date.now();
  try {
    const resp = await qxFetch(url, opt);
    const ms = Date.now() - t0;
    const code = resp && (resp.statusCode || resp.status);
    if (!resp || (code && code >= 400)) {
      return { ok: false, ms: ms, error: "HTTP " + (code || "0"), body: "" };
    }
    return { ok: true, ms: ms, status: code, body: (resp && resp.body) || "" };
  } catch (e) {
    return { ok: false, ms: Date.now() - t0, error: String(e && e.message ? e.message : e), body: "" };
  }
}

async function policyChain(node) {
  if (!node || typeof $configuration === "undefined") return node || "";
  try {
    const msg = await $configuration.sendMessage({
      action: "get_policy_state",
      content: node,
    });
    if (!msg || msg.error || !msg.ret) return node;
    const val = msg.ret[node];
    if (val == null) return node;
    return JSON.stringify(val).replace(/"|\[|\]/g, "").replace(/,/g, " ➟ ") || node;
  } catch (e) {
    return node;
  }
}

function isHttpRequest() {
  return typeof $request !== "undefined";
}

function envPolicy() {
  if (typeof $environment === "undefined") return "";
  return typeof $environment.params === "string" ? $environment.params : "";
}

function parsePairs(raw) {
  const out = {};
  String(raw || "")
    .replace(/^\?/, "")
    .split("&")
    .forEach((part) => {
      if (!part) return;
      const i = part.indexOf("=");
      const k = decodeURIComponent((i < 0 ? part : part.slice(0, i)).trim());
      const v = decodeURIComponent((i < 0 ? "" : part.slice(i + 1)).trim());
      if (k) out[k] = v;
    });
  return out;
}

function query() {
  const fromArg = typeof $argument === "string" ? parsePairs($argument) : {};
  if (!isHttpRequest()) return fromArg;
  const url = $request.url || "";
  const i = url.indexOf("?");
  const fromUrl = i >= 0 ? parsePairs(url.slice(i + 1)) : {};
  return Object.assign({}, fromArg, fromUrl);
}

function policyName() {
  const q = query();
  return q.policy || q.node || envPolicy() || "";
}

function qxFetch(url, opt) {
  opt = opt || {};
  const timeout = opt.timeout || 8000;
  const req = {
    url: url,
    method: opt.method || "GET",
    headers: Object.assign({ "User-Agent": UA }, opt.headers || {}),
    timeout: timeout,
    opts: { hints: false },
  };
  if (opt.policy) req.opts.policy = opt.policy;
  if (opt.redirection === false) req.opts.redirection = false;
  if (opt.body != null) req.body = opt.body;
  return Promise.race([
    $task.fetch(req),
    new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout)),
  ]);
}

function flagEmoji(cc) {
  if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return "";
  return String.fromCodePoint(
    ...cc
      .toUpperCase()
      .split("")
      .map((c) => 127397 + c.charCodeAt(0))
  );
}

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function pageWrap(title, inner) {
  return (
    "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<title>" +
    escapeHtml(title) +
    "</title><style>" +
    "body{margin:0;background:#f3f4f6;color:#111;font:16px/1.55 -apple-system,BlinkMacSystemFont,\"PingFang SC\",sans-serif}" +
    "main{max-width:480px;margin:20px auto;background:#fff;border-radius:16px;padding:20px 18px}" +
    "h1{margin:0 0 14px;font-size:18px;text-align:center}" +
    ".row{display:flex;justify-content:space-between;gap:10px;padding:9px 0;border-bottom:1px solid #eee}" +
    ".k{color:#6b7280;flex:0 0 108px}" +
    ".v{flex:1;text-align:right;word-break:break-all}" +
    ".foot{margin-top:14px;text-align:center;color:#5b4db1;font-size:14px}" +
    "</style></head><body><main><h1>" +
    escapeHtml(title) +
    "</h1>" +
    inner +
    "</main></body></html>"
  );
}

function renderRows(items, mode) {
  return (items || [])
    .filter((item) => item && item.value != null && item.value !== "")
    .map((item) => {
      const val = item.html || escapeHtml(item.value);
      if (mode === "http") {
        return (
          '<div class="row"><span class="k">' +
          escapeHtml(item.key) +
          '</span><span class="v">' +
          val +
          "</span></div>"
        );
      }
      return '<b><font color="#888">' + escapeHtml(item.key) + " : </font></b>" + val + "<br/>";
    })
    .join("");
}

function doneOK(title, items, extra) {
  extra = extra || {};
  const node = extra.node || policyName();
  const httpInner =
    renderRows(items, "http") + (node ? '<div class="foot">节点 ➟ ' + escapeHtml(node) + "</div>" : "");
  const popup =
    '<div style="text-align:center;font-family:-apple-system;font-size:15px;line-height:1.6">' +
    '<hr style="margin:10px 0;border:0;border-top:1px solid #ddd"/>' +
    renderRows(items, "popup") +
    '<hr style="margin:10px 0;border:0;border-top:1px solid #ddd"/>' +
    (node ? '<font color="#6959CD"><b>节点</b> ➟ ' + escapeHtml(node) + "</font>" : "") +
    "</div>";

  if (isHttpRequest()) {
    const asJson = query().format === "json";
    $done({
      status: "HTTP/1.1 200 OK",
      headers: {
        "Content-Type": asJson ? "application/json; charset=utf-8" : "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
      body: asJson
        ? JSON.stringify(
            {
              title: title,
              node: node,
              items: (items || []).map((i) => ({ key: i.key, value: i.value })),
              extra: extra.json || {},
            },
            null,
            2
          )
        : pageWrap(title, httpInner),
    });
    return;
  }
  $done({ title: title, htmlMessage: popup });
}

function doneErr(title, message) {
  doneOK(title, [
    {
      key: "错误",
      value: message,
      html: '<font color="#dc3545">' + escapeHtml(message) + "</font>",
    },
  ]);
}
