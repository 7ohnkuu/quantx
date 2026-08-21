/**
 * 节点风险详情 — Quantumult X
 *
 * 从 ddgksf2013/server-info-pure.js 重构：IPPure 欺诈分 / 住宅 vs 机房。
 * 同时支持：
 *   1. HTTP Request（script-echo-response）：Safari 打开 http://httpjs.local/risk
 *   2. event-interaction：长按节点 → 节点風險详情
 *
 * [rewrite_local]
 * ^http://httpjs\.local/risk url script-echo-response server-info.js
 *
 * [task_local]
 * event-interaction server-info.js, tag=节点風險详情, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/WiFi.png, enabled=true
 *
 * 查询参数：
 *   ?policy=节点名
 *   ?format=json
 */

const TITLE = "IPPure 节点详情";
const API = "https://my.ippure.com/v1/info";
const UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";

(async () => {
  const policy = policyName();
  const nodeLabel = await policyChain(policy);
  const resp = await qxFetch(API, { timeout: 8000, policy: policy });
  if (!resp || resp.statusCode !== 200) {
    throw new Error(resp && resp.statusCode ? "HTTP " + resp.statusCode : "查询超时");
  }
  const data = parseJSON(resp.body);
  if (!data || !data.ip) throw new Error("解析失败");

  const score = Number(data.fraudScore);
  const risk = riskLevel(isFinite(score) ? score : 0);
  const type = data.isResidential ? "住宅网络 🏠" : "数据中心 🏢";
  const loc = [flagEmoji(data.countryCode), data.countryCode, data.region, data.city]
    .filter(function (x) {
      return x;
    })
    .join(" - ");

  const items = [
    { key: "IP", value: data.ip },
    { key: "ISP", value: data.asOrganization || "-" },
    { key: "ASN", value: data.asn ? "AS" + data.asn : "-" },
    { key: "位置", value: loc || "-" },
    { key: "时区", value: data.timezone || "" },
    { key: "类型", value: type },
    {
      key: "广播",
      value: data.isBroadcast ? "是" : "否",
    },
    {
      key: "欺诈值",
      value: (isFinite(score) ? score : "-") + " 分",
    },
    {
      key: "风险等级",
      value: risk.label,
      html: '<font color="' + risk.color + '">' + escapeHtml(risk.label) + "</font>",
    },
  ];

  doneOK(TITLE, items, {
    node: nodeLabel || policy || "当前策略",
    json: data,
  });
})().catch((err) => {
  console.log("server-info error: " + err);
  doneErr(TITLE, String(err && err.message ? err.message : err));
});

function riskLevel(score) {
  if (score <= 25) return { label: "低风险 ✅", color: "#28a745" };
  if (score <= 50) return { label: "中风险 🟡", color: "#ffc107" };
  if (score <= 75) return { label: "高风险 ⚠️", color: "#ff8c00" };
  return { label: "极高风险 ‼️", color: "#dc3545" };
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

function parseJSON(text) {
  try {
    return JSON.parse(text);
  } catch (e) {
    return null;
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
  if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return "🌍";
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
