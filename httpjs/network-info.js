/**
 * Network Info — Quantumult X
 *
 * Rewrite of xream/net-lsp-x.js: QX only, no Surge/Loon/Stash/Env layer.
 * Modes:
 *   1. HTTP Request (script-echo-response): open http://httpjs.local/network
 *   2. event-interaction: long-press a node → Network Info
 *
 * [rewrite_local]
 * ^http://httpjs\.local/network url script-echo-response network-info.js
 *
 * [task_local]
 * event-interaction network-info.js, tag=Network Info, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Global.png, enabled=true
 *
 * Query:
 *   ?policy=NodeName   force egress node
 *   ?format=json
 */

const TITLE = "Network Info";
const UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

(async () => {
  const policy = policyName();
  const nodeLabel = await policyChain(policy);
  const ssid = wifiName();

  const [direct, land] = await Promise.all([
    firstOk([() => lookupIpip("direct"), () => lookupIpApi("", "direct")]).catch((e) => ({
      ip: "",
      error: String(e && e.message ? e.message : e),
    })),
    firstOk([() => lookupIpApi("", policy), () => lookupIpwho("", policy)]).catch((e) => ({
      ip: "",
      error: String(e && e.message ? e.message : e),
    })),
  ]);

  let entrance = null;
  const host = await entranceHost(policy);
  if (host && host !== land.ip && !isIP(host)) {
    entrance = { ip: host };
  } else if (host && isIP(host) && host !== land.ip) {
    try {
      entrance = await firstOk([() => lookupIpApi(host, "direct"), () => lookupIpwho(host, "")]);
    } catch (e) {
      entrance = { ip: host };
    }
  } else if (host && isIP(host)) {
    entrance = { ip: host };
  }

  const items = [];
  if (ssid) items.push({ key: "SSID", value: ssid });
  items.push({ key: "Direct IP", value: direct.ip || direct.error || "-" });
  items.push({ key: "Direct location", value: formatWhere(direct) });
  if (direct.isp) items.push({ key: "Direct ISP", value: direct.isp });
  if (entrance) {
    items.push({ key: "Ingress", value: entrance.ip || "-" });
    const where = formatWhere(entrance);
    if (where) items.push({ key: "Ingress location", value: where });
  }
  items.push({ key: "Egress IP", value: land.ip || land.error || "-" });
  items.push({ key: "Egress location", value: formatWhere(land) });
  if (land.isp) items.push({ key: "Egress ISP", value: land.isp });
  if (land.as) items.push({ key: "ASN", value: land.as });

  doneOK(TITLE, items, {
    node: nodeLabel || policy || "current policy",
    json: { direct, landing: land, entrance, ssid, policy },
  });
})().catch((err) => {
  console.log("network-info error: " + err);
  doneErr(TITLE, String(err && err.message ? err.message : err));
});

function formatWhere(info) {
  if (!info) return "";
  const parts = [flagEmoji(info.cc), info.country, info.region, info.city].filter(function (x) {
    return x;
  });
  return parts.join(" ").replace(/\s+/g, " ").trim();
}

async function lookupIpip(policy) {
  const resp = await qxFetch("https://myip.ipip.net/json", { timeout: 6000, policy: policy });
  const body = parseJSON(resp.body);
  if (!body || body.ret !== "ok") throw new Error("ipip lookup failed");
  const loc = (body.data && body.data.location) || [];
  const ip = body.data.ip;
  const cc = loc[0] === "\u4e2d\u56fd" ? "CN" : "";
  try {
    return await lookupIpApi(ip, "direct");
  } catch (e) {
    return {
      ip: ip,
      country: cc === "CN" ? "China" : "",
      region: "",
      city: "",
      isp: "",
      cc: cc,
      source: "ipip",
    };
  }
}

async function lookupIpApi(ip, policy) {
  const path = ip ? "/" + encodeURIComponent(ip) : "";
  const resp = await qxFetch("http://ip-api.com/json" + path, {
    timeout: 8000,
    policy: policy,
  });
  const body = parseJSON(resp.body);
  if (!body || body.status !== "success") throw new Error((body && body.message) || "ip-api lookup failed");
  return {
    ip: body.query,
    country: body.country || "",
    region: body.regionName || "",
    city: body.city || "",
    isp: body.isp || "",
    org: body.org || "",
    as: body.as || "",
    cc: body.countryCode || "",
    source: "ip-api",
  };
}

async function lookupIpwho(ip, policy) {
  const path = ip ? "/" + encodeURIComponent(ip) : "";
  const resp = await qxFetch("https://ipwho.is" + path, { timeout: 8000, policy: policy });
  const body = parseJSON(resp.body);
  if (!body || body.success === false) throw new Error((body && body.message) || "ipwho.is lookup failed");
  const conn = body.connection || {};
  return {
    ip: body.ip,
    country: body.country || "",
    region: body.region || "",
    city: body.city || "",
    isp: conn.isp || conn.org || "",
    org: conn.org || "",
    as: conn.asn ? "AS" + conn.asn : "",
    cc: body.country_code || "",
    source: "ipwho.is",
  };
}

async function firstOk(factories) {
  let last = new Error("all lookups failed");
  for (let i = 0; i < factories.length; i++) {
    try {
      return await factories[i]();
    } catch (e) {
      last = e;
      console.log(String(e && e.message ? e.message : e));
    }
  }
  throw last;
}

async function entranceHost(node) {
  if (!node || typeof $configuration === "undefined") return "";
  try {
    const msg = await $configuration.sendMessage({
      action: "get_server_description",
      content: node,
    });
    if (!msg || msg.error || !msg.ret) return "";
    const raw = Object.values(msg.ret)[0];
    const text = typeof raw === "string" ? raw : JSON.stringify(raw || "");
    const m = text.match(/=\s*(\S+):\d+/);
    return m ? m[1] : "";
  } catch (e) {
    console.log("entranceHost: " + e);
    return "";
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

function wifiName() {
  if (typeof $environment === "undefined") return "";
  const version = String($environment.version || "");
  if (version.indexOf("macOS") === 0) return "";
  return $environment.ssid || "";
}

function isIP(s) {
  return (
    /^(\d{1,3}\.){3}\d{1,3}$/.test(s) ||
    (typeof s === "string" && s.indexOf(":") >= 0 && /[0-9a-fA-F:]{2,}/.test(s))
  );
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
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
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
    renderRows(items, "http") + (node ? '<div class="foot">Node ➟ ' + escapeHtml(node) + "</div>" : "");
  const popup =
    '<div style="text-align:center;font-family:-apple-system;font-size:15px;line-height:1.6">' +
    '<hr style="margin:10px 0;border:0;border-top:1px solid #ddd"/>' +
    renderRows(items, "popup") +
    '<hr style="margin:10px 0;border:0;border-top:1px solid #ddd"/>' +
    (node ? '<font color="#6959CD"><b>Node</b> ➟ ' + escapeHtml(node) + "</font>" : "") +
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
      key: "Error",
      value: message,
      html: '<font color="#dc3545">' + escapeHtml(message) + "</font>",
    },
  ]);
}
