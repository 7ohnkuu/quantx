/**
 * 节点风险详情 — Quantumult X
 *
 * 不再只信 IPPure。并行查询：
 *   - ipapi.is      机房 / VPN / 代理 / Tor / 滥用（免费匿名）
 *   - proxycheck.io VPN/代理类型 + 0–100 风险分（免费匿名）
 *   - IPPure        欺诈分（权重最低，容易低估机房/VPN）
 *
 * 综合分按来源加权，并列出各库结论，避免单库误判。
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
 *   ?ipapi_key=  ?pc_key=   可选，提高额度
 */

const TITLE = "节点风险详情";
const UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";

(async () => {
  const policy = policyName();
  const q = query();
  const nodeLabel = await policyChain(policy);

  const pIpapi = lookupIpapiIs(policy, q.ipapi_key);
  const pPure = lookupIppure(policy);
  const pGeo = lookupIpApi(policy);
  const ip = await firstIp([pIpapi, pPure, pGeo]);
  const pPc = ip ? lookupProxycheck(ip, policy, q.pc_key || q.proxycheck_key) : Promise.resolve(failReport("proxycheck", "无 IP"));

  const reports = settleReports(await Promise.allSettled([pIpapi, pPc, pPure, pGeo]));
  const verdict = summarize(reports);
  if (!verdict.ip) throw new Error("全部数据源失败");

  const loc = [flagEmoji(verdict.cc), verdict.cc, verdict.region, verdict.city]
    .filter(function (x) {
      return x;
    })
    .join(" - ");
  const risk = riskLevel(verdict.score);
  const items = [
    { key: "IP", value: verdict.ip },
    { key: "ISP", value: verdict.isp || "-" },
    { key: "ASN", value: verdict.asn || "-" },
    { key: "位置", value: loc || "-" },
    { key: "类型", value: verdict.kindLabel, html: kindHtml(verdict) },
    {
      key: "综合风险",
      value: verdict.score + " · " + risk.label,
      html: '<font color="' + risk.color + '">' + escapeHtml(verdict.score + " · " + risk.label) + "</font>",
    },
    { key: "依据", value: verdict.basis },
  ].concat(
    reports.map(function (r) {
      return {
        key: r.source,
        value: r.ok ? r.line : "失败 " + r.error,
        html: r.ok
          ? escapeHtml(r.line)
          : '<font color="#9ca3af">' + escapeHtml("失败 " + r.error) + "</font>",
      };
    })
  );

  doneOK(TITLE, items, {
    node: nodeLabel || policy || "当前策略",
    json: { verdict: verdict, reports: reports },
  });
})().catch((err) => {
  console.log("server-info error: " + err);
  doneErr(TITLE, String(err && err.message ? err.message : err));
});

function failReport(source, error) {
  return { source: source, ok: false, error: String(error || "未知错误") };
}

function settleReports(settled) {
  return settled.map(function (s, i) {
    if (s.status === "fulfilled" && s.value) return s.value;
    const names = ["ipapi.is", "proxycheck", "IPPure", "ip-api"];
    return failReport(names[i] || "source", s.reason || "rejected");
  });
}

function firstIp(promises) {
  return new Promise(function (resolve) {
    var pending = promises.length;
    var done = false;
    function one(p) {
      Promise.resolve(p).then(
        function (r) {
          if (!done && r && r.ok && r.ip) {
            done = true;
            resolve(r.ip);
            return;
          }
          pending -= 1;
          if (!done && pending <= 0) resolve("");
        },
        function () {
          pending -= 1;
          if (!done && pending <= 0) resolve("");
        }
      );
    }
    for (var i = 0; i < promises.length; i++) one(promises[i]);
  });
}

async function lookupIpapiIs(policy, key) {
  try {
    var url = "https://api.ipapi.is/";
    if (key) url += (url.indexOf("?") >= 0 ? "&" : "?") + "key=" + encodeURIComponent(key);
    const resp = await qxFetch(url, { timeout: 7000, policy: policy });
    const data = parseJSON(resp && resp.body);
    if (!data || !data.ip) throw new Error(statusErr(resp));
    const dc = !!data.is_datacenter;
    const vpn = !!data.is_vpn;
    const proxy = !!data.is_proxy;
    const tor = !!data.is_tor;
    const abuser = !!data.is_abuser;
    const flags = [];
    if (tor) flags.push("Tor");
    if (abuser) flags.push("滥用");
    if (vpn) flags.push("VPN");
    if (proxy) flags.push("代理");
    if (dc) flags.push("数据中心");
    if (!flags.length) flags.push("未标代理");
    return {
      source: "ipapi.is",
      ok: true,
      ip: data.ip,
      cc: data.cc || (data.location && data.location.country_code) || "",
      region: (data.location && (data.location.state || data.location.region)) || "",
      city: (data.location && data.location.city) || "",
      isp: data.company_name || (data.company && data.company.name) || data.asn_org || "",
      asn: data.asn_num ? "AS" + data.asn_num + (data.asn_org ? " " + data.asn_org : "") : "",
      kind: tor ? "tor" : vpn ? "vpn" : proxy ? "proxy" : dc ? "datacenter" : "clean",
      score: ipapiFlagScore(data),
      weight: 1.2,
      line: flags.join(" · "),
      raw: data,
    };
  } catch (e) {
    return failReport("ipapi.is", e && e.message ? e.message : e);
  }
}

function ipapiFlagScore(data) {
  if (data.is_bogon) return 95;
  if (data.is_tor) return 92;
  if (data.is_abuser) return 80;
  if (data.is_vpn) return 72;
  if (data.is_proxy) return 68;
  if (data.is_datacenter) return 48;
  return 8;
}

async function lookupProxycheck(ip, policy, key) {
  try {
    var url =
      "https://proxycheck.io/v2/" +
      encodeURIComponent(ip) +
      "?vpn=1&asn=1&risk=1&port=1&seen=1";
    if (key) url += "&key=" + encodeURIComponent(key);
    const resp = await qxFetch(url, { timeout: 7000, policy: policy });
    const data = parseJSON(resp && resp.body);
    if (!data || data.status !== "ok") {
      throw new Error((data && data.message) || statusErr(resp));
    }
    const rec = data[ip] || pickRecord(data);
    if (!rec) throw new Error("无记录");
    const isProxy = String(rec.proxy).toLowerCase() === "yes";
    const type = String(rec.type || "");
    const kind = proxycheckKind(type, isProxy);
    const score = rec.risk == null || rec.risk === "" ? kindDefaultScore(kind) : Number(rec.risk);
    const bits = [];
    if (type) bits.push(type);
    if (isProxy) bits.push("代理");
    if (isFinite(score)) bits.push(score + " 分");
    return {
      source: "proxycheck",
      ok: true,
      ip: ip,
      cc: rec.isocode || "",
      region: rec.region || "",
      city: rec.city || "",
      isp: rec.provider || rec.organisation || "",
      asn: rec.asn || "",
      kind: kind,
      score: isFinite(score) ? score : null,
      weight: 1.3,
      line: bits.join(" · ") || "无标记",
      raw: rec,
    };
  } catch (e) {
    return failReport("proxycheck", e && e.message ? e.message : e);
  }
}

function pickRecord(data) {
  const keys = Object.keys(data || {});
  for (var i = 0; i < keys.length; i++) {
    const v = data[keys[i]];
    if (v && typeof v === "object" && (v.proxy != null || v.type != null || v.risk != null)) return v;
  }
  return null;
}

function proxycheckKind(type, isProxy) {
  const t = String(type || "").toLowerCase();
  if (t.indexOf("tor") >= 0) return "tor";
  if (t.indexOf("vpn") >= 0) return "vpn";
  if (t.indexOf("residential") >= 0) return isProxy ? "resiproxy" : "residential";
  if (t.indexOf("wireless") >= 0 || t.indexOf("cellular") >= 0 || t.indexOf("mobile") >= 0) return "mobile";
  if (t.indexOf("business") >= 0 || t.indexOf("education") >= 0 || t.indexOf("school") >= 0) return "business";
  if (
    t.indexOf("hosting") >= 0 ||
    t.indexOf("dch") >= 0 ||
    t.indexOf("data") >= 0 ||
    t.indexOf("server") >= 0
  ) {
    return "datacenter";
  }
  if (isProxy || t.indexOf("sock") >= 0 || t.indexOf("http") >= 0 || t.indexOf("comp") >= 0) return "proxy";
  return isProxy ? "proxy" : "clean";
}

function kindDefaultScore(kind) {
  if (kind === "tor") return 92;
  if (kind === "vpn" || kind === "proxy" || kind === "resiproxy") return 70;
  if (kind === "datacenter") return 48;
  if (kind === "business") return 20;
  if (kind === "mobile" || kind === "residential") return 10;
  return 12;
}

async function lookupIppure(policy) {
  try {
    const resp = await qxFetch("https://my.ippure.com/v1/info", { timeout: 7000, policy: policy });
    const data = parseJSON(resp && resp.body);
    if (!data || !data.ip) throw new Error(statusErr(resp));
    const score = Number(data.fraudScore);
    const kind = data.isResidential ? "residential" : "datacenter";
    const bits = [data.isResidential ? "住宅" : "机房"];
    if (data.isBroadcast) bits.push("广播");
    if (isFinite(score)) bits.push(score + " 分");
    return {
      source: "IPPure",
      ok: true,
      ip: data.ip,
      cc: data.countryCode || "",
      region: data.region || "",
      city: data.city || "",
      isp: data.asOrganization || "",
      asn: data.asn ? "AS" + data.asn + (data.asOrganization ? " " + data.asOrganization : "") : "",
      kind: kind,
      score: isFinite(score) ? score : null,
      weight: 0.5,
      line: bits.join(" · "),
      raw: data,
    };
  } catch (e) {
    return failReport("IPPure", e && e.message ? e.message : e);
  }
}

async function lookupIpApi(policy) {
  try {
    const resp = await qxFetch(
      "http://ip-api.com/json?lang=zh-CN&fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query",
      { timeout: 7000, policy: policy }
    );
    const data = parseJSON(resp && resp.body);
    if (!data || data.status !== "success" || !data.query) {
      throw new Error((data && data.message) || statusErr(resp));
    }
    return {
      source: "ip-api",
      ok: true,
      ip: data.query,
      cc: data.countryCode || "",
      region: data.regionName || "",
      city: data.city || "",
      isp: data.isp || data.org || "",
      asn: data.as || "",
      kind: "",
      score: null,
      weight: 0,
      line: "仅地理 / ASN",
      raw: data,
    };
  } catch (e) {
    return failReport("ip-api", e && e.message ? e.message : e);
  }
}

function summarize(reports) {
  const ok = reports.filter(function (r) {
    return r.ok;
  });
  const geo = pickGeo(ok);
  const kinds = {};
  ok.forEach(function (r) {
    if (r.kind) kinds[r.kind] = (kinds[r.kind] || 0) + 1;
  });
  const kind = consensusKind(kinds);
  var num = 0;
  var den = 0;
  ok.forEach(function (r) {
    if (r.weight > 0 && r.score != null && isFinite(r.score)) {
      num += r.score * r.weight;
      den += r.weight;
    }
  });
  var score = den ? Math.round(num / den) : kindDefaultScore(kind);
  if (kind === "tor") score = Math.max(score, 90);
  if (kind === "vpn" || kind === "proxy" || kind === "resiproxy") score = Math.max(score, 50);
  if (kind === "datacenter") score = Math.max(score, 40);
  score = Math.max(0, Math.min(100, score));

  const nRisk = ok.filter(function (r) {
    return r.weight > 0;
  }).length;
  const basis =
    nRisk +
    " 个风控库 · " +
    kindLabel(kind) +
    (kinds[kind] ? " " + kinds[kind] + " 票" : "");

  return {
    ip: geo.ip || (ok[0] && ok[0].ip) || "",
    cc: geo.cc,
    region: geo.region,
    city: geo.city,
    isp: geo.isp,
    asn: geo.asn,
    kind: kind,
    kindLabel: kindLabel(kind),
    score: score,
    basis: basis,
    votes: kinds,
  };
}

function pickGeo(ok) {
  const order = ["ip-api", "proxycheck", "ipapi.is", "IPPure"];
  const out = { ip: "", cc: "", region: "", city: "", isp: "", asn: "" };
  order.forEach(function (name) {
    const r = ok.filter(function (x) {
      return x.source === name;
    })[0];
    if (!r) return;
    if (!out.ip && r.ip) out.ip = r.ip;
    if (!out.cc && r.cc) out.cc = r.cc;
    if (!out.region && r.region) out.region = r.region;
    if (!out.city && r.city) out.city = r.city;
    if (!out.isp && r.isp) out.isp = r.isp;
    if (!out.asn && r.asn) out.asn = r.asn;
  });
  return out;
}

function consensusKind(votes) {
  const rank = ["tor", "vpn", "proxy", "resiproxy", "datacenter", "mobile", "business", "residential", "clean"];
  for (var i = 0; i < rank.length; i++) {
    if (votes[rank[i]]) return rank[i];
  }
  return "clean";
}

function kindLabel(kind) {
  if (kind === "tor") return "Tor 出口";
  if (kind === "vpn") return "VPN";
  if (kind === "proxy") return "代理";
  if (kind === "resiproxy") return "住宅代理";
  if (kind === "datacenter") return "数据中心";
  if (kind === "mobile") return "蜂窝网络";
  if (kind === "business") return "商业宽带";
  if (kind === "residential") return "住宅网络";
  return "普通";
}

function kindHtml(verdict) {
  const risky = { tor: 1, vpn: 1, proxy: 1, resiproxy: 1, datacenter: 1 };
  const color = risky[verdict.kind] ? "#b45309" : "#15803d";
  return '<font color="' + color + '">' + escapeHtml(verdict.kindLabel) + "</font>";
}

function riskLevel(score) {
  if (score <= 24) return { label: "低风险 ✅", color: "#28a745" };
  if (score <= 49) return { label: "中风险 🟡", color: "#ffc107" };
  if (score <= 74) return { label: "高风险 ⚠️", color: "#ff8c00" };
  return { label: "极高风险 ‼️", color: "#dc3545" };
}

function statusErr(resp) {
  if (!resp) return "无响应";
  if (resp.error) return String(resp.error);
  if (resp.statusCode) return "HTTP " + resp.statusCode;
  return "查询失败";
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
