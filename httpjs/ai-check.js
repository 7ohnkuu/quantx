/**
 * AI Node Check — Quantumult X
 *
 * Tests OpenAI, Anthropic, Gemini, and Grok network reachability.
 * Authentication errors mean the provider authentication edge was reached;
 * they do NOT prove that a real account/key/model request will succeed.
 * Geo verdicts come from live endpoint responses, not static country lists.
 *
 * [rewrite_local]
 * ^http://httpjs\.local/ai url script-echo-response ai-check.js
 *
 * [task_local]
 * event-interaction ai-check.js, tag=AI Models, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/ChatGPT.png, enabled=true
 *
 * Query:
 *   ?policy=NodeName
 *   ?format=json
 *   ?ipapi_key=  ?pc_key=
 */

const TITLE = "AI Node Check";
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

(async () => {
  const policy = policyName();
  const q = query();
  const nodeLabel = await policyChain(policy);

  const pIpapi = lookupIpapiIs(policy, q.ipapi_key);
  const pPure = lookupIppure(policy);
  const ip = await firstIp([pIpapi, pPure]);
  const pPc = ip
    ? lookupProxycheck(ip, policy, q.pc_key || q.proxycheck_key)
    : Promise.resolve(failReport("proxycheck", "no IP"));

  const settled = await Promise.all([
    pIpapi,
    pPc,
    pPure,
    checkOpenAI(policy),
    checkAnthropic(policy),
    checkGemini(policy),
    checkGrok(policy),
  ]);

  const reports = settled.slice(0, 3);
  const risk = summarizeRisk(reports);
  const vendors = [
    finalizeVendor("OpenAI", settled[3], risk),
    finalizeVendor("Anthropic", settled[4], risk),
    finalizeVendor("Gemini", settled[5], risk),
    finalizeVendor("Grok", settled[6], risk),
  ];
  const verdict = overall(vendors, risk);

  const items = [
    { key: "IP", value: risk.ip || "-" },
    { key: "ASN", value: risk.asn || "" },
    { key: "IP type", value: risk.kindLabel, html: kindHtml(risk) },
    {
      key: "Risk",
      value: risk.score + " · " + riskLevel(risk.score).label,
      html:
        '<font color="' +
        riskLevel(risk.score).color +
        '">' +
        escapeHtml(risk.score + " · " + riskLevel(risk.score).label) +
        "</font>",
    },
    { key: "Location", value: [flagEmoji(risk.cc), risk.cc, risk.region, risk.city].filter(Boolean).join(" ") },
  ];

  vendors.forEach(function (v) {
    items.push({ key: v.name, value: v.text, html: colorizeVendor(v) });
  });
  items.push({ key: "Verdict", value: verdict.text, html: colorizeOverall(verdict) });

  doneOK(TITLE, items, {
    node: nodeLabel || policy || "current policy",
    json: { risk: risk, vendors: vendors, reports: reports },
  });
})().catch((err) => {
  console.log("ai-check error: " + err);
  doneErr(TITLE, String(err && err.message ? err.message : err));
});

async function checkOpenAI(policy) {
  const [trace, ios, api] = await Promise.all([
    safeFetch("https://chatgpt.com/cdn-cgi/trace", { policy: policy, timeout: 8000 }),
    safeFetch("https://ios.chat.openai.com/", { policy: policy, timeout: 8000 }),
    safeFetch("https://api.openai.com/v1/models", { policy: policy, timeout: 8000 }),
  ]);
  const loc = parseTrace(trace.body).loc || "";
  const iosJson = parseJSON(ios.body) || {};
  const waf = String(iosJson.type || "").toLowerCase();
  let web = "fail";
  if (waf === "country" || /unsupported.?country|not available in (your )?(country|region)/i.test(ios.body)) web = "blocked";
  else if (waf === "dc" || waf === "datacenter" || waf === "vpn" || waf === "proxy") web = "friction";
  else if (ios.status && ios.status < 400) web = "reachable";
  else if (ios.status === 403) web = "challenge";
  return {
    loc: loc,
    api: classifyApi(api, [/missing bearer/i, /invalid_api_key/i, /authentication/i, /unauthorized/i]),
    web: web,
    detail: waf ? "waf:" + waf : "",
  };
}

async function checkAnthropic(policy) {
  const [trace, api, web] = await Promise.all([
    safeFetch("https://claude.ai/cdn-cgi/trace", { policy: policy, timeout: 8000 }),
    safeFetch("https://api.anthropic.com/v1/messages", {
      policy: policy,
      timeout: 8000,
      method: "POST",
      headers: { "content-type": "application/json", "anthropic-version": "2023-06-01" },
      body: "{}",
    }),
    safeFetch("https://claude.ai/", { policy: policy, timeout: 8000 }),
  ]);
  const body = String(web.body || "");
  let webSt = "fail";
  if (/not available in (your )?(country|region)|isn't available in/i.test(body)) webSt = "blocked";
  else if (/just a moment|cf-mitigated|attention required/i.test(body) || web.status === 403) webSt = "challenge";
  else if (web.status && web.status < 400) webSt = "reachable";
  return {
    loc: parseTrace(trace.body).loc || "",
    api: classifyApi(api, [/x-api-key/i, /authentication_error/i, /unauthorized/i]),
    web: webSt,
    detail: "",
  };
}

async function checkGemini(policy) {
  const [api, web] = await Promise.all([
    safeFetch("https://generativelanguage.googleapis.com/v1beta/models?key=invalid", {
      policy: policy,
      timeout: 8000,
    }),
    safeFetch("https://aistudio.google.com/robots.txt", { policy: policy, timeout: 8000 }),
  ]);
  let webSt = "fail";
  if (web.status && web.status < 400) webSt = "reachable";
  else if (web.status === 403) webSt = "challenge";
  return { loc: "", api: classifyGemini(api), web: webSt, detail: "" };
}

async function checkGrok(policy) {
  const [trace, api] = await Promise.all([
    safeFetch("https://grok.com/cdn-cgi/trace", { policy: policy, timeout: 8000 }),
    safeFetch("https://api.x.ai/v1/models", { policy: policy, timeout: 8000 }),
  ]);
  return {
    loc: parseTrace(trace.body).loc || "",
    api: classifyApi(api, [/no credentials/i, /unauthenticated/i, /unauthorized/i, /missing.*api.?key/i]),
    web: trace.status && trace.status < 400 ? "reachable" : "fail",
    detail: "",
  };
}

function classifyApi(api, authRes) {
  if (!api || (api.ok === false && api.error === "timeout")) return "fail";
  const body = String(api.body || "");
  const code = api.status;
  if (/unsupported.?country|not available in|region.*(block|restrict)|forbidden.*region|requests from this location/i.test(body)) {
    return "blocked";
  }
  for (let i = 0; i < authRes.length; i++) {
    if (authRes[i].test(body)) return "reachable";
  }
  if (code === 401) return "reachable";
  if (code === 403) return "challenge";
  if (code === 404) return "reachable";
  if (code && code >= 500) return "fail";
  return code ? "reachable" : "fail";
}

function classifyGemini(api) {
  const body = String((api && api.body) || "");
  const code = api && api.status;
  if (!api || (api.ok === false && api.error === "timeout")) return "fail";
  if (/FAILED_PRECONDITION|not available|PERMISSION_DENIED.*location|Requests from this location/i.test(body)) return "blocked";
  if (/API_KEY_INVALID|API key not valid|API key not found/i.test(body)) return "reachable";
  if (code === 400 || code === 401) return "reachable";
  if (code === 403 && /unregistered callers|PERMISSION_DENIED/i.test(body) && !/location/i.test(body)) return "reachable";
  if (code === 403) return "challenge";
  if (code && code >= 500) return "fail";
  return code ? "reachable" : "fail";
}

function finalizeVendor(name, raw, risk) {
  const r = raw || { api: "fail", web: "fail", loc: "", detail: "" };
  const cc = String(r.loc || risk.cc || "").toUpperCase();
  const endpoint = r.api === "reachable";
  const riskyIp = risk.score >= 50 || /datacenter|vpn|proxy|tor|resiproxy/.test(risk.kind || "");
  let status = "fail";
  const parts = [];

  if (r.api === "blocked" || r.web === "blocked") {
    status = "blocked";
    parts.push("Geo/service blocked");
  } else if (endpoint && (r.web === "friction" || r.web === "challenge" || riskyIp)) {
    status = "risky";
    parts.push("Auth edge reached");
    if (r.web === "friction") parts.push("WAF/IP friction");
    else if (r.web === "challenge") parts.push("web challenge");
    else if (riskyIp) parts.push(risk.kindLabel);
  } else if (endpoint) {
    status = "ok";
    parts.push("Auth edge reached");
    if (r.web === "reachable") parts.push("web reachable");
  } else if (r.api === "challenge" || r.web === "reachable" || r.web === "challenge") {
    status = "partial";
    parts.push(r.web === "reachable" ? "Web reachable" : "Endpoint challenged");
  } else {
    parts.push("Unreachable / unknown");
  }

  if (cc) parts.push(flagEmoji(cc) + " " + cc);
  return { name: name, status: status, api: r.api, web: r.web, loc: cc, text: parts.join(" · "), detail: r.detail || "" };
}

function overall(vendors, risk) {
  const reached = vendors.filter((v) => v.api === "reachable").length;
  const blocked = vendors.filter((v) => v.status === "blocked").length;
  const riskyIp = risk.score >= 50 || /datacenter|vpn|proxy|tor|resiproxy/.test(risk.kind || "");
  if (blocked === 4) return { status: "blocked", text: "All four providers returned blocking signals" };
  if (reached === 0) return { status: "partial", text: "No provider authentication edge confirmed" };
  if (reached === 4 && !riskyIp && risk.score < 35) {
    return { status: "ok", text: "4/4 authentication edges reachable · IP reputation looks low-risk" };
  }
  if (reached >= 3 && riskyIp) {
    return { status: "risky", text: reached + "/4 authentication edges reachable · elevated WAF/abuse-control friction" };
  }
  return { status: reached >= 3 ? "ok" : "partial", text: reached + "/4 authentication edges reachable" };
}

function colorizeVendor(v) {
  const map = { ok: "#15803d", risky: "#b45309", partial: "#ca8a04", blocked: "#b91c1c", fail: "#6b7280" };
  return '<font color="' + (map[v.status] || "#6b7280") + '">' + escapeHtml(v.text) + "</font>";
}

function colorizeOverall(o) {
  const map = { ok: "#15803d", risky: "#b45309", partial: "#ca8a04", blocked: "#b91c1c", fail: "#6b7280" };
  return '<b><font color="' + (map[o.status] || "#111") + '">' + escapeHtml(o.text) + "</font></b>";
}

function kindHtml(risk) {
  const risky = { tor: 1, vpn: 1, proxy: 1, resiproxy: 1, datacenter: 1 };
  const color = risky[risk.kind] ? "#b45309" : "#15803d";
  return '<font color="' + color + '">' + escapeHtml(risk.kindLabel) + "</font>";
}

async function safeFetch(url, opt) {
  try {
    const resp = await qxFetch(url, opt);
    const status = (resp && (resp.statusCode || resp.status)) || 0;
    return { ok: true, status: status, body: String((resp && resp.body) || ""), headers: (resp && resp.headers) || {}, error: "" };
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    return { ok: false, status: 0, body: "", headers: {}, error: msg === "timeout" ? "timeout" : msg };
  }
}

function parseTrace(text) {
  const o = {};
  String(text || "").split("\n").forEach(function (line) {
    const i = line.indexOf("=");
    if (i > 0) o[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return o;
}

function failReport(source, error) {
  return { source: source, ok: false, error: String(error || "unknown error") };
}

function firstIp(promises) {
  return new Promise(function (resolve) {
    let pending = promises.length;
    let done = false;
    promises.forEach(function (p) {
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
    });
  });
}

async function lookupIpapiIs(policy, key) {
  try {
    let url = "https://api.ipapi.is/";
    if (key) url += "?key=" + encodeURIComponent(key);
    const resp = await qxFetch(url, { timeout: 7000, policy: policy });
    const data = parseJSON(resp && resp.body);
    if (!data || !data.ip) throw new Error(statusErr(resp));
    const dc = !!data.is_datacenter;
    const vpn = !!data.is_vpn;
    const proxy = !!data.is_proxy;
    const tor = !!data.is_tor;
    const abuser = !!data.is_abuser;
    return {
      source: "ipapi.is",
      ok: true,
      ip: data.ip,
      cc: data.cc || (data.location && data.location.country_code) || "",
      region: (data.location && (data.location.state || data.location.region)) || "",
      city: (data.location && data.location.city) || "",
      isp: data.company_name || data.asn_org || "",
      asn: data.asn_num ? "AS" + data.asn_num + (data.asn_org ? " " + data.asn_org : "") : "",
      kind: tor ? "tor" : vpn ? "vpn" : proxy ? "proxy" : dc ? "datacenter" : "clean",
      score: tor ? 92 : abuser ? 80 : vpn ? 72 : proxy ? 68 : dc ? 48 : 8,
      weight: 1.2,
    };
  } catch (e) {
    return failReport("ipapi.is", e && e.message ? e.message : e);
  }
}

async function lookupProxycheck(ip, policy, key) {
  try {
    let url = "https://proxycheck.io/v2/" + encodeURIComponent(ip) + "?vpn=1&asn=1&risk=1";
    if (key) url += "&key=" + encodeURIComponent(key);
    const resp = await qxFetch(url, { timeout: 7000, policy: policy });
    const data = parseJSON(resp && resp.body);
    if (!data || data.status !== "ok") throw new Error((data && data.message) || statusErr(resp));
    let rec = data[ip];
    if (!rec) {
      Object.keys(data).some(function (k) {
        if (data[k] && data[k].proxy != null) {
          rec = data[k];
          return true;
        }
        return false;
      });
    }
    if (!rec) throw new Error("no record");
    const isProxy = String(rec.proxy).toLowerCase() === "yes";
    const t = String(rec.type || "").toLowerCase();
    let kind = "clean";
    if (t.indexOf("tor") >= 0) kind = "tor";
    else if (t.indexOf("vpn") >= 0) kind = "vpn";
    else if (t.indexOf("residential") >= 0) kind = isProxy ? "resiproxy" : "residential";
    else if (t.indexOf("hosting") >= 0 || t.indexOf("dch") >= 0 || t.indexOf("data") >= 0) kind = "datacenter";
    else if (isProxy) kind = "proxy";
    else if (t.indexOf("business") >= 0) kind = "business";
    const score = rec.risk == null || rec.risk === "" ? null : Number(rec.risk);
    return {
      source: "proxycheck", ok: true, ip: ip, cc: rec.isocode || "", region: rec.region || "", city: rec.city || "",
      isp: rec.provider || rec.organisation || "", asn: rec.asn || "", kind: kind,
      score: isFinite(score) ? score : null, weight: 1.3,
    };
  } catch (e) {
    return failReport("proxycheck", e && e.message ? e.message : e);
  }
}

async function lookupIppure(policy) {
  try {
    const resp = await qxFetch("https://my.ippure.com/v1/info", { timeout: 7000, policy: policy });
    const data = parseJSON(resp && resp.body);
    if (!data || !data.ip) throw new Error(statusErr(resp));
    const score = Number(data.fraudScore);
    return {
      source: "IPPure", ok: true, ip: data.ip, cc: data.countryCode || "", region: data.region || "", city: data.city || "",
      isp: data.asOrganization || "", asn: data.asn ? "AS" + data.asn : "",
      kind: data.isResidential ? "residential" : "datacenter", score: isFinite(score) ? score : null, weight: 0.5,
    };
  } catch (e) {
    return failReport("IPPure", e && e.message ? e.message : e);
  }
}

function summarizeRisk(reports) {
  const ok = reports.filter((r) => r && r.ok);
  const kinds = {};
  ok.forEach((r) => { if (r.kind) kinds[r.kind] = (kinds[r.kind] || 0) + 1; });
  const rank = ["tor", "vpn", "proxy", "resiproxy", "datacenter", "business", "residential", "clean"];
  let kind = "clean";
  for (let i = 0; i < rank.length; i++) if (kinds[rank[i]]) { kind = rank[i]; break; }
  let num = 0;
  let den = 0;
  ok.forEach((r) => {
    if (r.weight > 0 && r.score != null && isFinite(r.score)) { num += r.score * r.weight; den += r.weight; }
  });
  let score = den ? Math.round(num / den) : 12;
  if (kind === "tor") score = Math.max(score, 90);
  if (kind === "vpn" || kind === "proxy" || kind === "resiproxy") score = Math.max(score, 50);
  if (kind === "datacenter") score = Math.max(score, 40);
  score = Math.max(0, Math.min(100, score));

  const geo = { ip: "", cc: "", region: "", city: "", isp: "", asn: "" };
  ["proxycheck", "ipapi.is", "IPPure"].forEach(function (name) {
    const r = ok.find((x) => x.source === name);
    if (!r) return;
    ["ip", "cc", "region", "city", "isp", "asn"].forEach((k) => { if (!geo[k] && r[k]) geo[k] = r[k]; });
  });
  const labels = { tor: "Tor exit", vpn: "VPN", proxy: "Proxy", resiproxy: "Residential proxy", datacenter: "Datacenter", business: "Business", residential: "Residential", clean: "Clean" };
  return { ip: geo.ip, cc: geo.cc, region: geo.region, city: geo.city, isp: geo.isp, asn: geo.asn, kind: kind, kindLabel: labels[kind] || kind, score: score };
}

function riskLevel(score) {
  if (score <= 24) return { label: "Low", color: "#28a745" };
  if (score <= 49) return { label: "Medium", color: "#ffc107" };
  if (score <= 74) return { label: "High", color: "#ff8c00" };
  return { label: "Critical", color: "#dc3545" };
}

function statusErr(resp) {
  if (!resp) return "no response";
  if (resp.error) return String(resp.error);
  if (resp.statusCode || resp.status) return "HTTP " + (resp.statusCode || resp.status);
  return "lookup failed";
}

async function policyChain(node) {
  if (!node || typeof $configuration === "undefined") return node || "";
  try {
    const msg = await $configuration.sendMessage({ action: "get_policy_state", content: node });
    if (!msg || msg.error || !msg.ret) return node;
    const val = msg.ret[node];
    if (val == null) return node;
    return JSON.stringify(val).replace(/"|\[|\]/g, "").replace(/,/g, " ➟ ") || node;
  } catch (e) { return node; }
}

function parseJSON(text) { try { return JSON.parse(text); } catch (e) { return null; } }
function isHttpRequest() { return typeof $request !== "undefined"; }
function envPolicy() { return typeof $environment !== "undefined" && typeof $environment.params === "string" ? $environment.params : ""; }

function parsePairs(raw) {
  const out = {};
  String(raw || "").replace(/^\?/, "").split("&").forEach((part) => {
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
  return Object.assign({}, fromArg, i >= 0 ? parsePairs(url.slice(i + 1)) : {});
}

function policyName() { const q = query(); return q.policy || q.node || envPolicy() || ""; }

function qxFetch(url, opt) {
  opt = opt || {};
  const timeout = opt.timeout || 8000;
  const req = {
    url: url, method: opt.method || "GET", headers: Object.assign({ "User-Agent": UA }, opt.headers || {}),
    timeout: timeout, opts: { hints: false },
  };
  if (opt.policy) req.opts.policy = opt.policy;
  if (opt.redirection === false) req.opts.redirection = false;
  if (opt.body != null) req.body = opt.body;
  return Promise.race([$task.fetch(req), new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), timeout))]);
}

function flagEmoji(cc) {
  if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return "";
  return String.fromCodePoint(...cc.toUpperCase().split("").map((c) => 127397 + c.charCodeAt(0)));
}

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function pageWrap(title, inner) {
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' +
    escapeHtml(title) +
    '</title><style>body{margin:0;background:#f3f4f6;color:#111;font:16px/1.55 -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif}main{max-width:480px;margin:20px auto;background:#fff;border-radius:16px;padding:20px 18px}h1{margin:0 0 14px;font-size:18px;text-align:center}.row{display:flex;justify-content:space-between;gap:10px;padding:9px 0;border-bottom:1px solid #eee}.k{color:#6b7280;flex:0 0 108px}.v{flex:1;text-align:right;word-break:break-all}.foot{margin-top:14px;text-align:center;color:#5b4db1;font-size:14px}</style></head><body><main><h1>' +
    escapeHtml(title) + "</h1>" + inner + "</main></body></html>";
}

function renderRows(items, mode) {
  return (items || []).filter((item) => item && item.value != null && item.value !== "").map((item) => {
    const val = item.html || escapeHtml(item.value);
    if (mode === "http") return '<div class="row"><span class="k">' + escapeHtml(item.key) + '</span><span class="v">' + val + "</span></div>";
    return '<b><font color="#888">' + escapeHtml(item.key) + " : </font></b>" + val + "<br/>";
  }).join("");
}

function doneOK(title, items, extra) {
  extra = extra || {};
  const node = extra.node || policyName();
  const httpInner = renderRows(items, "http") + (node ? '<div class="foot">Node ➟ ' + escapeHtml(node) + "</div>" : "");
  const popup = '<div style="text-align:center;font-family:-apple-system;font-size:15px;line-height:1.6"><hr style="margin:10px 0;border:0;border-top:1px solid #ddd"/>' +
    renderRows(items, "popup") + '<hr style="margin:10px 0;border:0;border-top:1px solid #ddd"/>' +
    (node ? '<font color="#6959CD"><b>Node</b> ➟ ' + escapeHtml(node) + "</font>" : "") + "</div>";
  if (isHttpRequest()) {
    const asJson = query().format === "json";
    $done({
      status: "HTTP/1.1 200 OK",
      headers: { "Content-Type": asJson ? "application/json; charset=utf-8" : "text/html; charset=utf-8", "Cache-Control": "no-store" },
      body: asJson ? JSON.stringify({ title: title, node: node, items: (items || []).map((i) => ({ key: i.key, value: i.value })), extra: extra.json || {} }, null, 2) : pageWrap(title, httpInner),
    });
    return;
  }
  $done({ title: title, htmlMessage: popup });
}

function doneErr(title, message) {
  doneOK(title, [{ key: "Error", value: message, html: '<font color="#dc3545">' + escapeHtml(message) + "</font>" }]);
}
