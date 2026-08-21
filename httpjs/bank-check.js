/**
 * US Banks Node Check — Quantumult X
 *
 * Tests public login-edge reachability for Bank of America, Citi, and Chase.
 * It does NOT log in, submit credentials, or predict internal fraud scoring.
 * Signals:
 *   - Akamai/edge deny pages
 *   - public login-page reachability
 *   - HTTPS-only IP reputation from ipapi.is / proxycheck / IPPure
 *
 * [rewrite_local]
 * ^http://httpjs\.local/banks url script-echo-response bank-check.js
 *
 * [task_local]
 * event-interaction bank-check.js, tag=US Banks, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/United_States.png, enabled=true
 *
 * Query:
 *   ?policy=NodeName
 *   ?format=json
 *   ?ipapi_key=  ?pc_key=
 */

const TITLE = "US Banks Check";
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const US_OK = { US: 1, PR: 1, GU: 1, VI: 1, AS: 1, MP: 1 };

const BANKS = [
  {
    name: "BofA",
    url: "https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go",
    expect: /bank of america/i,
    extra: /log\s*in|user id|online banking/i,
    header: "x-boa-requestid",
  },
  {
    name: "Citi",
    url: "https://online.citi.com/US/ag/signin",
    expect: /citi/i,
    extra: /sign\s*in|log\s*in|online/i,
    header: "x-akamai-citisite",
  },
  {
    name: "Chase",
    url: "https://secure.chase.com/web/auth/",
    expect: /chase/i,
    extra: /logon|sign\s*in|online/i,
    header: "x-akamai-transformed",
  },
];

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

  const settled = await Promise.all([pIpapi, pPc, pPure].concat(BANKS.map((b) => checkBank(b, policy))));
  const reports = settled.slice(0, 3);
  const risk = summarizeRisk(reports);
  const banks = settled.slice(3);
  const sum = overall(banks, risk);

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
  banks.forEach((b) => items.push({ key: b.name, value: b.text, html: colorize(b.status, b.text) }));
  items.push({ key: "Verdict", value: sum.text, html: "<b>" + colorize(sum.status, sum.text) + "</b>" });

  doneOK(TITLE, items, {
    node: nodeLabel || policy || "current policy",
    json: { risk: risk, banks: banks, reports: reports },
  });
})().catch((err) => {
  console.log("bank-check error: " + err);
  doneErr(TITLE, String(err && err.message ? err.message : err));
});

async function checkBank(bank, policy) {
  const resp = await safeFetch(bank.url, { policy: policy, timeout: 12000 });
  const body = String(resp.body || "");
  const title = pageTitle(body);
  const server = headerOf(resp.headers, "server");
  let status = "fail";
  const parts = [];

  if (resp.error === "timeout" || (!resp.status && resp.ok === false)) {
    parts.push("Unreachable");
  } else if (isAkamaiDeny(resp.status, body, server)) {
    status = "blocked";
    parts.push("Edge denied");
  } else if (resp.status === 403 || resp.status === 401) {
    status = "blocked";
    parts.push("HTTP " + resp.status);
  } else if (resp.status && resp.status >= 500) {
    parts.push("HTTP " + resp.status);
  } else if (resp.status && resp.status < 400) {
    const named = bank.expect.test(body) || bank.expect.test(title);
    const loginish = !bank.extra || bank.extra.test(body) || bank.extra.test(title);
    const hdrHit = bank.header && headerOf(resp.headers, bank.header);
    if (named || hdrHit) {
      status = "ok";
      parts.push("Public edge reachable");
      if (loginish) parts.push("login page detected");
    } else if (/just a moment|cf-mitigated|captcha|attention required/i.test(body)) {
      status = "challenge";
      parts.push("Edge challenge");
    } else {
      status = "partial";
      parts.push("HTTP " + resp.status + " · identity unconfirmed");
    }
  } else {
    parts.push(resp.status ? "HTTP " + resp.status : "Failed");
  }

  return {
    name: bank.name,
    status: status,
    http: resp.status || 0,
    title: title,
    text: parts.join(" · "),
  };
}

function isAkamaiDeny(status, body, server) {
  if (!(status === 403 || status === 401)) return false;
  if (/Access Denied/i.test(body) && /Reference #/i.test(body)) return true;
  if (/AkamaiGHost/i.test(server) && /Access Denied|permission to access/i.test(body)) return true;
  return false;
}

function pageTitle(html) {
  const m = String(html || "").match(/<title[^>]*>([^<]+)<\/title>/i);
  return m ? m[1].replace(/\s+/g, " ").trim() : "";
}

function headerOf(headers, name) {
  const h = headers || {};
  const hit = Object.keys(h).find((k) => k.toLowerCase() === String(name).toLowerCase());
  return hit ? String(h[hit]) : "";
}

function overall(banks, risk) {
  const us = !!(risk.cc && US_OK[String(risk.cc).toUpperCase()]);
  const riskyIp = risk.score >= 40 || /datacenter|vpn|proxy|tor|resiproxy/.test(risk.kind || "");
  const ok = banks.filter((b) => b.status === "ok").length;
  const blocked = banks.filter((b) => b.status === "blocked").length;
  const challenged = banks.filter((b) => b.status === "challenge").length;
  const fail = banks.filter((b) => b.status === "fail").length;

  if (blocked > 0) {
    return { status: "blocked", text: blocked + "/3 public bank edge(s) denied this egress" };
  }
  if (ok === 3 && us && !riskyIp && risk.score < 30) {
    return { status: "ok", text: "All three public login edges reachable · low observed edge friction" };
  }
  if (risk.cc && !us) {
    return { status: "risky", text: "Non-US egress (" + risk.cc + ") · public edges may apply additional friction" };
  }
  if (ok >= 2 && riskyIp) {
    return { status: "risky", text: ok + "/3 public edges reachable · elevated IP/WAF friction" };
  }
  if (challenged > 0) {
    return { status: "partial", text: ok + "/3 public edges reachable · " + challenged + " edge challenge(s)" };
  }
  if (ok >= 2) return { status: "ok", text: ok + "/3 public login edges reachable" };
  if (fail === 3) return { status: "fail", text: "Public bank edges unreachable on this node" };
  return { status: "partial", text: ok + "/3 public login edges reachable · result inconclusive" };
}

function colorize(status, text) {
  const map = { ok: "#15803d", risky: "#b45309", partial: "#ca8a04", challenge: "#ca8a04", blocked: "#b91c1c", fail: "#6b7280" };
  return '<font color="' + (map[status] || "#6b7280") + '">' + escapeHtml(text) + "</font>";
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
    return {
      ok: true,
      status: status,
      body: String((resp && resp.body) || ""),
      headers: (resp && resp.headers) || {},
      error: "",
    };
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    return { ok: false, status: 0, body: "", headers: {}, error: msg === "timeout" ? "timeout" : msg };
  }
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
      source: "ipapi.is", ok: true, ip: data.ip,
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
      Object.keys(data).some((k) => {
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
  const code = resp.statusCode || resp.status;
  return code ? "HTTP " + code : "lookup failed";
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
    url: url,
    method: opt.method || "GET",
    headers: Object.assign({ "User-Agent": UA }, opt.headers || {}),
    timeout: timeout,
    opts: { hints: false },
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
