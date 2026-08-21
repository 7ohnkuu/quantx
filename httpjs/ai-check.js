/**
 * AI Node Check — Quantumult X
 *
 * Test a node against OpenAI, Anthropic, Gemini, and Grok model APIs.
 * Combines live endpoint signals with a multi-source IP risk score:
 *   - API 401/invalid-key  = reachable (auth missing, not geo-blocked)
 *   - OpenAI ios.chat      = Cloudflare WAF type dc / country
 *   - ipapi.is + proxycheck + IPPure = datacenter / VPN / fraud
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

const OPENAI_OK =
  "AL DZ AD AO AG AR AM AU AT AZ BS BD BB BE BZ BJ BT BA BW BR BG BF CV CA CL CO KM CR HR CY DK DJ DM DO EC SV EE FJ FI FR GA GM GE DE GH GR GD GT GN GW GY HT HN HU IS IN ID IQ IE IL IT JM JP JO KZ KE KI KW KG LV LB LS LR LI LT LU MG MW MY MV ML MT MH MR MU MX MC MN ME MA MZ MM NA NR NP NL NZ NI NE NG MK NO OM PK PW PA PG PE PH PL PT QA RO RW KN LC VC WS SM ST SN RS SC SL SG SK SI SB ZA ES LK SR SE CH TH TG TO TT TN TR TV UG AE US UY VU ZM BO BN CG CZ VA FM MD PS KR TW TZ TL GB HK MO".split(
    " "
  );
const EMBARGO = { CN: 1, RU: 1, BY: 1, IR: 1, KP: 1, CU: 1, SY: 1, MM: 1, SD: 1, SS: 1, YE: 1 };
const ANTHROPIC_BLOCK = Object.assign({ HK: 1, MO: 1, VE: 1 }, EMBARGO);
const GEMINI_BLOCK = Object.assign({}, EMBARGO);
const GROK_BLOCK = Object.assign({ HK: 1 }, EMBARGO);

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

  const pOpen = checkOpenAI(policy);
  const pClaude = checkAnthropic(policy);
  const pGemini = checkGemini(policy);
  const pGrok = checkGrok(policy);

  const settled = await Promise.all([pIpapi, pPc, pPure, pOpen, pClaude, pGemini, pGrok]);
  const reports = [settled[0], settled[1], settled[2]];
  const risk = summarizeRisk(reports);
  const loc = risk.cc || "";
  const vendors = [
    finalizeVendor("OpenAI", settled[3], loc, OPENAI_OK, null, risk),
    finalizeVendor("Anthropic", settled[4], loc, null, ANTHROPIC_BLOCK, risk),
    finalizeVendor("Gemini", settled[5], loc, null, GEMINI_BLOCK, risk),
    finalizeVendor("Grok", settled[6], loc, null, GROK_BLOCK, risk),
  ];

  const items = [
    { key: "IP", value: risk.ip || "-" },
    { key: "ASN", value: risk.asn || "" },
    {
      key: "IP type",
      value: risk.kindLabel,
      html: kindHtml(risk),
    },
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
    items.push({
      key: v.name,
      value: v.text,
      html: colorizeVendor(v),
    });
  });
  items.push({
    key: "Verdict",
    value: overall(vendors, risk).text,
    html: colorizeOverall(overall(vendors, risk)),
  });

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
  var web = "fail";
  if (waf === "dc" || waf === "datacenter" || waf === "vpn" || waf === "proxy") web = "dc";
  else if (waf === "country" || /unsupported.?country/i.test(ios.body)) web = "blocked";
  else if (ios.status && ios.status < 400) web = "ok";
  else if (ios.ok === false && ios.error === "timeout") web = "fail";
  else if (ios.status === 403) web = "challenge";
  else if (ios.status) web = "challenge";

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
  const loc = parseTrace(trace.body).loc || "";
  var webSt = "fail";
  const body = String(web.body || "");
  if (/not available in (your )?(country|region)|isn't available in/i.test(body)) webSt = "blocked";
  else if (/just a moment|cf-mitigated|attention required/i.test(body)) webSt = "challenge";
  else if (web.status && web.status < 400) webSt = "ok";
  else if (web.status === 403) webSt = "challenge";
  return {
    loc: loc,
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
  var webSt = "fail";
  if (web.status && web.status < 400) webSt = "ok";
  else if (web.status === 403) webSt = "blocked";
  const apiSt = classifyGemini(api);
  return { loc: "", api: apiSt, web: webSt, detail: "" };
}

function classifyGemini(api) {
  const body = String((api && api.body) || "");
  const code = api && api.status;
  if (!api || api.ok === false && api.error === "timeout") return "fail";
  if (/API_KEY_INVALID|API key not valid|API key not found/i.test(body)) return "ok";
  if (code === 400 || code === 401) return "ok";
  if (/FAILED_PRECONDITION|not available|PERMISSION_DENIED.*location|Requests from this location/i.test(body)) {
    return "blocked";
  }
  if (code === 403 && /unregistered callers|PERMISSION_DENIED/i.test(body) && !/location/i.test(body)) return "ok";
  if (code === 403) return "blocked";
  if (code && code >= 500) return "fail";
  return code ? "ok" : "fail";
}

async function checkGrok(policy) {
  const [trace, api] = await Promise.all([
    safeFetch("https://grok.com/cdn-cgi/trace", { policy: policy, timeout: 8000 }),
    safeFetch("https://api.x.ai/v1/models", { policy: policy, timeout: 8000 }),
  ]);
  return {
    loc: parseTrace(trace.body).loc || "",
    api: classifyApi(api, [/no credentials/i, /unauthenticated/i, /unauthorized/i, /missing.*api.?key/i]),
    web: trace.status && trace.status < 400 ? "ok" : "fail",
    detail: "",
  };
}

function classifyApi(api, authRes) {
  if (!api || (api.ok === false && api.error === "timeout")) return "fail";
  const body = String(api.body || "");
  const code = api.status;
  for (var i = 0; i < authRes.length; i++) {
    if (authRes[i].test(body)) return "ok";
  }
  if (code === 401) return "ok";
  if (/unsupported.?country|not available in|region.*(block|restrict)|access.?denied|forbidden.*region/i.test(body)) {
    return "blocked";
  }
  if (code === 403) return "blocked";
  if (code === 404) return "ok";
  if (code && code < 500) return "ok";
  return "fail";
}

function finalizeVendor(name, raw, loc, allow, block, risk) {
  const r = raw || { api: "fail", web: "fail", loc: "", detail: "" };
  const cc = (r.loc || loc || "").toUpperCase();
  var geoBlock = false;
  if (cc) {
    if (allow && allow.indexOf(cc) < 0) geoBlock = true;
    if (block && block[cc]) geoBlock = true;
  }
  const apiOk = r.api === "ok";
  const riskyIp = risk.score >= 50 || /datacenter|vpn|proxy|tor|resiproxy/.test(risk.kind || "");
  var status = "fail";
  var parts = [];

  if (r.api === "blocked" || (geoBlock && !apiOk)) {
    status = "blocked";
    parts.push("Blocked");
  } else if (apiOk && (r.web === "dc" || r.web === "blocked" || riskyIp || geoBlock)) {
    status = "risky";
    parts.push("API OK");
    if (r.web === "dc" || r.detail.indexOf("waf:dc") >= 0) parts.push("WAF=datacenter");
    else if (r.web === "blocked" || geoBlock) parts.push("web/geo limited");
    else if (riskyIp) parts.push(risk.kindLabel);
  } else if (apiOk) {
    status = "ok";
    parts.push("API OK");
    if (r.web === "ok") parts.push("web OK");
  } else if (r.web === "ok" && !geoBlock) {
    status = "partial";
    parts.push("Web only");
  } else if (r.web === "challenge") {
    status = apiOk ? "risky" : "fail";
    parts.push(apiOk ? "API OK · web challenge" : "Web challenge");
  } else {
    status = "fail";
    parts.push(r.api === "fail" ? "Unreachable" : "Failed");
  }
  if (cc) parts.push(flagEmoji(cc) + " " + cc);
  return {
    name: name,
    status: status,
    api: r.api,
    web: r.web,
    loc: cc,
    text: parts.join(" · "),
    detail: r.detail || "",
  };
}

function overall(vendors, risk) {
  var apiOk = 0;
  var blocked = 0;
  vendors.forEach(function (v) {
    if (v.api === "ok") apiOk += 1;
    if (v.status === "blocked") blocked += 1;
  });
  const riskyIp = risk.score >= 50 || /datacenter|vpn|proxy|tor|resiproxy/.test(risk.kind || "");
  if (blocked === 4 || apiOk === 0) {
    return { status: "blocked", text: "AI APIs blocked or unreachable on this node" };
  }
  if (apiOk === 4 && !riskyIp && risk.score < 35) {
    return { status: "ok", text: "All four APIs reachable · IP looks clean" };
  }
  if (apiOk >= 3 && riskyIp) {
    return {
      status: "risky",
      text: apiOk + "/4 APIs reachable · " + risk.kindLabel + " IP — accounts may be banned",
    };
  }
  if (apiOk >= 3) {
    return { status: "ok", text: apiOk + "/4 APIs reachable" };
  }
  return { status: "partial", text: apiOk + "/4 APIs reachable" };
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
    return { ok: true, status: status, body: String((resp && resp.body) || ""), error: "" };
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    return { ok: false, status: 0, body: "", error: msg === "timeout" ? "timeout" : msg };
  }
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

function failReport(source, error) {
  return { source: source, ok: false, error: String(error || "unknown error") };
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
      cc: data.cc || "",
      region: "",
      city: "",
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
    var url = "https://proxycheck.io/v2/" + encodeURIComponent(ip) + "?vpn=1&asn=1&risk=1";
    if (key) url += "&key=" + encodeURIComponent(key);
    const resp = await qxFetch(url, { timeout: 7000, policy: policy });
    const data = parseJSON(resp && resp.body);
    if (!data || data.status !== "ok") throw new Error((data && data.message) || statusErr(resp));
    var rec = data[ip];
    if (!rec) {
      const keys = Object.keys(data);
      for (var i = 0; i < keys.length; i++) {
        if (data[keys[i]] && data[keys[i]].proxy != null) rec = data[keys[i]];
      }
    }
    if (!rec) throw new Error("no record");
    const isProxy = String(rec.proxy).toLowerCase() === "yes";
    const t = String(rec.type || "").toLowerCase();
    var kind = "clean";
    if (t.indexOf("tor") >= 0) kind = "tor";
    else if (t.indexOf("vpn") >= 0) kind = "vpn";
    else if (t.indexOf("residential") >= 0) kind = isProxy ? "resiproxy" : "residential";
    else if (t.indexOf("hosting") >= 0 || t.indexOf("dch") >= 0 || t.indexOf("data") >= 0) kind = "datacenter";
    else if (isProxy) kind = "proxy";
    else if (t.indexOf("business") >= 0) kind = "business";
    const score = rec.risk == null || rec.risk === "" ? null : Number(rec.risk);
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
      source: "IPPure",
      ok: true,
      ip: data.ip,
      cc: data.countryCode || "",
      region: data.region || "",
      city: data.city || "",
      isp: data.asOrganization || "",
      asn: data.asn ? "AS" + data.asn : "",
      kind: data.isResidential ? "residential" : "datacenter",
      score: isFinite(score) ? score : null,
      weight: 0.5,
    };
  } catch (e) {
    return failReport("IPPure", e && e.message ? e.message : e);
  }
}

function summarizeRisk(reports) {
  const ok = reports.filter(function (r) {
    return r && r.ok;
  });
  const kinds = {};
  ok.forEach(function (r) {
    if (r.kind) kinds[r.kind] = (kinds[r.kind] || 0) + 1;
  });
  const rank = ["tor", "vpn", "proxy", "resiproxy", "datacenter", "business", "residential", "clean"];
  var kind = "clean";
  for (var i = 0; i < rank.length; i++) {
    if (kinds[rank[i]]) {
      kind = rank[i];
      break;
    }
  }
  var num = 0;
  var den = 0;
  ok.forEach(function (r) {
    if (r.weight > 0 && r.score != null && isFinite(r.score)) {
      num += r.score * r.weight;
      den += r.weight;
    }
  });
  var score = den ? Math.round(num / den) : 12;
  if (kind === "tor") score = Math.max(score, 90);
  if (kind === "vpn" || kind === "proxy" || kind === "resiproxy") score = Math.max(score, 50);
  if (kind === "datacenter") score = Math.max(score, 40);
  score = Math.max(0, Math.min(100, score));
  const geo = { ip: "", cc: "", region: "", city: "", isp: "", asn: "" };
  ["proxycheck", "ipapi.is", "IPPure"].forEach(function (name) {
    const r = ok.filter(function (x) {
      return x.source === name;
    })[0];
    if (!r) return;
    if (!geo.ip && r.ip) geo.ip = r.ip;
    if (!geo.cc && r.cc) geo.cc = r.cc;
    if (!geo.region && r.region) geo.region = r.region;
    if (!geo.city && r.city) geo.city = r.city;
    if (!geo.isp && r.isp) geo.isp = r.isp;
    if (!geo.asn && r.asn) geo.asn = r.asn;
  });
  const labels = {
    tor: "Tor exit",
    vpn: "VPN",
    proxy: "Proxy",
    resiproxy: "Residential proxy",
    datacenter: "Datacenter",
    business: "Business",
    residential: "Residential",
    clean: "Clean",
  };
  return {
    ip: geo.ip,
    cc: geo.cc,
    region: geo.region,
    city: geo.city,
    isp: geo.isp,
    asn: geo.asn,
    kind: kind,
    kindLabel: labels[kind] || kind,
    score: score,
  };
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
  if (resp.statusCode) return "HTTP " + resp.statusCode;
  return "lookup failed";
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
