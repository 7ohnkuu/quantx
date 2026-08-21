/**
 * Streaming Unlock — Quantumult X
 *
 * Rewrite of KOP-XIAO/streaming-ui-check.js:
 *   - Await every check before $done (original fired YouTube/DAZN/Paramount without waiting)
 *   - Drop duplicate $configuration.sendMessage
 *   - Unknown regions stay unknown instead of defaulting to US
 *   - HTTP Request and event-interaction
 *
 * [rewrite_local]
 * ^http://httpjs\.local/stream url script-echo-response streaming-check.js
 *
 * [task_local]
 * event-interaction streaming-check.js, tag=Streaming Unlock, img-url=https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Siri.png, enabled=true
 *
 * Query:
 *   ?policy=NodeName
 *   ?format=json
 */

const TITLE = "Streaming Unlock";
const NF_TITLE = "81280792";
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

(async () => {
  const policy = policyName();
  const nodeLabel = await policyChain(policy);
  const results = await Promise.all([
    wrap("YouTube", () => checkYoutube(policy)),
    wrap("Netflix", () => checkNetflix(policy)),
    wrap("Disney+", () => checkDisney(policy)),
    wrap("DAZN", () => checkDazn(policy)),
    wrap("Paramount+", () => checkParamount(policy)),
    wrap("Discovery+", () => checkDiscovery(policy)),
  ]);

  const items = results.map((r) => ({
    key: r.name,
    value: r.text,
    html: colorize(r),
  }));

  doneOK(TITLE, items, {
    node: nodeLabel || policy || "current policy",
    json: { policy: policy, results: results },
  });
})().catch((err) => {
  console.log("streaming-check error: " + err);
  doneErr(TITLE, String(err && err.message ? err.message : err));
});

async function wrap(name, fn) {
  try {
    const r = await fn();
    r.name = name;
    r.text = formatText(r);
    return r;
  } catch (e) {
    const status = String(e && e.message ? e.message : e) === "timeout" ? "timeout" : "error";
    return { name: name, status: status, region: "", text: status === "timeout" ? "Timeout 🚦" : "Failed ❗️" };
  }
}

function formatText(r) {
  if (r.status === "available") {
    return r.region ? "Yes ➟ " + flagEmoji(r.region) + " " + r.region + " 🎉" : "Yes · region unknown 🎉";
  }
  if (r.status === "partial") {
    return r.note || (r.region ? "Partial ➟ " + flagEmoji(r.region) + " " + r.region + " ⚠️" : "Partial / unknown ⚠️");
  }
  if (r.status === "blocked") return r.region ? "No ➟ " + flagEmoji(r.region) + " " + r.region + " 🚫" : "No 🚫";
  if (r.status === "timeout") return "Timeout 🚦";
  return "Failed ❗️";
}

function colorize(r) {
  const text = escapeHtml(r.text);
  if (r.status === "available") return '<font color="#15803d">' + text + "</font>";
  if (r.status === "partial") return '<font color="#b45309">' + text + "</font>";
  if (r.status === "blocked") return '<font color="#b91c1c">' + text + "</font>";
  return '<font color="#6b7280">' + text + "</font>";
}

async function checkYoutube(policy) {
  const resp = await qxFetch("https://www.youtube.com/premium", { timeout: 8000, policy: policy });
  const body = String(resp.body || "");
  if (resp.statusCode !== 200) throw new Error("http");
  if (body.indexOf("Premium is not available in your country") !== -1) {
    return { status: "blocked", region: "" };
  }
  let region = "";
  const m = body.match(/"GL":"([A-Z]{2})"/);
  if (m) region = m[1];
  else if (body.indexOf("www.google.cn") !== -1) region = "CN";
  return { status: "available", region: region };
}

async function checkNetflix(policy) {
  const resp = await qxFetch("https://www.netflix.com/title/" + NF_TITLE, { timeout: 8000, policy: policy });
  const code = resp.statusCode;
  if (code === 403 || code === 451) return { status: "blocked", region: "" };
  if (code === 404) return { status: "partial", region: "", note: "Originals only ⚠️" };
  if (code !== 200) throw new Error("http");
  const loc = headerOf(resp, "X-Originating-URL") || headerOf(resp, "Location") || "";
  let region = "";
  const m = loc.match(/netflix\.com\/([A-Za-z]{2})(?:-|\/)/);
  if (m) region = m[1].toUpperCase();
  else {
    const parts = loc.split("/");
    if (parts[3] && parts[3] !== "title" && /^[A-Za-z]{2}(?:-|$)/.test(parts[3])) {
      region = parts[3].split("-")[0].toUpperCase();
    }
  }
  return { status: "available", region: region };
}

async function checkDisney(policy) {
  const home = await qxFetch("https://www.disneyplus.com", { timeout: 8000, policy: policy });
  const body = String(home.body || "");
  if (home.statusCode !== 200 || body.indexOf("not available in your region") !== -1) {
    return { status: "blocked", region: "" };
  }
  let region = "";
  const m = body.match(/Region:\s*([A-Za-z]{2})/);
  if (m) region = m[1].toUpperCase();

  try {
    const gql = await qxFetch("https://disney.api.edge.bamgrid.com/graph/v1/device/graphql", {
      timeout: 7000,
      policy: policy,
      method: "POST",
      headers: {
        "Accept-Language": "en",
        Authorization: "ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query:
          "mutation registerDevice($input: RegisterDeviceInput!) { registerDevice(registerDevice: $input) { grant { grantType assertion } } }",
        variables: {
          input: {
            applicationRuntime: "chrome",
            attributes: {
              browserName: "chrome",
              browserVersion: "120.0.0",
              manufacturer: "apple",
              model: null,
              operatingSystem: "macintosh",
              operatingSystemVersion: "10.15.7",
              osDeviceIds: [],
            },
            deviceFamily: "browser",
            deviceLanguage: "en",
            deviceProfile: "macosx",
          },
        },
      }),
    });
    const data = parseJSON(gql.body);
    const sdk = data && data.extensions && data.extensions.sdk;
    const loc = sdk && sdk.session && sdk.session.location;
    if (loc && loc.countryCode) region = String(loc.countryCode).toUpperCase();
    if (sdk && sdk.session && (sdk.session.inSupportedLocation === false || sdk.session.inSupportedLocation === "false")) {
      return { status: "partial", region: region, note: "Coming soon" + (region ? " ➟ " + flagEmoji(region) + " " + region : "") + " ⚠️" };
    }
  } catch (e) {
    console.log("disney graphql: " + e);
  }
  return { status: "available", region: region };
}

async function checkDazn(policy) {
  const resp = await qxFetch("https://startup.core.indazn.com/misl/v5/Startup", {
    timeout: 8000,
    policy: policy,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      LandingPageKey: "generic",
      Platform: "web",
      PlatformAttributes: {},
      Manufacturer: "",
      PromoCode: "",
      Version: "2",
    }),
  });
  if (resp.statusCode !== 200) throw new Error("http");
  const m = String(resp.body || "").match(/"GeolocatedCountry"\s*:\s*"([A-Za-z]{2})"/);
  if (!m) return { status: "partial", region: "", note: "Reachable · region unknown ⚠️" };
  return { status: "available", region: m[1].toUpperCase() };
}

async function checkParamount(policy) {
  const resp = await qxFetch("https://www.paramountplus.com/", {
    timeout: 8000,
    policy: policy,
    redirection: false,
  });
  if (resp.statusCode === 200) return { status: "available", region: "" };
  if (resp.statusCode === 301 || resp.statusCode === 302 || resp.statusCode === 307 || resp.statusCode === 308) {
    const target = headerOf(resp, "Location");
    return {
      status: "partial",
      region: "",
      note: target ? "Redirected · availability unknown ⚠️" : "Redirected · unknown ⚠️",
    };
  }
  if (resp.statusCode === 403 || resp.statusCode === 451) return { status: "blocked", region: "" };
  throw new Error("http");
}

async function checkDiscovery(policy) {
  const tokenResp = await qxFetch(
    "https://us1-prod-direct.discoveryplus.com/token?deviceId=d1a4a5d25212400d1e6985984604d740&realm=go&shortlived=true",
    { timeout: 8000, policy: policy, redirection: false }
  );
  const tokenBody = parseJSON(tokenResp.body);
  const token = tokenBody && tokenBody.data && tokenBody.data.attributes && tokenBody.data.attributes.token;
  if (!token) return { status: "partial", region: "", note: "Token unavailable · status unknown ⚠️" };
  const me = await qxFetch("https://us1-prod-direct.discoveryplus.com/users/me", {
    timeout: 8000,
    policy: policy,
    redirection: false,
    headers: { Cookie: "st=" + token },
  });
  const data = parseJSON(me.body);
  const loc = data && data.data && data.data.attributes && data.data.attributes.currentLocationTerritory;
  if (!loc) return { status: "partial", region: "", note: "Reachable · region unknown ⚠️" };
  if (String(loc).toLowerCase() === "us") return { status: "available", region: "US" };
  return { status: "blocked", region: String(loc).toUpperCase() };
}

function headerOf(resp, name) {
  const headers = (resp && resp.headers) || {};
  const hit = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return hit ? headers[hit] : "";
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
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<title>" +
    escapeHtml(title) +
    "</title><style>" +
    "body{margin:0;background:#f3f4f6;color:#111;font:16px/1.55 -apple-system,BlinkMacSystemFont,\"PingFang SC\",sans-serif}" +
    "main{max-width:480px;margin:20px auto;background:#fff;border-radius:16px;padding:20px 18px}" +
    "h1{margin:0 0 14px;font-size:18px;text-align:center}" +
    ".row{display:flex;justify-content:space-between;gap:10px;padding:9px 0;border-bottom:1px solid #eee}" +
    ".k{color:#6b7280;flex:0 0 120px}" +
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
      return "<b>" + escapeHtml(item.key) + ": </b>" + val + "<br/><br/>";
    })
    .join("");
}

function doneOK(title, items, extra) {
  extra = extra || {};
  const node = extra.node || policyName();
  const httpInner =
    renderRows(items, "http") + (node ? '<div class="foot">Node ➟ ' + escapeHtml(node) + "</div>" : "");
  const popup =
    '<p style="text-align:center;font-family:-apple-system;font-size:large;font-weight:thin">' +
    "--------------------------------------<br/>" +
    renderRows(items, "popup") +
    "--------------------------------------<br/>" +
    (node ? '<font color="#CD5C5C"><b>Node</b> ➟ ' + escapeHtml(node) + "</font>" : "") +
    "</p>";

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
