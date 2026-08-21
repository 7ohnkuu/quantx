/*
 * Quantumult X HTTPJS
 * Node IP Risk Checker
 *
 * Purpose:
 * - Audit proxy exit IP reputation
 * - Show ASN / ISP / country
 * - Detect datacenter / proxy / VPN signals
 * - Provide suitability hints for Apple Intelligence / AI services
 */

const ENV = typeof $environment !== "undefined" ? $environment : {};

function qxFetch(url) {
  return new Promise((resolve) => {
    $task.fetch({ url, timeout: 8000 }).then(
      r => resolve({ ok: true, status: r.statusCode, body: r.body || "" }),
      e => resolve({ ok: false, error: String(e) })
    );
  });
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[c]));
}

function riskLevel(data) {
  let score = 0;

  if (data.type === "hosting" || data.type === "datacenter") score += 2;
  if (data.proxy === true) score += 2;
  if (data.vpn === true) score += 2;

  if (score >= 4) return "HIGH";
  if (score >= 2) return "MEDIUM";
  return "LOW";
}

(async () => {
  const sources = await Promise.all([
    qxFetch("https://ipwho.is/"),
    qxFetch("https://api.ipapi.is/"),
    qxFetch("https://ipapi.is/json")
  ]);

  let ip = {};
  let raw = {};

  for (const s of sources) {
    if (!s.ok) continue;
    try {
      const j = JSON.parse(s.body);
      raw = { ...raw, ...j };
    } catch (_) {}
  }

  ip = raw;

  const network = ip.connection || ip.company || {};
  const security = ip.security || {};

  const report = {
    ip: ip.ip || "unknown",
    country: ip.country || ip.location?.country || "unknown",
    city: ip.city || ip.location?.city || "unknown",
    asn: network.asn || network.ASN || "unknown",
    isp: network.isp || network.name || "unknown",
    datacenter: security.datacenter ?? false,
    proxy: security.proxy ?? false,
    vpn: security.vpn ?? false
  };

  report.type = report.datacenter ? "datacenter" : "residential/ISP";
  report.risk = riskLevel(report);

  const apple = report.risk === "LOW" || report.risk === "MEDIUM"
    ? "Potentially suitable"
    : "Higher friction expected";

  const html = `
  <html><head><meta name="viewport" content="width=device-width,initial-scale=1">
  <style>body{font-family:-apple-system;padding:18px}table{width:100%;border-collapse:collapse}td{padding:8px;border-bottom:1px solid #ddd}</style>
  </head><body>
  <h2>Node IP Risk Audit</h2>
  <table>
  ${Object.entries({
    IP: report.ip,
    Country: report.country,
    City: report.city,
    ASN: report.asn,
    ISP: report.isp,
    Type: report.type,
    Datacenter: report.datacenter,
    Proxy: report.proxy,
    VPN: report.vpn,
    Risk: report.risk,
    "Apple Intelligence Suitability": apple
  }).map(([k,v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}
  </table>
  </body></html>`;

  if (typeof $done === "function") {
    $done({
      title: "Node IP Risk",
      html
    });
  }
})();
