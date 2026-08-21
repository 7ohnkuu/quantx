# quantx

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Quantumult X rules and HTTP Request scripts.

- **Rules:** Send Apple Intelligence / Siri / Private Cloud Compute hosts through the proxy so generic Apple lists cannot leak them to mainland CDNs.
- **Scripts:** Local `script-echo-response` tools that also work as node long-press actions.

## Rules

| File | Format |
|---|---|
| [`rules/apple-ai.quantx.list`](rules/apple-ai.quantx.list) | Quantumult X `[filter_remote]` |
| [`rules/apple-ai.list`](rules/apple-ai.list) | Surge / Clash style (policy `PROXY`) |

Place this list **before** broad Apple rules such as blackmatrix7. Otherwise `icloud.com` / `apple.com` wildcards send PCC traffic direct.

Quantumult X remote filter:

```text
https://raw.githubusercontent.com/7ohnkuu/quantx/main/rules/apple-ai.quantx.list, tag=Apple Intelligence, update-interval=86400, opt-parser=false, enabled=true
```

## HTTP scripts

1. Copy the `.js` files from [`httpjs/`](httpjs/) into **Quantumult X → Scripts**.
2. Merge [`httpjs/qx-http-request.conf`](httpjs/qx-http-request.conf) into your profile (`[dns]`, `[filter_local]`, `[rewrite_local]`, `[task_local]`).
3. Turn the Quantumult X tunnel on.

| Script | Purpose | Safari |
|---|---|---|
| [`network-info.js`](httpjs/network-info.js) | Direct / egress IP, ingress, SSID | http://httpjs.local/network |
| [`server-info.js`](httpjs/server-info.js) | Node risk (ipapi.is + proxycheck + IPPure) | http://httpjs.local/risk |
| [`streaming-check.js`](httpjs/streaming-check.js) | Streaming and ChatGPT unlock | http://httpjs.local/stream |
| [`speed-test.js`](httpjs/speed-test.js) | Latency, jitter, download, upload via Cloudflare | http://httpjs.local/speed |

Long-press a node for the same tools (`[task_local]` tags: Network Info, Node Risk, Streaming Unlock, Speed Test).

### Query parameters

| Param | Scripts | Meaning |
|---|---|---|
| `policy=NodeName` | all | Force that node (same as a long-press) |
| `format=json` | all | JSON instead of HTML |
| `size=2` | speed | Download size in MB (1–5, default 2) |
| `pings=5` | speed | Latency samples (3–8) |
| `noup=1` | speed | Skip upload |
| `ipapi_key=` / `pc_key=` | risk | Optional keys for higher quota |

Example: `http://httpjs.local/speed?policy=NodeName&size=5`

[`httpjs/sample.txt`](httpjs/sample.txt) is the original remote `event-interaction` sample. [`httpjs/original/`](httpjs/original/) holds upstream snapshots (their comments stay as published).

## License

Released under the [MIT License](LICENSE).

Rewritten scripts are based on:

- [xream/scripts](https://github.com/xream/scripts) `net-lsp-x.js`
- [ddgksf2013](https://github.com/ddgksf2013) `server-info-pure.js`
- [KOP-XIAO/QuantumultX](https://github.com/KOP-XIAO/QuantumultX) `streaming-ui-check.js`
