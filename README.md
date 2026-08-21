# quantx

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Quantumult X 自用规则与脚本。

- **规则：** 把 Apple Intelligence / Siri / Private Cloud Compute 相关域名走到代理，避免被通用 Apple 规则直连到国内 CDN。
- **脚本：** 把三条常见的节点交互脚本改成圈 X 本地 HTTP Request（`script-echo-response`），同时保留长按节点。

## 规则

| 文件 | 格式 |
|---|---|
| [`rules/apple-ai.quantx.list`](rules/apple-ai.quantx.list) | Quantumult X `[filter_remote]` |
| [`rules/apple-ai.list`](rules/apple-ai.list) | Surge / Clash 风格（策略名为 `PROXY`） |

必须放在 blackmatrix7 等宽泛 Apple 规则**之前**，否则 `icloud.com` / `apple.com` 通配会把 PCC 流量漏到直连。

Quantumult X 远程分流：

```text
https://raw.githubusercontent.com/7ohnkuu/quantx/main/rules/apple-ai.quantx.list, tag=Apple Intelligence, update-interval=86400, opt-parser=false, enabled=true
```

## HTTP 脚本

把下面文件复制到 **Quantumult X → Scripts**，再把 [`httpjs/qx-http-request.conf`](httpjs/qx-http-request.conf) 合并进配置。

| 脚本 | 作用 | Safari（隧道开启） |
|---|---|---|
| [`httpjs/network-info.js`](httpjs/network-info.js) | 直连 / 落地 IP、入口、SSID | http://httpjs.local/network |
| [`httpjs/server-info.js`](httpjs/server-info.js) | 节点风险：ipapi.is + proxycheck + IPPure 交叉验证 | http://httpjs.local/risk |
| [`httpjs/streaming-check.js`](httpjs/streaming-check.js) | 流媒体与 ChatGPT 解锁查询 | http://httpjs.local/stream |
| [`httpjs/speed-test.js`](httpjs/speed-test.js) | 节点测速：延迟 / 抖动 / 下载 / 上传（Cloudflare） | http://httpjs.local/speed |

可选参数：`?policy=节点名`、`?format=json`。

长按节点仍可用，配置见 `qx-http-request.conf` 的 `[task_local]`。原始远程样本在 [`httpjs/sample.txt`](httpjs/sample.txt)，下载原文在 [`httpjs/original/`](httpjs/original/)。

## License

本仓库以 [MIT License](LICENSE) 发布。

`httpjs/original/` 中的文件来自上游作者，仅作对照，版权仍归原作者。重构脚本基于：

- [xream/scripts](https://github.com/xream/scripts) `net-lsp-x.js`
- [ddgksf2013](https://github.com/ddgksf2013) `server-info-pure.js`
- [KOP-XIAO/QuantumultX](https://github.com/KOP-XIAO/QuantumultX) `streaming-ui-check.js`
