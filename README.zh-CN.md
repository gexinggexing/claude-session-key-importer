# Claude Session Key Importer

[English](README.md)

一个跨平台桌面工具，用于把 Claude `sessionKey` 导入到本机浏览器或 Claude Desktop 的 profile 中。应用会扫描常见 Chromium 系浏览器 profile，也支持手动选择 `Cookies` SQLite 数据库；直接写库前会创建时间戳备份，写入后会验证 cookie 是否存在。

## 功能

- 使用 Tauri 2、React、Vite 和 Rust 构建桌面应用。
- 支持 macOS、Windows、Linux。
- 自动扫描 Chrome、Chromium、Brave、Edge、Claude Desktop 等常见 profile 路径，并尽量识别对应浏览器可执行文件。
- 支持手动选择浏览器 profile 或 `Cookies` 数据库文件。
- 支持粘贴原始 `sk-ant-sid...`、`sessionKey=...`、Cookie header、Netscape `cookies.txt` 行。
- 写入 `.claude.ai` 域名下的 `sessionKey`，可选写入 `lastActiveOrg`。
- 支持 Auto、profile 级 CDP、Direct SQLite、Manual SQLite 四种导入模式。
- UI 和结果面板只显示脱敏后的 key，不回显完整 session key。
- SQLite 写入前强制创建 `Cookies.<timestamp>.backup` 备份。
- GitHub Actions 自动构建 Windows、Linux、macOS 三个平台的 zip artifact。

## 下载成品

打开仓库的 Actions 页面，选择最近一次成功的 `build` workflow，在 Artifacts 区域下载对应系统的压缩包：

- `claude-session-key-importer-macos.zip`
- `claude-session-key-importer-windows.zip`
- `claude-session-key-importer-linux.zip`

## 本地开发

要求：

- Node.js 22+ 或 24+
- pnpm 11+
- Rust 1.85+
- Tauri 所需平台依赖，Linux 需要 WebKitGTK 等依赖

本地运行：

```bash
pnpm install
pnpm test
pnpm build
cd src-tauri && cargo test
pnpm tauri dev
```

构建桌面包：

```bash
pnpm tauri build
```

## 导入模式

`Auto` 模式会在选中 profile 能识别到浏览器可执行文件时优先使用 profile 级 CDP。应用会用临时 localhost remote-debugging 端口拉起这个具体 profile，让浏览器自己通过 CDP 写入 cookie，并通过 CDP 验证结果，不直接打开 SQLite 数据库。

手动 CDP endpoint 仍然保留，作为高级兜底：适合目标 profile 已经用 `--remote-debugging-port` 启动的情况。

选中 profile 无法通过 CDP 自动拉起时，`Auto` 会回退到 SQLite 写入。

`Direct SQLite` 会直接写入扫描到的 `Cookies` 数据库，并在写入后读取数据库验证结果。目标浏览器正在运行时，数据库可能被锁定；这种情况下建议使用 CDP 模式，或先关闭目标浏览器。

`Manual SQLite` 适合无法自动扫描到 profile 的情况，用户可以手动选择 `Cookies` 数据库文件。

## 安全边界

- 应用只在本机运行，不把 session key 发送到远程服务。
- 完整 session key 不进入 UI 状态文本、日志或结果面板。
- SQLite 导入前一定会在 `Cookies` 数据库旁边创建备份。
- profile 级 CDP 自动启动只绑定 `127.0.0.1` remote debugging。
- 手动 CDP endpoint 只接受 localhost。
- 不管理 OAuth token，不做账号状态监控。

## 许可证

MIT
