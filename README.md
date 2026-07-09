# Claude Session Key Importer

A cross-platform desktop utility for importing a Claude `sessionKey` into a
local browser or Claude Desktop profile. The app scans local Chromium-style
profiles, accepts a manually selected `Cookies` SQLite database, creates a
timestamped backup before direct database writes, and verifies the result.

## Features

- Desktop app built with Tauri 2, React, Vite, and Rust.
- Scans common Chrome, Chromium, Brave, Edge, and Claude Desktop profile paths on
  macOS, Windows, and Linux.
- Supports raw `sk-ant-sid...`, `sessionKey=...`, Cookie header text, and
  Netscape `cookies.txt` lines.
- Imports `.claude.ai` `sessionKey`, with optional `lastActiveOrg`.
- Supports Auto, CDP, Direct SQLite, and Manual SQLite modes.
- Masks secrets in the UI and never logs or renders the full session key.
- Creates `Cookies.<timestamp>.backup` before SQLite writes.
- GitHub Actions builds Windows, Linux, and macOS zip artifacts.

## Development

Requirements:

- Node.js 22+ or 24+
- pnpm 11+
- Rust 1.85+
- Platform dependencies required by Tauri, especially WebKitGTK on Linux

Run locally:

```bash
pnpm install
pnpm test
pnpm build
cd src-tauri && cargo test
pnpm tauri dev
```

Build a desktop package:

```bash
pnpm tauri build
```

## Import Modes

`Auto` uses CDP when a localhost CDP endpoint is supplied, otherwise it falls
back to SQLite import. CDP injection asks the running browser to store cookies
through the browser's own cookie implementation. SQLite import writes directly
to the selected `Cookies` database and verifies the inserted rows afterward.

Direct SQLite writes are best-effort for Chromium-compatible schemas. For locked
or actively running profiles, use CDP mode or close the target browser first.

## Safety Boundaries

- The app is local-only and does not send session keys to a remote service.
- The full session key is kept out of UI status text, logs, and result panels.
- SQLite imports always create a backup next to the selected `Cookies` database.
- The app only accepts localhost CDP endpoints.

## License

MIT

