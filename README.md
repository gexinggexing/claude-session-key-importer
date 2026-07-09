# Claude Session Key Importer

[中文说明](README.zh-CN.md)

A cross-platform desktop utility for importing a Claude `sessionKey` into a
local browser or Claude Desktop profile. The app scans local Chromium-style
profiles, accepts a manually selected `Cookies` SQLite database, creates a
timestamped backup before direct database writes, and verifies the result.

## Features

- Desktop app built with Tauri 2, React, Vite, and Rust.
- Scans common Chrome, Chromium, Brave, Edge, and Claude Desktop profile paths on
  macOS, Windows, and Linux, including the browser executable when it can be
  detected.
- Supports raw `sk-ant-sid...`, `sessionKey=...`, Cookie header text, and
  Netscape `cookies.txt` lines.
- Imports `.claude.ai` `sessionKey`, with optional `lastActiveOrg`.
- Supports Auto, profile-level CDP, Direct SQLite, and Manual SQLite modes.
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

`Auto` prefers profile-level CDP when the selected profile has a detected
browser executable. The app launches that exact profile with a temporary
localhost remote-debugging port, asks the browser to store cookies through CDP,
and verifies cookies through CDP without opening the SQLite database. If the
selected profile cannot be launched through CDP, Auto falls back to SQLite
import.

Manual CDP endpoints are still supported as an advanced fallback for profiles
that are already running with `--remote-debugging-port`.

SQLite import writes directly to the selected `Cookies` database and verifies
the inserted rows afterward.

Direct SQLite writes are best-effort for Chromium-compatible schemas. For locked
or actively running profiles, use a localhost CDP endpoint or close the target
browser first so the app can launch the selected profile itself.

## Safety Boundaries

- The app is local-only and does not send session keys to a remote service.
- The full session key is kept out of UI status text, logs, and result panels.
- SQLite imports always create a backup next to the selected `Cookies` database.
- Profile-level CDP launches use `127.0.0.1` remote debugging only.
- Manual CDP endpoints must point to localhost.

## License

MIT
