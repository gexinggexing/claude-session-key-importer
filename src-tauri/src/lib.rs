use chrono::Utc;
use regex::Regex;
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;
use tungstenite::{Message, connect};

const CHROME_EPOCH_DELTA_MICROS: i64 = 11_644_473_600_000_000;
const CLAUDE_COOKIE_HOST: &str = ".claude.ai";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserProfile {
    pub id: String,
    pub browser: String,
    pub profile_name: String,
    pub profile_path: String,
    pub cookies_db_path: String,
    pub exists: bool,
    pub cookies_db_exists: bool,
    pub is_locked_suspected: bool,
    pub is_running: bool,
    pub cdp_endpoint: Option<String>,
    pub browser_executable_path: Option<String>,
    pub cdp_user_data_dir: Option<String>,
    pub cdp_profile_directory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportTarget {
    pub profile: BrowserProfile,
    pub manual_cookie_db_path: Option<String>,
    pub cdp_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedSession {
    pub kind: String,
    pub value: String,
    pub masked: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ImportMethod {
    Auto,
    Cdp,
    Sqlite,
    ManualSqlite,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyResult {
    pub cookies_db_path: String,
    pub exists: bool,
    pub is_writable: bool,
    pub has_session_key: bool,
    pub has_last_active_org: bool,
    pub value_present: bool,
    pub encrypted_present: bool,
    pub is_locked_suspected: bool,
    pub is_running: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportResult {
    pub backup_path: String,
    pub method_used: ImportMethod,
    pub verification: VerifyResult,
    pub masked_session_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CdpLaunchArgs {
    executable_path: PathBuf,
    args: Vec<String>,
    endpoint: String,
}

struct LaunchedCdp {
    endpoint: String,
    #[allow(dead_code)]
    child: Child,
}

#[derive(Debug, Clone)]
struct CookieColumn {
    name: String,
    col_type: String,
    not_null: bool,
    default_value: Option<String>,
}

pub fn chrome_time_from_unix_seconds(unix_seconds: i64) -> i64 {
    CHROME_EPOCH_DELTA_MICROS + unix_seconds * 1_000_000
}

fn chrome_time_now() -> i64 {
    chrome_time_from_unix_seconds(Utc::now().timestamp())
}

pub fn mask_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 4 {
        return "•••".to_string();
    }
    if chars.len() <= 8 {
        return format!(
            "{}...{}",
            chars.iter().take(2).collect::<String>(),
            chars
                .iter()
                .rev()
                .take(2)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>()
        );
    }
    format!(
        "{}...{}",
        chars.iter().take(6).collect::<String>(),
        chars
            .iter()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<String>()
    )
}

fn session_re() -> &'static Regex {
    static SESSION_RE: OnceLock<Regex> = OnceLock::new();
    SESSION_RE.get_or_init(|| Regex::new(r"sk-ant-sid[0-9A-Za-z._\-]+").unwrap())
}

pub fn parse_session_input(text: String) -> Result<ParsedSession, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("no sessionKey text provided".to_string());
    }

    for line in trimmed.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() >= 7 && fields[5].trim() == "sessionKey" {
            let candidate = fields[6].trim();
            if let Some(matched) = session_re().find(candidate) {
                let value = matched.as_str().to_string();
                return Ok(ParsedSession {
                    kind: "sessionKey".to_string(),
                    masked: mask_secret(&value),
                    value,
                });
            }
            return Err(
                "cookie line names sessionKey but does not contain a Claude sessionKey".to_string(),
            );
        }
    }

    if let Some(matched) = session_re().find(trimmed) {
        let value = matched.as_str().to_string();
        return Ok(ParsedSession {
            kind: "sessionKey".to_string(),
            masked: mask_secret(&value),
            value,
        });
    }

    Err("could not find a Claude sessionKey; expected a sk-ant-sid... value".to_string())
}

pub fn scan_profiles() -> Result<Vec<BrowserProfile>, String> {
    let mut profiles = Vec::new();
    for base in profile_bases() {
        profiles.extend(scan_profile_base(&base));
    }
    profiles.sort_by(|a, b| {
        a.browser
            .cmp(&b.browser)
            .then(a.profile_name.cmp(&b.profile_name))
            .then(a.profile_path.cmp(&b.profile_path))
    });
    profiles.dedup_by(|a, b| a.cookies_db_path == b.cookies_db_path);
    Ok(profiles)
}

pub fn open_cookie_db_picker() -> Result<Option<BrowserProfile>, String> {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Select Chromium Cookies database")
        .pick_file()
    else {
        return Ok(None);
    };
    let profile_path = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(""));
    let profile = BrowserProfile {
        id: format!("manual:{}", path.display()),
        browser: "Manual Cookies DB".to_string(),
        profile_name: profile_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Manual".to_string()),
        exists: profile_path.exists(),
        cookies_db_exists: path.is_file(),
        is_locked_suspected: lock_files_exist(&path),
        is_running: detect_profile_running(&profile_path),
        profile_path: profile_path.to_string_lossy().to_string(),
        cookies_db_path: path.to_string_lossy().to_string(),
        cdp_endpoint: None,
        browser_executable_path: None,
        cdp_user_data_dir: None,
        cdp_profile_directory: None,
    };
    Ok(Some(profile))
}

pub fn verify_target(target: ImportTarget) -> Result<VerifyResult, String> {
    let cookie_path = target_cookie_db_path(&target);
    verify_cookie_db(&cookie_path, &target.profile)
}

pub fn import_session(
    target: ImportTarget,
    session_key: String,
    method: ImportMethod,
    last_active_org: Option<String>,
) -> Result<ImportResult, String> {
    let parsed = parse_session_input(session_key)?;
    let method_used = select_import_method(&target, method);

    match method_used {
        ImportMethod::Cdp => import_via_cdp(&target, &parsed.value, last_active_org),
        ImportMethod::Sqlite | ImportMethod::ManualSqlite => {
            import_via_sqlite(&target, &parsed.value, method_used, last_active_org)
        }
        ImportMethod::Auto => unreachable!("auto is normalized before import"),
    }
}

fn select_import_method(target: &ImportTarget, method: ImportMethod) -> ImportMethod {
    match method {
        ImportMethod::Auto => {
            if explicit_cdp_endpoint(target).is_some() || supports_profile_cdp(target) {
                ImportMethod::Cdp
            } else {
                ImportMethod::Sqlite
            }
        }
        other => other,
    }
}

fn explicit_cdp_endpoint(target: &ImportTarget) -> Option<&str> {
    target
        .cdp_endpoint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            target
                .profile
                .cdp_endpoint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
}

fn supports_profile_cdp(target: &ImportTarget) -> bool {
    target.manual_cookie_db_path.is_none()
        && target
            .profile
            .browser_executable_path
            .as_deref()
            .map(str::trim)
            .is_some_and(|p| !p.is_empty())
}

fn target_cookie_db_path(target: &ImportTarget) -> PathBuf {
    target
        .manual_cookie_db_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&target.profile.cookies_db_path))
}

fn import_via_sqlite(
    target: &ImportTarget,
    session_key: &str,
    method_used: ImportMethod,
    last_active_org: Option<String>,
) -> Result<ImportResult, String> {
    let cookie_path = target_cookie_db_path(target);
    if !cookie_path.is_file() {
        return Err(format!(
            "Cookies database not found: {}",
            cookie_path.display()
        ));
    }

    let backup_path = backup_cookie_db(&cookie_path)?;
    let conn = Connection::open_with_flags(
        &cookie_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("open cookies database failed: {e}"))?;
    conn.busy_timeout(std::time::Duration::from_millis(800))
        .map_err(|e| format!("set sqlite busy timeout failed: {e}"))?;

    let columns = cookie_columns(&conn)?;
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| format!("start sqlite transaction failed: {e}"))?;
    tx.execute(
        "DELETE FROM cookies WHERE host_key IN ('.claude.ai', 'claude.ai') AND name IN ('sessionKey', 'sessionKeyLC')",
        [],
    )
    .map_err(|e| format!("delete existing sessionKey rows failed: {e}"))?;
    insert_cookie_row(&tx, &columns, "sessionKey", session_key, true, 30)?;

    if let Some(org) = last_active_org
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        tx.execute(
            "DELETE FROM cookies WHERE host_key IN ('.claude.ai', 'claude.ai') AND name = 'lastActiveOrg'",
            [],
        )
        .map_err(|e| format!("delete existing lastActiveOrg rows failed: {e}"))?;
        insert_cookie_row(&tx, &columns, "lastActiveOrg", org, false, 365)?;
    }

    tx.commit()
        .map_err(|e| format!("commit sqlite cookie import failed: {e}"))?;

    let verification = verify_cookie_db(&cookie_path, &target.profile)?;
    Ok(ImportResult {
        backup_path: backup_path.to_string_lossy().to_string(),
        method_used,
        verification,
        masked_session_key: mask_secret(session_key),
    })
}

fn backup_cookie_db(cookie_path: &Path) -> Result<PathBuf, String> {
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let file_name = cookie_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Cookies".to_string());
    let backup = cookie_path.with_file_name(format!("{file_name}.{stamp}.backup"));
    fs::copy(cookie_path, &backup).map_err(|e| {
        format!(
            "backup failed from {} to {}: {e}",
            cookie_path.display(),
            backup.display()
        )
    })?;
    Ok(backup)
}

fn cookie_columns(conn: &Connection) -> Result<Vec<CookieColumn>, String> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(cookies)")
        .map_err(|e| format!("read cookies schema failed: {e}"))?;
    let columns = stmt
        .query_map([], |row| {
            Ok(CookieColumn {
                name: row.get::<_, String>(1)?,
                col_type: row.get::<_, String>(2).unwrap_or_default(),
                not_null: row.get::<_, i64>(3).unwrap_or(0) != 0,
                default_value: row.get::<_, Option<String>>(4).ok().flatten(),
            })
        })
        .map_err(|e| format!("read cookies schema failed: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read cookies schema failed: {e}"))?;

    if columns.is_empty() {
        return Err("cookies table is missing or has no columns".to_string());
    }
    Ok(columns)
}

fn insert_cookie_row(
    conn: &Connection,
    columns: &[CookieColumn],
    name: &str,
    value: &str,
    http_only: bool,
    expires_days: i64,
) -> Result<(), String> {
    let now = chrome_time_now();
    let expires = chrome_time_from_unix_seconds(Utc::now().timestamp() + expires_days * 86_400);
    let mut row = HashMap::<String, Value>::new();
    row.insert("creation_utc".to_string(), Value::Integer(now));
    row.insert(
        "host_key".to_string(),
        Value::Text(CLAUDE_COOKIE_HOST.to_string()),
    );
    row.insert("top_frame_site_key".to_string(), Value::Text(String::new()));
    row.insert("name".to_string(), Value::Text(name.to_string()));
    row.insert("value".to_string(), Value::Text(value.to_string()));
    row.insert("encrypted_value".to_string(), Value::Blob(Vec::new()));
    row.insert("path".to_string(), Value::Text("/".to_string()));
    row.insert("expires_utc".to_string(), Value::Integer(expires));
    row.insert("is_secure".to_string(), Value::Integer(1));
    row.insert(
        "is_httponly".to_string(),
        Value::Integer(if http_only { 1 } else { 0 }),
    );
    row.insert("last_access_utc".to_string(), Value::Integer(now));
    row.insert("has_expires".to_string(), Value::Integer(1));
    row.insert("is_persistent".to_string(), Value::Integer(1));
    row.insert("priority".to_string(), Value::Integer(1));
    row.insert("samesite".to_string(), Value::Integer(1));
    row.insert("source_scheme".to_string(), Value::Integer(2));
    row.insert("source_port".to_string(), Value::Integer(443));
    row.insert("last_update_utc".to_string(), Value::Integer(now));
    row.insert("source_type".to_string(), Value::Integer(0));
    row.insert("has_cross_site_ancestor".to_string(), Value::Integer(0));
    row.insert("is_same_party".to_string(), Value::Integer(0));
    row.insert("partition_key".to_string(), Value::Text(String::new()));

    let mut insert_cols = Vec::new();
    let mut insert_vals = Vec::new();
    for column in columns {
        if let Some(v) = row.get(&column.name) {
            insert_cols.push(column.name.clone());
            insert_vals.push(v.clone());
        } else if column.not_null && column.default_value.is_none() {
            insert_cols.push(column.name.clone());
            insert_vals.push(fallback_value_for_column(column));
        }
    }

    let placeholders = std::iter::repeat_n("?", insert_cols.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO cookies ({}) VALUES ({})",
        insert_cols.join(", "),
        placeholders
    );
    conn.execute(&sql, rusqlite::params_from_iter(insert_vals))
        .map_err(|e| format!("insert {name} cookie failed: {e}"))?;
    Ok(())
}

fn fallback_value_for_column(column: &CookieColumn) -> Value {
    let upper = column.col_type.to_ascii_uppercase();
    if upper.contains("INT") {
        Value::Integer(0)
    } else if upper.contains("BLOB") {
        Value::Blob(Vec::new())
    } else {
        Value::Text(String::new())
    }
}

fn verify_cookie_db(cookie_path: &Path, profile: &BrowserProfile) -> Result<VerifyResult, String> {
    let exists = cookie_path.is_file();
    if !exists {
        return Ok(VerifyResult {
            cookies_db_path: cookie_path.to_string_lossy().to_string(),
            exists: false,
            is_writable: false,
            has_session_key: false,
            has_last_active_org: false,
            value_present: false,
            encrypted_present: false,
            is_locked_suspected: false,
            is_running: false,
            message: Some("Cookies database does not exist".to_string()),
        });
    }

    let conn = match Connection::open_with_flags(
        cookie_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(conn) => conn,
        Err(e) => {
            return Ok(VerifyResult {
                cookies_db_path: cookie_path.to_string_lossy().to_string(),
                exists: true,
                is_writable: false,
                has_session_key: false,
                has_last_active_org: false,
                value_present: false,
                encrypted_present: false,
                is_locked_suspected: true,
                is_running: profile.is_running
                    || detect_profile_running(Path::new(&profile.profile_path)),
                message: Some(format!("open failed: {e}")),
            });
        }
    };
    let _ = conn.busy_timeout(std::time::Duration::from_millis(500));
    let is_writable = conn.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").is_ok();

    let columns = cookie_columns(&conn).unwrap_or_default();
    let has_encrypted_column = columns.iter().any(|c| c.name == "encrypted_value");
    let has_session_key = count_cookie(&conn, "sessionKey") > 0;
    let has_last_active_org = count_cookie(&conn, "lastActiveOrg") > 0;
    let value_present = cookie_value_len(&conn, "sessionKey", "value") > 0;
    let encrypted_present =
        has_encrypted_column && cookie_blob_len(&conn, "sessionKey", "encrypted_value") > 0;
    let running = profile.is_running || detect_profile_running(Path::new(&profile.profile_path));
    let lock_suspected = lock_files_exist(cookie_path) || !is_writable || running;

    Ok(VerifyResult {
        cookies_db_path: cookie_path.to_string_lossy().to_string(),
        exists,
        is_writable,
        has_session_key,
        has_last_active_org,
        value_present,
        encrypted_present,
        is_locked_suspected: lock_suspected,
        is_running: running,
        message: None,
    })
}

fn count_cookie(conn: &Connection, name: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM cookies WHERE host_key IN ('.claude.ai', 'claude.ai') AND name = ?1",
        params![name],
        |row| row.get(0),
    )
    .unwrap_or(0)
}

fn cookie_value_len(conn: &Connection, name: &str, column: &str) -> usize {
    let sql = format!(
        "SELECT COALESCE(LENGTH({column}), 0) FROM cookies WHERE host_key IN ('.claude.ai', 'claude.ai') AND name = ?1 ORDER BY LENGTH({column}) DESC LIMIT 1"
    );
    conn.query_row(&sql, params![name], |row| row.get::<_, i64>(0))
        .unwrap_or(0)
        .max(0) as usize
}

fn cookie_blob_len(conn: &Connection, name: &str, column: &str) -> usize {
    cookie_value_len(conn, name, column)
}

fn import_via_cdp(
    target: &ImportTarget,
    session_key: &str,
    last_active_org: Option<String>,
) -> Result<ImportResult, String> {
    let launched;
    let endpoint = if let Some(endpoint) = explicit_cdp_endpoint(target) {
        endpoint.to_string()
    } else {
        launched = launch_profile_cdp(&target.profile)?;
        launched.endpoint.clone()
    };
    let ws_url = resolve_cdp_websocket_with_retry(&endpoint, 50, Duration::from_millis(120))?;
    let (mut socket, _) =
        connect(ws_url.as_str()).map_err(|e| format!("connect CDP websocket failed: {e}"))?;

    let mut cookies = vec![json!({
        "name": "sessionKey",
        "value": session_key,
        "domain": CLAUDE_COOKIE_HOST,
        "path": "/",
        "secure": true,
        "httpOnly": true,
        "sameSite": "Lax",
        "expires": Utc::now().timestamp() + 30 * 86_400
    })];
    if let Some(org) = last_active_org
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        cookies.push(json!({
            "name": "lastActiveOrg",
            "value": org,
            "domain": CLAUDE_COOKIE_HOST,
            "path": "/",
            "secure": true,
            "httpOnly": false,
            "sameSite": "Lax",
            "expires": Utc::now().timestamp() + 365 * 86_400
        }));
    }

    cdp_call(
        &mut socket,
        1,
        "Storage.setCookies",
        json!({ "cookies": cookies }),
    )?;
    let cookie_payload = cdp_call(&mut socket, 2, "Storage.getCookies", json!({}))?;

    let verification = verify_cdp_cookie_payload(&cookie_payload, target);
    Ok(ImportResult {
        backup_path: String::new(),
        method_used: ImportMethod::Cdp,
        verification,
        masked_session_key: mask_secret(session_key),
    })
}

fn cdp_call(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    id: i64,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let request = json!({
        "id": id,
        "method": method,
        "params": params
    })
    .to_string();
    socket
        .send(Message::Text(request.into()))
        .map_err(|e| format!("send CDP {method} failed: {e}"))?;

    loop {
        let reply = socket
            .read()
            .map_err(|e| format!("read CDP {method} response failed: {e}"))?;
        let reply_text = reply
            .to_text()
            .map_err(|e| format!("read CDP {method} response text failed: {e}"))?;
        let payload: serde_json::Value = serde_json::from_str(reply_text)
            .map_err(|e| format!("decode CDP {method} response failed: {e}"))?;
        if payload.get("id").and_then(|v| v.as_i64()) != Some(id) {
            continue;
        }
        if let Some(error) = payload.get("error") {
            return Err(format!("CDP {method} failed: {error}"));
        }
        return Ok(payload);
    }
}

fn verify_cdp_cookie_payload(payload: &serde_json::Value, target: &ImportTarget) -> VerifyResult {
    let cookies = payload
        .get("result")
        .and_then(|v| v.get("cookies"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let has_session_key = cookies.iter().any(|cookie| {
        cookie.get("name").and_then(|v| v.as_str()) == Some("sessionKey")
            && cookie
                .get("domain")
                .and_then(|v| v.as_str())
                .is_some_and(|domain| domain == CLAUDE_COOKIE_HOST || domain == "claude.ai")
    });
    let value_present = cookies.iter().any(|cookie| {
        cookie.get("name").and_then(|v| v.as_str()) == Some("sessionKey")
            && cookie
                .get("value")
                .and_then(|v| v.as_str())
                .is_some_and(|value| !value.is_empty())
    });
    let has_last_active_org = cookies
        .iter()
        .any(|cookie| cookie.get("name").and_then(|v| v.as_str()) == Some("lastActiveOrg"));

    VerifyResult {
        cookies_db_path: target_cookie_db_path(target).to_string_lossy().to_string(),
        exists: target_cookie_db_path(target).is_file(),
        is_writable: true,
        has_session_key,
        has_last_active_org,
        value_present,
        encrypted_present: false,
        is_locked_suspected: false,
        is_running: true,
        message: Some("Verified through profile-level CDP; SQLite database was not opened".into()),
    }
}

fn launch_profile_cdp(profile: &BrowserProfile) -> Result<LaunchedCdp, String> {
    if profile.is_running || detect_profile_running(Path::new(&profile.profile_path)) {
        return Err(
            "selected profile appears to be running; close it first or provide its localhost CDP endpoint"
                .to_string(),
        );
    }
    let port = allocate_local_port()?;
    let launch = profile_cdp_launch_args(profile, port)?;
    let child = Command::new(&launch.executable_path)
        .args(&launch.args)
        .spawn()
        .map_err(|e| {
            format!(
                "launch browser for profile-level CDP failed ({}): {e}",
                launch.executable_path.display()
            )
        })?;
    Ok(LaunchedCdp {
        endpoint: launch.endpoint,
        child,
    })
}

fn profile_cdp_launch_args(profile: &BrowserProfile, port: u16) -> Result<CdpLaunchArgs, String> {
    let executable_path = profile
        .browser_executable_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "selected profile does not include a browser executable path".to_string())?;
    let user_data_dir = profile
        .cdp_user_data_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            Path::new(&profile.profile_path)
                .parent()
                .map(Path::to_path_buf)
        })
        .ok_or_else(|| "selected profile does not include a user-data directory".to_string())?;
    let profile_directory = profile
        .cdp_profile_directory
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let mut args = vec![
        "--remote-debugging-address=127.0.0.1".to_string(),
        format!("--remote-debugging-port={port}"),
        "--remote-allow-origins=*".to_string(),
        format!("--user-data-dir={}", user_data_dir.display()),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
    ];
    if let Some(profile_directory) = profile_directory {
        args.push(format!("--profile-directory={profile_directory}"));
    }
    args.push("about:blank".to_string());

    Ok(CdpLaunchArgs {
        executable_path,
        args,
        endpoint: format!("http://127.0.0.1:{port}"),
    })
}

fn allocate_local_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("allocate localhost CDP port failed: {e}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| format!("read allocated localhost CDP port failed: {e}"))
}

fn resolve_cdp_websocket_with_retry(
    endpoint: &str,
    attempts: usize,
    delay: Duration,
) -> Result<String, String> {
    let mut last_error = String::new();
    for _ in 0..attempts {
        match resolve_cdp_websocket(endpoint) {
            Ok(ws) => return Ok(ws),
            Err(e) => {
                last_error = e;
                thread::sleep(delay);
            }
        }
    }
    Err(format!(
        "CDP endpoint did not become ready at {endpoint}: {last_error}"
    ))
}

fn resolve_cdp_websocket(endpoint: &str) -> Result<String, String> {
    let normalized = normalize_cdp_endpoint(endpoint)?;
    if normalized.starts_with("ws://") || normalized.starts_with("wss://") {
        return Ok(normalized);
    }
    let url = format!("{}/json/version", normalized.trim_end_matches('/'));
    let mut response = ureq::get(&url)
        .call()
        .map_err(|e| format!("query CDP /json/version failed: {e}"))?;
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("read CDP /json/version failed: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("decode CDP /json/version failed: {e}"))?;
    value
        .get("webSocketDebuggerUrl")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| "CDP /json/version did not expose webSocketDebuggerUrl".to_string())
}

fn normalize_cdp_endpoint(raw: &str) -> Result<String, String> {
    let value = raw.trim().trim_end_matches('/');
    if value.is_empty() {
        return Err("CDP endpoint is empty".to_string());
    }
    if value.chars().all(|c| c.is_ascii_digit()) {
        return Ok(format!("http://127.0.0.1:{value}"));
    }
    if value.starts_with("127.0.0.1:") || value.starts_with("localhost:") {
        return Ok(format!("http://{value}"));
    }
    let parsed = url::Url::parse(value).map_err(|e| format!("invalid CDP endpoint: {e}"))?;
    match parsed.scheme() {
        "http" | "ws" | "wss" => {}
        _ => {
            return Err(
                "CDP endpoint must be http://, ws://, wss://, host:port, or port".to_string(),
            );
        }
    }
    let host = parsed.host_str().unwrap_or_default();
    if host != "127.0.0.1" && host != "localhost" {
        return Err("CDP endpoint must point to localhost".to_string());
    }
    Ok(value.to_string())
}

#[derive(Clone)]
struct ProfileBase {
    browser: String,
    base_path: PathBuf,
    electron_root: bool,
    executable_path: Option<PathBuf>,
}

fn profile_bases() -> Vec<ProfileBase> {
    let mut bases = Vec::new();
    let Some(home) = dirs::home_dir() else {
        return bases;
    };

    #[cfg(target_os = "macos")]
    {
        let app_support = home.join("Library/Application Support");
        bases.extend([
            ProfileBase {
                browser: "Chrome".into(),
                base_path: app_support.join("Google/Chrome"),
                electron_root: false,
                executable_path: browser_executable_path("Chrome"),
            },
            ProfileBase {
                browser: "Chromium".into(),
                base_path: app_support.join("Chromium"),
                electron_root: false,
                executable_path: browser_executable_path("Chromium"),
            },
            ProfileBase {
                browser: "Brave".into(),
                base_path: app_support.join("BraveSoftware/Brave-Browser"),
                electron_root: false,
                executable_path: browser_executable_path("Brave"),
            },
            ProfileBase {
                browser: "Microsoft Edge".into(),
                base_path: app_support.join("Microsoft Edge"),
                electron_root: false,
                executable_path: browser_executable_path("Microsoft Edge"),
            },
        ]);
        if let Ok(entries) = fs::read_dir(&app_support) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("Claude") && path.is_dir() {
                    bases.push(ProfileBase {
                        browser: name.clone(),
                        base_path: path,
                        electron_root: true,
                        executable_path: browser_executable_path(&name),
                    });
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            bases.extend([
                ProfileBase {
                    browser: "Chrome".into(),
                    base_path: local.join("Google/Chrome/User Data"),
                    electron_root: false,
                    executable_path: browser_executable_path("Chrome"),
                },
                ProfileBase {
                    browser: "Chromium".into(),
                    base_path: local.join("Chromium/User Data"),
                    electron_root: false,
                    executable_path: browser_executable_path("Chromium"),
                },
                ProfileBase {
                    browser: "Brave".into(),
                    base_path: local.join("BraveSoftware/Brave-Browser/User Data"),
                    electron_root: false,
                    executable_path: browser_executable_path("Brave"),
                },
                ProfileBase {
                    browser: "Microsoft Edge".into(),
                    base_path: local.join("Microsoft/Edge/User Data"),
                    electron_root: false,
                    executable_path: browser_executable_path("Microsoft Edge"),
                },
            ]);
        }
        if let Some(roaming) = std::env::var_os("APPDATA").map(PathBuf::from) {
            let claude = roaming.join("Claude");
            bases.push(ProfileBase {
                browser: "Claude Desktop".into(),
                base_path: claude,
                electron_root: true,
                executable_path: browser_executable_path("Claude Desktop"),
            });
        }
    }

    #[cfg(target_os = "linux")]
    {
        let config = home.join(".config");
        bases.extend([
            ProfileBase {
                browser: "Chrome".into(),
                base_path: config.join("google-chrome"),
                electron_root: false,
                executable_path: browser_executable_path("Chrome"),
            },
            ProfileBase {
                browser: "Chromium".into(),
                base_path: config.join("chromium"),
                electron_root: false,
                executable_path: browser_executable_path("Chromium"),
            },
            ProfileBase {
                browser: "Brave".into(),
                base_path: config.join("BraveSoftware/Brave-Browser"),
                electron_root: false,
                executable_path: browser_executable_path("Brave"),
            },
            ProfileBase {
                browser: "Microsoft Edge".into(),
                base_path: config.join("microsoft-edge"),
                electron_root: false,
                executable_path: browser_executable_path("Microsoft Edge"),
            },
            ProfileBase {
                browser: "Claude Desktop".into(),
                base_path: config.join("Claude"),
                electron_root: true,
                executable_path: browser_executable_path("Claude Desktop"),
            },
        ]);
    }

    bases
}

fn scan_profile_base(base: &ProfileBase) -> Vec<BrowserProfile> {
    if !base.base_path.is_dir() {
        return Vec::new();
    }
    if base.electron_root {
        return vec![build_profile(
            &base.browser,
            "Default",
            base.base_path.clone(),
            true,
            None,
            base.executable_path.clone(),
            Some(base.base_path.clone()),
            None,
        )];
    }

    let friendly_names = local_state_profile_names(&base.base_path);
    let mut profiles = Vec::new();
    for child_name in [
        "Default",
        "Profile 1",
        "Profile 2",
        "Profile 3",
        "Profile 4",
        "Profile 5",
    ] {
        let path = base.base_path.join(child_name);
        if path.is_dir() {
            profiles.push(build_profile(
                &base.browser,
                friendly_names
                    .get(child_name)
                    .map(String::as_str)
                    .unwrap_or(child_name),
                path,
                false,
                Some(child_name),
                base.executable_path.clone(),
                Some(base.base_path.clone()),
                Some(child_name.to_string()),
            ));
        }
    }
    if let Ok(entries) = fs::read_dir(&base.base_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().to_string()) else {
                continue;
            };
            if !name.starts_with("Profile ")
                || profiles
                    .iter()
                    .any(|p| p.profile_path == path.to_string_lossy())
            {
                continue;
            }
            profiles.push(build_profile(
                &base.browser,
                friendly_names
                    .get(&name)
                    .map(String::as_str)
                    .unwrap_or(&name),
                path,
                false,
                Some(&name),
                base.executable_path.clone(),
                Some(base.base_path.clone()),
                Some(name.clone()),
            ));
        }
    }
    profiles
}

fn build_profile(
    browser: &str,
    profile_name: &str,
    profile_path: PathBuf,
    electron_root: bool,
    profile_id_hint: Option<&str>,
    executable_path: Option<PathBuf>,
    cdp_user_data_dir: Option<PathBuf>,
    cdp_profile_directory: Option<String>,
) -> BrowserProfile {
    let cookie_db = preferred_cookie_db(&profile_path, electron_root);
    BrowserProfile {
        id: format!("{}:{}", browser, profile_id_hint.unwrap_or(profile_name)),
        browser: browser.to_string(),
        profile_name: profile_name.to_string(),
        exists: profile_path.is_dir(),
        cookies_db_exists: cookie_db.is_file(),
        is_locked_suspected: lock_files_exist(&cookie_db),
        is_running: detect_profile_running(&profile_path),
        profile_path: profile_path.to_string_lossy().to_string(),
        cookies_db_path: cookie_db.to_string_lossy().to_string(),
        cdp_endpoint: None,
        browser_executable_path: executable_path.map(|p| p.to_string_lossy().to_string()),
        cdp_user_data_dir: cdp_user_data_dir.map(|p| p.to_string_lossy().to_string()),
        cdp_profile_directory,
    }
}

fn browser_executable_path(browser: &str) -> Option<PathBuf> {
    browser_executable_candidates(browser)
        .into_iter()
        .find(|path| path.is_file())
}

fn browser_executable_candidates(browser: &str) -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let mut candidates = Vec::new();
        let app_specs: Vec<(String, String)> = match browser {
            "Chrome" => vec![("Google Chrome".into(), "Google Chrome".into())],
            "Chromium" => vec![("Chromium".into(), "Chromium".into())],
            "Brave" => vec![("Brave Browser".into(), "Brave Browser".into())],
            "Microsoft Edge" => vec![("Microsoft Edge".into(), "Microsoft Edge".into())],
            "Claude Desktop" => vec![("Claude".into(), "Claude".into())],
            other if other.starts_with("Claude") => vec![
                (other.into(), other.into()),
                (other.into(), "Claude".into()),
                ("Claude".into(), "Claude".into()),
            ],
            _ => Vec::new(),
        };
        let mut roots = vec![PathBuf::from("/Applications")];
        if let Some(home) = dirs::home_dir() {
            roots.push(home.join("Applications"));
        }
        for root in roots {
            for (app, executable) in &app_specs {
                candidates.push(
                    root.join(format!("{app}.app"))
                        .join("Contents/MacOS")
                        .join(executable),
                );
            }
        }
        return candidates;
    }

    #[cfg(target_os = "windows")]
    {
        let mut roots = Vec::new();
        for key in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
            if let Some(root) = std::env::var_os(key).map(PathBuf::from) {
                roots.push(root);
            }
        }
        let suffixes: &[&str] = match browser {
            "Chrome" => &["Google/Chrome/Application/chrome.exe"],
            "Chromium" => &[
                "Chromium/Application/chrome.exe",
                "Chromium/Application/chromium.exe",
            ],
            "Brave" => &["BraveSoftware/Brave-Browser/Application/brave.exe"],
            "Microsoft Edge" => &["Microsoft/Edge/Application/msedge.exe"],
            "Claude Desktop" => &["Programs/Claude/Claude.exe", "Claude/Claude.exe"],
            other if other.starts_with("Claude") => {
                &["Programs/Claude/Claude.exe", "Claude/Claude.exe"]
            }
            _ => &[],
        };
        return roots
            .into_iter()
            .flat_map(|root| suffixes.iter().map(move |suffix| root.join(suffix)))
            .collect();
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let names: &[&str] = match browser {
            "Chrome" => &["google-chrome", "google-chrome-stable"],
            "Chromium" => &["chromium", "chromium-browser"],
            "Brave" => &["brave-browser", "brave"],
            "Microsoft Edge" => &["microsoft-edge", "microsoft-edge-stable"],
            "Claude Desktop" => &["claude"],
            other if other.starts_with("Claude") => &["claude"],
            _ => &[],
        };
        return std::env::var_os("PATH")
            .into_iter()
            .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
            .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
            .collect();
    }
}

fn preferred_cookie_db(profile_path: &Path, electron_root: bool) -> PathBuf {
    let network = profile_path.join("Network/Cookies");
    if !electron_root && network.exists() {
        return network;
    }
    let root = profile_path.join("Cookies");
    if root.exists() || electron_root {
        return root;
    }
    network
}

fn local_state_profile_names(base: &Path) -> HashMap<String, String> {
    let path = base.join("Local State");
    let Ok(text) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return HashMap::new();
    };
    let Some(cache) = value
        .get("profile")
        .and_then(|v| v.get("info_cache"))
        .and_then(|v| v.as_object())
    else {
        return HashMap::new();
    };
    cache
        .iter()
        .filter_map(|(key, value)| {
            value
                .get("name")
                .and_then(|v| v.as_str())
                .map(|name| (key.clone(), name.to_string()))
        })
        .collect()
}

fn lock_files_exist(cookie_db: &Path) -> bool {
    ["-journal", "-wal", "-shm"]
        .iter()
        .any(|suffix| PathBuf::from(format!("{}{}", cookie_db.display(), suffix)).exists())
}

fn detect_profile_running(profile_path: &Path) -> bool {
    let needle = profile_path.to_string_lossy();
    if needle.is_empty() {
        return false;
    }

    #[cfg(target_os = "windows")]
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Process | Select-Object -ExpandProperty CommandLine",
        ])
        .output();

    #[cfg(target_os = "macos")]
    let output = Command::new("ps").args(["-axo", "command"]).output();

    #[cfg(all(unix, not(target_os = "macos")))]
    let output = Command::new("ps").args(["-eo", "command"]).output();

    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8_lossy(&output.stdout).contains(needle.as_ref())
}

mod commands {
    use super::*;

    #[tauri::command]
    pub fn scan_profiles() -> Result<Vec<BrowserProfile>, String> {
        super::scan_profiles()
    }

    #[tauri::command]
    pub fn parse_session_input(text: String) -> Result<ParsedSession, String> {
        super::parse_session_input(text)
    }

    #[tauri::command]
    pub fn open_cookie_db_picker() -> Result<Option<BrowserProfile>, String> {
        super::open_cookie_db_picker()
    }

    #[tauri::command]
    pub fn verify_target(target: ImportTarget) -> Result<VerifyResult, String> {
        super::verify_target(target)
    }

    #[tauri::command(rename_all = "camelCase")]
    pub fn import_session(
        target: ImportTarget,
        session_key: String,
        method: ImportMethod,
        last_active_org: Option<String>,
    ) -> Result<ImportResult, String> {
        super::import_session(target, session_key, method, last_active_org)
    }
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::scan_profiles,
            commands::parse_session_input,
            commands::open_cookie_db_picker,
            commands::verify_target,
            commands::import_session
        ])
        .run(tauri::generate_context!())
        .expect("error while running Claude Session Key Importer");
}

#[cfg(test)]
mod profile_cdp_tests {
    use super::*;

    fn profile_with_executable(profile_path: PathBuf, executable_path: PathBuf) -> BrowserProfile {
        BrowserProfile {
            id: "Chrome:Profile 2".into(),
            browser: "Chrome".into(),
            profile_name: "Work".into(),
            profile_path: profile_path.to_string_lossy().into_owned(),
            cookies_db_path: profile_path
                .join("Network/Cookies")
                .to_string_lossy()
                .into_owned(),
            exists: true,
            cookies_db_exists: true,
            is_locked_suspected: false,
            is_running: false,
            cdp_endpoint: None,
            browser_executable_path: Some(executable_path.to_string_lossy().into_owned()),
            cdp_user_data_dir: profile_path
                .parent()
                .map(|path| path.to_string_lossy().into_owned()),
            cdp_profile_directory: profile_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
        }
    }

    #[test]
    fn auto_prefers_profile_level_cdp_when_profile_has_browser_executable() {
        let dir = tempfile::tempdir().unwrap();
        let profile_path = dir.path().join("User Data/Profile 2");
        let executable_path = dir.path().join("chrome");
        let target = ImportTarget {
            profile: profile_with_executable(profile_path, executable_path),
            manual_cookie_db_path: None,
            cdp_endpoint: None,
        };

        assert_eq!(
            select_import_method(&target, ImportMethod::Auto),
            ImportMethod::Cdp
        );
    }

    #[test]
    fn profile_level_cdp_launch_args_bind_to_selected_profile_directory() {
        let dir = tempfile::tempdir().unwrap();
        let profile_path = dir.path().join("User Data/Profile 2");
        let executable_path = dir.path().join("chrome");
        let profile = profile_with_executable(profile_path.clone(), executable_path.clone());

        let launch = profile_cdp_launch_args(&profile, 49_221).unwrap();

        assert_eq!(launch.executable_path, executable_path);
        assert!(
            launch
                .args
                .contains(&"--remote-debugging-address=127.0.0.1".to_string())
        );
        assert!(
            launch
                .args
                .contains(&"--remote-debugging-port=49221".to_string())
        );
        assert!(launch.args.contains(&format!(
            "--user-data-dir={}",
            profile_path.parent().unwrap().display()
        )));
        assert!(
            launch
                .args
                .contains(&"--profile-directory=Profile 2".to_string())
        );
    }

    #[test]
    fn profile_level_cdp_launch_args_omit_profile_directory_when_profile_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let profile_path = dir.path().join("Claude");
        let executable_path = dir.path().join("Claude");
        let mut profile = profile_with_executable(profile_path, executable_path);
        profile.cdp_profile_directory = None;

        let launch = profile_cdp_launch_args(&profile, 49_222).unwrap();

        assert!(
            !launch
                .args
                .iter()
                .any(|arg| arg.starts_with("--profile-directory="))
        );
    }
}
