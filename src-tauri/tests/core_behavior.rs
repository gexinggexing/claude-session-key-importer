use claude_session_key_importer_lib::{
    BrowserProfile, ImportMethod, ImportTarget, chrome_time_from_unix_seconds, import_session,
    mask_secret, parse_session_input, verify_target,
};
use rusqlite::Connection;
use tempfile::tempdir;

fn create_cookie_db(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE cookies (
            creation_utc INTEGER NOT NULL,
            host_key TEXT NOT NULL,
            top_frame_site_key TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            encrypted_value BLOB NOT NULL DEFAULT X'',
            path TEXT NOT NULL,
            expires_utc INTEGER NOT NULL,
            is_secure INTEGER NOT NULL,
            is_httponly INTEGER NOT NULL,
            last_access_utc INTEGER NOT NULL,
            has_expires INTEGER NOT NULL,
            is_persistent INTEGER NOT NULL,
            priority INTEGER NOT NULL,
            samesite INTEGER NOT NULL,
            source_scheme INTEGER NOT NULL,
            source_port INTEGER NOT NULL,
            last_update_utc INTEGER NOT NULL,
            source_type INTEGER NOT NULL,
            has_cross_site_ancestor INTEGER NOT NULL DEFAULT 0
        );
        "#,
    )
    .unwrap();
}

#[test]
fn parses_supported_session_input_shapes_without_leaking_the_value() {
    let token = "sk-ant-sid02-ABC_def-1234567890";
    let cases = [
        token.to_string(),
        format!("sessionKey={token}"),
        format!("Cookie: other=1; sessionKey={token}; x=y"),
        format!(".claude.ai\tTRUE\t/\tTRUE\t1999999999\tsessionKey\t{token}"),
    ];

    for text in cases {
        let parsed = parse_session_input(text).expect("session input should parse");
        assert_eq!(parsed.kind, "sessionKey");
        assert_eq!(parsed.value, token);
        assert_eq!(parsed.masked, "sk-ant...7890");
        assert!(!parsed.masked.contains("ABC_def"));
    }
}

#[test]
fn rejects_non_session_tokens() {
    let err = parse_session_input("sk-ant-oat01-not-a-session-token".into()).unwrap_err();
    assert!(err.to_string().contains("sessionKey"));
}

#[test]
fn masks_short_and_long_secrets_safely() {
    assert_eq!(mask_secret("abcdef"), "ab...ef");
    assert_eq!(mask_secret("sk-ant-sid02-123456789"), "sk-ant...6789");
}

#[test]
fn converts_unix_seconds_to_chromium_microseconds() {
    assert_eq!(chrome_time_from_unix_seconds(0), 11_644_473_600_000_000);
    assert_eq!(
        chrome_time_from_unix_seconds(1_700_000_000),
        13_344_473_600_000_000
    );
}

#[test]
fn sqlite_import_creates_backup_writes_cookie_and_verifies_result() {
    let dir = tempdir().unwrap();
    let profile_dir = dir.path().join("Default");
    std::fs::create_dir_all(&profile_dir).unwrap();
    let cookie_db = profile_dir.join("Cookies");
    create_cookie_db(&cookie_db);

    let token = "sk-ant-sid02-FIXTURE-DO-NOT-USE-1234567890";
    let target = ImportTarget {
        profile: BrowserProfile {
            id: "manual:Default".into(),
            browser: "Manual".into(),
            profile_name: "Default".into(),
            profile_path: profile_dir.to_string_lossy().into_owned(),
            cookies_db_path: cookie_db.to_string_lossy().into_owned(),
            exists: true,
            cookies_db_exists: true,
            is_locked_suspected: false,
            is_running: false,
            cdp_endpoint: None,
        },
        manual_cookie_db_path: None,
        cdp_endpoint: None,
    };

    let result = import_session(
        target.clone(),
        token.into(),
        ImportMethod::Sqlite,
        Some("4dc351bd-ac9d-4317-a072-091eafbb9faa".into()),
    )
    .unwrap();

    assert_eq!(result.method_used, ImportMethod::Sqlite);
    assert!(result.backup_path.ends_with(".backup"));
    assert!(std::path::Path::new(&result.backup_path).is_file());
    assert!(result.verification.has_session_key);
    assert!(result.verification.has_last_active_org);
    assert!(result.verification.value_present);

    let verify = verify_target(target).unwrap();
    assert!(verify.has_session_key);
    assert!(verify.has_last_active_org);
    assert!(verify.is_writable);
}

#[test]
fn sqlite_import_replaces_existing_plaintext_rows_without_duplicates() {
    let dir = tempdir().unwrap();
    let profile_dir = dir.path().join("Default");
    std::fs::create_dir_all(&profile_dir).unwrap();
    let cookie_db = profile_dir.join("Cookies");
    create_cookie_db(&cookie_db);

    let conn = Connection::open(&cookie_db).unwrap();
    conn.execute(
        "INSERT INTO cookies (creation_utc, host_key, top_frame_site_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, source_port, last_update_utc, source_type, has_cross_site_ancestor)
         VALUES (1, '.claude.ai', '', 'sessionKey', 'old', X'', '/', 2, 1, 1, 1, 1, 1, 1, 1, 2, 443, 1, 0, 0)",
        [],
    ).unwrap();
    drop(conn);

    let target = ImportTarget {
        profile: BrowserProfile {
            id: "manual:Default".into(),
            browser: "Manual".into(),
            profile_name: "Default".into(),
            profile_path: profile_dir.to_string_lossy().into_owned(),
            cookies_db_path: cookie_db.to_string_lossy().into_owned(),
            exists: true,
            cookies_db_exists: true,
            is_locked_suspected: false,
            is_running: false,
            cdp_endpoint: None,
        },
        manual_cookie_db_path: None,
        cdp_endpoint: None,
    };

    import_session(
        target,
        "sk-ant-sid02-NEW-VALUE-1234567890".into(),
        ImportMethod::Sqlite,
        None,
    )
    .unwrap();

    let conn = Connection::open(&cookie_db).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM cookies WHERE host_key='.claude.ai' AND name='sessionKey'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let value: String = conn
        .query_row(
            "SELECT value FROM cookies WHERE host_key='.claude.ai' AND name='sessionKey'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(value, "sk-ant-sid02-NEW-VALUE-1234567890");
}
