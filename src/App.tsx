import { invoke } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";

type BrowserProfile = {
  id: string;
  browser: string;
  profile_name: string;
  profile_path: string;
  cookies_db_path: string;
  exists: boolean;
  cookies_db_exists: boolean;
  is_locked_suspected: boolean;
  is_running: boolean;
  cdp_endpoint: string | null;
};

type ParsedSession = {
  kind: string;
  value: string;
  masked: string;
};

type VerifyResult = {
  cookies_db_path: string;
  exists: boolean;
  is_writable: boolean;
  has_session_key: boolean;
  has_last_active_org: boolean;
  value_present: boolean;
  encrypted_present: boolean;
  is_locked_suspected: boolean;
  is_running: boolean;
  message: string | null;
};

type ImportResult = {
  backup_path: string;
  method_used: ImportMethod;
  verification: VerifyResult;
  masked_session_key: string;
};

type ImportMethod = "auto" | "cdp" | "sqlite" | "manualSqlite";

type ImportTarget = {
  profile: BrowserProfile;
  manual_cookie_db_path: string | null;
  cdp_endpoint: string | null;
};

const emptyProfile: BrowserProfile = {
  id: "manual:none",
  browser: "Manual",
  profile_name: "No profile selected",
  profile_path: "",
  cookies_db_path: "",
  exists: false,
  cookies_db_exists: false,
  is_locked_suspected: false,
  is_running: false,
  cdp_endpoint: null,
};

function profileStatus(profile: BrowserProfile) {
  if (!profile.cookies_db_exists) return "Missing Cookies DB";
  if (profile.is_running) return "Profile running";
  if (profile.is_locked_suspected) return "Lock suspected";
  return "Ready";
}

function buildTarget(profile: BrowserProfile, cdpEndpoint: string): ImportTarget {
  return {
    profile: { ...profile, cdp_endpoint: cdpEndpoint.trim() || profile.cdp_endpoint },
    manual_cookie_db_path: profile.browser === "Manual Cookies DB" ? profile.cookies_db_path : null,
    cdp_endpoint: cdpEndpoint.trim() || profile.cdp_endpoint,
  };
}

export default function App() {
  const [profiles, setProfiles] = useState<BrowserProfile[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [sessionInput, setSessionInput] = useState("");
  const [lastActiveOrg, setLastActiveOrg] = useState("");
  const [cdpEndpoint, setCdpEndpoint] = useState("");
  const [method, setMethod] = useState<ImportMethod>("auto");
  const [parsed, setParsed] = useState<ParsedSession | null>(null);
  const [parseError, setParseError] = useState("");
  const [status, setStatus] = useState("Idle");
  const [result, setResult] = useState<ImportResult | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);

  const selectedProfile =
    profiles.find((profile) => profile.id === selectedId) ?? profiles[0] ?? emptyProfile;

  async function refreshProfiles() {
    setStatus("Scanning local profiles");
    try {
      const scanned = await invoke<BrowserProfile[]>("scan_profiles");
      setProfiles(scanned);
      setSelectedId((current) => current || scanned[0]?.id || "");
      setStatus(scanned.length ? `Found ${scanned.length} profiles` : "No local profiles found");
    } catch (error) {
      setStatus(String(error));
    }
  }

  useEffect(() => {
    void refreshProfiles();
  }, []);

  useEffect(() => {
    const text = sessionInput.trim();
    setResult(null);
    if (!text) {
      setParsed(null);
      setParseError("");
      return;
    }
    const timer = window.setTimeout(async () => {
      try {
        const parsedSession = await invoke<ParsedSession>("parse_session_input", { text });
        setParsed(parsedSession);
        setParseError("");
      } catch (error) {
        setParsed(null);
        setParseError(String(error));
      }
    }, 180);
    return () => window.clearTimeout(timer);
  }, [sessionInput]);

  async function chooseManualDb() {
    setBusy(true);
    setStatus("Opening file picker");
    try {
      const profile = await invoke<BrowserProfile | null>("open_cookie_db_picker");
      if (profile) {
        setProfiles((current) => [profile, ...current.filter((p) => p.id !== profile.id)]);
        setSelectedId(profile.id);
        setStatus("Manual Cookies DB selected");
      } else {
        setStatus("Manual selection cancelled");
      }
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function verifySelected() {
    setBusy(true);
    setResult(null);
    try {
      const target = buildTarget(selectedProfile, cdpEndpoint);
      const nextVerify = await invoke<VerifyResult>("verify_target", { target });
      setVerify(nextVerify);
      setStatus(nextVerify.has_session_key ? "Existing sessionKey detected" : "Target verified");
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  }

  async function importSelected() {
    setBusy(true);
    setResult(null);
    try {
      const target = buildTarget(selectedProfile, cdpEndpoint);
      const importResult = await invoke<ImportResult>("import_session", {
        target,
        sessionKey: sessionInput,
        method,
        lastActiveOrg: lastActiveOrg.trim() || null,
      });
      setResult(importResult);
      setVerify(importResult.verification);
      setStatus("Import completed");
    } catch (error) {
      setStatus(String(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">Local profile operations · no secret echo</p>
          <h1>Claude Session Key Importer</h1>
          <p className="lede">
            Select a local Chromium or Claude Desktop profile, parse a sessionKey safely,
            back up the Cookies database, then inject and verify the cookie.
          </p>
        </div>
        <div className="status-panel" aria-live="polite">
          <span className={busy ? "pulse-dot busy" : "pulse-dot"} />
          <span>{status}</span>
        </div>
      </section>

      <section className="workspace">
        <aside className="profiles-card">
          <div className="card-title-row">
            <div>
              <p className="section-kicker">Detected profiles</p>
              <h2>Browser profile target</h2>
            </div>
            <button className="ghost-button" onClick={refreshProfiles} disabled={busy}>
              Rescan
            </button>
          </div>

          <div className="profile-list">
            {profiles.length === 0 ? (
              <div className="empty-state">No profiles found yet. Use manual Cookies DB selection.</div>
            ) : (
              profiles.map((profile) => (
                <button
                  className={profile.id === selectedProfile.id ? "profile-row active" : "profile-row"}
                  key={profile.id}
                  onClick={() => {
                    setSelectedId(profile.id);
                    setVerify(null);
                    setResult(null);
                  }}
                  type="button"
                >
                  <span className="profile-main">
                    <strong>{profile.browser}</strong>
                    <span>{profile.profile_name}</span>
                  </span>
                  <span className={profile.cookies_db_exists ? "chip ok" : "chip warn"}>
                    {profileStatus(profile)}
                  </span>
                </button>
              ))
            )}
          </div>

          <button className="manual-button" onClick={chooseManualDb} disabled={busy}>
            Choose Cookies DB manually
          </button>
        </aside>

        <section className="control-card">
          <div className="selected-paths">
            <p>
              <span>Profile</span>
              <code>{selectedProfile.profile_path || "No profile selected"}</code>
            </p>
            <p>
              <span>Cookies DB</span>
              <code>{selectedProfile.cookies_db_path || "No Cookies database selected"}</code>
            </p>
          </div>

          <label className="field-block">
            <span>Session input</span>
            <textarea
              aria-label="Session input"
              value={sessionInput}
              onChange={(event) => setSessionInput(event.target.value)}
              placeholder="Paste sk-ant-sid..., sessionKey=..., Cookie header, or Netscape cookies.txt line"
              spellCheck={false}
            />
          </label>
          <div className="parse-line">
            {parsed ? (
              <span className="chip ok">Parsed {parsed.kind}: {parsed.masked}</span>
            ) : parseError ? (
              <span className="chip danger">{parseError}</span>
            ) : (
              <span className="chip muted">Waiting for sessionKey input</span>
            )}
          </div>

          <div className="grid-two">
            <label className="field-block">
              <span>Import method</span>
              <select value={method} onChange={(event) => setMethod(event.target.value as ImportMethod)}>
                <option value="auto">Auto: CDP when available, otherwise SQLite backup</option>
                <option value="cdp">CDP / live browser injection</option>
                <option value="sqlite">Direct SQLite import</option>
                <option value="manualSqlite">Manual SQLite import</option>
              </select>
              <small>Database writes always create a timestamped backup first.</small>
            </label>

            <label className="field-block">
              <span>CDP endpoint</span>
              <input
                value={cdpEndpoint}
                onChange={(event) => setCdpEndpoint(event.target.value)}
                placeholder="9222 / 127.0.0.1:9222 / ws://localhost:9222/..."
                spellCheck={false}
              />
              <small>Used only by Auto/CDP; must be localhost.</small>
            </label>
          </div>

          <label className="field-block">
            <span>lastActiveOrg (optional)</span>
            <input
              value={lastActiveOrg}
              onChange={(event) => setLastActiveOrg(event.target.value)}
              placeholder="4dc351bd-ac9d-4317-a072-091eafbb9faa"
              spellCheck={false}
            />
          </label>

          <div className="action-row">
            <button className="secondary-button" onClick={verifySelected} disabled={busy || !selectedProfile.cookies_db_path}>
              Verify target
            </button>
            <button
              className="primary-button"
              onClick={importSelected}
              disabled={busy || !parsed || !selectedProfile.cookies_db_path}
            >
              Import sessionKey
            </button>
          </div>
        </section>
      </section>

      <section className="result-grid">
        <ResultCard title="Verification" verify={verify} />
        <div className="result-card">
          <p className="section-kicker">Import result</p>
          {result ? (
            <>
              <h2>{result.method_used} complete</h2>
              <p>Masked session: <code>{result.masked_session_key}</code></p>
              <p>Backup: <code>{result.backup_path || "CDP import did not touch the SQLite DB"}</code></p>
            </>
          ) : (
            <>
              <h2>Ready for an import</h2>
              <p>Secrets stay in the local process and are never rendered in full.</p>
            </>
          )}
        </div>
      </section>
    </main>
  );
}

function ResultCard({ title, verify }: { title: string; verify: VerifyResult | null }) {
  return (
    <div className="result-card">
      <p className="section-kicker">{title}</p>
      {verify ? (
        <>
          <h2>{verify.has_session_key ? "sessionKey present" : "No sessionKey found"}</h2>
          <dl>
            <dt>Writable</dt>
            <dd>{verify.is_writable ? "yes" : "no"}</dd>
            <dt>Plain value</dt>
            <dd>{verify.value_present ? "present" : "absent"}</dd>
            <dt>Encrypted value</dt>
            <dd>{verify.encrypted_present ? "present" : "absent"}</dd>
            <dt>Lock suspicion</dt>
            <dd>{verify.is_locked_suspected ? "yes" : "no"}</dd>
          </dl>
          <code>{verify.cookies_db_path}</code>
        </>
      ) : (
        <>
          <h2>No verification run yet</h2>
          <p>Run Verify target before import when you want a read-only preflight.</p>
        </>
      )}
    </div>
  );
}
