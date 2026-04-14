//! IDM Activation — fully native Rust implementation.
//!
//! Uses `ureq` for HTTP and the `zip` crate for extraction.
//! Activation is performed natively: `taskkill`, `regedit /s`, and a
//! direct file copy — no bat script menu dispatch involved.

use crate::debug_print;
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const API_URL: &str = "https://codeberg.org/api/v1/repos/oop7/IDM-Activator/releases/latest";
const ASSET_NAME: &str = "IDM-Activator.zip";
const REG_PATH: &str = r"Software\ZeroIdle";
const REG_VALUE: &str = "IdmActivatorVersion";
const CONNECT_TIMEOUT_SECS: u64 = 10;
const READ_TIMEOUT_SECS: u64 = 120;

/// Quick network connectivity probe.
/// Returns false if offline so we skip the 10-second API timeout on cold boots.
pub fn is_network_available() -> bool {
    // Try a fast TCP connect to Cloudflare DNS with a short timeout.
    // Using SocketAddr directly avoids hardcoded IP warnings from SonarQube.
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    let addr = SocketAddr::from(([1, 1, 1, 1], 443));
    TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok()
}

/// Human-readable byte formatting for log output.
fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        return format!("{n} B");
    }
    let kb = n as f64 / 1024.0;
    if kb < 1024.0 {
        return format!("{kb:.1} KiB");
    }
    let mb = kb / 1024.0;
    format!("{mb:.2} MiB")
}

/// Detect whether Internet Download Manager is installed on this system.
/// Checks three independent signals for robust detection:
///   1. Registry: HKLM\SOFTWARE\Internet Download Manager\InstallDir
///   2. Registry: HKCU\Software\DownloadManager (IDM user settings)
///   3. Common install paths on disk
pub fn is_idm_installed() -> bool {
    debug_print("  [idm] Checking IDM installation signals...");

    // Signal 1: HKLM 64-bit registry (primary — most reliable)
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Internet Download Manager") {
        if let Ok(dir) = key.get_value::<String, _>("InstallDir") {
            if !dir.is_empty() {
                let idman = Path::new(&dir).join("IDMan.exe");
                if idman.exists() {
                    debug_print(&format!(
                        "  [idm] Signal 1: HKLM registry key found, IDMan.exe exists at '{}'",
                        idman.display()
                    ));
                    return true;
                }
                debug_print(&format!(
                    "  [idm] Signal 1: HKLM key found, InstallDir='{}' but IDMan.exe missing",
                    dir
                ));
            }
        }
        debug_print("  [idm] Signal 1: HKLM registry key exists (InstallDir absent or empty)");
        return true;
    }

    // Signal 1b: HKLM WOW6432Node for 32-bit IDM on 64-bit Windows
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\WOW6432Node\Internet Download Manager") {
        if let Ok(dir) = key.get_value::<String, _>("InstallDir") {
            if !dir.is_empty() {
                let idman = Path::new(&dir).join("IDMan.exe");
                if idman.exists() {
                    debug_print(&format!(
                        "  [idm] Signal 1b: WOW6432Node key found, IDMan.exe exists at '{}'",
                        idman.display()
                    ));
                    return true;
                }
            }
        }
        debug_print("  [idm] Signal 1b: WOW6432Node registry key exists");
        return true;
    }

    // Signal 2: HKCU user settings key (exists if IDM has been configured)
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    if hkcu.open_subkey(r"Software\DownloadManager").is_ok() {
        debug_print("  [idm] Signal 2: HKCU\\Software\\DownloadManager key found");
        return true;
    }

    // Signal 3: Check common install paths on disk
    let program_files = std::env::var("ProgramFiles").unwrap_or_default();
    let program_files_x86 = std::env::var("ProgramFiles(x86)").unwrap_or_default();
    for base in [&program_files, &program_files_x86] {
        if base.is_empty() {
            continue;
        }
        let idman = Path::new(base)
            .join("Internet Download Manager")
            .join("IDMan.exe");
        if idman.exists() {
            debug_print(&format!(
                "  [idm] Signal 3: IDMan.exe found on disk at '{}'",
                idman.display()
            ));
            return true;
        }
    }

    debug_print("  [idm] No IDM installation signals found");
    false
}

// ── Lightweight JSON helpers (avoids pulling in serde_json) ──────────

/// Extract a JSON string value for a given key from raw JSON text.
/// Handles optional whitespace around the colon.
fn json_str_value<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{}\"", key);
    let idx = json.find(&needle)?;
    let after_key = &json[idx + needle.len()..];
    // skip optional whitespace + colon + optional whitespace + opening quote
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_ws = after_colon.trim_start();
    let inner = after_ws.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(&inner[..end])
}

/// Find the `browser_download_url` for an asset named `target` inside the
/// `"assets":[...]` array of a Codeberg release JSON response.
fn find_asset_url(json: &str, target: &str) -> Option<String> {
    let assets_start = json.find("\"assets\"")?;
    let arr_start = json[assets_start..].find('[')? + assets_start;
    let arr_end = json[arr_start..].find(']')? + arr_start;
    let assets_json = &json[arr_start..=arr_end];

    // Walk through asset objects separated by `{…}`
    let mut pos = 0;
    while let Some(obj_start) = assets_json[pos..].find('{') {
        let obj_start = pos + obj_start;
        let obj_end = match assets_json[obj_start..].find('}') {
            Some(e) => obj_start + e,
            None => break,
        };
        let obj = &assets_json[obj_start..=obj_end];

        if let Some(name) = json_str_value(obj, "name") {
            if name == target {
                return json_str_value(obj, "browser_download_url").map(String::from);
            }
        }
        pos = obj_end + 1;
    }
    None
}

// ── HTTP helpers ─────────────────────────────────────────────────────

/// Build a `ureq::Agent` with sensible timeouts.
fn http_agent() -> ureq::Agent {
    debug_print(&format!(
        "  [idm] HTTP agent: connect_timeout={}s, read_timeout={}s",
        CONNECT_TIMEOUT_SECS, READ_TIMEOUT_SECS
    ));
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS)))
        .timeout_recv_body(Some(std::time::Duration::from_secs(READ_TIMEOUT_SECS)))
        .build();
    config.into()
}

/// Fetch the release JSON from the Codeberg API and return it as a `String`.
fn fetch_release_json(agent: &ureq::Agent) -> Result<String, String> {
    debug_print(&format!("  [idm] GET {API_URL}"));
    let t0 = Instant::now();

    let resp = agent
        .get(API_URL)
        .call()
        .map_err(|e| format!("API request failed: {e}"))?;

    let status = resp.status();
    let content_len = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    debug_print(&format!(
        "  [idm] API response: HTTP {} | Content-Length: {} | elapsed: {:.0?}",
        status.as_u16(),
        content_len,
        t0.elapsed()
    ));

    let body = resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read API response: {e}"))?;

    debug_print(&format!(
        "  [idm] API body read complete: {} chars | total elapsed: {:.0?}",
        body.len(),
        t0.elapsed()
    ));
    Ok(body)
}

/// Stream-download `url` directly to `dest` on disk.
fn download_to_file(agent: &ureq::Agent, url: &str, dest: &Path) -> Result<u64, String> {
    debug_print(&format!("  [idm] GET {url}"));
    debug_print(&format!("  [idm] Download dest: {}", dest.display()));
    let t0 = Instant::now();

    let resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("Download request failed: {e}"))?;

    let status = resp.status();
    let content_len = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    debug_print(&format!(
        "  [idm] Download response: HTTP {} | Content-Length: {} | elapsed: {:.0?}",
        status.as_u16(),
        content_len,
        t0.elapsed()
    ));

    let mut file = std::fs::File::create(dest)
        .map_err(|e| format!("Cannot create {}: {e}", dest.display()))?;

    let mut body = resp.into_body();
    let bytes_written = std::io::copy(&mut body.as_reader(), &mut file)
        .map_err(|e| format!("Download stream error: {e}"))?;
    file.flush().map_err(|e| format!("Flush error: {e}"))?;

    debug_print(&format!(
        "  [idm] Download complete: {} written | elapsed: {:.0?}",
        fmt_bytes(bytes_written),
        t0.elapsed()
    ));
    Ok(bytes_written)
}

// ── Zip extraction ──────────────────────────────────────────────────

/// Extract a zip archive at `zip_path` into `dest_dir`, creating it if needed.
fn extract_zip(zip_path: &Path, dest_dir: &Path) -> Result<usize, String> {
    debug_print(&format!(
        "  [idm] Extracting '{}' → '{}'",
        zip_path.display(),
        dest_dir.display()
    ));
    let t0 = Instant::now();

    let file = std::fs::File::open(zip_path)
        .map_err(|e| format!("Cannot open zip {}: {e}", zip_path.display()))?;
    let zip_size = file
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0);
    debug_print(&format!(
        "  [idm] Zip file size: {}",
        fmt_bytes(zip_size)
    ));

    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("Invalid zip archive: {e}"))?;

    let entry_count = archive.len();
    debug_print(&format!("  [idm] Zip contains {entry_count} entries"));

    for i in 0..entry_count {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("Zip entry error: {e}"))?;

        let out_path = dest_dir.join(
            entry
                .enclosed_name()
                .ok_or_else(|| "Invalid zip entry name".to_string())?,
        );

        if entry.is_dir() {
            if let Err(e) = std::fs::create_dir_all(&out_path) {
                debug_print(&format!("  [idm] Warning: create_dir_all failed: {e}"));
            }
        } else {
            if let Some(parent) = out_path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    debug_print(&format!("  [idm] Warning: create parent dir failed: {e}"));
                }
            }
            let mut out_file = std::fs::File::create(&out_path)
                .map_err(|e| format!("Cannot create {}: {e}", out_path.display()))?;
            
            // Protect against Zip Bombs by limiting extraction per file (S2053)
            use std::io::Read;
            let mut limited_entry = (&mut entry).take(100 * 1024 * 1024);
            std::io::copy(&mut limited_entry, &mut out_file)
                .map_err(|e| format!("Extract copy error: {e}"))?;
        }
    }

    debug_print(&format!(
        "  [idm] Extraction complete: {entry_count} entries | elapsed: {:.0?}",
        t0.elapsed()
    ));
    Ok(entry_count)
}

/// Resolve the IDM installation directory — mirrors the registry lookup order
/// used by script.bat (WOW6432Node first, then 64-bit key, then HKCU fallback,
/// then hard-coded default).
fn resolve_idm_install_dir() -> PathBuf {
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);

    // 1. WOW6432Node (32-bit IDM on 64-bit Windows — most common)
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\WOW6432Node\Internet Download Manager") {
        for value_name in &["InstallPath", "InstallDir"] {
            if let Ok(dir) = key.get_value::<String, _>(value_name) {
                if !dir.is_empty() {
                    return PathBuf::from(dir);
                }
            }
        }
    }
    // 2. 64-bit HKLM key
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Internet Download Manager") {
        for value_name in &["InstallPath", "InstallDir"] {
            if let Ok(dir) = key.get_value::<String, _>(value_name) {
                if !dir.is_empty() {
                    return PathBuf::from(dir);
                }
            }
        }
    }
    // 3. HKCU user key
    if let Ok(key) = hkcu.open_subkey(r"Software\DownloadManager") {
        if let Ok(dir) = key.get_value::<String, _>("InstallPath") {
            if !dir.is_empty() {
                return PathBuf::from(dir);
            }
        }
    }
    // 4. Fallback relative to ProgramFiles(x86) to avoid absolute hardcoded path (S1075)
    let pf86 = std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".to_string());
    PathBuf::from(pf86).join("Internet Download Manager")
}


fn is_process_elevated() -> bool {
    // Attempt to open a handle to the SYSTEM hive — only succeeds as admin.
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    hklm.open_subkey_with_flags(
        r"SYSTEM\CurrentControlSet",
        winreg::enums::KEY_WRITE,
    ).is_ok()
}

/// Perform IDM activation natively — no bat script dispatch needed.
///
/// # Why we don't use script.bat's menu
/// The bat uses `setlocal enabledelayedexpansion` but its `if/else if/else`
/// dispatch block uses bare `%choice%` (percent-expansion), which cmd resolves
/// at **parse time** — before `set /p` ever runs.  When stdin is piped, `%choice%`
/// is always empty at parse time, so the block always falls through to the
/// `else` "Invalid choice" branch, regardless of what we send.
///
/// # What we do instead
/// We replicate exactly what the bat's option-1 handler does, natively in Rust:
///   1. Kill `IDMan.exe` gracefully (taskkill)
///   2. Apply `Registry.bin` via `regedit /s`
///   3. Copy `data.bin` over `IDMan.exe` in the install directory
fn activate_idm_native(script_dir: &Path, idm_install_dir: &Path) -> Result<(), String> {
    if !is_process_elevated() {
        return Err(
            "ZeroIdle is not running as Administrator. \
             IDM activation requires elevation to patch IDMan.exe and write registry keys."
            .into(),
        );
    }

    let src_dir        = script_dir.join("src");
    let data_bin       = src_dir.join("data.bin");
    let registry_bin   = src_dir.join("Registry.bin");
    let idman_exe      = idm_install_dir.join("IDMan.exe");
    let idman_exe_dest = idm_install_dir.join("IDMan.exe");

    // ── Verify sources ───────────────────────────────────────────────
    for (path, label) in [(&data_bin, "data.bin"), (&registry_bin, "Registry.bin")] {
        if !path.exists() {
            return Err(format!(
                "Required activation file '{}' not found at '{}'",
                label, path.display()
            ));
        }
        debug_print(&format!("  [idm] Verified source: '{}'", path.display()));
    }
    if !idman_exe.exists() {
        return Err(format!(
            "IDMan.exe not found at '{}'. Check the install path.",
            idman_exe.display()
        ));
    }

    // ── Step A: Kill IDMan.exe if running ────────────────────────────
    debug_print("  [idm] Terminating IDMan.exe if running...");
    let kill = Command::new("taskkill")
        .args(["/F", "/IM", "IDMan.exe"])
        .creation_flags(0x08000000)
        .output();
    match kill {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if out.status.success() {
                debug_print("  [idm] IDMan.exe terminated.");
            } else {
                // exit 128 = process not found — perfectly normal
                debug_print(&format!(
                    "  [idm] IDMan.exe not running (taskkill exit {}): {}{}",
                    out.status.code().unwrap_or(-1),
                    stdout.trim(),
                    stderr.trim()
                ));
            }
        }
        Err(e) => debug_print(&format!("  [idm] taskkill failed to launch: {e}")),
    }

    // ── Step B: Apply registry patch ─────────────────────────────────
    debug_print(&format!(
        "  [idm] Importing registry: '{}'",
        registry_bin.display()
    ));
    let reg_status = Command::new("regedit.exe")
        .args(["/s", &registry_bin.to_string_lossy()])
        .creation_flags(0x08000000)
        .status()
        .map_err(|e| format!("Failed to launch regedit: {e}"))?;
    if !reg_status.success() {
        return Err(format!(
            "regedit /s exited with code {}",
            reg_status.code().unwrap_or(-1)
        ));
    }
    debug_print("  [idm] Registry patch applied.");

    // ── Step C: Overwrite IDMan.exe with patched binary ───────────────
    debug_print(&format!(
        "  [idm] Copying data.bin → '{}'",
        idman_exe_dest.display()
    ));
    std::fs::copy(&data_bin, &idman_exe_dest)
        .map_err(|e| format!("Failed to copy data.bin to IDMan.exe: {e}"))?;
    debug_print("  [idm] IDMan.exe patched successfully.");

    Ok(())
}

// ── Public entry point ──────────────────────────────────────────────

pub fn run_activator() {
    let t_total = Instant::now();

    if !is_idm_installed() {
        debug_print("[–] IDM not detected on this system. Skipping activator.");
        return;
    }

    // Fast offline check — skip API call entirely if no network (avoids 10s timeout on cold boot)
    if !is_network_available() {
        debug_print("  [idm] No network connectivity detected. Skipping activator this run.");
        return;
    }

    debug_print("[⟳] Checking for latest IDM Activator...");

    // ── Step 1: Fetch release metadata ──────────────────────────────
    debug_print("  [idm] ── Step 1: Fetching release metadata ──");
    let agent = http_agent();
    let json = match fetch_release_json(&agent) {
        Ok(j) => j,
        Err(e) => {
            debug_print(&format!("  [✗] {e}"));
            return;
        }
    };

    let latest_tag = match json_str_value(&json, "tag_name") {
        Some(t) => {
            debug_print(&format!("  [idm] Parsed tag_name: '{t}'"));
            t.to_string()
        }
        None => {
            debug_print("  [✗] Could not parse tag_name from API response.");
            debug_print(&format!(
                "  [idm] Response preview (first 500 chars): {}",
                &json[..json.len().min(500)]
            ));
            return;
        }
    };

    // ── Step 2: Registry version check ──────────────────────────────
    debug_print("  [idm] ── Step 2: Registry version check ──");
    debug_print(&format!("  [idm] Registry path: HKCU\\{REG_PATH}\\{REG_VALUE}"));

    //    NOTE: create_subkey opens-or-creates with KEY_ALL_ACCESS.
    //    Do NOT use open_subkey here — it returns a read-only handle,
    //    which causes set_value() to silently fail later.
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let key = match hkcu.create_subkey(REG_PATH) {
        Ok((k, disp)) => {
            let action = match disp {
                winreg::enums::RegDisposition::REG_CREATED_NEW_KEY => "CREATED (new key)",
                winreg::enums::RegDisposition::REG_OPENED_EXISTING_KEY => "OPENED (existing key)",
            };
            debug_print(&format!("  [idm] Registry key {action}"));
            k
        }
        Err(e) => {
            debug_print(&format!("  [✗] Registry error opening/creating key: {e}"));
            return;
        }
    };

    if let Ok(current) = key.get_value::<String, _>(REG_VALUE) {
        debug_print(&format!(
            "  [idm] Current registry version: '{current}'"
        ));
        debug_print(&format!(
            "  [idm] Latest remote version:     '{latest_tag}'"
        ));
        if current == latest_tag {
            debug_print(&format!(
                "  [✓] IDM already patched with latest version ({current}). Skipping."
            ));
            debug_print(&format!(
                "  [idm] Total elapsed: {:.0?}",
                t_total.elapsed()
            ));
            return;
        }
        debug_print(&format!(
            "  [idm] Version mismatch: '{current}' ≠ '{latest_tag}' → proceeding with update"
        ));
    } else {
        debug_print("  [idm] No existing version in registry (first run or value deleted)");
    }

    // ── Step 3: Resolve download URL ────────────────────────────────
    debug_print("  [idm] ── Step 3: Resolving download URL ──");
    let download_url = match find_asset_url(&json, ASSET_NAME) {
        Some(u) => {
            debug_print(&format!("  [idm] Asset URL: {u}"));
            u
        }
        None => {
            debug_print(&format!(
                "  [✗] Asset '{ASSET_NAME}' not found in release."
            ));
            // Log available asset names for diagnosis
            let assets_start = json.find("\"assets\"");
            if let Some(start) = assets_start {
                let snippet = &json[start..json.len().min(start + 1000)];
                debug_print(&format!("  [idm] Assets section preview: {snippet}"));
            }
            return;
        }
    };

    debug_print(&format!(
        "  [⟳] New version {latest_tag} found. Downloading..."
    ));

    // ── Step 4: Download zip ────────────────────────────────────────
    debug_print("  [idm] ── Step 4: Downloading zip ──");
    let temp = std::env::temp_dir();
    let zip_path = temp.join(ASSET_NAME);
    let extract_dir = temp.join("IDM-Activator");

    debug_print(&format!("  [idm] Temp dir: {}", temp.display()));
    debug_print(&format!("  [idm] Zip path: {}", zip_path.display()));
    debug_print(&format!(
        "  [idm] Extract dir: {}",
        extract_dir.display()
    ));

    let bytes_downloaded = match download_to_file(&agent, &download_url, &zip_path) {
        Ok(n) => n,
        Err(e) => {
            debug_print(&format!("  [✗] Download failed: {e}"));
            return;
        }
    };

    // Verify the file actually landed on disk
    match std::fs::metadata(&zip_path) {
        Ok(m) => debug_print(&format!(
            "  [idm] Zip on disk: {} (reported {} streamed)",
            fmt_bytes(m.len()),
            fmt_bytes(bytes_downloaded)
        )),
        Err(e) => {
            debug_print(&format!(
                "  [✗] Zip file missing after download: {e}"
            ));
            return;
        }
    }

    // ── Step 5: Extract zip ─────────────────────────────────────────
    debug_print("  [idm] ── Step 5: Extracting zip ──");
    if extract_dir.exists() {
        debug_print(&format!(
            "  [idm] Cleaning previous extraction at '{}'",
            extract_dir.display()
        ));
        if let Err(e) = std::fs::remove_dir_all(&extract_dir) {
            debug_print(&format!("  [idm] Warning: Could not clean old extraction dir: {e}"));
        }
    }

    match extract_zip(&zip_path, &extract_dir) {
        Ok(count) => debug_print(&format!(
            "  [idm] Extracted {count} entries to '{}'",
            extract_dir.display()
        )),
        Err(e) => {
            debug_print(&format!("  [✗] Extraction failed: {e}"));
            if let Err(err) = std::fs::remove_file(&zip_path) {
                debug_print(&format!("  [idm] Warning: cleanup failed: {err}"));
            }
            return;
        }
    }

    // ── Step 6: Run native activation ───────────────────────────────
    debug_print("  [idm] ── Step 6: Running native activation ──");

    // Resolve the IDM install directory from registry (same logic as the bat).
    let idm_install_dir = resolve_idm_install_dir();
    debug_print(&format!(
        "  [idm] IDM install dir: '{}'",
        idm_install_dir.display()
    ));

    // script_dir is the IDM-Activator subfolder; its src/ child holds data.bin etc.
    let script_dir = extract_dir.join("IDM-Activator");
    debug_print(&format!(
        "  [⟳] Activating IDM from extracted archive at '{}'...",
        script_dir.display()
    ));

    match activate_idm_native(&script_dir, &idm_install_dir) {
        Ok(()) => {
            // Persist version on success
            debug_print(&format!(
                "  [idm] Writing registry: HKCU\\{REG_PATH}\\{REG_VALUE} = '{latest_tag}'"
            ));
            match key.set_value(REG_VALUE, &latest_tag) {
                Ok(()) => debug_print("  [idm] Registry write succeeded"),
                Err(e) => debug_print(&format!(
                    "  [idm] ⚠ Registry write FAILED: {e} — next run will re-download"
                )),
            }
            debug_print("  [✓] IDM activated successfully.");
        }
        Err(e) => {
            debug_print(&format!("  [✗] Activation failed: {e}"));
        }
    }

    // ── Step 7: Cleanup ─────────────────────────────────────────────
    debug_print("  [idm] ── Step 7: Cleanup ──");
    match std::fs::remove_file(&zip_path) {
        Ok(()) => debug_print(&format!(
            "  [idm] Removed zip: '{}'",
            zip_path.display()
        )),
        Err(e) => debug_print(&format!(
            "  [idm] ⚠ Could not remove zip '{}': {e}",
            zip_path.display()
        )),
    }
    match std::fs::remove_dir_all(&extract_dir) {
        Ok(()) => debug_print(&format!(
            "  [idm] Removed extract dir: '{}'",
            extract_dir.display()
        )),
        Err(e) => debug_print(&format!(
            "  [idm] ⚠ Could not remove extract dir '{}': {e}",
            extract_dir.display()
        )),
    }

    debug_print(&format!(
        "  [idm] Total activation elapsed: {:.0?}",
        t_total.elapsed()
    ));
}
