//! IDM (Internet Download Manager) registry operations.
//! Full port of the IDM activation.bat reset logic.

use winreg::enums::*;
use winreg::RegKey;

use crate::debug_print;

// ─────────────────────────────────────────────────────────────
//  Architecture detection
// ─────────────────────────────────────────────────────────────

fn get_arch() -> &'static str {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"Hardware\Description\System\CentralProcessor\0") {
        if let Ok(id) = key.get_value::<String, _>("Identifier") {
            if id.to_lowercase().contains("x86") {
                return "x86";
            }
        }
    }
    "x64"
}

fn get_clsid_paths() -> Vec<&'static str> {
    if get_arch() == "x86" {
        vec![r"Software\Classes\CLSID"]
    } else {
        vec![
            r"Software\Classes\CLSID",
            r"Software\Classes\Wow6432Node\CLSID",
        ]
    }
}

fn get_hklm_idm_path() -> String {
    if get_arch() == "x86" {
        r"SOFTWARE\Internet Download Manager".to_string()
    } else {
        r"SOFTWARE\Wow6432Node\Internet Download Manager".to_string()
    }
}

// ─────────────────────────────────────────────────────────────
//  Reset IDM Activation / Trial
// ─────────────────────────────────────────────────────────────

pub fn reset_activation() {
    // Step 1: Unconditionally kill IDM before messing with its registry keys
    kill_idm();

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey(r"Software\DownloadManager") {
        if key.get_value::<String, _>("Serial").is_ok() {
            debug_print("  [i] Serial key found in registry.");
        }
    }

    // Step 2: Delete settings.bak (bat line 293)
    delete_settings_backup();

    // Step 3: Delete queue — individual values + HKLM key (bat :delete_queue, lines 492-514)
    debug_print("  [⟳] Deleting activation registry values...");
    delete_queue();

    // Step 4: Scan CLSID and delete IDM tracking keys WITH permission takeover (bat :action with take_permission=1)
    debug_print("  [⟳] Scanning and deleting CLSID tracking keys...");
    delete_clsid_keys(true); // true = take_permission on failure

    // Step 5: Clean and lockdown IDM hidden folders in INetCache
    clean_and_lock_inetcache_idm();

    // Step 6: Re-add the AdvIntDriverEnabled2 key (bat :add_key, lines 518-538)
    debug_print("  [⟳] Adding driver registry key...");
    add_driver_key();

    debug_print("  [✓] IDM Activation / Trial reset complete.");
}

// ─────────────────────────────────────────────────────────────
//  Fix IDM Popup  (port of Fix-IDM-Popup.ps1)
// ─────────────────────────────────────────────────────────────

pub fn fix_popup() {
    debug_print("[⟳] Applying permanent IDM popup fix...");
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // 1. Registry Date Manipulation (Trick IDM into thinking it checked far in the future)
    match hkcu.open_subkey_with_flags(r"Software\DownloadManager", KEY_READ | KEY_WRITE) {
        Ok(key) => {
            let _ = key.set_value("LastCheckQU", &0x99999999u32);
            let _ = key.set_value("LstCheck", &"01/01/99");
            let _ = key.set_value("CheckUpdtVM", &0u32);
            debug_print("  [✓] Registry check dates set to the year 2099.");
        }
        Err(_) => debug_print("  [✗] IDM registry path not found."),
    }

    // 2. Neutralize IDMIntegrator64.exe
    neutralize_integrator();
}

pub fn neutralize_integrator() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let idm_path = match hkcu.open_subkey(r"Software\DownloadManager") {
        Ok(key) => key
            .get_value::<String, _>("ExePath")
            .map(|p| {
                std::path::Path::new(&p)
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new(""))
                    .to_path_buf()
            })
            .unwrap_or_default(),
        Err(_) => return,
    };

    if idm_path.as_os_str().is_empty() {
        return;
    }

    let integrator_path = idm_path.join("IDMIntegrator64.exe");
    if integrator_path.exists() {
        // Check size
        if let Ok(metadata) = std::fs::metadata(&integrator_path) {
            if metadata.len() == 0 {
                debug_print("  [✓] IDMIntegrator64.exe is already neutralized.");
                return;
            }
        }

        debug_print(&format!("  [⟳] Neutralizing: {}", integrator_path.display()));

        kill_idm();

        let backup_path = idm_path.join("IDMIntegrator64.exe.bak");
        let integrator_str = integrator_path.to_string_lossy();

        // 1. Take ownership and grant full access via cmd to avoid access denied
        let _ = crate::hidden_command("takeown")
            .args(["/F", &integrator_str])
            .output();
        let _ = crate::hidden_command("icacls")
            .args([&integrator_str, "/grant", "administrators:F", "/Q"])
            .output();

        // 2. Manage backup via Rust native for reliability
        if backup_path.exists() {
            let _ = std::fs::remove_file(&backup_path);
        }

        // 3. Rename current to backup
        match std::fs::rename(&integrator_path, &backup_path) {
            Ok(_) => debug_print("  [✓] IDMIntegrator64.exe renamed to .bak"),
            Err(e) => {
                debug_print(&format!("  [✗] Failed to rename: {}", e));
                // Force copy and delete
                if std::fs::copy(&integrator_path, &backup_path).is_ok() {
                    let _ = std::fs::remove_file(&integrator_path);
                }
            }
        }

        // 4. Create empty file and lock it
        match std::fs::write(&integrator_path, "") {
            Ok(_) => {
                let _ = crate::hidden_command("icacls")
                    .args([&integrator_str, "/deny", "Everyone:(W)", "/Q"])
                    .output();
                debug_print("  [✓] IDMIntegrator64.exe neutralized/replaced.");
            }
            Err(e) => debug_print(&format!("  [✗] Failed to write 0-byte file: {}", e)),
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  Helpers — mirrors exact .bat logic
// ─────────────────────────────────────────────────────────────

fn kill_idm() {
    let processes = ["idman.exe", "IDMIntegrator64.exe"];
    let mut killed_any = false;

    for proc in processes {
        let output = crate::hidden_command("tasklist")
            .args(["/fi", &format!("imagename eq {}", proc)])
            .output();

        let is_running = match &output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.to_lowercase().contains(&proc.to_lowercase())
            }
            Err(_) => false,
        };

        if is_running {
            debug_print(&format!("  [i] {} is running, terminating...", proc));
            let _ = crate::hidden_command("taskkill")
                .args(["/f", "/im", proc])
                .output();
            killed_any = true;
        }
    }

    if killed_any {
        std::thread::sleep(std::time::Duration::from_millis(800));
    }
}

fn delete_settings_backup() {
    if let Ok(appdata) = std::env::var("APPDATA") {
        let backup_path = format!("{}\\DMCache\\settings.bak", appdata);
        if std::path::Path::new(&backup_path).exists() {
            match std::fs::remove_file(&backup_path) {
                Ok(_) => debug_print("  [✓] Deleted settings.bak"),
                Err(e) => debug_print(&format!("  [✗] Failed to delete settings.bak: {}", e)),
            }
        }
    }
}

/// Mirrors :delete_queue in the bat file (lines 492-514).
/// Deletes individual HKCU\Software\DownloadManager values and the HKLM IDM key.
fn delete_queue() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    if let Ok(key) = hkcu.open_subkey_with_flags(r"Software\DownloadManager", KEY_READ | KEY_WRITE) {
        [
            "FName",
            "LName",
            "Email",
            "Serial",
            "scansk",
            "tvfrdt",
            "radxcnt",
            "LstCheck",
            "ptrk_scdt",
            "LastCheckQU",
        ]
        .iter()
        .for_each(|val| {
            match key.delete_value(val) {
                Ok(_) => debug_print(&format!(
                    "    Deleted — HKCU\\Software\\DownloadManager\\{}",
                    val
                )),
                Err(_) => {} // value didn't exist — fine
            }
        });
    }

    // Delete HKLM IDM key (bat line 509)
    let hklm_path = get_hklm_idm_path();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.delete_subkey_all(&hklm_path) {
        Ok(_) => debug_print(&format!("    Deleted — HKLM\\{}", hklm_path)),
        Err(_) => {} // didn't exist
    }

    // Extra methods for deeper cleanups
    let vs_machine = r"Software\Classes\VirtualStore\MACHINE\SOFTWARE\Internet Download Manager";
    match hkcu.delete_subkey_all(vs_machine) {
        Ok(_) => debug_print(&format!("    Deleted — HKCU\\{}", vs_machine)),
        Err(_) => {}
    }

    let vs_wow6432 =
        r"Software\Classes\VirtualStore\MACHINE\SOFTWARE\Wow6432Node\Internet Download Manager";
    match hkcu.delete_subkey_all(vs_wow6432) {
        Ok(_) => debug_print(&format!("    Deleted — HKCU\\{}", vs_wow6432)),
        Err(_) => {}
    }
}

/// Re-create the AdvIntDriverEnabled2 value (bat :add_key, lines 518-538).
fn add_driver_key() {
    let hklm_path = get_hklm_idm_path();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    match hklm.create_subkey(&hklm_path) {
        Ok((key, _)) => match key.set_value("AdvIntDriverEnabled2", &1u32) {
            Ok(_) => debug_print(&format!(
                "    Added — HKLM\\{}\\AdvIntDriverEnabled2 = 1",
                hklm_path
            )),
            Err(e) => debug_print(&format!(
                "    [✗] Failed to set AdvIntDriverEnabled2: {}",
                e
            )),
        },
        Err(e) => debug_print(&format!("    [✗] Failed to create {}: {}", hklm_path, e)),
    }
}

// ─────────────────────────────────────────────────────────────
//  CLSID scanning  (bat :action → :scan_key → :delete_key)
// ─────────────────────────────────────────────────────────────

/// Enumerate CLSID, identify IDM tracking keys, and delete them.
fn delete_clsid_keys(take_permission: bool) {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    get_clsid_paths().iter().for_each(|clsid_path| {
        debug_print(&format!("    [⟳] Scanning CLSID path: {}...", clsid_path));
        let clsid_key = match hkcu.open_subkey(clsid_path) {
            Ok(k) => k,
            Err(_) => {
                debug_print("    [i] CLSID path not found, skipping.");
                return;
            }
        };

        // Collect names using iterator chain — no explicit for-loop
        let keys_to_delete: Vec<String> = clsid_key
            .enum_keys()
            .filter_map(|r| r.ok())
            .filter(|name| is_guid_format(name) && is_idm_clsid_key(&clsid_key, name))
            .collect();

        if keys_to_delete.is_empty() {
            debug_print("    [i] No IDM CLSID tracking keys found in this path.");
            return;
        }

        debug_print(&format!(
            "    [i] Found {} IDM tracking key(s).",
            keys_to_delete.len()
        ));

        let clsid_write = hkcu.open_subkey_with_flags(clsid_path, KEY_WRITE).ok();

        keys_to_delete
            .iter()
            .for_each(|key_name| {
                let mut deleted = false;
                if let Some(ref cw) = clsid_write {
                    deleted = cw.delete_subkey_all(key_name).is_ok();
                }

                if deleted {
                    debug_print(&format!("    Deleted — {}", key_name));
                } else if take_permission {
                    let full_path = format!("HKCU\\{}\\{}", clsid_path, key_name);
                    debug_print(&format!("    [⟳] Taking ownership of {}...", key_name));
                    take_ownership_and_delete(&full_path);
                } else {
                    debug_print(&format!("    [✗] Failed — {}", key_name));
                }
            });
    });
}

/// GUID format check: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
fn is_guid_format(name: &str) -> bool {
    name.starts_with('{') && name.ends_with('}') && name.contains('-')
}

/// Determine if a CLSID subkey is an IDM tracking key.
/// This mirrors the bat :scan_key logic (lines 562-591).
fn is_idm_clsid_key(parent: &RegKey, name: &str) -> bool {
    let subkey = match parent.open_subkey(name) {
        Ok(k) => k,
        Err(e) => return e.raw_os_error() == Some(5), // ERROR_ACCESS_DENIED commonly implies IDM blocked access
    };

    // bat line 564: skip if has LocalServer32 / InProcServer32 / InProcHandler32
    let has_server_subkey = ["LocalServer32", "InProcServer32", "InProcHandler32"]
        .iter()
        .any(|sub| subkey.open_subkey(sub).is_ok());
    if has_server_subkey {
        return false;
    }

    // bat line 566-569: if key has no subkeys with "H" → match
    let sub_names: Vec<String> = subkey.enum_keys().filter_map(|r| r.ok()).collect();
    let has_h_subkey = sub_names.iter().any(|s| s.contains('H') || s.contains('h'));
    if sub_names.is_empty() && subkey.enum_values().count() == 0 {
        return true;
    }
    if !has_h_subkey && !sub_names.is_empty() {
        return true;
    }

    // bat line 571-574: default value is purely numeric → match
    if let Ok(default_val) = subkey.get_value::<String, _>("") {
        let trimmed = default_val.trim();
        if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
        // bat line 586-589: default value contains "+" → match
        if trimmed.contains('+') {
            return true;
        }
    }

    // bat line 576-579: Version subkey with numeric-only default → match
    if let Ok(ver_key) = subkey.open_subkey("Version") {
        if let Ok(ver_val) = ver_key.get_value::<String, _>("") {
            if !ver_val.trim().is_empty() && ver_val.trim().chars().all(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }

    // bat line 581-584: subkey names contain MData, Model, scansk, or Therad → match
    let patterns = ["mdata", "model", "scansk", "therad"];
    sub_names.iter().any(|sub_name| {
        let lower = sub_name.to_lowercase();
        patterns.iter().any(|p| lower.contains(p))
    })
}

/// Take ownership, reset ACL, and delete a registry key via PowerShell.
fn take_ownership_and_delete(reg_path: &str) {
    let ps_script = format!(
        r#"
$ErrorActionPreference = 'Stop'
try {{
    # Enable privileges
    $d = [uri].Module.GetType('System.Diagnostics.Process').GetMethods(42) | Where-Object {{ $_.Name -eq 'SetPrivilege' }}
    @('SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege') | ForEach-Object {{
        $d.Invoke($null, @("$_", 2))
    }}

    $regPath = '{path}' -replace '^HKCU\\\\', 'HKCU:\\'
    $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

    # Take ownership
    $acl = Get-Acl $regPath
    $acl.SetOwner($owner)
    Set-Acl $regPath $acl

    # Grant ourselves FullControl
    $acl = Get-Acl $regPath
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($owner, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl $regPath $acl

    # Now delete
    Remove-Item -Path $regPath -Recurse -Force
    exit 0
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}}
"#,
        path = reg_path
    );

    let output = crate::hidden_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            debug_print(&format!("    Deleted (with ownership) — {}", reg_path));
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            debug_print(&format!(
                "    [✗] Failed — {} : {}",
                reg_path,
                stderr.trim()
            ));
        }
        Err(e) => {
            debug_print(&format!("    [✗] PowerShell error — {}: {}", reg_path, e));
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  INetCache IDM Hidden Files Lockdown
// ─────────────────────────────────────────────────────────────

fn clean_and_lock_inetcache_idm() {
    let localappdata = match std::env::var("LOCALAPPDATA") {
        Ok(v) => v,
        Err(_) => return,
    };
    
    let inetcache = std::path::PathBuf::from(localappdata).join(r"Microsoft\Windows\INetCache");
    if !inetcache.exists() { return; }

    debug_print("  [⟳] Scanning and wiping INetCache...");

    if let Ok(entries) = std::fs::read_dir(&inetcache) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
            
            // Skip desktop.ini to maintain basic Windows folder aesthetics if present
            if name == "desktop.ini" {
                continue;
            }

            if path.is_dir() {
                take_ownership_and_delete_fs(&path);
                
                // Recreate it as an empty folder and lock it down
                let _ = std::fs::create_dir_all(&path);
                lockdown_folder(&path);
                debug_print(&format!("    [✓] Wiped and locked down folder: {}", name));
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

fn take_ownership_and_delete_fs(path: &std::path::Path) {
    let path_str = path.to_string_lossy();
    
    let _ = crate::hidden_command("takeown")
        .args(["/F", &path_str, "/R", "/D", "Y"])
        .output();
        
    let _ = crate::hidden_command("icacls")
        .args([&path_str, "/grant", "administrators:F", "/T", "/C", "/Q"])
        .output();
        
    let _ = crate::hidden_command("cmd")
        .args(["/c", "rmdir", "/s", "/q", &path_str])
        .output();
}

fn lockdown_folder(path: &std::path::Path) {
    let path_str = path.to_string_lossy();
    let _ = crate::hidden_command("icacls")
        .args([&path_str, "/deny", "Everyone:(OI)(CI)(W)", "/Q"])
        .output();
}
