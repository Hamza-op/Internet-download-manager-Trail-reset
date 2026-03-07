//! Startup registration module.
//! Uses Task Scheduler with HIGHEST privileges so admin is only requested once.

use std::fs;
use std::path::PathBuf;


use crate::debug_print;

const TASK_NAME: &str = "IDMSystemTool";
const EXE_NAME: &str = "idm-system-tool.exe";

/// Get the persistent path where the executable should live.
fn get_persistent_path() -> Option<PathBuf> {
    dirs::data_dir().map(|mut p| {
        p.push("IDMSystemTool");
        // Ensure the directory exists
        let _ = fs::create_dir_all(&p);
        p.push(EXE_NAME);
        p
    })
}

/// Check if the startup task already exists and points to the correct path.
pub fn is_startup_enabled(target_path: &str) -> bool {
    // Normalization for comparison (schtasks might return double quotes or different casing)
    let target_norm = target_path.to_lowercase().replace("\"", "");

    let output = crate::hidden_command("schtasks")
        .args(["/Query", "/TN", TASK_NAME, "/FO", "LIST", "/V"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_lowercase();
            // Check if any line in the task's Verbose output contains our target path
            stdout.contains(&target_norm)
        }
        _ => false,
    }
}

/// Register the startup task if it doesn't already exist or points to the wrong path.
pub fn ensure_startup_registered() {
    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            debug_print(&format!("[✗] Cannot resolve exe path: {}", e));
            return;
        }
    };

    let target_exe = match get_persistent_path() {
        Some(p) => p,
        None => {
            debug_print("[✗] Cannot resolve AppData path for persistence.");
            return;
        }
    };

    let target_str = target_exe.to_string_lossy().to_string();

    // 1. If we are ALREADY running from the persistent location, just check the task and exit
    if current_exe == target_exe {
        if !is_startup_enabled(&target_str) {
            debug_print("[⟳] Running from persistent path but task missing. Re-registering...");
            let _ = create_scheduled_task(&target_str);
        }
        return;
    }

    // 2. Check if the file already exists in AppData
    if !target_exe.exists() {
        debug_print(&format!(
            "[⟳] Initial setup: Copying to persistent location: {}",
            target_str
        ));
        if let Err(e) = fs::copy(&current_exe, &target_exe) {
            debug_print(&format!("[✗] Failed to copy executable: {}", e));
            // If copy fails, we'll try to register the CURRENT path as a fallback
            let current_str = current_exe.to_string_lossy().to_string();
            if !is_startup_enabled(&current_str) {
                let _ = create_scheduled_task(&current_str);
            }
            return;
        }
    } else {
        debug_print("[✓] Persistent executable already exists in AppData.");
    }

    // 3. Ensure the task is correctly pointed to the persistent location
    if is_startup_enabled(&target_str) {
        debug_print("[✓] Startup task already registered and correctly configured.");
    } else {
        debug_print("[⟳] Registering startup task to persistent location...");
        match create_scheduled_task(&target_str) {
            Ok(_) => debug_print("[✓] Startup task registered successfully."),
            Err(e) => {
                debug_print(&format!("[✗] Task Scheduler failed: {}", e));
                register_startup_registry(&target_str);
            }
        }
    }
}

/// Create a scheduled task that runs at logon with highest privileges.
fn create_scheduled_task(exe_path: &str) -> Result<(), String> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>IDM System Tool — Auto maintenance on startup</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{}"</Command>
    </Exec>
  </Actions>
</Task>"#,
        exe_path
    );

    let temp_dir = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string());
    let xml_path = format!("{}\\{}.xml", temp_dir, TASK_NAME);

    // Write as UTF-16 LE with BOM (required by schtasks /XML)
    use std::io::Write;
    let mut file = std::fs::File::create(&xml_path).map_err(|e| e.to_string())?;
    file.write_all(&[0xFF, 0xFE]).map_err(|e| e.to_string())?;
    for code_unit in xml.encode_utf16() {
        file.write_all(&code_unit.to_le_bytes())
            .map_err(|e| e.to_string())?;
    }
    drop(file);

    let output = crate::hidden_command("schtasks")
        .args(["/Create", "/TN", TASK_NAME, "/XML", &xml_path, "/F"])
        .output()
        .map_err(|e| format!("schtasks exec failed: {}", e))?;

    let _ = std::fs::remove_file(&xml_path);

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(stderr.trim().to_string())
    }
}

/// Fallback: HKCU Run key (no admin on subsequent runs though).
fn register_startup_registry(exe_path: &str) {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_WRITE) {
        Ok(key) => match key.set_value(TASK_NAME, &format!("\"{}\"", exe_path)) {
            Ok(_) => debug_print("[✓] Added to registry Run key."),
            Err(e) => debug_print(&format!("[✗] Registry set failed: {}", e)),
        },
        Err(e) => debug_print(&format!("[✗] Cannot open Run key: {}", e)),
    }
}
