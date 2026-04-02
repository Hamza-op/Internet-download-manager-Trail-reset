use winreg::enums::*;
use winreg::RegKey;
use winreg::HKEY;

use crate::debug_print;

// ─────────────────────────────────────────────────────────────
// Registry & Command Helpers
// ─────────────────────────────────────────────────────────────

fn set_reg_dword(root: HKEY, path: &str, name: &str, value: u32) -> bool {
    let key = RegKey::predef(root);
    match key.create_subkey(path) {
        Ok((k, _)) => k.set_value(name, &value).is_ok(),
        Err(_) => false,
    }
}

fn set_reg_str(root: HKEY, path: &str, name: &str, value: &str) -> bool {
    let key = RegKey::predef(root);
    match key.create_subkey(path) {
        Ok((k, _)) => k.set_value(name, &value.to_string()).is_ok(),
        Err(_) => false,
    }
}

fn run_silent(program: &str, args: &[&str]) -> bool {
    crate::hidden_command(program)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_silent_ps(script: &str) -> bool {
    crate::hidden_command("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─────────────────────────────────────────────────────────────
// System Detection Helpers
// ─────────────────────────────────────────────────────────────

/// Returns true if the system drive (C:) is an SSD.
/// Queries via PowerShell Get-PhysicalDisk. Falls back to true (safe — don't harm SSDs).
pub fn is_system_ssd() -> bool {
    let result = crate::hidden_command("powershell")
        .args(&[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$disk = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq ((Get-Partition -DriveLetter C).DiskNumber) }; if ($disk) { $disk.MediaType } else { 'SSD' }",
        ])
        .output();

    match result {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout).trim().to_lowercase();
            // "SSD", "NVMe", or empty/unknown → treat as SSD (safe default)
            !out.contains("hdd") && !out.contains("unspecified") || out.is_empty()
        }
        Err(_) => true, // safe default: assume SSD
    }
}

/// Returns the Windows build number (e.g. 19041 for 20H1, 22000 for Win11).
fn windows_build() -> u32 {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .ok()
        .and_then(|k| k.get_value::<String, _>("CurrentBuildNumber").ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Returns total physical RAM in GB.
fn total_ram_gb() -> u64 {
    let result = crate::hidden_command("powershell")
        .args(&[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB",
        ])
        .output();

    match result {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .trim()
            .split('.') // handle decimal like "15.9"
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0),
        Err(_) => 0,
    }
}

/// Returns system uptime in minutes.
pub fn uptime_minutes() -> u64 {
    // GetTickCount64 in milliseconds, convert to minutes
    #[cfg(target_os = "windows")]
    {
        extern "system" {
            fn GetTickCount64() -> u64;
        }
        let ms = unsafe { GetTickCount64() };
        ms / 60_000
    }
    #[cfg(not(target_os = "windows"))]
    {
        u64::MAX // non-windows: never skip
    }
}

/// Log system context for remote diagnosis.
pub fn log_system_context() {
    let build = windows_build();
    let ram = total_ram_gb();
    let ssd = is_system_ssd();
    debug_print(&format!(
        "[i] System: Windows build {}, {} GB RAM, drive={}",
        build,
        ram,
        if ssd { "SSD" } else { "HDD" }
    ));
}

// ─────────────────────────────────────────────────────────────
// Granular Idempotency — per-task registry flags + schema versioning
// ─────────────────────────────────────────────────────────────

/// Bump this whenever new tweaks are added to existing one-time phases.
/// On mismatch, all completed-task flags are cleared so everything re-runs.
const TASK_SCHEMA_VERSION: &str = "v3";

const TASK_REGISTRY_PATH: &str = r"Software\ZeroIdle\CompletedTasks";

/// Called once at startup. If the stored schema version doesn't match
/// TASK_SCHEMA_VERSION, wipes all per-task flags so new code runs.
pub fn ensure_schema_current() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // Read stored version
    let stored: Option<String> = hkcu
        .open_subkey(TASK_REGISTRY_PATH)
        .ok()
        .and_then(|k| k.get_value("__schema_version").ok());

    if stored.as_deref() == Some(TASK_SCHEMA_VERSION) {
        return; // up-to-date, nothing to do
    }

    // Version mismatch or first run — clear all flags
    debug_print(&format!(
        "[⟳] Task schema {} → {}. Resetting completed-task flags so new optimizations apply.",
        stored.as_deref().unwrap_or("none"),
        TASK_SCHEMA_VERSION
    ));
    let _ = hkcu.delete_subkey_all(TASK_REGISTRY_PATH);

    // Write the new schema version
    if let Ok((key, _)) = hkcu.create_subkey(TASK_REGISTRY_PATH) {
        let _ = key.set_value("__schema_version", &TASK_SCHEMA_VERSION.to_string());
    }
}

pub fn is_task_done(task_id: &str) -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey(TASK_REGISTRY_PATH) {
        if let Ok(1u32) = key.get_value(task_id) {
            return true;
        }
    }
    false
}

pub fn mark_task_done(task_id: &str) {
    set_reg_dword(HKEY_CURRENT_USER, TASK_REGISTRY_PATH, task_id, 1);
    // Re-stamp schema version after each task so partial runs don't lose the version key
    if let Ok((key, _)) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(TASK_REGISTRY_PATH) {
        let _ = key.set_value("__schema_version", &TASK_SCHEMA_VERSION.to_string());
    }
}

/// Check if ALL one-time tasks are already completed (fast-path for quick exit).
pub fn all_onetime_tasks_done() -> bool {
    const TASK_IDS: &[&str] = &["gaming_opt", "system_privacy", "startup_services"];
    TASK_IDS.iter().all(|id| is_task_done(id))
}

// ─────────────────────────────────────────────────────────────
// Migration: honor the old single-flag system
// ─────────────────────────────────────────────────────────────

pub fn migrate_legacy_flag() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    if let Ok(key) = hkcu.open_subkey(r"Software\Optimizer") {
        if let Ok(1u32) = key.get_value("Optimized") {
            debug_print("[⟳] Migrating legacy optimization flag to per-task tracking...");
            mark_task_done("gaming_opt");
            mark_task_done("system_privacy");
            let _ = hkcu.delete_subkey_all(r"Software\Optimizer");
            debug_print("  [✓] Legacy flag migrated.");
        }
    }

    if let Ok(old_key) = hkcu.open_subkey(r"Software\IDMSystemTool\CompletedTasks") {
        debug_print("[⟳] Migrating IDMSystemTool task flags to ZeroIdle...");
        for task_id in &["gaming_opt", "system_privacy", "startup_services"] {
            if let Ok(1u32) = old_key.get_value(*task_id) {
                mark_task_done(task_id);
            }
        }
        let _ = hkcu.delete_subkey_all(r"Software\IDMSystemTool");
        debug_print("  [✓] IDMSystemTool flags migrated to ZeroIdle.");
    }
}

// ─────────────────────────────────────────────────────────────
// Phase: Gaming Optimizations (one-time, task_id = "gaming_opt")
// ─────────────────────────────────────────────────────────────

pub fn optimize_for_gaming() {
    debug_print("");
    debug_print("[⟳] Phase: Gaming Optimizations...");

    let build = windows_build();

    enable_game_mode();
    disable_game_dvr();
    set_ultimate_performance_power_plan();
    disable_usb_selective_suspend();
    disable_pcie_aspm();
    flush_dns();
    set_dns_cloudflare();
    optimize_network();
    optimize_network_extended();
    disable_mouse_acceleration();
    disable_nagles_algorithm();
    disable_xbox_game_bar();
    optimize_gpu(build);

    mark_task_done("gaming_opt");
    debug_print("  [✓] Gaming optimizations applied.");
}

// ─────────────────────────────────────────────────────────────
// Phase: System & Privacy (one-time, task_id = "system_privacy")
// ─────────────────────────────────────────────────────────────

pub fn optimize_system_and_privacy() {
    debug_print("");
    debug_print("[⟳] Phase: System & Privacy...");

    let build = windows_build();

    disable_telemetry();
    disable_sysmain_if_ssd();
    disable_hibernation();
    clear_event_logs();
    disable_start_menu_web_search();
    disable_consumer_features();
    disable_tips_and_suggestions();
    disable_app_launch_tracking();
    disable_transparency_effects();
    disable_lock_screen_tips();
    disable_feedback_notifications();
    disable_cortana(build);
    disable_recall_activity_history(build);
    disable_copilot(build);
    remove_extra_bloatware();
    optimize_disk_io();
    optimize_memory(build);

    mark_task_done("system_privacy");
    debug_print("  [✓] System & Privacy optimizations applied.");
}

// ─────────────────────────────────────────────────────────────
// Phase: Startup & Services (one-time, task_id = "startup_services")
// ─────────────────────────────────────────────────────────────

pub fn optimize_startup_and_services() {
    debug_print("");
    debug_print("[⟳] Phase: Startup & Services Optimization...");

    let is_ssd = is_system_ssd();

    disable_nonessential_services();
    disable_bloatware_startup_entries();
    maybe_disable_scheduled_defrag(is_ssd);
    disable_startup_delay();
    disable_background_apps();
    disable_storage_sense();

    mark_task_done("startup_services");
    debug_print("  [✓] Startup & Services optimizations applied.");
}

// ─────────────────────────────────────────────────────────────
// Phase: Adobe Optimization (always runs — kills active procs)
// ─────────────────────────────────────────────────────────────

pub fn optimize_for_adobe() {
    debug_print("");
    debug_print("[⟳] Phase: Adobe Optimization...");
    kill_adobe_background_processes();
    debug_print("  [✓] Adobe optimizations applied.");
}

// ─────────────────────────────────────────────────────────────
// Phase: Standby Memory Clear (always runs — conditional)
// ─────────────────────────────────────────────────────────────

/// Only clears standby memory if uptime > 10 minutes (non-trivial list build up).
pub fn maybe_clear_standby_memory() {
    if uptime_minutes() < 10 {
        debug_print("    [—] Skipping standby clear — system just booted.");
        return;
    }
    clear_standby_memory();
}

// ═════════════════════════════════════════════════════════════
// Implementation — Gaming
// ═════════════════════════════════════════════════════════════

fn enable_game_mode() {
    if set_reg_dword(HKEY_CURRENT_USER, r"Software\Microsoft\GameBar", "AutoGameModeEnabled", 1) {
        debug_print("    ✓ Game Mode enabled.");
    }
}

fn disable_game_dvr() {
    set_reg_dword(HKEY_CURRENT_USER, r"System\GameConfigStore", "GameDVR_Enabled", 0);
    set_reg_dword(HKEY_CURRENT_USER, r"System\GameConfigStore", "GameDVR_FSEBehaviorMode", 2);
    // Fix: add sibling value that was previously missing (review item #8)
    set_reg_dword(HKEY_CURRENT_USER, r"System\GameConfigStore", "GameDVR_DXGIHonorPowerPolicy", 0);
    set_reg_dword(HKEY_CURRENT_USER, r"System\GameConfigStore", "GameDVR_FSEBehavior", 2);
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\GameDVR", "AllowGameDVR", 0);
    debug_print("    ✓ Game DVR & FSO optimized.");
}

fn set_ultimate_performance_power_plan() {
    let _ = run_silent("powercfg", &["/duplicatescheme", "e9a42b02-d5df-448d-aa00-03f14749eb61"]);
    if run_silent("powercfg", &["/setactive", "e9a42b02-d5df-448d-aa00-03f14749eb61"]) {
        debug_print("    ✓ Power plan: Ultimate Performance.");
    } else if run_silent("powercfg", &["/setactive", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"]) {
        debug_print("    ✓ Power plan: High Performance (Ultimate unavailable).");
    }
}

fn disable_usb_selective_suspend() {
    // Disable USB selective suspend on AC power
    run_silent("powercfg", &[
        "/setacvalueindex", "SCHEME_CURRENT",
        "2a737441-1930-4402-8d77-b2bebba308a3",
        "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
        "0",
    ]);
    run_silent("powercfg", &["/setactive", "SCHEME_CURRENT"]);
    debug_print("    ✓ USB selective suspend disabled.");
}

fn disable_pcie_aspm() {
    // Disable PCI Express Link State Power Management
    run_silent("powercfg", &[
        "/setacvalueindex", "SCHEME_CURRENT",
        "501a4d13-42af-4429-9fd1-a8218c268e20",
        "ee12f906-d277-404b-b6da-e5fa1a576df5",
        "0",
    ]);
    run_silent("powercfg", &["/setactive", "SCHEME_CURRENT"]);
    debug_print("    ✓ PCIe ASPM disabled (eliminates latency spikes).");
}

fn flush_dns() {
    if run_silent("ipconfig", &["/flushdns"]) {
        debug_print("    ✓ DNS cache flushed.");
    }
}

fn set_dns_cloudflare() {
    // Set DNS to Cloudflare primary + Google secondary on all active interfaces
    let ps = r#"
$ErrorActionPreference = 'SilentlyContinue'
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
foreach ($adapter in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ('1.1.1.1','8.8.8.8') -ErrorAction SilentlyContinue
}
"#;
    run_silent_ps(ps);
    debug_print("    ✓ DNS set to Cloudflare (1.1.1.1) + Google (8.8.8.8).");
}

fn optimize_network() {
    // Log individual results instead of discarding them
    let cmds: &[(&str, &[&str])] = &[
        ("netsh", &["int", "tcp", "set", "heuristics", "disabled"]),
        ("netsh", &["int", "tcp", "set", "global", "autotuninglevel=normal"]),
        ("netsh", &["int", "tcp", "set", "global", "ecncapability=disabled"]),
        ("netsh", &["int", "tcp", "set", "global", "rss=enabled"]),
    ];
    let mut ok = 0u32;
    for (prog, args) in cmds {
        if run_silent(prog, args) { ok += 1; }
    }
    debug_print(&format!("    ✓ TCP/IP optimized ({}/{} commands succeeded).", ok, cmds.len()));
}

fn optimize_network_extended() {
    // Disable NetBIOS over TCP/IP (P-node)
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "NodeType", 2);
    // Disable LLMNR
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0);
    // Disable Wi-Fi Sense
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config", "AutoConnectAllowedOEM", 0);
    // Reduce TCP timed-wait delay from 120s to 30s
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TcpTimedWaitDelay", 30);
    // Remove Windows' default 10-packet throttle on non-multimedia traffic
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NetworkThrottlingIndex", 0xFFFFFFFF);
    debug_print("    ✓ Extended network optimizations applied (NetBIOS, LLMNR, throttle).");
}

fn optimize_gpu(build: u32) {
    // Hardware-accelerated GPU scheduling (Win10 2004+ = build 19041)
    if build >= 19041 {
        set_reg_dword(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", 2);
        debug_print("    ✓ Hardware GPU scheduling enabled.");
    }
    // GPU priority for games
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "GPU Priority", 8);
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Priority", 6);
    set_reg_str(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Scheduling Category", "High");
    // Disable display power gating
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power", "FLatMonitorPDCAction", 0);
    debug_print("    ✓ GPU priority and power gating optimized.");
}

fn clear_standby_memory() {
    let ps_script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$priv = [uri].Module.GetType('System.Diagnostics.Process').GetMethods(42) | Where-Object { $_.Name -eq 'SetPrivilege' }
$priv.Invoke($null, @('SeProfileSingleProcessPrivilege', 2))
$type = Add-Type -MemberDefinition '[DllImport("ntdll.dll")] public static extern int NtSetSystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength);' -Name 'Ntdll' -Namespace 'Win32' -PassThru
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
[System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, 0, 4)
$result = $type::NtSetSystemInformation(80, $ptr, 4)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
exit $result
"#;
    let ok = run_silent_ps(ps_script);
    if ok {
        debug_print("    ✓ Cleared Memory Standby List.");
    } else {
        debug_print("    [⚠] Standby memory clear returned non-zero (may need SeProfileSingleProcessPrivilege).");
    }
}

fn disable_mouse_acceleration() {
    if set_reg_str(HKEY_CURRENT_USER, r"Control Panel\Mouse", "MouseSpeed", "0")
        && set_reg_str(HKEY_CURRENT_USER, r"Control Panel\Mouse", "MouseThreshold1", "0")
        && set_reg_str(HKEY_CURRENT_USER, r"Control Panel\Mouse", "MouseThreshold2", "0")
    {
        debug_print("    ✓ Mouse acceleration disabled.");
    }
}

fn disable_nagles_algorithm() {
    let ps_script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$interfaces = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*"
foreach ($interface in $interfaces) {
    Set-ItemProperty -Path $interface.PSPath -Name "TcpAckFrequency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $interface.PSPath -Name "TCPNoDelay" -Value 1 -Type DWord -ErrorAction SilentlyContinue
}
"#;
    run_silent_ps(ps_script);
    debug_print("    ✓ Nagle's algorithm disabled (lower ping).");
}

fn disable_xbox_game_bar() {
    set_reg_dword(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", 0);
    let ps_script = r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-AppxPackage -AllUsers *XboxGamingOverlay* | Remove-AppxPackage -ErrorAction SilentlyContinue
"#;
    run_silent_ps(ps_script);
    debug_print("    ✓ Xbox Game Bar disabled.");
}

// ═════════════════════════════════════════════════════════════
// Implementation — System & Privacy
// ═════════════════════════════════════════════════════════════

fn disable_telemetry() {
    // Telemetry services only — SysMain (Superfetch) handled separately based on disk type
    let telemetry_services = ["DiagTrack", "dmwappushservice"];
    for srv in &telemetry_services {
        let _ = run_silent("sc", &["stop", srv]);
        run_silent("sc", &["config", srv, "start=", "disabled"]);
    }
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0);
    debug_print("    ✓ Windows Telemetry disabled.");
}

/// Disable SysMain (Superfetch) only on SSDs — it's beneficial on HDDs.
fn disable_sysmain_if_ssd() {
    if is_system_ssd() {
        let _ = run_silent("sc", &["stop", "SysMain"]);
        run_silent("sc", &["config", "SysMain", "start=", "disabled"]);
        debug_print("    ✓ SysMain (Superfetch) disabled (SSD detected).");
    } else {
        debug_print("    [—] SysMain kept enabled (HDD detected — Superfetch helps).");
    }
}

fn disable_hibernation() {
    if run_silent("powercfg", &["-h", "off"]) {
        debug_print("    ✓ Hibernation disabled (freed GBs on C:\\).");
    }
}

fn clear_event_logs() {
    let mut cleared = 0u32;
    for log in &["Application", "Security", "Setup", "System"] {
        if run_silent("wevtutil", &["cl", log]) { cleared += 1; }
    }
    debug_print(&format!("    ✓ {} Windows event logs cleared.", cleared));
}

fn disable_start_menu_web_search() {
    set_reg_dword(HKEY_CURRENT_USER, r"SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableSearchBoxSuggestions", 1);
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "DisableWebSearch", 1);
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "ConnectedSearchUseWeb", 0);
    debug_print("    ✓ Start menu web search disabled.");
}

fn disable_consumer_features() {
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", 1);
    debug_print("    ✓ Consumer features disabled (no auto-install bloatware).");
}

fn disable_tips_and_suggestions() {
    let path = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
    let keys = [
        ("SubscribedContent-338389Enabled", 0u32),
        ("SubscribedContent-310093Enabled", 0),
        ("SubscribedContent-338388Enabled", 0),
        ("SubscribedContent-338393Enabled", 0),
        ("SubscribedContent-353694Enabled", 0),
        ("SubscribedContent-353696Enabled", 0),
        ("SoftLandingEnabled", 0),
        ("SystemPaneSuggestionsEnabled", 0),
    ];
    for (name, val) in &keys {
        set_reg_dword(HKEY_CURRENT_USER, path, name, *val);
    }
    debug_print("    ✓ Tips, suggestions & ads disabled.");
}

fn disable_app_launch_tracking() {
    set_reg_dword(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackProgs", 0);
    debug_print("    ✓ App launch tracking disabled.");
}

fn disable_transparency_effects() {
    set_reg_dword(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency", 0);
    debug_print("    ✓ Transparency effects disabled.");
}

fn disable_lock_screen_tips() {
    let path = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";
    set_reg_dword(HKEY_CURRENT_USER, path, "RotatingLockScreenOverlayEnabled", 0);
    set_reg_dword(HKEY_CURRENT_USER, path, "RotatingLockScreenEnabled", 0);
    debug_print("    ✓ Lock screen tips & spotlight disabled.");
}

fn disable_feedback_notifications() {
    set_reg_dword(HKEY_CURRENT_USER, r"Software\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", 0);
    debug_print("    ✓ Feedback notifications disabled.");
}

fn disable_cortana(build: u32) {
    // Cortana policy key (effective on all supported builds)
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana", 0);
    // Also remove Cortana AppX on Win10 (build < 22000) — on Win11 it's a different package
    if build < 22000 {
        let ps = r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-AppxPackage -AllUsers *Microsoft.549981C3F5F10* | Remove-AppxPackage -ErrorAction SilentlyContinue
"#;
        run_silent_ps(ps);
    }
    debug_print("    ✓ Cortana disabled.");
}

fn disable_recall_activity_history(build: u32) {
    // Recall / Activity History — Win10+
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0);
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0);
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0);
    // Windows Recall AI (Win11 24H2+ = build 26100)
    if build >= 26100 {
        set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", 1);
        debug_print("    ✓ Windows Recall (AI) disabled.");
    }
    debug_print("    ✓ Activity history tracking disabled.");
}

fn disable_copilot(build: u32) {
    // Copilot sidebar — Win11 23H2+ (build 22631)
    if build >= 22631 {
        set_reg_dword(HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", 1);
        debug_print("    ✓ Windows Copilot sidebar disabled.");
    }
}

fn remove_extra_bloatware() {
    let ps = r#"
$ErrorActionPreference = 'SilentlyContinue'
$packages = @(
    'Microsoft.BingWeather',
    'Microsoft.GetHelp',
    'Microsoft.People',
    'Microsoft.Todos',
    'Clipchamp.Clipchamp',
    'Microsoft.MicrosoftSolitaireCollection',
    'Microsoft.ZuneMusic',
    'Microsoft.ZuneVideo',
    'Microsoft.MixedReality.Portal'
)
foreach ($pkg in $packages) {
    Get-AppxPackage -AllUsers *$pkg* | Remove-AppxPackage -ErrorAction SilentlyContinue
}
"#;
    run_silent_ps(ps);
    debug_print("    ✓ Extra UWP bloatware removed.");
}

fn optimize_disk_io() {
    // Disable NTFS Last Access Time updates (significant on HDDs, measurable on SSDs)
    run_silent("fsutil", &["behavior", "set", "DisableLastAccess", "1"]);
    // Disable 8.3 short name creation (legacy DOS filename overhead)
    run_silent("fsutil", &["behavior", "set", "Disable8dot3", "1"]);
    // Increase NTFS memory usage for metadata caching
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem", "NtfsMemoryUsage", 2);
    debug_print("    ✓ NTFS I/O optimizations applied (last-access, 8.3, memory).");
}

fn optimize_memory(build: u32) {
    // Large system cache (more RAM for file system cache)
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "LargeSystemCache", 1);

    // Disable memory compression on high-RAM systems (≥16 GB)
    let ram = total_ram_gb();
    if ram >= 16 {
        run_silent_ps("Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue");
        debug_print(&format!("    ✓ Memory compression disabled ({} GB RAM detected).", ram));
    }

    // Disable page file only on high-RAM systems (≥ 32 GB) to be safe
    if ram >= 32 {
        run_silent("wmic", &[
            "computersystem", "where",
            &format!("name='{}'", hostname()),
            "set", "AutomaticManagedPagefile=False",
        ]);
        debug_print("    ✓ Page file disabled (≥32 GB RAM).");
    }

    let _ = build; // reserved for version-specific memory tweaks
    debug_print(&format!("    ✓ Memory management optimized ({} GB RAM).", ram));
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "%COMPUTERNAME%".into())
}

// ═════════════════════════════════════════════════════════════
// Implementation — Startup & Services
// ═════════════════════════════════════════════════════════════

fn disable_nonessential_services() {
    let services: &[(&str, &str)] = &[
        ("WSearch", "Windows Search Indexer"),
        ("WerSvc", "Windows Error Reporting"),
        ("MapsBroker", "Downloaded Maps Manager"),
        ("lfsvc", "Geolocation Service"),
        ("RetailDemo", "Retail Demo Service"),
        ("wisvc", "Windows Insider Service"),
        ("WMPNetworkSvc", "Windows Media Player Sharing"),
        ("WpcMonSvc", "Parental Controls"),
        ("SEMgrSvc", "Payments & NFC Manager"),
        ("PhoneSvc", "Phone Service"),
        ("Fax", "Fax Service"),
        ("XblAuthManager", "Xbox Live Auth Manager"),
        ("XblGameSave", "Xbox Live Game Save"),
        ("XboxNetApiSvc", "Xbox Live Networking"),
        ("XboxGipSvc", "Xbox Accessory Management"),
    ];

    let mut stopped = 0u32;
    for (svc, _desc) in services {
        run_silent("sc", &["stop", svc]);
        if run_silent("sc", &["config", svc, "start=", "disabled"]) {
            stopped += 1;
        }
    }
    debug_print(&format!("    ✓ Disabled {} non-essential services.", stopped));
}

fn disable_bloatware_startup_entries() {
    let startup_entries: &[&str] = &[
        "OneDrive", "OneDriveSetup", "Cortana",
        "SecurityHealth", "iTunes Helper", "Spotify", "Steam",
        "Discord", "EpicGamesLauncher", "GoogleUpdate",
        "Teams", "Skype",
    ];

    let mut removed = 0u32;
    let run_key = r"Software\Microsoft\Windows\CurrentVersion\Run";

    for root in &[HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let target_path = if *root == HKEY_LOCAL_MACHINE {
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        } else {
            run_key
        };
        if let Ok(key) = RegKey::predef(*root).open_subkey_with_flags(target_path, KEY_READ | KEY_WRITE) {
            for entry in startup_entries {
                if key.get_raw_value(*entry).is_ok() {
                    if key.delete_value(*entry).is_ok() {
                        debug_print(&format!("    ✓ Removed startup: {}", entry));
                        removed += 1;
                    }
                }
            }
        }
    }
    debug_print(&format!("    ✓ {} bloatware startup entries removed.", removed));
}

/// Only disables scheduled defrag on HDDs. On SSDs, Windows uses this task for TRIM — critical.
fn maybe_disable_scheduled_defrag(is_ssd: bool) {
    if is_ssd {
        debug_print("    [—] Scheduled defrag kept enabled (SSD detected — provides TRIM).");
        return;
    }
    run_silent("schtasks", &[
        "/Change", "/TN",
        r"\Microsoft\Windows\Defrag\ScheduledDefrag",
        "/DISABLE",
    ]);
    debug_print("    ✓ Scheduled defragmentation disabled (HDD detected).");
}

fn disable_startup_delay() {
    set_reg_dword(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize", "StartupDelayInMSec", 0);
    debug_print("    ✓ Startup delay removed.");
}

fn disable_background_apps() {
    set_reg_dword(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications", "GlobalUserDisabled", 1);
    set_reg_dword(HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy", "LetAppsRunInBackground", 2);
    debug_print("    ✓ Background apps disabled globally.");
}

fn disable_storage_sense() {
    set_reg_dword(HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy", "01", 0);
    debug_print("    ✓ Storage Sense disabled (prevents silent file deletion).");
}

// ═════════════════════════════════════════════════════════════
// Implementation — Adobe (always runs)
// ═════════════════════════════════════════════════════════════

fn kill_adobe_background_processes() {
    let procs = [
        "AdobeIPCBroker.exe", "CCLibrary.exe", "CCXProcess.exe",
        "CoreSync.exe", "Adobe Desktop Service.exe", "AdobeUpdateService.exe",
        "AGMService.exe", "AGSService.exe", "ArmUI.exe",
    ];
    let mut killed = 0u32;
    for proc in &procs {
        if run_silent("taskkill", &["/f", "/im", proc]) { killed += 1; }
    }
    debug_print(&format!("    ✓ {} Adobe background processes terminated.", killed));
}
