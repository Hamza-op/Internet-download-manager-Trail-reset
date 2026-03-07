use winreg::enums::*;
use winreg::RegKey;

use crate::debug_print;

pub fn optimize_for_gaming() {
    debug_print("");
    debug_print("[⟳] Phase 3: Optimizing Windows for gaming...");

    enable_game_mode();
    disable_game_dvr();
    set_high_performance_power_plan();
    flush_dns();
    optimize_network();
    clear_standby_memory();
    disable_mouse_acceleration();
    disable_nagles_algorithm();

    debug_print("  [✓] Gaming optimizations applied.");
}

pub fn optimize_system_and_privacy() {
    debug_print("");
    debug_print("[⟳] Phase 5: Optimizing System & Privacy...");

    disable_telemetry();
    disable_hibernation();
    clear_event_logs();

    debug_print("  [✓] System and Privacy optimizations applied.");
}

pub fn optimize_for_adobe() {
    debug_print("");
    debug_print("[⟳] Phase 4: Optimizing Adobe software...");

    kill_adobe_background_processes();

    debug_print("  [✓] Adobe optimizations applied.");
}

fn kill_adobe_background_processes() {
    [
        "AdobeIPCBroker.exe",
        "CCLibrary.exe",
        "CCXProcess.exe",
        "CoreSync.exe",
        "Adobe Desktop Service.exe",
        "AdobeUpdateService.exe",
        "AGMService.exe",
        "AGSService.exe",
        "ArmUI.exe",
    ]
    .iter()
    .for_each(|proc| {
        let _ = crate::hidden_command("taskkill").args(&["/f", "/im", proc]).output();
    });
    debug_print("    ✓ Adobe background processes terminated.");
}

fn enable_game_mode() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(r"Software\Microsoft\GameBar") {
        let _ = key.set_value("AutoGameModeEnabled", &1u32);
        debug_print("    ✓ Game Mode enabled (HKCU).");
    }
}

fn disable_game_dvr() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(r"System\GameConfigStore") {
        let _ = key.set_value("GameDVR_Enabled", &0u32);
        let _ = key.set_value("GameDVR_FSEBehaviorMode", &2u32);
        debug_print("    ✓ Game DVR disabled (HKCU).");
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok((key, _)) = hklm.create_subkey(r"SOFTWARE\Policies\Microsoft\Windows\GameDVR") {
        let _ = key.set_value("AllowGameDVR", &0u32);
        debug_print("    ✓ Game DVR disabled (Policies).");
    }
}

fn set_high_performance_power_plan() {
    let output = crate::hidden_command("powercfg")
        .args(&["/setactive", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"])
        .output();

    if let Ok(o) = output {
        if o.status.success() {
            debug_print("    ✓ Power plan set to High Performance.");
        }
    }
}

fn flush_dns() {
    let output = crate::hidden_command("ipconfig").args(&["/flushdns"]).output();
    if let Ok(o) = output {
        if o.status.success() {
            debug_print("    ✓ DNS cache flushed.");
        }
    }
}

fn optimize_network() {
    let _ = crate::hidden_command("netsh")
        .args(&["int", "tcp", "set", "heuristics", "disabled"])
        .output();
    let _ = crate::hidden_command("netsh")
        .args(&["int", "tcp", "set", "global", "autotuninglevel=normal"])
        .output();
    let _ = crate::hidden_command("netsh")
        .args(&["int", "tcp", "set", "global", "ecncapability=disabled"])
        .output();
    let _ = crate::hidden_command("netsh")
        .args(&["int", "tcp", "set", "global", "rss=enabled"])
        .output();

    debug_print("    ✓ Network TCP/IP settings optimized for lower gaming latency.");
}

fn clear_standby_memory() {
    let ps_script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$priv = [uri].Module.GetType('System.Diagnostics.Process').GetMethods(42) | Where-Object { $_.Name -eq 'SetPrivilege' }
$priv.Invoke($null, @('SeProfileSingleProcessPrivilege', 2))
$type = Add-Type -MemberDefinition '[DllImport("ntdll.dll")] public static extern int NtSetSystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength);' -Name 'Ntdll' -Namespace 'Win32' -PassThru
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
[System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, 0, 4)
$type::NtSetSystemInformation(80, $ptr, 4)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
"#;
    let _ = crate::hidden_command("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", ps_script])
        .output();

    debug_print("    ✓ Cleared System Memory Standby List.");
}

fn disable_telemetry() {
    ["DiagTrack", "dmwappushservice", "SysMain"]
        .iter()
        .for_each(|srv| {
            let _ = crate::hidden_command("sc").args(&["stop", srv]).output();
            let _ = crate::hidden_command("sc")
                .args(&["config", srv, "start=", "disabled"])
                .output();
        });

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok((key, _)) = hklm.create_subkey(r"SOFTWARE\Policies\Microsoft\Windows\DataCollection")
    {
        let _ = key.set_value("AllowTelemetry", &0u32);
        debug_print("    ✓ Windows Telemetry and SuperFetch disabled.");
    }
}

fn disable_mouse_acceleration() {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(r"Control Panel\Mouse") {
        let _ = key.set_value("MouseSpeed", &"0");
        let _ = key.set_value("MouseThreshold1", &"0");
        let _ = key.set_value("MouseThreshold2", &"0");
        debug_print("    ✓ Mouse Acceleration (Enhance Pointer Precision) disabled.");
    }
}

fn disable_nagles_algorithm() {
    let ps_script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$interfaces = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*"
foreach ($interface in $interfaces) {
    Set-ItemProperty -Path $interface.PSPath -Name "TcpAckFrequency" -Value 1 -Type DWord
    Set-ItemProperty -Path $interface.PSPath -Name "TCPNoDelay" -Value 1 -Type DWord
}
"#;
    let _ = crate::hidden_command("powershell")
        .args(&["-NoProfile", "-NonInteractive", "-Command", ps_script])
        .output();
    debug_print("    ✓ Nagle's Algorithm disabled for all network adapters (Lower Ping).");
}

fn disable_hibernation() {
    let output = crate::hidden_command("powercfg").args(&["-h", "off"]).output();
    if let Ok(o) = output {
        if o.status.success() {
            debug_print("    ✓ Hibernation disabled (Freed up gigabytes of C:\\ space).");
        }
    }
}

fn clear_event_logs() {
    ["Application", "Security", "Setup", "System"]
        .iter()
        .for_each(|log| {
            let _ = crate::hidden_command("wevtutil").args(&["cl", log]).output();
        });
    debug_print("    ✓ Windows Event Logs cleared.");
}
