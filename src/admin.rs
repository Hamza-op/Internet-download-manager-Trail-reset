//! Admin privilege checking and UAC elevation.

use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

/// Check if the current process is running with administrator privileges.
pub fn is_admin() -> bool {
    use winreg::enums::HKEY_USERS;
    use winreg::RegKey;

    // Attempt to open HKU\S-1-5-19 (NT AUTHORITY\LOCAL SERVICE) — only possible as admin
    RegKey::predef(HKEY_USERS).open_subkey("S-1-5-19").is_ok()
}

/// Re-launch the current executable with elevated (admin) privileges via ShellExecuteW.
/// Returns `true` if the elevated process was launched successfully.
pub fn elevate_self() -> bool {
    let exe_path = match env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to get current exe path: {}", e);
            return false;
        }
    };

    let args: Vec<String> = env::args().skip(1).collect();
    let args_str = args.join(" ");

    let operation: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();
    let file: Vec<u16> = exe_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let parameters: Vec<u16> = OsStr::new(&args_str).encode_wide().chain(Some(0)).collect();

    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::UI::Shell::ShellExecuteW;

        let result = ShellExecuteW(
            None,
            PCWSTR(operation.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(parameters.as_ptr()),
            PCWSTR(ptr::null()),
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        );

        // ShellExecuteW returns > 32 on success
        result.0 as isize > 32
    }
}
