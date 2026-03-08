use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId, SendMessageW, WM_CLOSE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, SetProcessWorkingSetSize};

/// Known system window class names that must NEVER be closed.
const SYSTEM_CLASSES: &[&str] = &[
    "Shell_TrayWnd",
    "Progman",
    "WorkerW",
    "Shell_SecondaryTrayWnd",
    "DV2ControlHost",
    "NotifyIconOverflowWindow",
    "Windows.UI.Core.CoreWindow",
];

/// Context passed through EnumWindows callback.
struct KillerContext {
    idm_pids: Vec<u32>,
    self_pid: u32,
}

/// Runs infinitely in the background to kill IDM popups with empty titles.
pub fn run_background_loop() {
    println!("[i] Started background IDM popup killer loop...");

    // Drop working set size immediately to minimize RAM footprint (~1MB instead of ~15MB)
    unsafe {
        let _ = SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX);
    }

    let self_pid = unsafe { GetCurrentProcessId() };

    loop {
        let idm_pids = get_idm_pids();
        if !idm_pids.is_empty() {
            let ctx = KillerContext { idm_pids, self_pid };
            close_empty_idm_windows(&ctx);
            // IDM is running — check again in 5 seconds
            thread::sleep(Duration::from_secs(5));
        } else {
            // IDM not running — no work to do, sleep longer
            thread::sleep(Duration::from_secs(15));
        }
    }
}

fn close_empty_idm_windows(ctx: &KillerContext) {
    unsafe {
        let ptr = ctx as *const KillerContext as isize;
        let _ = EnumWindows(Some(enum_window_callback), LPARAM(ptr));
    }
}

unsafe extern "system" fn enum_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let ctx = &*(lparam.0 as *const KillerContext);

    // Get the owning process ID for this window
    let mut process_id = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut process_id));

    // SAFETY: Never touch our own process
    if process_id == ctx.self_pid {
        return BOOL(1);
    }

    // Only proceed if this window belongs to an IDM process
    if !ctx.idm_pids.contains(&process_id) {
        return BOOL(1);
    }

    // Only close windows with empty titles (IDM nag popups)
    let mut title_buf = [0u16; 64];
    let len = GetWindowTextW(hwnd, &mut title_buf);
    if len != 0 {
        return BOOL(1);
    }

    // SAFETY: Check class name — skip known system classes just in case
    let mut class_buf = [0u16; 128];
    let class_len = GetClassNameW(hwnd, &mut class_buf);
    if class_len > 0 {
        let class_name = String::from_utf16_lossy(&class_buf[..class_len as usize]);
        if SYSTEM_CLASSES.iter().any(|&sc| class_name.eq_ignore_ascii_case(sc)) {
            return BOOL(1);
        }
    }

    let _ = SendMessageW(hwnd, WM_CLOSE, windows::Win32::Foundation::WPARAM(0), LPARAM(0));

    BOOL(1) // Continue enumeration
}

fn get_idm_pids() -> Vec<u32> {
    let mut pids = Vec::with_capacity(2);
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if let Ok(handle) = snapshot {
            if !handle.is_invalid() {
                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                if Process32FirstW(handle, &mut entry).is_ok() {
                    let target = [
                        'i' as u16, 'd' as u16, 'm' as u16, 'a' as u16, 'n' as u16, 
                        '.' as u16, 'e' as u16, 'x' as u16, 'e' as u16
                    ];
                    
                    loop {
                        // Fast zero-allocation prefix match
                        let mut match_len = 0;
                        for i in 0..9 {
                            let mut c = entry.szExeFile[i];
                            if c == 0 {
                                break;
                            }
                            if c >= 'A' as u16 && c <= 'Z' as u16 {
                                c += 32; // to lowercase
                            }
                            if c == target[i] {
                                match_len += 1;
                            } else {
                                break;
                            }
                        }
                        
                        // ID Man processes are identified via matching all 9 letters right before the null byte
                        if match_len == 9 && entry.szExeFile[9] == 0 {
                            pids.push(entry.th32ProcessID);
                        }
                        
                        if Process32NextW(handle, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
        }
    }
    pids
}
