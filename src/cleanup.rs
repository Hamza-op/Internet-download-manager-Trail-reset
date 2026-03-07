//! Temporary file cleaning module.

use std::fs;
use std::path::PathBuf;

use crate::debug_print;

/// Clean temporary files from common Windows temp directories.
pub fn clean_temp_files() {
    let temp_dirs = get_temp_dirs();

    let (total_deleted, total_failed, total_bytes_freed) = temp_dirs
        .iter()
        .filter(|dir| {
            if !dir.exists() {
                debug_print(&format!("  [—] Skipped (not found): {}", dir.display()));
                false
            } else {
                true
            }
        })
        .fold((0u64, 0u64, 0u64), |(acc_del, acc_fail, acc_bytes), dir| {
            debug_print(&format!("  [⟳] Cleaning: {}", dir.display()));

            let (deleted, failed, bytes) = clean_directory(dir);

            debug_print(&format!(
                "      ✓ Deleted: {}  ✗ Failed: {}  Freed: {}",
                deleted,
                failed,
                format_bytes(bytes)
            ));

            (acc_del + deleted, acc_fail + failed, acc_bytes + bytes)
        });

    debug_print(&format!(
        "  Total: {} deleted | {} failed | {} freed",
        total_deleted,
        total_failed,
        format_bytes(total_bytes_freed)
    ));
}

/// Get list of temporary directories to clean.
fn get_temp_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // User %TEMP%
    if let Ok(temp) = std::env::var("TEMP") {
        dirs.push(PathBuf::from(temp));
    } else if let Ok(tmp) = std::env::var("TMP") {
        dirs.push(PathBuf::from(tmp));
    }

    // Windows\Temp
    if let Ok(windir) = std::env::var("SystemRoot") {
        dirs.push(PathBuf::from(format!("{}\\Temp", windir)));
    }

    // Prefetch (requires admin — we have it)
    if let Ok(windir) = std::env::var("SystemRoot") {
        dirs.push(PathBuf::from(format!("{}\\Prefetch", windir)));
    }

    // Recent files
    if let Some(user_profile) = dirs::home_dir() {
        let recent = user_profile.join("AppData\\Roaming\\Microsoft\\Windows\\Recent");
        if recent.exists() {
            dirs.push(recent);
        }
    }

    // Windows Update cache
    if let Ok(windir) = std::env::var("SystemRoot") {
        dirs.push(PathBuf::from(format!(
            "{}\\SoftwareDistribution\\Download",
            windir
        )));
    }

    // DirectX & GPU Cache & CrashDumps
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        dirs.push(PathBuf::from(format!("{}\\D3DSCache", localappdata)));
        dirs.push(PathBuf::from(format!("{}\\NVIDIA\\GLCache", localappdata)));
        dirs.push(PathBuf::from(format!(
            "{}\\NVIDIA\\ComputeCache",
            localappdata
        )));
        dirs.push(PathBuf::from(format!("{}\\AMD\\DxCache", localappdata)));
        dirs.push(PathBuf::from(format!("{}\\AMD\\DxcCache", localappdata)));
        dirs.push(PathBuf::from(format!("{}\\CrashDumps", localappdata)));
    }

    // Windows Error Reporting
    if let Ok(programdata) = std::env::var("PROGRAMDATA") {
        dirs.push(PathBuf::from(format!(
            "{}\\Microsoft\\Windows\\WER\\ReportArchive",
            programdata
        )));
        dirs.push(PathBuf::from(format!(
            "{}\\Microsoft\\Windows\\WER\\ReportQueue",
            programdata
        )));
    }

    // Adobe Media Caches (often take tens of GBs)
    if let Ok(appdata) = std::env::var("APPDATA") {
        dirs.push(PathBuf::from(format!(
            "{}\\Adobe\\Common\\Media Cache Files",
            appdata
        )));
        dirs.push(PathBuf::from(format!(
            "{}\\Adobe\\Common\\Media Cache",
            appdata
        )));
        dirs.push(PathBuf::from(format!(
            "{}\\Adobe\\Common\\Peak Files",
            appdata
        )));
        dirs.push(PathBuf::from(format!("{}\\discord\\Cache", appdata)));
        dirs.push(PathBuf::from(format!("{}\\discord\\Code Cache", appdata)));
        dirs.push(PathBuf::from(format!("{}\\discord\\GPUCache", appdata)));
    }

    // Web Browser Caches (Chrome, Edge, Brave, Firefox)
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        [
            "Google\\Chrome",
            "Microsoft\\Edge",
            "BraveSoftware\\Brave-Browser",
        ]
        .iter()
        .for_each(|browser| {
            let base = format!("{}\\{}\\User Data\\Default", localappdata, browser);
            dirs.push(PathBuf::from(format!("{}\\Cache", base)));
            dirs.push(PathBuf::from(format!("{}\\Code Cache", base)));
            dirs.push(PathBuf::from(format!("{}\\GPUCache", base)));

            let base_sys = format!("{}\\{}\\User Data\\System Profile", localappdata, browser);
            dirs.push(PathBuf::from(format!("{}\\Cache", base_sys)));
            dirs.push(PathBuf::from(format!("{}\\Code Cache", base_sys)));
            dirs.push(PathBuf::from(format!("{}\\GPUCache", base_sys)));
        });

        // Firefox Caches
        let mozilla = PathBuf::from(format!("{}\\Mozilla\\Firefox\\Profiles", localappdata));
        if mozilla.exists() {
            if let Ok(entries) = std::fs::read_dir(&mozilla) {
                entries
                    .flatten()
                    .filter(|entry| entry.path().is_dir())
                    .for_each(|entry| {
                        dirs.push(entry.path().join("cache2"));
                        dirs.push(entry.path().join("startupCache"));
                    });
            }
        }
    }

    dirs
}

/// Recursively clean a directory. Returns (deleted_count, failed_count, bytes_freed).
fn clean_directory(dir: &PathBuf) -> (u64, u64, u64) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return (0, 1, 0),
    };

    let current_exe = std::env::current_exe().ok();

    entries.flatten().fold(
        (0u64, 0u64, 0u64),
        |(mut deleted, mut failed, mut bytes), entry| {
            let path = entry.path();

            // Never delete ourselves
            if current_exe.as_ref().map_or(false, |exe| path == *exe) {
                return (deleted, failed, bytes);
            }

            if path.is_dir() {
                let (d, f, b) = clean_directory(&path);
                deleted += d;
                failed += f;
                bytes += b;
                if fs::remove_dir(&path).is_ok() {
                    deleted += 1;
                }
            } else {
                let file_size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                match fs::remove_file(&path) {
                    Ok(_) => {
                        deleted += 1;
                        bytes += file_size;
                    }
                    Err(_) => {
                        failed += 1;
                    }
                }
            }

            (deleted, failed, bytes)
        },
    )
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
