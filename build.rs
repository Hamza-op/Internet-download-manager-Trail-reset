// Build script to embed the Windows application manifest for UAC elevation.

fn main() {
    // Only embed manifest on Windows
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows" {
        embed_manifest();
        // Tell Cargo to re-run if manifest changes
        println!("cargo:rerun-if-changed=app.manifest");
    }
}

fn embed_manifest() {
    let manifest_path = std::path::Path::new("app.manifest");
    if !manifest_path.exists() {
        println!("cargo:warning=app.manifest not found, skipping manifest embedding");
        return;
    }

    // Write a temporary .rc file that includes the manifest
    let rc_content = format!(
        "1 24 \"{}\"",
        manifest_path
            .canonicalize()
            .unwrap_or_else(|_| manifest_path.to_path_buf())
            .display()
            .to_string()
            .replace('\\', "\\\\")
    );

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let rc_path = format!("{}\\app.rc", out_dir);
    std::fs::write(&rc_path, &rc_content).expect("Failed to write .rc file");

    // Use the `embed-resource` approach: compile .rc to .res
    // We'll use the Windows rc.exe compiler if available, otherwise skip
    let rc_exe = find_rc_exe();
    if let Some(rc_compiler) = rc_exe {
        let res_path = format!("{}\\app.res", out_dir);
        let status = std::process::Command::new(&rc_compiler)
            .args(["/nologo", "/fo", &res_path, &rc_path])
            .status();

        if let Ok(s) = status {
            if s.success() {
                println!("cargo:rustc-link-arg-bins=/link");
                println!("cargo:rustc-link-arg-bins={}", res_path);
                return;
            }
        }
    }

    // Fallback: try winres crate approach via embed_resource
    // If rc.exe is not found, we'll try the mt.exe approach
    println!("cargo:warning=Cannot find rc.exe. Manifest embedding skipped. Run from VS Developer Command Prompt for full support.");
}

fn find_rc_exe() -> Option<String> {
    // Check if rc.exe is in PATH
    if let Ok(output) = std::process::Command::new("where").arg("rc.exe").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout);
            let first_line = path.lines().next().unwrap_or("").trim();
            if !first_line.is_empty() {
                return Some(first_line.to_string());
            }
        }
    }
    None
}
