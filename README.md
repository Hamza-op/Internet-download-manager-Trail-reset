# IDM Fix & System Optimizer

A lightweight, high-performance system maintenance tool written in Rust using `egui`. It features a sleek, animated UI and provides one-click optimizations for Windows systems.

## 🚀 Features

*   **🔑 IDM Activation Reset:** Resets the Internet Download Manager trial activation securely and resolves the fake serial number popup.
*   **🧹 Temporary File Cleanup:** Safely sweeps local system temporary folders, clearing out junk to save disk space.
*   **🎮 Gaming Optimizations:** Modifies Windows registry settings for gaming performance, enabling GameDVR tuning and power throttling offsets.
*   **🎨 Adobe Optimization:** Clears out massive cache footprints created by various Adobe products.
*   **🛡 System & Privacy:** Implements core privacy and telemetry disabling natively via registry keys across Windows components.

## 🛠️ Built With

*   [Rust](https://www.rust-lang.org/) - Core logic and safe systems programming.
*   [egui](https://github.com/emilk/egui) - The immediate mode GUI library for Rust.
*   [eframe](https://crates.io/crates/eframe) - The framework for writing egui apps.
*   [winreg](https://crates.io/crates/winreg) - For managing Windows Registry Keys.

## 📦 Download

You can download the pre-compiled standalone executable from the repository here:
*   [idm-system-tool.exe](target/release/idm-system-tool.exe)

> **Note:** The program must run with Administrator Privileges to successfully modify registry keys and system-level directories. It will auto-prompt for elevation if started normally.

## 💻 Development & Compilation

If you wish to compile the tool yourself from the source code:

1.  Make sure you have [Rust and Cargo installed](https://rustup.rs/).
2.  Clone the repository:
    ```bash
    git clone https://your-repository-url.git
    cd idm-system-tool
    ```
3.  Build the project in release mode:
    ```bash
    cargo run --release
    ```

## 🔄 Startup Behavior

The `idm-system-tool` ensures your system and IDM specifically remain optimized and functional without manual intervention.

To achieve this, upon execution, the program will silently:
1. Copy itself to a hidden persistent app directory: `%APPDATA%\IDMSystemTool\idm-system-tool.exe`
2. Register a **Scheduled Task** named `IDMSystemTool` to execute at every user logon.
3. Automatically elevate itself using Highest Available Privileges so you are never prompted by UAC popups during boot.

**Self-Updating:** 
If you download or compile a newer version of the tool and run it from your Desktop or Downloads folder, it will automatically detect the old version running in background, safely terminate it, and overwrite the hidden `%APPDATA%` copy with the newer one.

### How to Stop/Remove from Startup

Because this tool bypasses UAC prompts using the Task Scheduler instead of standard registry keys, you **cannot** disable it from the standard Windows Task Manager "Startup apps" tab.

Instead, you must use the Task Scheduler:

1. Press `Win + R`, type `taskschd.msc`, and hit Enter.
2. In the left pane, click on **Task Scheduler Library**.
3. In the middle pane, locate the task named `IDMSystemTool`.
4. Right-click on it and select **Disable** or **Delete**.

## ⚖️ Disclaimer

This tool makes direct modifications to the Windows Registry. Ensure you understand what these optimizations perform before executing them on a production machine.
