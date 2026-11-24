#![windows_subsystem = "windows"]

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zeroize::Zeroizing;

mod crypto;
mod gui;
mod index;
mod vault;

#[derive(Parser)]
#[command(name = "securevault")]
#[command(version)]
#[command(about = "🔐 SecureVault - High-performance cross-platform folder encryption")]
#[command(long_about = "Encrypt and lock folders with AES-256-GCM + Argon2id.\n\
    Works on Windows, macOS, and Linux (Ubuntu Desktop & CLI).\n\
    Files are encrypted in-place with filenames and directory structure obfuscated.\n\
    Password required to unlock.\n\n\
    SECURITY RECOMMENDATION: For high-security environments, it is strongly\n\
    recommended to use this tool on volumes protected by Full Disk Encryption\n\
    (Windows BitLocker, macOS FileVault, or Linux LUKS) to prevent shredded\n\
    original data from being recovered via SSD wear-leveling.\n\n\
    Run without arguments on desktop to launch the graphical user interface (GUI),\n\
    or use subcommands for command-line and automated workflows.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch the graphical interface
    Gui,
    /// Encrypt and lock one or more folders (supports multiple for batch encryption)
    Lock {
        /// Path(s) to the folder(s) to encrypt
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Optional password passed via flag (e.g. for automation/testing)
        #[arg(short, long)]
        password: Option<String>,
        /// Optional password hint to help remember password
        #[arg(long)]
        hint: Option<String>,
    },
    /// Decrypt and unlock one or more locked folders (supports multiple for batch decryption)
    Unlock {
        /// Path(s) to the locked folder(s)
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Optional password passed via flag (e.g. for automation/testing)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Encrypt newly added files in one or more locked folders using existing password
    Append {
        /// Path(s) to the locked folder(s)
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Check whether one or more folders are locked
    Status {
        /// Path(s) to check
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Show detailed metadata and inspection of a folder (contents, size, lock state, hint)
    #[command(alias = "inspect")]
    Info {
        /// Path to the folder to inspect
        path: PathBuf,
    },
    /// List all managed/tracked vaults and their current lock status
    #[command(alias = "vaults")]
    List,
    /// Add a folder to the managed/tracked vaults list
    Add {
        /// Path to the folder to add
        path: PathBuf,
        /// Optional custom name for the vault
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Remove a folder from the managed/tracked vaults list (does not delete files)
    Remove {
        /// Path or name of the folder to remove
        path: PathBuf,
    },
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn has_gui_display() -> bool {
    std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok()
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn has_gui_display() -> bool {
    true
}

fn main() -> Result<()> {
    #[cfg(windows)]
    init_console_if_needed();

    let cli = Cli::parse();

    match cli.command {
        None => {
            if has_gui_display() {
                launch_gui()?;
            } else {
                println!("💡 No graphical display detected (DISPLAY / WAYLAND_DISPLAY not set).");
                println!("   Running in command-line mode. Use 'securevault --help' to see all commands.\n");
                use clap::CommandFactory;
                Cli::command().print_help()?;
                println!();
            }
        }
        Some(Commands::Gui) => {
            launch_gui()?;
        }
        Some(Commands::Lock { paths, password, hint }) => {
            let pwd = match password {
                Some(p) => {
                    if p.is_empty() {
                        anyhow::bail!("Password cannot be empty");
                    }
                    p
                }
                None => prompt_new_password()?,
            };
            let total = paths.len();
            let mut success_count = 0;
            let mut fail_count = 0;

            for (i, path) in paths.iter().enumerate() {
                if total > 1 {
                    println!("\n🔐 [{}/{}] Locking folder: {}", i + 1, total, path.display());
                }
                match vault::lock_with_hint_and_progress(path, &pwd, hint.as_deref(), |_, _, _, _| {}) {
                    Ok(report) => {
                        success_count += 1;
                        if !report.is_complete() {
                            eprintln!(
                                "⚠️  {} file(s) were skipped (in use or locked by another program):",
                                report.skipped_files.len()
                            );
                            for (p, err) in &report.skipped_files {
                                eprintln!("  ⚠️  {} — {}", p.display(), err);
                            }
                            eprintln!(
                                "💡 Successfully encrypted {} file(s). You can run 'append' once locks are released.",
                                report.encrypted_files
                            );
                        }
                    }
                    Err(e) => {
                        fail_count += 1;
                        eprintln!("❌ Failed to lock {}: {}", path.display(), e);
                    }
                }
            }

            if total > 1 {
                println!("\n════════════════════════════════════════");
                if fail_count == 0 {
                    println!("✅ Batch lock complete: all {} folder(s) encrypted successfully.", success_count);
                } else {
                    println!("⚠️ Batch lock finished: {} succeeded, {} failed.", success_count, fail_count);
                }
            }
        }
        Some(Commands::Unlock { paths, password }) => {
            let pwd = match password {
                Some(p) => p,
                None => {
                    if paths.len() == 1 {
                        if let Ok((meta, _)) = vault::read_vault_meta(&paths[0]) {
                            if let Some(h) = &meta.password_hint {
                                if !h.trim().is_empty() {
                                    println!("💡 密码提示: {}", h.trim());
                                }
                            }
                        }
                    }
                    prompt_password("Enter password: ")?
                }
            };
            let total = paths.len();
            let mut success_count = 0;
            let mut fail_count = 0;

            for (i, path) in paths.iter().enumerate() {
                if total > 1 {
                    println!("\n🔓 [{}/{}] Unlocking folder: {}", i + 1, total, path.display());
                }
                match vault::unlock(path, &pwd) {
                    Ok(report) => {
                        success_count += 1;
                        if !report.is_complete() {
                            eprintln!(
                                "⚠️  {} file(s) failed to decrypt:",
                                report.failed.len()
                            );
                            for (p, err) in &report.failed {
                                eprintln!("  ❌ {} — {}", p, err);
                            }
                            eprintln!(
                                "💡 Successfully restored {} file(s). Encrypted vault preserved for failed files.",
                                report.restored.len()
                            );
                        }
                    }
                    Err(e) => {
                        fail_count += 1;
                        eprintln!("❌ Failed to unlock {}: {}", path.display(), e);
                    }
                }
            }

            if total > 1 {
                println!("\n════════════════════════════════════════");
                if fail_count == 0 {
                    println!("✅ Batch unlock complete: all {} folder(s) restored successfully.", success_count);
                } else {
                    println!("⚠️ Batch unlock finished: {} succeeded, {} failed.", success_count, fail_count);
                }
            }
        }
        Some(Commands::Append { paths }) => {
            eprintln!("💡 提示: 请输入该保险箱原加密密码（支持中文输入）。验证通过后仅对新增文件追加加密。");
            let password = Zeroizing::new(rpassword::prompt_password("Enter existing password: ")?);
            if password.is_empty() {
                anyhow::bail!("Password cannot be empty");
            }
            let total = paths.len();
            for (i, path) in paths.iter().enumerate() {
                if total > 1 {
                    println!("\n⚡ [{}/{}] Processing folder: {}", i + 1, total, path.display());
                }
                match vault::append(path, &password) {
                    Ok(report) => {
                        if report.is_complete() {
                            if report.added == 0 {
                                println!("No new files; empty directories synchronized. Existing encrypted files are unchanged.");
                            } else {
                                println!("Encrypted {} new file(s). Existing encrypted files are unchanged.", report.added);
                            }
                        } else {
                            eprintln!(
                                "⚠️  {} file(s) were skipped (in use or locked):",
                                report.skipped.len()
                            );
                            for (p, err) in &report.skipped {
                                eprintln!("  ⚠️  {} — {}", p.display(), err);
                            }
                            eprintln!(
                                "💡 Encrypted {} new file(s). You can run 'append' again once locks are released.",
                                report.added
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to append to {}: {}", path.display(), e);
                    }
                }
            }
        }
        Some(Commands::Status { paths }) => {
            for path in &paths {
                if !path.exists() {
                    println!("❌ Path does NOT exist: {}", path.display());
                } else if vault::is_locked(path) {
                    println!("🔒 Folder is LOCKED:   {}", path.display());
                } else {
                    println!("🔓 Folder is UNLOCKED: {}", path.display());
                }
            }
        }
        Some(Commands::Info { path }) => {
            if !path.exists() {
                eprintln!("❌ Path does not exist: {}", path.display());
                std::process::exit(1);
            }
            let insp = gui::inspect_vault(&path);
            println!("🛡️  SecureVault Folder Details");
            println!("────────────────────────────────────────");
            println!("  Path:           {}", path.display());
            if insp.is_locked {
                println!("  Status:         🔒 LOCKED (AES-256-GCM + Argon2id)");
                if let Some(ref h) = insp.password_hint {
                    println!("  Password Hint:  💡 {}", h);
                }
                println!("  Encrypted Data: {} blob(s) ({})", insp.encrypted_files.len(), gui::format_bytes(insp.total_encrypted_bytes));
            } else {
                println!("  Status:         🔓 UNLOCKED (Plaintext)");
                println!("  Contents:       {} file(s), {} director(ies)", insp.total_plain_files, insp.total_plain_dirs);
                println!("  Total Size:     {}", gui::format_bytes(insp.total_plain_bytes));
            }
            println!("────────────────────────────────────────");
        }
        Some(Commands::List) => {
            let vaults = gui::load_tracked_vaults();
            if vaults.is_empty() {
                println!("📁 No managed vaults found in configuration.");
                println!("   Use 'securevault add <path>' or the GUI to add folders.");
            } else {
                println!("📁 Managed Vaults ({}):", vaults.len());
                for (i, v) in vaults.iter().enumerate() {
                    let status = if !v.path.exists() {
                        "❌ NOT FOUND"
                    } else if vault::is_locked(&v.path) {
                        "🔒 LOCKED"
                    } else {
                        "🔓 UNLOCKED"
                    };
                    println!("  {:2}. {:<14} {:<12} ({})", i + 1, v.name, status, v.path.display());
                }
            }
        }
        Some(Commands::Add { path, name }) => {
            if !path.exists() {
                anyhow::bail!("Path does not exist: {}", path.display());
            }
            if !path.is_dir() {
                anyhow::bail!("Path is not a directory: {}", path.display());
            }
            let canonical = match vault::dunce_canonicalize(&path) {
                Ok(c) => c,
                Err(_) => path.clone(),
            };
            let mut vaults = gui::load_tracked_vaults();
            if vaults.iter().any(|v| v.path == canonical || v.path == path) {
                println!("⚠️ Folder is already in managed list: {}", path.display());
            } else {
                let vault_name = name.unwrap_or_else(|| {
                    path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Folder".into())
                });
                vaults.push(gui::TrackedVault {
                    name: vault_name.clone(),
                    path: canonical.clone(),
                });
                gui::save_tracked_vaults(&vaults);
                println!("✅ Added to managed vaults: {} ({})", vault_name, canonical.display());
            }
        }
        Some(Commands::Remove { path }) => {
            let canonical = vault::dunce_canonicalize(&path).unwrap_or_else(|_| path.clone());
            let path_str = path.to_string_lossy();
            let mut vaults = gui::load_tracked_vaults();
            let initial_len = vaults.len();
            vaults.retain(|v| v.path != canonical && v.path != path && v.name != path_str);
            if vaults.len() < initial_len {
                gui::save_tracked_vaults(&vaults);
                println!("✅ Removed from managed vaults: {}", path.display());
            } else {
                println!("⚠️ Vault not found in managed list: {}", path.display());
            }
        }
    }

    Ok(())
}

fn load_app_icon() -> Option<eframe::egui::IconData> {
    let icon_bytes = include_bytes!("../assets/icon.png");
    let img = image::load_from_memory(icon_bytes).ok()?.into_rgba8();
    let (width, height) = img.dimensions();
    let rgba = img.into_raw();
    Some(eframe::egui::IconData {
        rgba,
        width,
        height,
    })
}

fn launch_gui() -> Result<()> {
    let app_title = format!("SecureVault v{} - 跨平台安全文件夹保险箱 (免安装版)", env!("CARGO_PKG_VERSION"));
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size([1248.0, 780.0])
        .with_min_inner_size([760.0, 560.0])
        .with_title(app_title);

    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "SecureVault",
        options,
        Box::new(|cc| Ok(Box::new(gui::SecureVaultApp::new(cc)))),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {}", e))
}

/// Prompt for an existing password (single entry)
fn prompt_password(prompt: &str) -> Result<String> {
    eprintln!("💡 提示: 请输入加密时设置的原始密码（支持中文输入）。验证错误不会解密，多次尝试不会损坏密文。");
    let password = rpassword::prompt_password(prompt)?;
    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }
    Ok(password)
}

/// Prompt for a new password (with confirmation)
fn prompt_new_password() -> Result<String> {
    eprintln!("💡 提示: 密码支持中文、字母、数字及特殊符号。采用零知识高强加密，无密码找回机制，请务必牢记！");
    let password = rpassword::prompt_password("Enter new password: ")?;
    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    Ok(password)
}

#[cfg(windows)]
fn init_console_if_needed() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && !args.iter().any(|a| a == "gui") {
        unsafe {
            type HANDLE = *mut std::ffi::c_void;
            type DWORD = u32;
            type BOOL = i32;
            type LPCWSTR = *const u16;

            const ATTACH_PARENT_PROCESS: DWORD = 0xFFFFFFFF;
            const STD_INPUT_HANDLE: DWORD = 0xFFFFFFF6;
            const STD_OUTPUT_HANDLE: DWORD = 0xFFFFFFF5;
            const STD_ERROR_HANDLE: DWORD = 0xFFFFFFF4;

            const GENERIC_READ: DWORD = 0x80000000;
            const GENERIC_WRITE: DWORD = 0x40000000;
            const FILE_SHARE_READ: DWORD = 1;
            const FILE_SHARE_WRITE: DWORD = 2;
            const OPEN_EXISTING: DWORD = 3;
            const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

            #[link(name = "kernel32")]
            extern "system" {
                fn AttachConsole(dwProcessId: DWORD) -> BOOL;
                fn GetStdHandle(nStdHandle: DWORD) -> HANDLE;
                fn SetStdHandle(nStdHandle: DWORD, hHandle: HANDLE) -> BOOL;
                fn CreateFileW(
                    lpFileName: LPCWSTR,
                    dwDesiredAccess: DWORD,
                    dwShareMode: DWORD,
                    lpSecurityAttributes: *const std::ffi::c_void,
                    dwCreationDisposition: DWORD,
                    dwFlagsAndAttributes: DWORD,
                    hTemplateFile: HANDLE,
                ) -> HANDLE;
            }

            if AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
                let current_out = GetStdHandle(STD_OUTPUT_HANDLE);
                if current_out.is_null() || current_out == INVALID_HANDLE_VALUE {
                    let conout: Vec<u16> = "CONOUT$\0".encode_utf16().collect();
                    let h_out = CreateFileW(
                        conout.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null_mut(),
                    );
                    if h_out != INVALID_HANDLE_VALUE && !h_out.is_null() {
                        SetStdHandle(STD_OUTPUT_HANDLE, h_out);
                        SetStdHandle(STD_ERROR_HANDLE, h_out);
                    }
                }

                let current_in = GetStdHandle(STD_INPUT_HANDLE);
                if current_in.is_null() || current_in == INVALID_HANDLE_VALUE {
                    let conin: Vec<u16> = "CONIN$\0".encode_utf16().collect();
                    let h_in = CreateFileW(
                        conin.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null_mut(),
                    );
                    if h_in != INVALID_HANDLE_VALUE && !h_in.is_null() {
                        SetStdHandle(STD_INPUT_HANDLE, h_in);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn append_accepts_a_folder_path() {
        let cli = Cli::try_parse_from(["securevault", "append", "folder with spaces"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Append { paths }) if paths == vec![PathBuf::from("folder with spaces")]));
    }

    #[test]
    fn append_requires_a_path_and_rejects_password_flags() {
        assert!(Cli::try_parse_from(["securevault", "append"]).is_err());
        assert!(Cli::try_parse_from(["securevault", "append", "folder", "-p", "secret"]).is_err());
        assert!(Cli::try_parse_from(["securevault", "append", "folder", "--password", "secret"]).is_err());
    }

    #[test]
    fn append_supports_multiple_paths() {
        let cli = Cli::try_parse_from(["securevault", "append", "f1", "f2", "f3"]).unwrap();
        if let Some(Commands::Append { paths }) = cli.command {
            assert_eq!(paths, vec![PathBuf::from("f1"), PathBuf::from("f2"), PathBuf::from("f3")]);
        } else {
            panic!("Expected Commands::Append");
        }
    }

    #[test]
    fn lock_and_unlock_support_multiple_paths() {
        let cli_lock = Cli::try_parse_from(["securevault", "lock", "dir1", "dir2", "-p", "pass123", "--hint", "test"]).unwrap();
        if let Some(Commands::Lock { paths, password, hint }) = cli_lock.command {
            assert_eq!(paths, vec![PathBuf::from("dir1"), PathBuf::from("dir2")]);
            assert_eq!(password, Some("pass123".to_string()));
            assert_eq!(hint, Some("test".to_string()));
        } else {
            panic!("Expected Commands::Lock");
        }

        let cli_unlock = Cli::try_parse_from(["securevault", "unlock", "v1", "v2", "-p", "pass123"]).unwrap();
        if let Some(Commands::Unlock { paths, password }) = cli_unlock.command {
            assert_eq!(paths, vec![PathBuf::from("v1"), PathBuf::from("v2")]);
            assert_eq!(password, Some("pass123".to_string()));
        } else {
            panic!("Expected Commands::Unlock");
        }
    }

    #[test]
    fn status_supports_multiple_paths() {
        let cli = Cli::try_parse_from(["securevault", "status", "v1", "v2"]).unwrap();
        if let Some(Commands::Status { paths }) = cli.command {
            assert_eq!(paths, vec![PathBuf::from("v1"), PathBuf::from("v2")]);
        } else {
            panic!("Expected Commands::Status");
        }
    }

    #[test]
    fn info_and_inspect_subcommands() {
        let cli_info = Cli::try_parse_from(["securevault", "info", "test.vault"]).unwrap();
        assert!(matches!(cli_info.command, Some(Commands::Info { path }) if path == PathBuf::from("test.vault")));

        let cli_inspect = Cli::try_parse_from(["securevault", "inspect", "test.vault"]).unwrap();
        assert!(matches!(cli_inspect.command, Some(Commands::Info { path }) if path == PathBuf::from("test.vault")));
    }

    #[test]
    fn list_and_vaults_subcommands() {
        let cli_list = Cli::try_parse_from(["securevault", "list"]).unwrap();
        assert!(matches!(cli_list.command, Some(Commands::List)));

        let cli_vaults = Cli::try_parse_from(["securevault", "vaults"]).unwrap();
        assert!(matches!(cli_vaults.command, Some(Commands::List)));
    }

    #[test]
    fn add_and_remove_subcommands() {
        let cli_add = Cli::try_parse_from(["securevault", "add", "my.vault"]).unwrap();
        assert!(matches!(cli_add.command, Some(Commands::Add { path, name }) if path == PathBuf::from("my.vault") && name.is_none()));

        let cli_add_named = Cli::try_parse_from(["securevault", "add", "my.vault", "--name", "Personal"]).unwrap();
        assert!(matches!(cli_add_named.command, Some(Commands::Add { path, name }) if path == PathBuf::from("my.vault") && name == Some("Personal".to_string())));

        let cli_remove = Cli::try_parse_from(["securevault", "remove", "my.vault"]).unwrap();
        assert!(matches!(cli_remove.command, Some(Commands::Remove { path }) if path == PathBuf::from("my.vault")));
    }
}
