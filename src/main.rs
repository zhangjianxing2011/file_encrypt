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
    Works on both Windows and macOS. Files are encrypted in-place \n\
    with filenames obfuscated. Password required to unlock.\n\n\
    SECURITY RECOMMENDATION: For high-security environments, it is strongly\n\
    recommended to use this tool on volumes protected by Full Disk Encryption\n\
    (Windows BitLocker, macOS FileVault, or Linux LUKS) to prevent shredded\n\
    original data from being recovered via SSD wear-leveling.\n\n\
    Run without arguments to launch the graphical user interface (GUI).")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch the graphical interface
    Gui,
    /// Encrypt and lock a folder (requires password)
    Lock {
        /// Path to the folder to encrypt
        path: PathBuf,
        /// Optional password passed via flag (e.g. for automation/testing)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Decrypt and unlock a locked folder (requires password)
    Unlock {
        /// Path to the locked folder
        path: PathBuf,
        /// Optional password passed via flag (e.g. for automation/testing)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Encrypt newly added files in a locked folder using its existing password
    Append {
        /// Path to the locked folder
        path: PathBuf,
    },
    /// Check whether a folder is locked
    Status {
        /// Path to check
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    #[cfg(windows)]
    init_console_if_needed();

    let cli = Cli::parse();

    match cli.command {
        None | Some(Commands::Gui) => {
            launch_gui()?;
        }
        Some(Commands::Lock { path, password }) => {
            let pwd = match password {
                Some(p) => {
                    if p.is_empty() {
                        anyhow::bail!("Password cannot be empty");
                    }
                    p
                }
                None => prompt_new_password()?,
            };
            let report = vault::lock(&path, &pwd)?;
            if !report.is_complete() {
                eprintln!(
                    "⚠️  {} file(s) were skipped (in use or locked by another program):",
                    report.skipped_files.len()
                );
                for (path, err) in &report.skipped_files {
                    eprintln!("  ⚠️  {} — {}", path.display(), err);
                }
                eprintln!(
                    "💡 Successfully encrypted {} file(s). You can run 'append' once locks are released.",
                    report.encrypted_files
                );
            }
        }
        Some(Commands::Unlock { path, password }) => {
            let pwd = match password {
                Some(p) => p,
                None => prompt_password("Enter password: ")?,
            };
            let report = vault::unlock(&path, &pwd)?;
            if !report.is_complete() {
                eprintln!(
                    "⚠️  {} file(s) failed to decrypt:",
                    report.failed.len()
                );
                for (path, err) in &report.failed {
                    eprintln!("  ❌ {} — {}", path, err);
                }
                eprintln!("💡 Successfully restored {} file(s). Encrypted vault preserved for failed files.",
                    report.restored.len());
            }
        }
        Some(Commands::Append { path }) => {
            eprintln!("💡 提示: 请输入该保险箱原加密密码（支持中文输入）。验证通过后仅对新增文件追加加密。");
            let password = Zeroizing::new(rpassword::prompt_password("Enter existing password: ")?);
            if password.is_empty() {
                anyhow::bail!("Password cannot be empty");
            }
            let report = vault::append(&path, &password)?;
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
                for (path, err) in &report.skipped {
                    eprintln!("  ⚠️  {} — {}", path.display(), err);
                }
                eprintln!(
                    "💡 Encrypted {} new file(s). You can run 'append' again once locks are released.",
                    report.added
                );
            }
        }
        Some(Commands::Status { path }) => {
            if vault::is_locked(&path) {
                println!("🔒 Folder is LOCKED: {}", path.display());
            } else {
                println!("🔓 Folder is UNLOCKED: {}", path.display());
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
        assert!(matches!(cli.command, Some(Commands::Append { path }) if path == PathBuf::from("folder with spaces")));
    }

    #[test]
    fn append_requires_a_path_and_rejects_password_flags() {
        assert!(Cli::try_parse_from(["securevault", "append"]).is_err());
        assert!(Cli::try_parse_from(["securevault", "append", "folder", "-p", "secret"]).is_err());
        assert!(Cli::try_parse_from(["securevault", "append", "folder", "--password", "secret"]).is_err());
    }
}
