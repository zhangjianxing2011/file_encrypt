#![windows_subsystem = "windows"]

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    with filenames obfuscated. Password required to unlock.\n\
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
    /// Check whether a folder is locked
    Status {
        /// Path to check
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    #[cfg(windows)]
    if cli.command.is_some() && !matches!(cli.command, Some(Commands::Gui)) {
        unsafe {
            #[link(name = "kernel32")]
            extern "system" {
                fn AttachConsole(dwProcessId: u32) -> i32;
            }
            AttachConsole(0xFFFFFFFF);
        }
    }

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
            vault::lock(&path, &pwd)?;
        }
        Some(Commands::Unlock { path, password }) => {
            let pwd = match password {
                Some(p) => p,
                None => prompt_password("Enter password: ")?,
            };
            vault::unlock(&path, &pwd)?;
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
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size([1248.0, 780.0])
        .with_min_inner_size([760.0, 560.0])
        .with_title("SecureVault - 跨平台安全文件夹保险箱 (免安装版)");

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
    let password = rpassword::prompt_password(prompt)?;
    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }
    Ok(password)
}

/// Prompt for a new password (with confirmation)
fn prompt_new_password() -> Result<String> {
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
