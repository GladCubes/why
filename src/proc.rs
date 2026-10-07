//! The process model shared by every platform; each platform fills it in from its own source (/proc, WMI).
use std::path::PathBuf;

#[derive(Clone)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub exe: Option<PathBuf>,
    pub user: String,
    /// seconds since the epoch
    pub started: Option<u64>,
}

#[cfg(target_os = "linux")]
pub use crate::linux::process::{all, ancestors, children, read};
#[cfg(windows)]
pub use crate::windows::process::{all, ancestors, children, read};

/// Name without `.exe`, lowercase: how tools are matched on every platform.
pub fn norm(name: &str) -> String {
    name.to_ascii_lowercase().trim_end_matches(".exe").to_string()
}
