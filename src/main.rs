#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::main()
}

#[cfg(target_os = "windows")]
fn main() {
    windows::main()
}

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    macos::main()
}
