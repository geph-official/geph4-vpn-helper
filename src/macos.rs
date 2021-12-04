use std::{os::unix::prelude::AsRawFd, process::Stdio};

use anyhow::Context;
use geph4_protocol::VpnStdio;
use tun::Device;

extern "C" {
    fn create_utun(num: u64) -> i32;
}

#[cfg(target_os = "macos")]
pub fn get_utun() -> anyhow::Result<(i32, String)> {
    for utun_n in 0..255 {
        let fd = unsafe { create_utun(utun_n) };
        if fd >= 0 {
            let utun_name = format!("utun{}", utun_n);
            return Ok((fd, utun_name));
        }
    }
    return Err(std::io::Error::last_os_error().into());
}

pub fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return Ok(());
    }
    let (utun_fd, utun_name) = get_utun()?;
    eprintln!("hello world, allocated FD {:?}", utun_fd);
    let mut tun_device =
        tun::platform::macos::Device::new(tun::Configuration::default().raw_fd(utun_fd))?;
    // Run Geph itself
    let mut child = std::process::Command::new("sudo")
        .arg("-u")
        .arg("nobody")
        .arg("--")
        .args(&args)
        .arg("--vpn-tun-fd")
        .arg(tun_device.as_raw_fd().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut child_output = child.stdout.take().context("cannot take child output")?;
    loop {
        let msg = VpnStdio::read_blocking(&mut child_output)?;
        match msg.verb {
            1 => {
                let ipaddr_and_slash = String::from_utf8_lossy(&msg.body);
                let ipaddr = ipaddr_and_slash.split('/').next().unwrap();
                tun_device.set_address(ipaddr.parse()?)?;
                tun_device.set_netmask("255.192.0.0".parse()?)?;
                tun_device.set_destination("100.64.0.1".parse()?)?;
            }
            _ => log::warn!("invalid verb kind: {}", msg.verb),
        }
    }
}
