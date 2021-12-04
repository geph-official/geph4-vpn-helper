use std::{
    io::{Read, Write},
    os::unix::prelude::AsRawFd,
    process::Stdio,
};

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
        tun::platform::macos::Device::new(tun::Configuration::default().raw_fd(utun_fd).up())?;
    tun_device.set_address("10.1.2.3".parse()?)?;
    // Run Geph itself
    let mut child = std::process::Command::new("sudo")
        .arg("-u")
        .arg("nobody")
        .arg("--")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut child_input = child.stdin.take().context("cannot take child input")?;
    let mut child_output = child.stdout.take().context("cannot take child output")?;
    dbg!(tun_device.has_packet_information());
    let (mut tunread, mut tunwrite) = tun_device.split();
    std::thread::spawn(move || loop {
        let mut buf = [0u8; 4096];
        let pkt_len = tunread.read(&mut buf).unwrap();
        let to_stuff = VpnStdio {
            verb: 0,
            body: buf[4..pkt_len].to_vec().into(),
        };
        // eprintln!("sent {} bytes", pkt_len);
        to_stuff.write_blocking(&mut child_input).unwrap();
        child_input.flush().unwrap();
    });
    loop {
        let msg = VpnStdio::read_blocking(&mut child_output)?;
        let mut buf = [0u8; 4096];
        buf[2] = 0x08;
        match msg.verb {
            0 => {
                eprintln!("received {} bytes", msg.body.len());
                buf[4..4 + msg.body.len()].copy_from_slice(&msg.body);
                tunwrite.write_all(&buf[0..4 + msg.body.len()])?;
            }
            1 => {
                let ipaddr_and_slash = String::from_utf8_lossy(&msg.body);
                let ipaddr = ipaddr_and_slash.split('/').next().unwrap();
            }
            _ => log::warn!("invalid verb kind: {}", msg.verb),
        }
    }
}
