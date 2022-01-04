use std::{
    fs::File,
    io::{Read, Write},
    os::unix::prelude::{AsRawFd, FromRawFd},
    process::Stdio,
};

use anyhow::Context;
use geph4_protocol::VpnStdio;
use tun::Device;

pub fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return Ok(());
    }
    let mut tun_device = tun::platform::macos::Device::new(tun::Configuration::default().up())?;
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
    // upload loop
    {
        let fd = tun_device.as_raw_fd();
        let mut tun_device = unsafe { File::from_raw_fd(fd) };
        std::thread::spawn(move || loop {
            let mut buf = [0u8; 4096];
            let pkt_len = tun_device.read(&mut buf).unwrap();
            // eprintln!("FIRST FOUR BYTES ARE {:?}", &buf[..4]);
            let to_stuff = VpnStdio {
                verb: 0,
                body: buf[4..pkt_len].to_vec().into(),
            };
            // eprintln!("sent {} bytes", pkt_len);
            to_stuff.write_blocking(&mut child_input).unwrap();
            child_input.flush().unwrap();
        });
    }
    // download loop
    loop {
        let msg = VpnStdio::read_blocking(&mut child_output)?;
        let mut buf = [0u8; 4096];
        buf[3] = 0x02;
        match msg.verb {
            0 => {
                eprintln!("received {} bytes", msg.body.len());
                buf[4..4 + msg.body.len()].copy_from_slice(&msg.body);
                tun_device.write_all(&buf[0..4 + msg.body.len()])?;
            }
            1 => {
                let ipaddr_and_slash = String::from_utf8_lossy(&msg.body);
                let ipaddr = ipaddr_and_slash.split('/').next().unwrap();
                std::process::Command::new("ifconfig")
                    .arg(tun_device.name())
                    .arg(ipaddr)
                    .arg("100.64.0.1")
                    .spawn()?
                    .wait()?;
            }
            _ => log::warn!("invalid verb kind: {}", msg.verb),
        }
    }
}
