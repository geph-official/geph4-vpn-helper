use std::{
    fs::Permissions,
    os::unix::{net::UnixListener, prelude::RawFd},
    process::Stdio,
};

use bytes::Bytes;
use geph4_protocol::VpnStdio;
use once_cell::sync::Lazy;
use smol::{fs::unix::PermissionsExt, prelude::*};
use tundevice::TunDevice;
use uds::UnixStreamExt;

/// The raw TUN device.
static RAW_TUN: Lazy<TunDevice> = Lazy::new(|| {
    log::info!("initializing tun-geph");
    TunDevice::new_from_os("tun-geph").expect("could not initiate 'tun-geph' tun device!")
});

async fn run_sh(sh_str: &str) {
    let child = smol::process::Command::new("/usr/bin/env")
        .arg("sh")
        .arg("-c")
        .arg(sh_str)
        .spawn()
        .unwrap();
    child.output().await.unwrap();
}

async fn setup_iptables() {
    Lazy::force(&RAW_TUN);
    let to_run = r"
    export PATH=$PATH:/usr/sbin/:/sbin/
    # mark the owner
    iptables -D OUTPUT -t mangle -m owner ! --uid-owner nobody -j MARK --set-mark 8964
    iptables -A OUTPUT -t mangle -m owner ! --uid-owner nobody -j MARK --set-mark 8964
    iptables -D OUTPUT -t mangle -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j MARK --set-mark 11111
    iptables -A OUTPUT -t mangle -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j MARK --set-mark 11111
    # set up routing tables
    ip route flush table 8964
    ip route add default dev tun-geph table 8964
    ip rule del fwmark 8964 table 8964
    ip rule add fwmark 8964 table 8964
    # mangle
    iptables -t nat -D POSTROUTING -o tun-geph -j MASQUERADE
    iptables -t nat -A POSTROUTING -o tun-geph -j MASQUERADE
    # redirect DNS
    iptables -t nat -D OUTPUT -p udp --dport 53 -j DNAT -m owner ! --uid-owner nobody --to 127.0.0.1:15353
    iptables -t nat -D OUTPUT -p tcp --dport 53 -j DNAT -m owner ! --uid-owner nobody --to 127.0.0.1:15353
    iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT -m owner ! --uid-owner nobody --to 127.0.0.1:15353
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT -m owner ! --uid-owner nobody --to 127.0.0.1:15353
    # clamp MTU
    iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
    iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
    # block non-nobody ipv6 completely
    ip6tables -D OUTPUT -o lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -D OUTPUT -m owner ! --uid-owner nobody -j REJECT
    ip6tables -A OUTPUT -m owner ! --uid-owner nobody -j REJECT
    ";
    run_sh(to_run).await;
}

async fn clear_iptables() {
    let to_run = r"
    export PATH=$PATH:/usr/sbin/:/sbin/
    # mark the owner
    iptables -D OUTPUT -t mangle -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j MARK --set-mark 11111
    iptables -D OUTPUT -t mangle -m owner ! --uid-owner nobody -j MARK --set-mark 8964
    # set up routing tables
    ip rule del fwmark 8964 table 8964
    ip route flush table 8964
    # mangle
    iptables -t nat -D POSTROUTING -o tun-geph -j MASQUERADE
    # redirect DNS
    iptables -t nat -D OUTPUT -p udp --dport 53 -j DNAT -m owner ! --uid-owner nobody --to 127.0.0.1:15353
    iptables -t nat -D OUTPUT -p tcp --dport 53 -j DNAT -m owner ! --uid-owner nobody --to 127.0.0.1:15353
    # clamp MTU
    iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
    # ipv6
    ip6tables -D OUTPUT -o lo -j ACCEPT
    ip6tables -D OUTPUT -m owner ! --uid-owner nobody -j REJECT
    ";
    run_sh(to_run).await;
}

pub fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("geph4_vpn_helper=debug,warn"),
    )
    .format_timestamp_millis()
    .init();
    // escalate to root unconditionally
    nix::unistd::setuid(nix::unistd::Uid::from_raw(0))
        .expect("must be run with root privileges or setuid root");
    let uds_path = start_uds_loop(RAW_TUN.dup_rawfd());
    log::debug!("started UDS at {}", uds_path);
    smol::block_on(async move {
        clear_iptables().await;
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            return;
        }
        let mut child = smol::process::Command::new("/usr/bin/env")
            .arg("su")
            .arg("nobody")
            .arg("-s")
            .arg(&args[0])
            .arg("--")
            .args(&args[1..])
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut child_output = child.stdout.take().unwrap();
        let mut child_input = child.stdin.take().unwrap();
        VpnStdio {
            verb: 255,
            body: Bytes::copy_from_slice(uds_path.as_bytes()),
        }
        .write(&mut child_input)
        .await
        .unwrap();
        loop {
            let msg = VpnStdio::read(&mut child_output).await.unwrap();
            match msg.verb {
                0 => RAW_TUN.write_raw(&msg.body).await.unwrap(),
                1 => {
                    RAW_TUN.assign_ip(&String::from_utf8_lossy(&msg.body));
                    setup_iptables().await;
                }
                _ => log::warn!("invalid verb kind: {}", msg.verb),
            }
        }
    })
}

fn start_uds_loop(fd: RawFd) -> String {
    let path = format!("/tmp/{}", fastrand::u64(0..=u64::MAX));
    let listener = UnixListener::bind(&path).expect("cannot start unix listener");
    std::fs::set_permissions(&path, Permissions::from_mode(0o666)).expect("cannot set perms");
    std::thread::spawn(move || loop {
        let (client, _) = listener.accept().expect("cannot accept");
        log::debug!("unix client accepted!");
        let fd = unsafe { libc::dup(fd) };
        client
            .send_fds(b"HELLO", &[fd])
            .expect("could not send fds");
    });
    path
}
