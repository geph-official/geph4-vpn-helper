use std::process::Stdio;

use anyhow::Context;

use geph4_protocol::VpnStdio;
use once_cell::sync::Lazy;

use tundevice::TunDevice;

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

const SHARED_TUN_FD: i32 = 1109;

pub fn main() -> anyhow::Result<()> {
    scopeguard::defer!(smol::block_on(clear_iptables()));
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("geph4_vpn_helper=debug,warn"),
    )
    .format_timestamp_millis()
    .init();
    // escalate to root unconditionally
    nix::unistd::setuid(nix::unistd::Uid::from_raw(0))
        .expect("must be run with root privileges or setuid root");
    let orig_fd = RAW_TUN.dup_rawfd();
    // share the file descriptor at the well-known location
    let new_fd = unsafe { libc::dup(orig_fd) };
    smol::block_on(async move {
        clear_iptables().await;
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            return Ok(());
        }
        let mut child = smol::process::Command::new("/usr/bin/env")
            .arg("runuser")
            .arg("-u")
            .arg("nobody")
            .arg("-m")
            .arg(&args[0])
            .arg("--")
            .args(&args[1..])
            .arg("--vpn-tun-fd")
            .arg(new_fd.to_string())
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut child_output = child.stdout.take().context("cannot take child output")?;
        loop {
            let msg = VpnStdio::read(&mut child_output).await?;
            match msg.verb {
                0 => RAW_TUN
                    .write_raw(&msg.body)
                    .await
                    .context("cannot write into raw_tun")?,
                1 => {
                    RAW_TUN.assign_ip(&String::from_utf8_lossy(&msg.body));
                    setup_iptables().await;
                }
                _ => log::warn!("invalid verb kind: {}", msg.verb),
            }
        }
    })
}
