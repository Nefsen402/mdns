//! The network the daemon runs in: two veth pairs, the daemon's ends in a
//! namespace of its own (a packet from an address of one's own namespace
//! would be dropped as a martian), the fuzzer's in another.
//!
//! ```text
//! fuzzer's namespace                       daemon's namespace
//!   fuzz-a 10.0.1.2  ── veth ──  mdns-a 10.0.1.1 ┐
//!   fuzz-b 10.0.2.2  ── veth ──  mdns-b 10.0.2.1 ┘  mdns (one segment: mdns-a, mdns-b)
//! ```

use std::ffi::CString;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::process::Command;
use std::time::Duration;

use socket2::{Domain, InterfaceIndexOrAddress, Protocol, Socket, Type};

pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const PORT: u16 = 5353;

/// The daemon's interfaces, and the fuzzer's ends of them.
pub const DAEMON_A: &str = "mdns-a";
pub const DAEMON_B: &str = "mdns-b";
pub const FUZZ_A: &str = "fuzz-a";
pub const FUZZ_B: &str = "fuzz-b";

/// Run `ip` with `args`, failing loudly.
pub fn ip(args: &[&str]) -> io::Result<()> {
    let status = Command::new("ip").args(args).status()?;
    if !status.success() {
        return Err(io::Error::other(format!("ip {} failed: {status}", args.join(" "))));
    }
    Ok(())
}

/// Turn off duplicate address detection for `iface` (or `default`/`all`):
/// on a link of two, no one else has the address, and waiting for it would
/// leave IPv6 without an address to send from.
pub fn no_dad(iface: &str) -> io::Result<()> {
    std::fs::write(format!("/proc/sys/net/ipv6/conf/{iface}/accept_dad"), "0")
}

pub fn ifindex(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    // SAFETY: a valid NUL-terminated string.
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => None,
        i => Some(i),
    }
}

/// Make the veth pairs, in the fuzzer's namespace.
pub fn make_links() -> io::Result<()> {
    for iface in ["default", "all"] {
        no_dad(iface)?;
    }
    ip(&["link", "set", "lo", "up"])?;
    ip(&["link", "add", DAEMON_A, "type", "veth", "peer", "name", FUZZ_A])?;
    ip(&["link", "add", DAEMON_B, "type", "veth", "peer", "name", FUZZ_B])
}

/// Hand the daemon's ends to the namespace of process `pid`, and bring up
/// the fuzzer's. Waits for `pid` to be in a namespace of its own first: one
/// just started may not have unshared it yet, and moving them then would
/// leave them here.
pub fn hand_over(pid: u32) -> io::Result<()> {
    let ours = std::fs::read_link("/proc/self/ns/net")?;
    let theirs = format!("/proc/{pid}/ns/net");
    let mut tries = 0;
    while std::fs::read_link(&theirs)? == ours {
        tries += 1;
        if tries > 400 {
            return Err(io::Error::other("the daemon's namespace was not made within 10s"));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    for iface in [DAEMON_A, DAEMON_B] {
        ip(&["link", "set", iface, "netns", &pid.to_string()])?;
    }
    for (iface, addr) in [(FUZZ_A, "10.0.1.2/24"), (FUZZ_B, "10.0.2.2/24")] {
        no_dad(iface)?;
        ip(&["addr", "add", addr, "dev", iface])?;
        ip(&["link", "set", iface, "up"])?;
    }
    // The canaries' own addresses, each sent from by its canary.
    let canaries: String = (100..250).map(|i| format!("addr add 10.0.1.{i}/24 dev {FUZZ_A}\n")).collect();
    let mut batch = Command::new("ip").args(["-batch", "-"]).stdin(std::process::Stdio::piped()).spawn()?;
    std::io::Write::write_all(batch.stdin.as_mut().expect("piped"), canaries.as_bytes())?;
    drop(batch.stdin.take());
    if !batch.wait()?.success() {
        return Err(io::Error::other("adding the canaries' addresses failed"));
    }
    Ok(())
}

/// In the daemon's namespace: wait for its ends to arrive, and bring them up.
pub fn take_over() -> io::Result<()> {
    for _ in 0..400 {
        if ifindex(DAEMON_A).is_some() && ifindex(DAEMON_B).is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    for iface in ["default", "all"] {
        no_dad(iface)?;
    }
    ip(&["link", "set", "lo", "up"])?;
    for (iface, addr) in [(DAEMON_A, "10.0.1.1/24"), (DAEMON_B, "10.0.2.1/24")] {
        no_dad(iface)?;
        ip(&["addr", "add", addr, "dev", iface])?;
        ip(&["link", "set", iface, "up"])?;
    }
    Ok(())
}

fn index(iface: &str) -> io::Result<u32> {
    ifindex(iface).ok_or_else(|| io::Error::other(format!("no interface {iface}")))
}

fn base(domain: Domain, iface: &str) -> io::Result<Socket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind_device(Some(iface.as_bytes()))?;
    Ok(socket)
}

/// A socket that sends to the mDNS group on `iface`, from port 5353, as a
/// device does, and where to send to.
pub fn sender(iface: &str, v6: bool) -> io::Result<(UdpSocket, SocketAddr)> {
    let idx = index(iface)?;
    if v6 {
        let socket = base(Domain::IPV6, iface)?;
        socket.set_only_v6(true)?;
        socket.set_multicast_if_v6(idx)?;
        socket.set_multicast_hops_v6(255)?;
        socket.set_multicast_loop_v6(false)?;
        socket.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, PORT, 0, idx)).into())?;
        Ok((socket.into(), SocketAddr::V6(SocketAddrV6::new(GROUP_V6, PORT, 0, idx))))
    } else {
        let socket = base(Domain::IPV4, iface)?;
        socket.set_multicast_if_v4(&Ipv4Addr::new(10, 0, 1, 2))?;
        socket.set_multicast_ttl_v4(255)?;
        socket.set_multicast_loop_v4(false)?;
        socket.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).into())?;
        Ok((socket.into(), SocketAddr::V4(SocketAddrV4::new(GROUP_V4, PORT))))
    }
}

/// A socket that sends to the mDNS group on `iface` from `addr`, port 5353,
/// and where to send to: for a device that is its own sender.
pub fn sender_from(iface: &str, addr: Ipv4Addr) -> io::Result<(UdpSocket, SocketAddr)> {
    let socket = base(Domain::IPV4, iface)?;
    socket.set_multicast_if_v4(&addr)?;
    socket.set_multicast_ttl_v4(255)?;
    socket.set_multicast_loop_v4(false)?;
    socket.bind(&SocketAddr::V4(SocketAddrV4::new(addr, PORT)).into())?;
    Ok((socket.into(), SocketAddr::V4(SocketAddrV4::new(GROUP_V4, PORT))))
}

/// A socket that hears everything sent to the mDNS group on `iface`.
pub fn listener(iface: &str, v6: bool) -> io::Result<UdpSocket> {
    let idx = index(iface)?;
    let socket = if v6 {
        let socket = base(Domain::IPV6, iface)?;
        socket.set_only_v6(true)?;
        socket.bind(&SocketAddr::V6(SocketAddrV6::new(GROUP_V6, PORT, 0, idx)).into())?;
        socket.join_multicast_v6(&GROUP_V6, idx)?;
        socket
    } else {
        let socket = base(Domain::IPV4, iface)?;
        socket.bind(&SocketAddr::V4(SocketAddrV4::new(GROUP_V4, PORT)).into())?;
        socket.join_multicast_v4_n(&GROUP_V4, &InterfaceIndexOrAddress::Index(idx))?;
        socket
    };
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    Ok(socket.into())
}
