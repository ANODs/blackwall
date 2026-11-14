//! Service <-> root helper protocol (macOS).
//!
//! One JSON request line per connection over a Unix socket that only the
//! user who installed the helper (and root) may open. The reply to "up" is a
//! JSON line sent together with the utun descriptor (SCM_RIGHTS).
//!
//!   {"cmd":"up", ...UpRequest}   -> Reply + utun fd (when already up: the
//!                                   settings are applied again, same utun)
//!   {"cmd":"servers", ...}       -> Reply   (new VPN server addresses for the kill switch)
//!   {"cmd":"refresh"}            -> Reply   (the network changed, e.g. Wi-Fi <-> Ethernet:
//!                                   bind_index, bind_name and dns found again as "up"
//!                                   finds them, and the strict kill switch's DNS table
//!                                   follows; the utun and its routes stay. Nothing up:
//!                                   up=false and nothing changes. On an error nothing
//!                                   changes either)
//!   {"cmd":"down"}               -> Reply   (routes, DNS and kill switch removed, utun closed)
//!   {"cmd":"status"}             -> Reply
//!   {"cmd":"conflicts"}          -> Reply   (owners: the processes holding other VPNs'
//!                                   tunnels that capture traffic; pid 0 when unknown)
//!   {"cmd":"stop", pid, start_us, path, kill}
//!                                -> Reply   (asks one of those owners to quit: SIGTERM, or
//!                                   SIGKILL with kill. Refused unless pid, start time and
//!                                   path still match and it still holds a capturing tunnel;
//!                                   never for system processes; DPI tools such as
//!                                   zapret's tpws or ByeDPI also qualify)
//!   {"cmd":"stop_zapret"}        -> Reply   (zapret's own "stop", which also removes its pf
//!                                   rules; only from its standard, root-owned location)
//!
//! Every reply carries the helper's `version` and `build`.

/// Bumped whenever requests or replies change incompatibly; the window
/// reinstalls a helper that reports another one.
pub const version: u32 = 1;

pub const socket_path = "/var/run/dev.blackwall.helper.sock";
pub const label = "dev.blackwall.helper";
pub const install_path = "/Library/PrivilegedHelperTools/" ++ label;
pub const plist_path = "/Library/LaunchDaemons/" ++ label ++ ".plist";

/// Address of the TUN itself, and of the DNS server the TUN answers as.
pub const tun_addr = [4]u8{ 198, 18, 0, 1 };
pub const tun_dns = [4]u8{ 198, 18, 0, 2 };

pub const Request = struct {
    cmd: []const u8,
    mtu: u16 = 1500,
    /// "tunnel": IPv6 goes into the TUN too; "block": IPv6 is captured and
    /// refused; "system": IPv6 is left alone
    ipv6: []const u8 = "tunnel",
    /// "off" | "selective" | "strict"
    killswitch: []const u8 = "selective",
    allow_lan: bool = true,
    /// IPv4 addresses of the VPN servers (the strict kill switch lets only these out)
    servers: []const []const u8 = &.{},
    /// take over even though another VPN captures traffic
    force: bool = false,
    /// "stop": the process, as the window saw it
    pid: i32 = 0,
    start_us: u64 = 0,
    path: []const u8 = "",
    /// "stop": SIGKILL instead of asking it to quit
    kill: bool = false,
};

/// A process holding another VPN's tunnel.
pub const Owner = struct {
    ifname: []const u8 = "",
    /// 0 when nobody could be found holding it
    pid: i32 = 0,
    uid: u32 = 0,
    /// start time in microseconds: with pid and path, the process's identity
    start_us: u64 = 0,
    path: []const u8 = "",
};

pub const Reply = struct {
    version: u32 = 0,
    /// release of the helper binary: the root helper is updated with the app,
    /// so a window of another release reinstalls it ("" from older helpers)
    build: []const u8 = "",
    ok: bool = false,
    @"error": []const u8 = "",
    up: bool = false,
    ifname: []const u8 = "",
    /// the physical interface our own sockets must stay on
    bind_index: u32 = 0,
    bind_name: []const u8 = "",
    /// the real DNS servers, reachable through `bind_name`
    dns: []const []const u8 = &.{},
    /// interfaces of other VPNs that capture traffic (with error "conflict")
    conflicts: []const []const u8 = &.{},
    killswitch: []const u8 = "off",
    /// "conflicts": who holds them
    owners: []const Owner = &.{},
};
