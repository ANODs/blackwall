//! Linux pieces of the data plane: the TUN device.
//! Addresses and routes of the device are set up by whoever runs the
//! service (a root helper, systemd, or a test script).

const std = @import("std");
const c = std.c;

const TUNSETIFF: u32 = 0x400454ca; // _IOW('T', 202, int)
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

/// Open (or create) the TUN interface `name`. Needs CAP_NET_ADMIN.
pub fn openTun(name: []const u8) !c.fd_t {
    if (name.len == 0 or name.len > 15) return error.BadName;
    const fd = c.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .CLOEXEC = true });
    if (fd < 0) return error.TunUnavailable;
    errdefer _ = c.close(fd);
    // struct ifreq: name[16], then a union whose first member is the flags
    var ifr: [40]u8 = @splat(0);
    @memcpy(ifr[0..name.len], name);
    std.mem.writeInt(u16, ifr[16..18], IFF_TUN | IFF_NO_PI, .little);
    if (c.ioctl(fd, @bitCast(TUNSETIFF), &ifr) != 0) return error.TunSetupFailed;
    return fd;
}

