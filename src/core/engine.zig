//! Connection state and traffic counters consumed by the UI.
//!
//! IMPORTANT: this is a simulator. It models the state machine the real
//! engine will expose (status, per-app rates, history) so the interface and
//! the rules logic can be built and measured, but it moves no packets. The
//! real data plane (TUN, protocol modules, kill switch) replaces `tick`.

const std = @import("std");
const model = @import("model.zig");

pub const Status = enum { disconnected, connecting, connected, reconnecting, blocked };

pub const history_len = 120;

pub const Engine = struct {
    status: Status = .disconnected,
    /// seconds spent in the current `connected` session
    session_secs: u64 = 0,
    connecting_left: f32 = 0,

    down_bps: f32 = 0,
    up_bps: f32 = 0,
    total_down: u64 = 0,
    total_up: u64 = 0,

    /// ring buffers, one sample per second, newest at `head - 1`
    hist_down: [history_len]f32 = @splat(0),
    hist_up: [history_len]f32 = @splat(0),
    head: usize = 0,
    filled: usize = 0,

    prng: std.Random.DefaultPrng = .init(0x5eed),
    simulate_traffic: bool = false,
    /// Cumulative byte counters of the real data plane, when one is running.
    /// Set before `tick`; rates are derived from the difference.
    real_totals: ?[2]u64 = null,
    last_real: [2]u64 = .{ 0, 0 },
    /// seconds the latest real totals cover
    real_dt: f32 = 1,
    /// a real data plane is starting: `connected` comes from it, not a timer
    pending: bool = false,
    /// per-app figures come from the data plane; `tick` leaves them alone
    real_apps: bool = false,

    pub fn connect(e: *Engine) void {
        if (e.status == .connected or e.status == .connecting) return;
        e.status = .connecting;
        e.connecting_left = 0.9;
    }

    pub fn disconnect(e: *Engine) void {
        e.status = .disconnected;
        e.session_secs = 0;
        e.down_bps = 0;
        e.up_bps = 0;
    }

    /// Forget the counters and the graph (the sample data is being replaced).
    pub fn resetHistory(e: *Engine) void {
        e.hist_down = @splat(0);
        e.hist_up = @splat(0);
        e.head = 0;
        e.filled = 0;
        e.total_down = 0;
        e.total_up = 0;
        e.down_bps = 0;
        e.up_bps = 0;
    }

    pub fn toggle(e: *Engine) void {
        if (e.status == .disconnected or e.status == .blocked) e.connect() else e.disconnect();
    }

    /// Advance the fast part of the state machine. `dt` in seconds.
    pub fn advance(e: *Engine, dt: f32) void {
        if (e.status == .connecting or e.status == .reconnecting) {
            e.connecting_left -= dt;
            if (e.connecting_left <= 0 and !e.pending) e.status = .connected;
        }
    }

    pub fn busy(e: *const Engine) bool {
        return e.status == .connecting or e.status == .reconnecting;
    }

    /// Whether traffic following `route` can currently flow.
    pub fn flows(e: *const Engine, state: *model.State, route: model.Route) bool {
        const r: model.Route = if (route == .default) state.settings.default_route else route;
        return switch (r) {
            .block => false,
            .direct, .dpi => state.settings.kill_switch != .strict or e.status == .connected or e.status == .disconnected,
            .default, .auto, .server => e.status == .connected,
        };
    }

    /// One-second step: per-app rates, totals and history.
    pub fn tick(e: *Engine, state: *model.State) void {
        const rnd = e.prng.random();
        var down: f32 = 0;
        var up: f32 = 0;
        for (state.apps.items) |*a| {
            if (e.real_apps) break;
            if (e.simulate_traffic and a.online and e.flows(state, a.route)) {
                const seed: f32 = @floatFromInt(std.hash.Fnv1a_32.hash(a.id) % 97);
                const base = 40_000 + seed * 28_000;
                const burst: f32 = if (rnd.float(f32) > 0.82) 3.5 else 1.0;
                const target = base * burst * (0.35 + rnd.float(f32));
                a.down_bps += (target - a.down_bps) * 0.45;
                a.up_bps = a.down_bps * (0.06 + rnd.float(f32) * 0.08);
            } else {
                a.down_bps = 0;
                a.up_bps = 0;
            }
            a.total_down += @intFromFloat(a.down_bps);
            a.total_up += @intFromFloat(a.up_bps);
            down += a.down_bps;
            up += a.up_bps;
        }
        if (e.real_totals) |t| {
            const dd = t[0] -| e.last_real[0];
            const du = t[1] -| e.last_real[1];
            e.last_real = t;
            e.total_down += dd;
            e.total_up += du;
            const dt = @max(e.real_dt, 0.1);
            down = @as(f32, @floatFromInt(dd)) / dt;
            up = @as(f32, @floatFromInt(du)) / dt;
        } else {
            e.total_down += @intFromFloat(down);
            e.total_up += @intFromFloat(up);
        }
        e.down_bps = down;
        e.up_bps = up;
        if (e.status == .connected) e.session_secs += 1;

        e.hist_down[e.head] = down;
        e.hist_up[e.head] = up;
        e.head = (e.head + 1) % history_len;
        e.filled = @min(e.filled + 1, history_len);
    }

    /// Sample `i` seconds ago (0 = newest). Zero outside recorded history.
    pub fn sample(e: *const Engine, comptime which: enum { down, up }, i: usize) f32 {
        if (i >= e.filled) return 0;
        const idx = (e.head + history_len - 1 - i) % history_len;
        return if (which == .down) e.hist_down[idx] else e.hist_up[idx];
    }

    pub fn peak(e: *const Engine, n: usize) f32 {
        var m: f32 = 0;
        for (0..@min(n, e.filled)) |i| m = @max(m, @max(e.sample(.down, i), e.sample(.up, i)));
        return m;
    }
};

test "kill switch: strict blocks direct routes while reconnecting" {
    var s: model.State = .init(std.testing.allocator);
    defer s.deinit();
    var e: Engine = .{};
    s.settings.kill_switch = .strict;
    e.status = .reconnecting;
    try std.testing.expect(!e.flows(&s, .direct));
    try std.testing.expect(!e.flows(&s, .auto));
    s.settings.kill_switch = .selective;
    try std.testing.expect(e.flows(&s, .direct));
    try std.testing.expect(!e.flows(&s, .auto));
    try std.testing.expect(!e.flows(&s, .block));
}
