//! Tests of the window-side platform code that needs no UI (the module root
//! sits in src/ so these files can reach src/helper/darwin).

test {
    _ = @import("platform/conflicts.zig");
    _ = @import("platform/autostart.zig");
}
