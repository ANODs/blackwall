const std = @import("std");

/// Interface language, fixed at build time (src/i18n.zig). One codebase, one
/// binary per language: `zig build -Dlang=en`.
const Lang = enum { en, ru, zh };

/// The version lives in one place — build.zig.zon; -Dversion=... overrides it.
const zon_version = blk: {
    const zon = @embedFile("build.zig.zon");
    const key = ".version = \"";
    const start = std.mem.indexOf(u8, zon, key).? + key.len;
    const end = std.mem.indexOfScalarPos(u8, zon, start, '"').?;
    break :blk zon[start..end];
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const lang = b.option(Lang, "lang", "Interface language: en, ru, zh (default: ru)") orelse .ru;
    const version = b.option([]const u8, "version", "Version (default: from build.zig.zon)") orelse zon_version;
    const os = target.result.os.tag;
    // Release builds drop debug info: the shipped app stays small (spec: lightweight).
    const strip = b.option(bool, "strip", "Strip debug info (default: on in release builds)") orelse (optimize != .debug);

    // Auto-update (src/core/update.zig, docs/updates.md). Release CI passes both;
    // without a repository the updater is compiled out of the app.
    const update_repo = b.option([]const u8, "update-repo", "GitHub owner/name to take updates from (default: none, updater off)") orelse "";
    const update_pubkey = b.option([]const u8, "update-pubkey", "Base64 Ed25519 public key that signs releases (required with -Dupdate-repo)") orelse "";

    const options = b.addOptions();
    options.addOption([]const u8, "lang", @tagName(lang));
    options.addOption([]const u8, "version", version);
    options.addOption([]const u8, "update_repo", update_repo);
    options.addOption([]const u8, "update_pubkey", update_pubkey);

    const dvui_dep = b.dependency("dvui", .{ .target = target, .optimize = optimize, .backend = .sdl3 });

    const core = b.addModule("core", .{
        .root_source_file = b.path("src/core/core.zig"),
        .target = target,
        .optimize = optimize,
        // sockets bound to an interface and the TUN device use the C API
        .link_libc = true,
    });

    // Its own module: the app and the signing tool share it.
    const update = b.createModule(.{
        .root_source_file = b.path("src/core/update.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "blackwall",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .imports = &.{
                .{ .name = "dvui", .module = dvui_dep.module("dvui_sdl3") },
                .{ .name = "core", .module = core },
                .{ .name = "update", .module = update },
            },
        }),
        // DPI awareness and modern controls, as in DVUI's own examples.
        .win32_manifest = if (os == .windows) dvui_dep.path("src/main.manifest") else null,
    });
    if (os == .windows) exe.subsystem = .windows; // no console window behind the app
    if (os == .windows) exe.root_module.addWin32ResourceFile(.{ .file = b.path("assets/icon/blackwall.rc") });
    exe.root_module.addAnonymousImport("icon_png", .{ .root_source_file = b.path("assets/icon/window.png") });
    exe.root_module.addOptions("build_options", options);
    exe.root_module.addAnonymousImport("font_regular", .{ .root_source_file = b.path("assets/fonts/Geist-Regular.ttf") });
    exe.root_module.addAnonymousImport("font_medium", .{ .root_source_file = b.path("assets/fonts/Geist-Medium.ttf") });
    exe.root_module.addAnonymousImport("font_semibold", .{ .root_source_file = b.path("assets/fonts/Geist-SemiBold.ttf") });
    exe.root_module.addAnonymousImport("font_mono", .{ .root_source_file = b.path("assets/fonts/GeistMono-Regular.ttf") });
    // Only the zh build carries CJK glyphs (src/ui/theme.zig); en/ru stay as small as before.
    if (lang == .zh) exe.root_module.addAnonymousImport("font_cjk", .{ .root_source_file = b.path("assets/fonts/NotoSansSC-Regular.ttf") });
    if (update_repo.len > 0 and update_pubkey.len == 0)
        exe.step.dependOn(&b.addFail("-Dupdate-repo needs -Dupdate-pubkey (see docs/updates.md)").step);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run the app").dependOn(&run_cmd.step);

    const proxy_cli = b.addExecutable(.{
        .name = "blackwall-proxy",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/proxy_cli.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "core", .module = core }},
        }),
    });
    b.installArtifact(proxy_cli);

    // Descriptor passing over Unix sockets, shared by the service and the helper.
    const fdpass = b.createModule(.{
        .root_source_file = b.path("src/helper/fdpass.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // Background service: the data plane without the window. `zig build service`
    // builds only it (also for Linux targets, where the window is not needed).
    const service: ?*std.Build.Step.Compile = if (true) b.addExecutable(.{
        .name = "blackwall-service",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/service/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .imports = &.{
                .{ .name = "core", .module = core },
                .{ .name = "fdpass", .module = fdpass },
            },
        }),
    }) else null;
    // Windows: the service carries wintun.dll and puts it next to itself; the
    // app carries the service (and, in a release, its signature, so an
    // installed service can replace itself with it: core/win_scm.zig)
    const wintun_dll = b.option([]const u8, "wintun", "Windows: wintun.dll (amd64, from www.wintun.net) for the service to carry");
    if (os == .windows) if (service) |sv| {
        const dll = b.addWriteFiles();
        if (wintun_dll) |p| _ = dll.addCopyFile(.{ .cwd_relative = p }, "wintun.dll") else _ = dll.add("wintun.dll", "");
        sv.root_module.addAnonymousImport("wintun_dll", .{ .root_source_file = dll.getDirectory().path(b, "wintun.dll") });

        const files = b.addWriteFiles();
        _ = files.addCopyFile(sv.getEmittedBin(), "blackwall-service.exe");
        if (update_pubkey.len > 0 and b.graph.environ_map.get("BLACKWALL_UPDATE_KEY") != null) {
            // the signing tool runs here, on the build machine
            const host_core = b.createModule(.{ .root_source_file = b.path("src/core/core.zig"), .target = b.graph.host, .optimize = .ReleaseSafe, .link_libc = true });
            const host_update = b.createModule(.{ .root_source_file = b.path("src/core/update.zig"), .target = b.graph.host, .optimize = .ReleaseSafe });
            const host_sign = b.addExecutable(.{ .name = "blackwall-sign-host", .root_module = b.createModule(.{
                .root_source_file = b.path("src/tools/sign.zig"),
                .target = b.graph.host,
                .optimize = .ReleaseSafe,
                .imports = &.{ .{ .name = "update", .module = host_update }, .{ .name = "core", .module = host_core } },
            }) });
            const sig = b.addRunArtifact(host_sign);
            sig.addArgs(&.{ "sign-helper", version });
            sig.addFileArg(sv.getEmittedBin());
            _ = files.addCopyFile(sig.addOutputFileArg("blackwall-service.sig"), "blackwall-service.sig");
        } else _ = files.add("blackwall-service.sig", "");
        const embed = files.add("embed.zig",
            \\pub const service = @embedFile("blackwall-service.exe");
            \\pub const service_sig = @embedFile("blackwall-service.sig");
            \\
        );
        exe.root_module.addAnonymousImport("win_embed", .{ .root_source_file = embed });
    };
    const service_step = b.step("service", "Build only the background service (and the macOS helper)");
    if (service) |sv| {
        // its release is reported to the window, which restarts an older one
        sv.root_module.addOptions("build_options", options);
        b.installArtifact(sv);
        service_step.dependOn(&b.addInstallArtifact(sv, .{}).step);
    }

    // Linux: the small program that holds CAP_NET_ADMIN and hands the TUN
    // device to the service (src/service/tun_main.zig)
    const tun_tool: ?*std.Build.Step.Compile = if (os == .linux and !target.result.abi.isAndroid()) b.addExecutable(.{
        .name = "blackwall-tun",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/service/tun_main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .link_libc = true,
            .imports = &.{.{ .name = "fdpass", .module = fdpass }},
        }),
    }) else null;
    if (tun_tool) |t| {
        b.installArtifact(t);
        service_step.dependOn(&b.addInstallArtifact(t, .{}).step);
    }

    // libproc (macOS): who holds a tunnel, for the conflict handling of the
    // helper and the window (src/helper/darwin/proc.zig)
    const libproc: ?*std.Build.Module = if (os == .macos) b.addTranslateC(.{
        .root_source_file = b.path("src/helper/darwin/libproc.h"),
        .target = target,
        .optimize = optimize,
    }).createModule() else null;
    if (libproc) |m| exe.root_module.addImport("libproc", m);

    // Root helper (macOS only): utun, routes, DNS and the pf kill switch.
    const helper: ?*std.Build.Step.Compile = if (os == .macos) b.addExecutable(.{
        .name = "blackwall-helper",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/helper/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .imports = &.{
                .{ .name = "core", .module = core },
                .{ .name = "fdpass", .module = fdpass },
                .{ .name = "libproc", .module = libproc.? },
            },
        }),
    }) else null;
    if (helper) |h| {
        // the helper reports its release, so the window can tell when it is outdated
        h.root_module.addOptions("build_options", options);
        b.installArtifact(h);
        service_step.dependOn(&b.addInstallArtifact(h, .{}).step);
    }

    // Signs release files for the updater; `zig build sign` builds only it (CI).
    const sign = b.addExecutable(.{
        .name = "blackwall-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{ .{ .name = "update", .module = update }, .{ .name = "core", .module = core } },
        }),
    });
    b.installArtifact(sign);
    b.step("sign", "Build only the release signing tool").dependOn(&b.addInstallArtifact(sign, .{}).step);

    const core_tests = b.addTest(.{ .root_module = core });
    const update_tests = b.addTest(.{ .root_module = update });
    const test_step = b.step("test", "Run core and service tests");
    test_step.dependOn(&b.addRunArtifact(core_tests).step);
    test_step.dependOn(&b.addRunArtifact(update_tests).step);
    if (service) |sv| test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = sv.root_module })).step);
    if (os != .windows) test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = fdpass })).step);
    if (helper) |h| test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = h.root_module })).step);
    // what stands in the way of the connection (macOS)
    if (libproc) |m| test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/platform_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{ .{ .name = "core", .module = core }, .{ .name = "libproc", .module = m } },
    }) })).step);
    // the window's link to the service (no UI inside, so it tests without DVUI)
    if (os != .windows) test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/link.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "core", .module = core }},
    }) })).step);

    // the Android core (src/android): its session runs and is tested on the
    // host; the library itself is built by the `android` step
    const routes = b.createModule(.{
        .root_source_file = b.path("src/service/routes.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "core", .module = core }},
    });
    if (os != .windows) test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/android/session.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{ .{ .name = "core", .module = core }, .{ .name = "routes", .module = routes } },
    }) })).step);

    package(b, exe, service, helper, tun_tool, sign, update_pubkey.len > 0, lang, version, target.result);
    android(b, optimize, strip, version);
}

/// `zig build android -Doptimize=ReleaseSafe` → zig-out/package/BLACKWALL-<version>-android.apk
/// `zig build android-bundle -Doptimize=ReleaseSafe` → ...-android.aab, for Google Play
///
/// One APK for every interface language (Android picks by the system's)
/// and both 64-bit ABIs. The core is src/android/lib.zig built against the
/// NDK's libc; the shell in android/ is compiled and packed by
/// android/build.sh with the SDK's own tools, without Gradle.
///
/// Needs ANDROID_HOME (SDK with a platform, build-tools and an NDK) and a
/// JDK 17+ (JAVA_HOME or `javac` on the PATH); ANDROID_NDK_HOME picks a
/// particular NDK.
fn android(b: *std.Build, optimize: std.builtin.OptimizeMode, strip: bool, version: []const u8) void {
    const step = b.step("android", "Android app (APK) in zig-out/package");
    const env = b.graph.environ_map;
    const sdk = env.get("ANDROID_HOME") orelse env.get("ANDROID_SDK_ROOT") orelse {
        step.dependOn(&b.addFail("ANDROID_HOME is not set (the Android SDK; see README, Building for Android)").step);
        return;
    };
    const ndk = env.get("ANDROID_NDK_HOME") orelse b.fmt("{s}/ndk/{s}", .{ sdk, android_ndk });
    const host = switch (b.graph.host.result.os.tag) {
        .macos => "darwin-x86_64", // universal binaries under this name
        .windows => "windows-x86_64",
        else => "linux-x86_64",
    };
    const sysroot = b.fmt("{s}/toolchains/llvm/prebuilt/{s}/sysroot", .{ ndk, host });

    // the same script packs both forms: an APK to install directly, and an
    // App Bundle, which is what Google Play takes (`zig build android-bundle`)
    const bundle_step = b.step("android-bundle", "Android App Bundle for Google Play in zig-out/package");
    var packs: [2]*std.Build.Step.Run = undefined;
    var outputs: [2]std.Build.LazyPath = undefined;
    for ([_][]const u8{ "blackwall.apk", "blackwall.aab" }, 0..) |name, i| {
        const pack = b.addSystemCommand(&.{"sh"});
        pack.addFileArg(b.path("android/build.sh"));
        pack.addArgs(&.{ sdk, version });
        outputs[i] = pack.addOutputFileArg(name);
        // the shell's sources are not arguments, so the step cannot tell when they change
        pack.has_side_effects = true;
        packs[i] = pack;
    }

    const Abi = struct { name: []const u8, arch: std.Target.Cpu.Arch, triple: []const u8 };
    for ([_]Abi{
        .{ .name = "arm64-v8a", .arch = .aarch64, .triple = "aarch64-linux-android" },
        .{ .name = "x86_64", .arch = .x86_64, .triple = "x86_64-linux-android" },
    }) |abi| {
        const target = b.resolveTargetQuery(.{ .cpu_arch = abi.arch, .os_tag = .linux, .abi = .android, .android_api_level = android_min_api });
        const lib_dir = b.fmt("{s}/usr/lib/{s}/{d}", .{ sysroot, abi.triple, android_min_api });
        const libc = b.addWriteFiles().add(b.fmt("libc-{s}.txt", .{abi.name}), b.fmt(
            \\include_dir={s}/usr/include
            \\sys_include_dir={s}/usr/include/{s}
            \\crt_dir={s}
            \\cc_dir={s}
            \\msvc_lib_dir=
            \\kernel32_lib_dir=
            \\darwin_sdk_dir=
            \\
        , .{ sysroot, sysroot, abi.triple, lib_dir, lib_dir }));
        const core = b.createModule(.{
            .root_source_file = b.path("src/core/core.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        const routes = b.createModule(.{
            .root_source_file = b.path("src/service/routes.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "core", .module = core }},
        });
        const lib = b.addLibrary(.{
            .linkage = .dynamic,
            .name = "blackwall",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/android/lib.zig"),
                .target = target,
                .optimize = optimize,
                .strip = strip,
                .link_libc = true,
                .imports = &.{ .{ .name = "core", .module = core }, .{ .name = "routes", .module = routes } },
            }),
        });
        lib.setLibCFile(libc);
        lib.root_module.addLibraryPath(.{ .cwd_relative = lib_dir });
        lib.root_module.linkSystemLibrary("log", .{});
        // devices with 16 KB pages load only libraries aligned for them
        lib.link_z_max_page_size = 16384;
        for (packs) |pack| pack.addPrefixedFileArg(b.fmt("{s}=", .{abi.name}), lib.getEmittedBin());
    }
    step.dependOn(&b.addInstallFileWithDir(outputs[0], .{ .custom = "package" }, b.fmt("BLACKWALL-{s}-android.apk", .{version})).step);
    bundle_step.dependOn(&b.addInstallFileWithDir(outputs[1], .{ .custom = "package" }, b.fmt("BLACKWALL-{s}-android.aab", .{version})).step);
}

/// Android 10: the first release that tells a VPN who owns a connection.
const android_min_api = 29;
/// The NDK used when ANDROID_NDK_HOME does not name one.
const android_ndk = "29.0.14206865";

/// `zig build package -Dlang=.. -Doptimize=ReleaseSafe` → one release file in zig-out/package:
///   BLACKWALL-<version>-<lang>-macos-arm64.zip       (BLACKWALL.app with the service and
///                                                     the root helper, ad-hoc signed)
///   BLACKWALL-<version>-<lang>-windows-x86_64.exe    (single file, nothing to install)
///   BLACKWALL-<version>-<lang>-linux-x86_64.tar.gz
/// Android has its own step (`zig build android`, below).
fn package(
    b: *std.Build,
    exe: *std.Build.Step.Compile,
    service: ?*std.Build.Step.Compile,
    helper: ?*std.Build.Step.Compile,
    tun_tool: ?*std.Build.Step.Compile,
    /// the signing tool, and whether this build carries the update key
    sign_tool: *std.Build.Step.Compile,
    updater: bool,
    lang: Lang,
    version: []const u8,
    t: std.Target,
) void {
    const step = b.step("package", "Release file for this target and language in zig-out/package");
    const os_name = switch (t.os.tag) {
        .macos => "macos",
        .windows => "windows",
        .linux => if (t.abi.isAndroid()) "android" else "linux",
        else => @tagName(t.os.tag),
    };
    const arch = switch (t.cpu.arch) {
        .aarch64 => "arm64",
        else => @tagName(t.cpu.arch),
    };
    const base = b.fmt("BLACKWALL-{s}-{s}-{s}-{s}", .{ version, @tagName(lang), os_name, arch });

    switch (t.os.tag) {
        .macos => {
            const plist = b.addWriteFiles().add("Info.plist", b.fmt(
                \\<?xml version="1.0" encoding="UTF-8"?>
                \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                \\<plist version="1.0">
                \\<dict>
                \\  <key>CFBundleName</key><string>BLACKWALL</string>
                \\  <key>CFBundleDisplayName</key><string>BLACKWALL</string>
                \\  <key>CFBundleIdentifier</key><string>dev.blackwall</string>
                \\  <key>CFBundleExecutable</key><string>blackwall</string>
                \\  <key>CFBundleIconFile</key><string>AppIcon</string>
                \\  <key>CFBundleIconName</key><string>AppIcon</string>
                \\  <key>CFBundlePackageType</key><string>APPL</string>
                \\  <key>CFBundleShortVersionString</key><string>{s}</string>
                \\  <key>CFBundleVersion</key><string>{s}</string>
                \\  <key>CFBundleDevelopmentRegion</key><string>{s}</string>
                \\  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
                \\  <key>NSHighResolutionCapable</key><true/>
                \\</dict>
                \\</plist>
                \\
            , .{ version, version, @tagName(lang) }));
            const app_dir = "BLACKWALL.app";
            const macos_dir: std.Build.InstallDir = .{ .custom = app_dir ++ "/Contents/MacOS" };
            const bin = b.addInstallArtifact(exe, .{ .dest_dir = .{ .override = macos_dir } });
            const info = b.addInstallFileWithDir(plist, .{ .custom = app_dir ++ "/Contents" }, "Info.plist");
            // macOS 26 icon (Assets.car, from assets/icon/AppIcon.icon) + .icns for older systems
            const resources: std.Build.InstallDir = .{ .custom = app_dir ++ "/Contents/Resources" };
            const car = b.addInstallFileWithDir(b.path("assets/icon/Assets.car"), resources, "Assets.car");
            const icns = b.addInstallFileWithDir(b.path("assets/icon/AppIcon.icns"), resources, "AppIcon.icns");
            // Ad-hoc signature: Apple Silicon refuses to run unsigned binaries.
            // The service and the helper are signed first, then the bundle seals them.
            const sign = b.addSystemCommand(&.{ "codesign", "--force", "--sign", "-", "--identifier", "dev.blackwall" });
            sign.addDirectoryArg(b.graph.path(.install_prefix, app_dir));
            sign.has_side_effects = true;
            sign.step.dependOn(&bin.step);
            sign.step.dependOn(&info.step);
            sign.step.dependOn(&icns.step);
            sign.step.dependOn(&car.step);
            for ([_]?*std.Build.Step.Compile{ service, helper }) |maybe| {
                const part = maybe orelse continue;
                const installed = b.addInstallArtifact(part, .{ .dest_dir = .{ .override = macos_dir } });
                const sign_part = b.addSystemCommand(&.{ "codesign", "--force", "--sign", "-", "--identifier" });
                sign_part.addArg(b.fmt("dev.blackwall.{s}", .{part.name["blackwall-".len..]}));
                sign_part.addFileArg(b.graph.path(.install_prefix, b.fmt("{s}/Contents/MacOS/{s}", .{ app_dir, part.out_filename })));
                sign_part.has_side_effects = true;
                sign_part.step.dependOn(&installed.step);
                sign.step.dependOn(&sign_part.step);
                // A release signs the helper with the update key (the seed is in
                // the environment), so an installed helper can replace itself
                // with this one without the administrator (core/helper_ipc.zig).
                // Signed as it ships: after its own code signature, before the
                // bundle is sealed.
                if (part == helper.? and updater and b.graph.environ_map.get("BLACKWALL_UPDATE_KEY") != null) {
                    const sig = b.addRunArtifact(sign_tool);
                    sig.addArgs(&.{ "sign-helper", version });
                    sig.addFileArg(b.graph.path(.install_prefix, b.fmt("{s}/Contents/MacOS/{s}", .{ app_dir, part.out_filename })));
                    sig.addFileArg(b.graph.path(.install_prefix, app_dir ++ "/Contents/Resources/blackwall-helper.sig"));
                    sig.has_side_effects = true;
                    sig.step.dependOn(&sign_part.step);
                    sig.step.dependOn(&icns.step); // the Resources folder exists
                    sign.step.dependOn(&sig.step);
                }
            }
            const zip = b.addSystemCommand(&.{ "/usr/bin/ditto", "-c", "-k", "--norsrc", "--noextattr", "--keepParent" });
            zip.addDirectoryArg(b.graph.path(.install_prefix, app_dir));
            const archive = zip.addOutputFileArg(b.fmt("{s}.zip", .{base}));
            zip.has_side_effects = true;
            zip.step.dependOn(&sign.step);
            step.dependOn(&b.addInstallFileWithDir(archive, .{ .custom = "package" }, b.fmt("{s}.zip", .{base})).step);
        },
        .windows => {
            step.dependOn(&b.addInstallFileWithDir(exe.getEmittedBin(), .{ .custom = "package" }, b.fmt("{s}.exe", .{base})).step);
        },
        .linux => if (t.abi.isAndroid()) {
            step.dependOn(&b.addFail("Android is built by `zig build android`").step);
        } else {
            // the window, the service, blackwall-tun, and what puts them in
            // the applications menu (assets/linux/install.sh)
            const files = b.addWriteFiles();
            _ = files.addCopyFile(exe.getEmittedBin(), exe.out_filename);
            if (service) |sv| _ = files.addCopyFile(sv.getEmittedBin(), sv.out_filename);
            if (tun_tool) |tt| _ = files.addCopyFile(tt.getEmittedBin(), tt.out_filename);
            _ = files.addCopyFile(b.path("assets/linux/install.sh"), "install.sh");
            _ = files.addCopyFile(b.path("assets/linux/blackwall.desktop"), "blackwall.desktop");
            _ = files.addCopyFile(b.path("assets/icon/window.png"), "blackwall.png");
            const tar = b.addSystemCommand(&.{ "tar", "-czf" });
            const archive = tar.addOutputFileArg(b.fmt("{s}.tar.gz", .{base}));
            tar.addArg("-C");
            tar.addDirectoryArg(files.getDirectory());
            tar.addArgs(&.{ "blackwall", "blackwall-service", "blackwall-tun", "install.sh", "blackwall.desktop", "blackwall.png" });
            step.dependOn(&b.addInstallFileWithDir(archive, .{ .custom = "package" }, b.fmt("{s}.tar.gz", .{base})).step);
        },
        else => step.dependOn(&b.addFail(b.fmt("no package for {s}", .{os_name})).step),
    }
}
