const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // libcrypto, built by Zig for the target — never found on the system.
    // Zig's C sanitizers are off for the vendored C in every mode: this is
    // zgix's #283 verbatim (ReleaseSafe arms `-fsanitize=function` as a
    // `ud1` trap, and `OPENSSL_sk_pop_free` calling its `free_func` through
    // a cast pointer SIGILLs at key load). One setting for every mode keeps
    // the shipped archive identical to the tested one.
    const openssl_dependency = b.dependency("openssl", .{
        .target = target,
        .optimize = optimize,
    });
    const libcrypto = openssl_dependency.artifact("crypto");
    libcrypto.root_module.sanitize_c = .off;

    const zssl_module = b.addModule("zssl", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    zssl_module.link_libc = true;
    zssl_module.linkLibrary(libcrypto);

    // Zig 0.17 removed `@cImport`. Translate zssl's single C surface
    // (`src/crypto/c.h`) once, and expose the result as the `c` module the
    // tree imports. The translated code needs the same include paths the
    // libcrypto compilation used, including OpenSSL's generated headers.
    const c_translate = b.addTranslateC(.{
        .root_source_file = b.path("src/crypto/c.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    for (libcrypto.root_module.include_dirs.items) |include_dir| {
        switch (include_dir) {
            .path => |path| c_translate.addIncludePath(path),
            .path_system => |path| c_translate.addSystemIncludePath(path),
            .path_after => |path| c_translate.addAfterIncludePath(path),
            else => {},
        }
    }
    const c_module = c_translate.addModule("c");
    zssl_module.addImport("c", c_module);

    const module_tests = b.addRunArtifact(b.addTest(.{ .root_module = zssl_module }));
    const test_step = b.step("test", "Run unit tests (RFC 8448 vectors + differentials)");
    test_step.dependOn(&module_tests.step);

    // The interop gate: our machines against the real `openssl` binary —
    // genuine libssl, no shared code. Its own executable rather than a
    // test, because it spawns processes and binds sockets, and because a
    // developer without an openssl on PATH should get a SKIP they can
    // read rather than a red unit suite.
    const interop_module = b.createModule(.{
        .root_source_file = b.path("interop/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    interop_module.addImport("zssl", zssl_module);
    interop_module.addAnonymousImport("cert_pem", .{ .root_source_file = b.path("src/testdata/cert.pem") });
    interop_module.addAnonymousImport("key_pem", .{ .root_source_file = b.path("src/testdata/key.pem") });
    const interop_exe = b.addExecutable(.{ .name = "zssl-interop", .root_module = interop_module });
    const interop_run = b.addRunArtifact(interop_exe);
    interop_run.has_side_effects = true;
    const interop_step = b.step("interop", "Interop gate: openssl s_client/s_server against zssl");
    interop_step.dependOn(&interop_run.step);
}
