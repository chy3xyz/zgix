const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // hparse is a real dependency now, not the -Dhparse experiment: it is the
    // head scanner src/parser.zig runs on. DESIGN.md rule 6 records why the
    // leaf-package guarantee survives it — hparse is std-only and brings no
    // runtime and no TLS stack of its own, so it cannot be the second copy of
    // anything a consumer already pins.
    const hparse_dep = b.dependency("hparse", .{ .target = target, .optimize = optimize });
    const hparse_mod = hparse_dep.module("hparse");
    const hparse_import: std.Build.Module.Import = .{ .name = "hparse", .module = hparse_mod };

    const mod = b.addModule("zurl", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{hparse_import},
    });

    // Compile-only gate for the executables that are otherwise reachable only
    // through a run step. CI must fail on a bench/ or smoke/ file that stopped
    // compiling; it must NOT run them -- benchmark numbers off a shared runner
    // are not a control (rule 8), and tls-smoke needs a live origin.
    const check_step = b.step("check", "Compile everything without running it");

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{hparse_import},
        }),
    });
    check_step.dependOn(&tests.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    // The fuzz gate is the same sources filtered to the parser's oracles: the
    // seed corpus at every split position, 20k deterministic mutations of it,
    // and the tests that prove the oracle can fail. Cheap enough (~0.15s) to
    // run on every slice.
    //
    // `zig build fuzz --fuzz` would hand the same oracle to Zig's
    // coverage-guided fuzzer, and does not build on Zig 0.16.0: the bundled
    // compiler/test_runner.zig fails under -ffuzz with a StackTrace type
    // mismatch at test_runner.zig:566. That is why the mutator in
    // src/fuzz.zig is in-tree; its `mutation_iterations` records the whole
    // story.
    const fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{hparse_import},
        }),
        .filters = &.{"fuzz"},
    });
    const fuzz_step = b.step("fuzz", "Run the parser fuzz oracles: corpus, mutations, vacuity");
    fuzz_step.dependOn(&b.addRunArtifact(fuzz_tests).step);

    // The head-parser comparison. It was `-Dhparse`-gated while hparse was an
    // experiment the default build must not fetch; hparse is a real dependency
    // now, so the gate is gone and the harness is an ordinary benchmark. It
    // stays because the question it answers did not stop being asked when the
    // answer changed: it is what measures the segmented cases (rule 8), which
    // is where adopting the resume cursor was supposed to pay.
    const hparse_step = b.step("bench-head", "Compare head parsers, whole and segmented");
    {
        const exe = b.addExecutable(.{
            .name = "bench-head",
            .root_module = b.createModule(.{
                .root_source_file = b.path("bench/head.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "zurl", .module = mod },
                    hparse_import,
                },
            }),
        });
        check_step.dependOn(&exe.step);

        const run = b.addRunArtifact(exe);
        run.addPassthruArgs();
        hparse_step.dependOn(&run.step);
    }

    // The curl-shaped binary. It allocates, deliberately: docs/SCOPE.md's
    // scoping principle is that zero allocation binds src/, not an executable,
    // and this is where the convenience lives so the library does not carry
    // it. Its real job is the other half of `curl-diff`.
    const cli = b.addExecutable(.{
        .name = "zurl",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zurl", .module = mod }},
        }),
    });
    b.installArtifact(cli);
    check_step.dependOn(&cli.step);

    // The argument parser is a pure function of argv, so it tests without a
    // network and belongs in `zig build test` rather than behind a live gate.
    const cli_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/args.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zurl", .module = mod }},
        }),
    });
    test_step.dependOn(&b.addRunArtifact(cli_tests).step);
    check_step.dependOn(&cli_tests.step);

    const cli_run = b.addRunArtifact(cli);
    cli_run.addPassthruArgs();
    b.step("cli", "Run the zurl binary: -- <args>").dependOn(&cli_run.step);

    // The differential oracle: the same request through curl and through the
    // binary above, and one answer. Rule 4's discipline one level up — the
    // fuzz oracle says a parse must not depend on how bytes were split, this
    // says a request must not depend on which client sent it.
    //
    // A live gate for the same reason as tls-smoke: it needs a network, a
    // real origin, and curl on PATH. `-- <url>` aims it elsewhere.
    const curl_diff = b.addSystemCommand(&.{"sh"});
    curl_diff.addFileArg(b.path("smoke/curl-diff.sh"));
    curl_diff.addArtifactArg(cli);
    curl_diff.addPassthruArgs();
    // Inherited stdio: the per-case list IS the report, and a gate whose
    // output only appears when it fails is one nobody reads while it passes.
    // `has_side_effects` keeps it from being cached away -- it talks to a
    // network, so yesterday's answer is not this run's.
    curl_diff.stdio = .inherit;
    curl_diff.has_side_effects = true;
    b.step("curl-diff", "Differential run against curl (needs network)")
        .dependOn(&curl_diff.step);

    // The live TLS gate. Deliberately its own step and not part of `test`:
    // std ships no TLS server, so a real handshake needs a real origin, and a
    // unit test that fails when DNS is down is a gate people learn to ignore.
    const tls_smoke = b.addExecutable(.{
        .name = "tls-smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("smoke/tls.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zurl", .module = mod }},
        }),
    });
    check_step.dependOn(&tls_smoke.step);

    const tls_smoke_step = b.step("tls-smoke", "Live TLS handshake against a real origin");
    const tls_smoke_run = b.addRunArtifact(tls_smoke);
    tls_smoke_run.addPassthruArgs();
    tls_smoke_step.dependOn(&tls_smoke_run.step);

    // Benchmarks are executables, not tests: they print numbers and never
    // assert on them — a perf gate that fails on a loaded laptop teaches
    // people to delete perf gates. Run with -Doptimize=ReleaseFast.
    inline for (.{ "parse", "e2e" }) |name| {
        const exe = b.addExecutable(.{
            .name = "bench-" ++ name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("bench/" ++ name ++ ".zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "zurl", .module = mod }},
            }),
        });
        check_step.dependOn(&exe.step);

        const step = b.step("bench-" ++ name, "Run the " ++ name ++ " benchmark");
        const run = b.addRunArtifact(exe);
        run.addPassthruArgs();
        step.dependOn(&run.step);
    }
}
