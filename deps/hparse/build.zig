const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Which scan tier the parser compiles. Both default to null, meaning "detect
    // from the target CPU" — what every ordinary build wants, and identical to the
    // hardcoded detection these replace. Forcing them is for testing: on every
    // target hparse builds for, `std.simd.suggestVectorLength` is non-null (SSE2 on
    // baseline x86_64, NEON on aarch64), so the SWAR/scalar tier was unreachable and
    // therefore untested. `-Duse-vectors=false` reaches it, and the fuzz harness
    // diffs a build of each (issue #2).
    const use_vectors = b.option(bool, "use-vectors", "Force the @Vector scan tier on or off (default: detect from the target CPU)");
    const vec_size = b.option(u16, "vec-size", "Force the vector width in bytes (default: detect from the target CPU)");

    const parser_options = b.addOptions();
    parser_options.addOption(?bool, "use_vectors", use_vectors);
    parser_options.addOption(?u16, "vec_size", vec_size);

    // Expose hparse as a public module.
    // This creates a "module", which represents a collection of source files alongside
    // some compilation options, such as optimization mode and linked system libraries.
    // Every executable or library we compile will be based on one or more modules.
    const lib_mod = b.addModule("hparse", .{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addOptions("build_options", parser_options);

    // We will also create a module for our other entry point, 'main.zig'.
    const exe_mod = b.createModule(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    // src/bench.zig reaches the parser with @import("root.zig"), so this module
    // compiles it as well and needs the same options.
    exe_mod.addOptions("build_options", parser_options);

    // This creates another `std.Build.Step.Compile`, but this one builds an executable
    // rather than a static library.
    const exe = b.addExecutable(.{
        .name = "hparse",
        .root_module = exe_mod,
    });

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    run_cmd.addPassthruArgs();

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Now, we will create a static library based on the module we created above.
    // This creates a `std.Build.Step.Compile`, which is the build step responsible
    // for actually invoking the compiler.
    const lib = b.addLibrary(.{
        .name = "hparse",
        .root_module = lib_mod,
    });

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    // Fuzzing harness (see src/fuzz.zig and issue #2).
    // `zig build fuzz` replays the seed corpus through the oracles (regression mode);
    // `zig build fuzz --fuzz` runs coverage-guided fuzzing.

    // A second copy of the parser with the @Vector tier forced off, so the
    // path-differential oracle can run both tiers over the same input in one
    // process.
    //
    // Unless this build is already the scalar one, in which case the shipped
    // parser IS that tier and the oracle compares it with itself. That case has
    // to be handled rather than just compiled twice: two option sets with
    // identical contents generate one cached options.zig, and a single file
    // cannot be the root of two modules.
    const scalar_mod = if (use_vectors == false) lib_mod else blk: {
        // `vec_size` is left to its default rather than inherited: with vectors off
        // the SWAR loops measure in `block_size`, and a forced vector width would
        // describe a tier this build does not contain.
        const scalar_options = b.addOptions();
        scalar_options.addOption(?bool, "use_vectors", false);
        scalar_options.addOption(?u16, "vec_size", null);

        // A generated copy, because Zig refuses to let one file root two modules
        // ("files must belong to only one module"). src/root.zig imports nothing
        // but std, builtin and build_options, so a copy of that one file is the
        // whole parser.
        const scalar_src = b.addWriteFiles().addCopyFile(b.path("src/root.zig"), "root_scalar.zig");

        const mod = b.createModule(.{
            .root_source_file = scalar_src,
            .target = target,
            .optimize = optimize,
        });
        mod.addOptions("build_options", scalar_options);
        break :blk mod;
    };

    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
        // For picohttpparser, below.
        .link_libc = true,
        .imports = &.{
            .{ .name = "hparse", .module = lib_mod },
            .{ .name = "hparse_scalar", .module = scalar_mod },
        },
    });

    // picohttpparser, as the reference parser for the differential oracle. It is
    // the copy already vendored for the benchmarks rather than a second one.
    //
    // bench/ is deliberately outside this package's `paths`, so this path resolves
    // only inside the repo. That is the only place the fuzz step is ever built: a
    // consumer depending on hparse gets `src/` and builds `lib_mod`, never this.
    //
    // As its own library rather than C sources added to `fuzz_mod`, because
    // `--fuzz` compiles that module with `-ffuzz` and the instrumentation reaches
    // C too: the `__sanitizer_cov_trace_cmp*` callbacks clang then emits have no
    // implementation in Zig's fuzzer runtime, and the link fails. Compiled
    // separately, the reference parser is simply uninstrumented — the fuzzer gets
    // no coverage feedback from inside it, which is right, since it is the
    // yardstick and not the thing under test.
    const pico_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    pico_mod.addCSourceFile(.{
        .file = b.path("bench/picohttpparser/picohttpparser.c"),
        .flags = &.{"-O2"},
    });
    const pico_lib = b.addLibrary(.{
        .name = "picohttpparser",
        .root_module = pico_mod,
    });

    fuzz_mod.addIncludePath(b.path("bench/picohttpparser"));
    fuzz_mod.linkLibrary(pico_lib);

    // llhttp, as the second reference parser. Vendored for the benchmarks like
    // picohttpparser, and compiled as its own uninstrumented library for the same
    // reason (see above).
    //
    // A second reference earns its place by being wrong differently: llhttp is a
    // generated state machine walking one byte at a time, picohttpparser is
    // hand-written and block-oriented, so a bug they would both wave through is
    // unlikely to be the same bug.
    const llhttp_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    llhttp_mod.addCSourceFiles(.{
        .root = b.path("bench/llhttp"),
        .files = &.{ "api.c", "http.c", "llhttp.c" },
        .flags = &.{"-O2"},
    });
    const llhttp_lib = b.addLibrary(.{
        .name = "llhttp",
        .root_module = llhttp_mod,
    });

    fuzz_mod.addIncludePath(b.path("bench/llhttp"));
    fuzz_mod.linkLibrary(llhttp_lib);

    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_mod,
        // Patched copy of the default test runner; the stock one fails to compile in
        // fuzz mode (`-ffuzz`) on Zig 0.16.0. See the doc comment in the file.
        .test_runner = .{ .path = b.path("src/fuzz_test_runner.zig"), .mode = .server },
        // The self-hosted x86_64 backend emits no fuzz coverage instrumentation (the
        // build runner's coverage thread panics on an empty PC table). It also
        // scalarizes @Vector code, and we want to fuzz the real SIMD paths.
        .use_llvm = true,
    });

    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);

    const fuzz_step = b.step("fuzz", "Run fuzz harness (pass --fuzz to actually fuzz)");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    // Regular test runs also replay the fuzz corpus as regression tests.
    test_step.dependOn(&run_fuzz_tests.step);
}
