//! TLS as a transport, never as a feature (design rule 5).
//!
//! `Connection` is a `*Io.Reader` + `*Io.Writer`, and `std.crypto.tls.Client`
//! is exactly that shape on both sides: it consumes an encrypted reader and
//! writer, and exposes a plaintext reader and writer. So this file is an
//! adapter and nothing else. No branch reaches into the parser, nothing above
//! it knows whether the bytes were encrypted, and a caller who would rather
//! terminate TLS with zrk's ztls hands `Connection` those two pointers instead
//! and never compiles this file at all. That is the whole point of the seam:
//! `suite.probeOnce` speaks over zrk's TLS specifically, so that a handshake
//! the probe accepts is one the measurement will accept, and a client that
//! insisted on its own TLS could not express that.
//!
//! Zero allocation holds here too, but it is the caller who pays: std's
//! certificate verifier needs an allocator and a lock, so the trust anchors
//! are a caller-owned `Ca.Bundle` and not something this file quietly builds.
//! A CA bundle is also exactly the thing a process wants to load once and
//! share, which is why borrowing it is the right shape and not a concession.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;
/// Test-only, and imported at file scope because Zig has no test-only import.
/// It reaches nothing in production: `Transport` never constructs one.
const SegmentedReader = @import("SegmentedReader.zig");

/// Every buffer here must hold one whole TLS ciphertext record: 16645 bytes.
/// std asserts it for the encrypted reader and demands it of the encrypted
/// writer, so it is checked up front rather than met with a panic in a
/// dependency.
pub const buffer_bytes_min = std.crypto.tls.Client.min_buffer_len;

/// Four causes, because those are the four things a caller does something
/// different about. std's `InitError` has forty-five members and most of them
/// are one protocol detail; a caller cannot act on "the server's P-384 point
/// was not canonical", but it can act on "this certificate is not trusted".
pub const Error = error{
    /// A buffer cannot hold one TLS record. A caller bug, and the one error
    /// here that is fixed by changing the call rather than the peer.
    TlsBufferTooSmall,
    /// The whole-request deadline fired mid-handshake — rule 3's cancellation
    /// reaching in. Deliberately NOT folded into the three below: it is
    /// neither the peer's fault nor the transport's, and a caller retrying it
    /// as a transport failure would be retrying its own deadline.
    Canceled,
    /// The certificate chain did not verify against the configured trust
    /// anchors, or was not issued for this host, or has expired. Retrying
    /// changes nothing; either the peer or the trust configuration is wrong.
    TlsCertificateInvalid,
    /// The handshake failed for a protocol reason — an alert, a bad record, a
    /// parameter neither side would accept.
    TlsHandshakeFailed,
    /// The transport underneath TLS failed or ended mid-handshake.
    TlsTransportFailed,
};

/// How to establish trust in the server's certificate.
pub const Ca = union(enum) {
    /// Verify against a caller-owned bundle. The usual case.
    bundle: Bundle,
    /// Accept any valid self-signed certificate. This authenticates nothing —
    /// anyone can sign their own certificate — and exists for test origins.
    self_signed,
    /// Verify nothing at all. Named to be conspicuous in a diff: a connection
    /// made this way is encrypted against a passive observer and worthless
    /// against an active one.
    ///
    /// It also changes what you are talking to. std omits the SNI extension
    /// entirely when host verification is off, so against a name-based
    /// virtual host or a CDN the handshake either fails or terminates at a
    /// DIFFERENT origin than the URL names, with only the HTTP `Host:` header
    /// left to tell them apart. Measured: `https://example.com/` answers 200
    /// through `bundle` and 404 through this arm. `self_signed` keeps SNI.
    insecure_no_verification,

    /// The trust anchors, plus the two things std's verifier needs and this
    /// library will not create: somewhere to allocate, and a lock, because a
    /// bundle is meant to be loaded once and shared across connections.
    ///
    /// The caller loads it — `bundle.rescan(gpa, io, .now(io, .real))` — and
    /// owns it for at least as long as the fetch.
    pub const Bundle = struct {
        gpa: std.mem.Allocator,
        lock: *Io.RwLock,
        certificates: *std.crypto.Certificate.Bundle,
    };
};

/// Optional out-parameter for the detail the four-error API deliberately
/// drops.
///
/// Collapsing forty-five errors into four is right for a caller DECIDING what
/// to do, and wrong for a human working out why. std keeps the same
/// distinction — its `Options.alert` exists for exactly this — so the detail
/// is available on request and never in the way.
pub const Diagnostics = struct {
    /// std's own error, before `classify` grouped it.
    raw: ?anyerror = null,
    /// The alert the peer sent, when it sent one.
    alert: ?std.crypto.tls.Alert = null,
};

/// Policy, separate from the buffers: what a caller sets once and passes to
/// every request.
pub const Config = struct {
    ca: Ca,
    /// Written on failure when present. Borrowed only for the handshake.
    diagnostics: ?*Diagnostics = null,
    /// Whether a stream that ends without `close_notify` is a clean end.
    ///
    /// Left FALSE on purpose. The whole of rule 7 is that a truncated answer
    /// must not be indistinguishable from a complete one, and this is that
    /// rule at the TLS layer: without close_notify an attacker who can cut
    /// the connection chooses where the body ends. std's own note says the
    /// application layer may take over the check "such as HTTP with the
    /// Content-Length header" — which this parser does enforce exactly — but
    /// a close-delimited body has no length to check against, and that is
    /// precisely the case where truncation is undetectable above TLS.
    ///
    /// `fetch` makes that the common case rather than the rare one: it sends
    /// `connection: close` on every request, so any https response without
    /// Content-Length or chunked framing IS close-delimited and depends on the
    /// origin sending close_notify before FIN. An origin that does not will
    /// fail here where plain HTTP would have quietly succeeded — which is the
    /// trade rule 7 asks for, stated so nobody has to rediscover it.
    allow_truncation_attacks: bool = false,
};

pub const Params = struct {
    io: Io,
    /// The encrypted side: whatever transport was dialed. BOTH buffers must
    /// be at least `buffer_bytes_min`, because each holds one whole ciphertext
    /// record — `init` checks them rather than letting std assert.
    input: *Io.Reader,
    output: *Io.Writer,
    /// Verified against the certificate unless `ca` says not to verify.
    host: []const u8,
    /// Plaintext buffers. `read_buffer` bounds the longest response head line
    /// the parser above can ever see, exactly as the socket's buffer does on
    /// the plain-HTTP path.
    read_buffer: []u8,
    /// Bounds how much request body is staged before it is encrypted. Unlike
    /// the ciphertext buffers it has no minimum: it is ordinary writer
    /// scratch, and a small one costs extra records, not correctness.
    write_buffer: []u8,
    config: Config,
};

/// One TLS session over an injected transport.
pub const Transport = struct {
    client: std.crypto.tls.Client,
    /// What `Connection` writes into, and the reason this is not simply
    /// `&client.writer`.
    ///
    /// `std.crypto.tls.Client.flush` encrypts the plaintext into the SOCKET
    /// writer's buffer and stops there; getting those bytes onto the wire is
    /// a second flush that std.http.Client performs by hand. A caller of
    /// `Connection` cannot be asked to know that — `writeRequest` ends in
    /// `out.flush()` and must mean it — so `flush` here does both steps.
    /// Unbuffered on purpose: it forwards straight through, and a buffer of
    /// its own would be a third copy of every request for no benefit.
    plaintext_out: Io.Writer,

    /// In-place init through an out-pointer: `Client` is over a kilobyte of
    /// cipher state, and it embeds the very `Io.Reader` and `Io.Writer` whose
    /// addresses the caller takes next. Returning it by value would copy all
    /// of that for no reason.
    ///
    /// Performs the handshake, so it talks to the peer and can block. The
    /// whole-request deadline (rule 3) covers it, because it covers
    /// everything between `fetch` being called and the response arriving.
    pub fn init(target: *Transport, params: Params) Error!void {
        assert(params.host.len > 0);
        assert(params.read_buffer.len > 0);
        // A bundle that was never `rescan`d trusts nothing, and the resulting
        // TlsCertificateNotVerified is indistinguishable from a genuinely
        // untrusted peer — in `Diagnostics` too. That is caller state, not
        // wire input, so it is an assertion and not an error.
        if (params.config.ca == .bundle) {
            assert(params.config.ca.bundle.certificates.map.count() > 0);
        }

        // Checked, not asserted: a caller can reach these with a buffer that
        // is merely too small, and an assertion would be a panic in release
        // and a dependency's panic in debug.
        if (params.input.buffer.len < buffer_bytes_min) return error.TlsBufferTooSmall;
        if (params.output.buffer.len < buffer_bytes_min) return error.TlsBufferTooSmall;

        // Through `Io`, not around it: both backends are first class, and a
        // client that reached for the OS CSPRNG directly would be one more
        // thing zio could not schedule or a test could not control. std reads
        // the entropy during init and does not capture the pointer.
        var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        params.io.random(&entropy);

        if (params.config.diagnostics) |d| d.* = .{};
        var alert: std.crypto.tls.Alert = undefined;

        target.client = std.crypto.tls.Client.init(params.input, params.output, .{
            .host = switch (params.config.ca) {
                // Verifying the name against a chain nobody vouched for is
                // theatre, and std refuses the combination anyway.
                .insecure_no_verification => .no_verification,
                .bundle, .self_signed => .{ .explicit = params.host },
            },
            .ca = switch (params.config.ca) {
                .insecure_no_verification => .no_verification,
                .self_signed => .self_signed,
                .bundle => |b| .{ .bundle = .{
                    .gpa = b.gpa,
                    .io = params.io,
                    .lock = b.lock,
                    .bundle = b.certificates,
                } },
            },
            .read_buffer = params.read_buffer,
            .write_buffer = params.write_buffer,
            .entropy = &entropy,
            .realtime_now = .now(params.io, .real),
            .allow_truncation_attacks = params.config.allow_truncation_attacks,
            .alert = &alert,
        }) catch |err| {
            if (params.config.diagnostics) |d| {
                d.raw = err;
                // std populates the alert only for error.TlsAlert; reading it
                // otherwise would report an uninitialised value as fact.
                if (err == error.TlsAlert) d.alert = alert;
            }
            return classify(err);
        };

        target.plaintext_out = .{
            // `rebase` is explicit because the default one loops on
            // `buffer.len - end < minimum_len`, which a zero-length buffer can
            // never satisfy: an assertion failure in safe builds and a spin in
            // ReleaseFast. std sets `failingRebase` on `Writer.fixed` for the
            // same reason. Nothing on today's path reaches it — `writeRequest`
            // only prints, writes and flushes — but `writableSlice` would, and
            // an error beats a hang.
            .vtable = &.{ .drain = drain, .flush = flush, .rebase = Io.Writer.failingRebase },
            .buffer = &.{},
        };
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        // Unbuffered, so there is never anything of ours held back and the
        // "consume the buffer first" half of the contract is vacuous.
        assert(w.end == 0);
        assert(w.buffer.len == 0);

        const transport: *Transport = @alignCast(@fieldParentPtr("plaintext_out", w));
        return forward(&transport.client.writer, data, splat);
    }

    /// One `drain` call forwarded to `target`, returning what the `Io.Writer`
    /// contract asks for: every byte consumed from `data`, the splat pattern
    /// counted `splat` times, and nothing counted from a buffer.
    ///
    /// A free function taking primitive arguments so a test can drive it
    /// against any writer. The multi-slice and splat-not-1 paths are the
    /// subtle half of that contract and `writeRequest` exercises neither —
    /// it sends one slice at a time, every time.
    fn forward(target: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        assert(data.len > 0);

        const head = data[0 .. data.len - 1];
        var written: usize = 0;
        for (head) |bytes| {
            try target.writeAll(bytes);
            written += bytes.len;
        }
        // The last element is the splat pattern and is NOT part of `head`, so
        // a splat of zero correctly writes and counts nothing.
        const pattern = data[head.len];
        for (0..splat) |_| try target.writeAll(pattern);

        return written + pattern.len * splat;
    }

    fn flush(w: *Io.Writer) Io.Writer.Error!void {
        const transport: *Transport = @alignCast(@fieldParentPtr("plaintext_out", w));

        // Two steps, and the second is the one that is easy to miss: the TLS
        // writer's own flush only encrypts into the socket writer's buffer.
        // Leaving the bytes there is a request that never reaches the wire and
        // a response that never comes — which is exactly how the live gate
        // reported it, as an UnexpectedEof out of the parser.
        try transport.client.writer.flush();
        assert(transport.client.writer.end == 0);

        try transport.client.output.flush();
        assert(transport.client.output.end == 0);
    }

    /// The plaintext side, which is all `Connection` ever sees.
    pub fn reader(transport: *Transport) *Io.Reader {
        return &transport.client.reader;
    }

    pub fn writer(transport: *Transport) *Io.Writer {
        return &transport.plaintext_out;
    }

    /// Sends `close_notify`, which is what lets the PEER tell a finished
    /// session from a truncation attack — the same courtesy this end insists
    /// on by default. Best-effort by nature: it is called while tearing the
    /// connection down, the socket may already be gone, and there is no
    /// recovery that would change the outcome.
    /// std's detail for a failure AFTER the handshake, which `Diagnostics`
    /// cannot reach: a truncated or corrupted record mid-body arrives at the
    /// caller as a bare `error.ReadFailed`. Given that truncation is refused
    /// by default, this is the failure most likely to be seen in production
    /// and the one a bare ReadFailed explains least.
    pub fn readError(transport: *const Transport) ?std.crypto.tls.Client.ReadError {
        return transport.client.read_err;
    }

    pub fn close(transport: *Transport) void {
        // `end` encrypts close_notify into the socket writer's buffer; the
        // flush is what actually sends it, for the same reason as above.
        transport.client.end() catch return;
        transport.client.output.flush() catch {};
    }
};

/// Collapses std's forty-five handshake errors into the four a caller can act
/// on. Exhaustive with no `else`, so a toolchain that adds a member breaks the
/// build here instead of silently landing in whichever bucket looked closest.
fn classify(err: std.crypto.tls.Client.InitError) Error {
    return switch (err) {
        error.CertificateExpired,
        error.CertificateFieldHasInvalidLength,
        error.CertificateFieldHasWrongDataType,
        error.CertificateHasInvalidBitString,
        error.CertificateHasUnrecognizedObjectId,
        error.CertificateHostMismatch,
        error.CertificateIssuerMismatch,
        error.CertificateNotYetValid,
        error.CertificatePublicKeyInvalid,
        error.CertificateSignatureAlgorithmMismatch,
        error.CertificateSignatureAlgorithmUnsupported,
        error.CertificateSignatureInvalid,
        error.CertificateSignatureInvalidLength,
        error.CertificateSignatureNamedCurveUnsupported,
        error.CertificateSignatureUnsupportedBitCount,
        error.CertificateTimeInvalid,
        error.SignatureVerificationFailed,
        error.InvalidSignature,
        error.TlsCertificateNotVerified,
        error.UnsupportedCertificateVersion,
        => error.TlsCertificateInvalid,

        error.IdentityElement,
        error.InsufficientEntropy,
        error.InvalidEncoding,
        error.MessageTooLong,
        error.NegativeIntoUnsigned,
        error.NonCanonical,
        error.NotSquare,
        error.TlsAlert,
        error.TlsBadRecordMac,
        error.TlsBadRsaSignatureBitCount,
        error.TlsBadSignatureScheme,
        error.TlsDecodeError,
        error.TlsDecryptError,
        error.TlsDecryptFailure,
        error.TlsIllegalParameter,
        error.TlsRecordOverflow,
        error.TlsUnexpectedMessage,
        error.WeakPublicKey,
        => error.TlsHandshakeFailed,

        error.BufferTooSmall,
        error.TargetTooSmall,
        => error.TlsBufferTooSmall,

        error.Canceled => error.Canceled,

        error.DiskQuota,
        error.LockViolation,
        error.NotOpenForWriting,
        error.ReadFailed,
        error.TlsConnectionTruncated,
        error.WriteFailed,
        => error.TlsTransportFailed,
    };
}

// ---------------------------------------------------------------------------
// tests
//
// A handshake needs a peer, and std ships no TLS server, so what can be tested
// without a network is the seam and the refusals. The real handshake is
// `zig build tls-smoke`, which dials a live origin and is deliberately not
// part of `zig build test`.

const t = std.testing;

test "buffers too small to hold a record are refused, not asserted" {
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // One byte short on each side in turn. std would assert on the reader and
    // fail obscurely on the writer; both must come back as our own error.
    var small: [buffer_bytes_min - 1]u8 = undefined;
    var big: [buffer_bytes_min]u8 = undefined;
    var plaintext: [256]u8 = undefined;

    var reader_small: Io.Reader = .fixed(&small);
    var writer_big: Io.Writer = .fixed(&big);
    var transport: Transport = undefined;
    try t.expectError(error.TlsBufferTooSmall, transport.init(.{
        .io = io,
        .input = &reader_small,
        .output = &writer_big,
        .host = "example.com",
        .read_buffer = &plaintext,
        .write_buffer = &plaintext,
        .config = .{ .ca = .insecure_no_verification },
    }));

    var reader_big: Io.Reader = .fixed(&big);
    var writer_small: Io.Writer = .fixed(&small);
    try t.expectError(error.TlsBufferTooSmall, transport.init(.{
        .io = io,
        .input = &reader_big,
        .output = &writer_small,
        .host = "example.com",
        .read_buffer = &plaintext,
        .write_buffer = &plaintext,
        .config = .{ .ca = .insecure_no_verification },
    }));
}

test "a peer that says nothing fails the handshake rather than hanging" {
    var threaded: Io.Threaded = .init(t.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A properly sized transport that is simply at end-of-stream, so the size
    // check passes and std really does run a handshake against silence. An
    // earlier version of this test used `Reader.fixed("")`, whose buffer is
    // the data — zero bytes — so it tripped the size check instead and tested
    // the same thing as the test above under a name claiming otherwise.
    var in_buf: [buffer_bytes_min]u8 = undefined;
    var in = SegmentedReader.init("", 1, null, &in_buf);
    var out_buf: [buffer_bytes_min]u8 = undefined;
    var out: Io.Writer = .fixed(&out_buf);
    var plaintext_in: [buffer_bytes_min]u8 = undefined;
    var plaintext_out: [1024]u8 = undefined;

    var transport: Transport = undefined;
    const result = transport.init(.{
        .io = io,
        .input = &in.interface,
        .output = &out,
        .host = "example.com",
        .read_buffer = &plaintext_in,
        .write_buffer = &plaintext_out,
        .config = .{ .ca = .insecure_no_verification },
    });
    // It must fail, and as one of OURS — the point of `classify` is that no
    // std error escapes this file. Which of the four is std's business.
    try t.expectError(error.TlsTransportFailed, result);
}

test "the writer wrapper honours the Io.Writer drain contract" {
    // `writeRequest` sends one slice with splat 1, every time, so the live
    // gate never exercises the multi-slice or splat paths at all. This drives
    // `forward` directly, which is why it is a free function.
    var collected: Io.Writer.Allocating = .init(t.allocator);
    defer collected.deinit();

    // Multi-slice with a splat of 1: everything is consumed and counted.
    const n = try Transport.forward(&collected.writer, &.{ "GET ", "/x", "\r\n" }, 1);
    try t.expectEqual(@as(usize, 8), n);
    try t.expectEqualStrings("GET /x\r\n", collected.written());

    // A splat of zero writes and counts nothing from the pattern.
    const zero = try Transport.forward(&collected.writer, &.{ "a", "PAD" }, 0);
    try t.expectEqual(@as(usize, 1), zero);
    try t.expectEqualStrings("GET /x\r\na", collected.written());

    // A splat of N repeats the pattern N times and counts it N times.
    const many = try Transport.forward(&collected.writer, &.{ "b", "-" }, 3);
    try t.expectEqual(@as(usize, 4), many);
    try t.expectEqualStrings("GET /x\r\nab---", collected.written());

    // The probe `Io.Writer.defaultRebase` makes: one empty pattern, splat 1,
    // which must consume nothing. std asserts this returns 0.
    const probe = try Transport.forward(&collected.writer, &.{""}, 1);
    try t.expectEqual(@as(usize, 0), probe);
}

test "classify covers every InitError member" {
    // The switch in `classify` is exhaustive, so this compiles only while that
    // stays true — the test is the compile. Spot-check the mapping's shape.
    try t.expectEqual(Error.TlsCertificateInvalid, classify(error.CertificateExpired));
    try t.expectEqual(Error.TlsCertificateInvalid, classify(error.CertificateHostMismatch));
    try t.expectEqual(Error.TlsHandshakeFailed, classify(error.TlsAlert));
    try t.expectEqual(Error.TlsTransportFailed, classify(error.TlsConnectionTruncated));
    try t.expectEqual(Error.TlsBufferTooSmall, classify(error.BufferTooSmall));
}
