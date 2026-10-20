//! RFC 9113 section 8.3: which pseudo-header fields may appear, where, and how
//! many times — and section 8.2.2's connection-specific fields.
//!
//! Where `syntax.zig` asks whether a string is a legal field name, this asks
//! whether a *message* is well-formed. Those are different questions with
//! different shapes: the first is a pure function of one string, and this one
//! needs to remember what it has already seen.
//!
//! ## Fed one field at a time, on purpose
//!
//! The decoder is an iterator, and the fields it emits borrow from a buffer the
//! caller is free to reuse on the next step. A validator taking a `[]const
//! Field` would force a consumer to materialize a whole block first, which is
//! the allocation this package spends its design on avoiding.
//!
//! So nothing here retains a slice across a call. Where a later rule depends on
//! an earlier field's *value* — whether the method was CONNECT, whether the
//! scheme was http-like, whether the path was empty — the bit is computed while
//! the field is in hand and only the bit is kept. That is the same lifetime
//! rule `Field` states, enforced rather than restated.
//!
//! ## What is checked here and what is not
//!
//! Checked: every rule in section 8.3 that the field block decides on its own —
//! that pseudo-header fields are defined, are the ones defined for this
//! direction, precede every regular field, do not repeat, and that the
//! mandatory ones are present; section 8.5's restrictions on CONNECT; and
//! section 8.2.2's connection-specific fields, which is where a
//! `transfer-encoding` smuggled through an HTTP/1.1 downgrade would be caught.
//!
//! Not checked, because none of it is decidable from a field block alone:
//! whether `:authority` and a `Host` header identify the same entity (section
//! 8.3.1 wants both normalized as URIs), whether `:authority` carries the
//! deprecated userinfo subcomponent, whether a `content-length` matches the
//! DATA frames that follow it (section 8.1.1), and whether a method or status
//! is one that exists. The first two want a URI parser and the last two want
//! connection state; both belong to a consumer.
//!
//! ## Malformed is always the same answer
//!
//! Section 8.1.1: every violation here is "a stream error (Section 5.4.2) of
//! type PROTOCOL_ERROR". There is deliberately no `errorCode` or `severity`
//! function to go with these errors, unlike `frame.Header`, because there is
//! nothing for one to decide — the errors are distinguished so a consumer can
//! log which rule broke, not so it can answer the peer differently.

const std = @import("std");

const Field = @import("../hpack/Field.zig");
const syntax = @import("syntax.zig");

const MessageValidator = @This();

const assert = @import("../assert.zig").assert;

/// Which set of pseudo-header fields is defined for this field block.
pub const Kind = enum {
    /// A HEADERS or PUSH_PROMISE field block opening a request.
    request,
    /// A HEADERS field block opening a response, interim ones included.
    response,
    /// A trailer section. Section 8.3: "Pseudo-header fields MUST NOT appear
    /// in a trailer section" — so every one of them is misplaced here, in
    /// either direction.
    trailer,
};

/// RFC 9113 section 8.3's pseudo-header fields, plus RFC 8441's `:protocol`.
pub const Pseudo = enum {
    // Section 8.3.1, defined for requests.
    method,
    scheme,
    authority,
    path,
    // Section 8.3.2, defined for responses.
    status,
    /// RFC 8441 section 4: the extended CONNECT protocol, which exists only on
    /// a connection where the server sent `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
    /// That is connection state this package does not hold, so `Options` takes
    /// it as a parameter — the check stays here and the decision stays with the
    /// consumer.
    protocol,

    /// Whether this one is defined for requests. Section 8.3: "Pseudo-header
    /// fields defined for requests MUST NOT appear in responses; pseudo-header
    /// fields defined for responses MUST NOT appear in requests."
    pub fn forRequest(pseudo: Pseudo) bool {
        return pseudo != .status;
    }

    /// The wire name, colon included.
    pub fn name(pseudo: Pseudo) []const u8 {
        const wire = pseudoName(pseudo);
        // A pseudo-header name is a colon and at least one more octet, which is
        // what `syntax.validateName` requires of one and what the comptime
        // block below checks against the registry.
        assert(wire.len >= 2);
        assert(wire[0] == syntax.pseudo_prefix);
        return wire;
    }

    fn pseudoName(pseudo: Pseudo) []const u8 {
        return switch (pseudo) {
            .method => ":method",
            .scheme => ":scheme",
            .authority => ":authority",
            .path => ":path",
            .status => ":status",
            .protocol => ":protocol",
        };
    }
};

/// The pseudo-header names, resolved by a perfect hash rather than by a chain
/// of comparisons.
const pseudo_names = std.StaticStringMap(Pseudo).initComptime(.{
    .{ ":method", .method },
    .{ ":scheme", .scheme },
    .{ ":authority", .authority },
    .{ ":path", .path },
    .{ ":status", .status },
    .{ ":protocol", .protocol },
});

/// One bit per `Pseudo`, which is what makes "seen already" and "present at the
/// end" the same piece of state.
const Set = std.EnumSet(Pseudo);

comptime {
    // The map and the enum have to stay in step: a pseudo-header added to one
    // and not the other would be silently unrecognized, which under section 8.3
    // means silently rejected as undefined.
    assert(pseudo_names.kvs.len == std.enums.values(Pseudo).len);
    for (std.enums.values(Pseudo)) |pseudo| {
        assert(pseudo_names.get(pseudo.name()).? == pseudo);
        // Every pseudo-header name is one `syntax.validateName` accepts, or a
        // conforming message would be rejected before it got here.
        syntax.validateName(pseudo.name(), .strict) catch unreachable;
    }
}

/// RFC 9113 section 8.2.2's connection-specific header fields, which "MUST be
/// treated as malformed".
///
/// This is the other half of the downgrade guard. `transfer-encoding` arriving
/// over HTTP/2 and forwarded into HTTP/1.1 is the classic request-smuggling
/// desync, and section 8.2.2 exists so that it never gets that far.
const connection_specific = std.StaticStringMap(void).initComptime(.{
    .{"connection"},
    .{"proxy-connection"},
    .{"keep-alive"},
    .{"transfer-encoding"},
    .{"upgrade"},
});

/// The one value section 8.2.2 permits in a `te` field, and the one kind of
/// block it permits the field in.
///
/// `te` is not in section 8.2.2's parenthetical list, but it *is* in RFC 9110
/// section 7.6.1's, which that parenthetical points at — and section 8.2.2 then
/// writes "the only exception to this is the TE header field, which MAY be
/// present in an HTTP/2 request". That sentence has work to do only if `te`
/// would otherwise be banned, so it is: permitted in a request, and
/// connection-specific everywhere else.
///
/// A trailer section counts as everywhere else. `Kind.trailer` does not carry a
/// direction, and the exception is written for a request's *header* section;
/// transfer-coding negotiation after the content has been sent means nothing in
/// any case. That is the conservative reading of an ambiguity, taken because
/// this package writes to the stricter consumer's threat model.
const te_field_name = "te";
const te_permitted_value = "trailers";

/// RFC 9113 section 8.5's method, compared exactly: RFC 9110 section 9.1 says
/// "the method token is case-sensitive", so `connect` is a different method
/// and not a sloppy spelling of this one.
const connect_method = "CONNECT";

/// The two schemes section 8.3.1's non-empty-`:path` rule is written for,
/// compared without regard to case: RFC 3986 section 3.1 says schemes are
/// case-insensitive and that an implementation "should accept uppercase letters
/// as equivalent to lowercase in scheme names (e.g., allow 'HTTP' as well as
/// 'http')". A case-sensitive comparison here would let `HTTPS` with an empty
/// `:path` through, which is the accept-a-malformed-message direction.
const path_bearing_schemes = [_][]const u8{ "http", "https" };

pub const Options = struct {
    kind: Kind,
    /// Which reading of section 8.2.1 to apply to every name and value. See
    /// `syntax.Rules`; the choice is the consumer's.
    rules: syntax.Rules,
    /// Whether `SETTINGS_ENABLE_CONNECT_PROTOCOL` is in force on this
    /// connection (RFC 8441). False makes `:protocol` an undefined
    /// pseudo-header, which is what section 8.3 requires of one that was never
    /// negotiated.
    extended_connect: bool = false,
};

pub const Error = syntax.NameError || syntax.ValueError || error{
    /// A pseudo-header field this document does not define (section 8.3).
    UnknownPseudo,
    /// A pseudo-header field defined for the other direction, or any
    /// pseudo-header field at all in a trailer section (section 8.3).
    MisplacedPseudo,
    /// A pseudo-header field after a regular one (section 8.3).
    PseudoAfterRegular,
    /// The same pseudo-header field name twice in one field block (section
    /// 8.3).
    DuplicatePseudo,
    /// A connection-specific header field (section 8.2.2).
    ConnectionSpecific,
    /// A `te` field with a value other than `trailers` (section 8.2.2).
    UnsupportedTe,
    /// An empty value on a pseudo-header field that must carry one. Section
    /// 8.3.1 asks for "exactly one *valid* value", and section 8.5 for an
    /// `:authority` naming a host and port; `:path` is exempt because whether
    /// an empty one is legal depends on the scheme.
    EmptyPseudo,
};

pub const FinishError = error{
    /// A mandatory pseudo-header field is absent: `:method`, `:scheme` or
    /// `:path` on a non-CONNECT request (section 8.3.1), or `:status` on a
    /// response (section 8.3.2).
    MissingPseudo,
    /// A pseudo-header field this particular message must not carry: `:scheme`
    /// or `:path` on a CONNECT request that has no `:protocol` (section 8.5),
    /// or `:protocol` on a request whose method is not CONNECT (RFC 8441
    /// section 4).
    ForbiddenPseudo,
    /// An empty `:path` under an `http` or `https` scheme (section 8.3.1).
    EmptyPath,
};

kind: Kind,
rules: syntax.Rules,
extended_connect: bool,
/// Which pseudo-header fields have been offered, which serves as both the
/// duplicate check and the presence check.
seen: Set,
/// Section 8.3's ordering rule needs only this one bit.
regular_seen: bool,
/// Derived from values while they were in hand, never from a retained slice.
/// See the lifetime note at the top of this file.
method_is_connect: bool,
scheme_is_http: bool,
path_is_empty: bool,
/// Whether `finish` has run, so that using a validator past its end is a
/// programming error rather than a wrong answer.
finished: bool,

comptime {
    // The lifetime rule at the top of this file, enforced rather than promised.
    // A borrowed slice is a `.pointer` in Zig's type info whether it is a slice
    // or a single item, so a struct with no pointer and no optional field has
    // nothing a caller's buffer reuse could invalidate — and adding one later
    // fails the build here instead of failing in a proxy.
    for (@typeInfo(MessageValidator).@"struct".field_types) |FieldType| {
        const kind = @typeInfo(FieldType);
        assert(kind != .pointer);
        assert(kind != .optional);
    }
}

pub fn init(options: Options) MessageValidator {
    const validator: MessageValidator = .{
        .kind = options.kind,
        .rules = options.rules,
        .extended_connect = options.extended_connect,
        .seen = .empty,
        .regular_seen = false,
        .method_is_connect = false,
        .scheme_is_http = false,
        .path_is_empty = false,
        .finished = false,
    };
    // The type's whole correctness rests on starting with nothing seen: `seen`
    // is both the duplicate check and the presence check, so a validator that
    // began non-empty would accept a request missing a pseudo-header it thinks
    // it already has.
    assert(validator.seen.count() == 0);
    assert(!validator.regular_seen);
    assert(!validator.finished);
    return validator;
}

/// Offer the next field of the block, in the order it was decoded.
///
/// Order matters to the answer — section 8.3's ordering and duplicate rules are
/// about position — so a caller that reorders fields before calling this is
/// asking a different question than the one the RFC poses.
///
/// A validator is spent once this returns an error. Section 8.1.1 makes every
/// violation here a malformed message, and a malformed message is refused whole
/// — there is no partial verdict to keep collecting. The distinct errors exist
/// so a consumer can say in a log *which* rule broke, not so it can carry on
/// past one; the state after a rejection is not defined and `finish` is not
/// meaningful on it.
pub fn field(validator: *MessageValidator, offered: *const Field) Error!void {
    assert(!validator.finished);
    assert(validator.kind != .trailer or validator.seen.count() == 0);

    // Section 8.2.1 first. Everything below compares names against lowercase
    // literals with no case folding, which is only sound because both readings
    // reject every uppercase octet — so this ordering is a correctness
    // dependency, not a preference.
    try syntax.validateName(offered.name, validator.rules);
    try syntax.validateValue(offered.value, validator.rules);
    assert(offered.name.len >= 1);

    if (offered.name[0] != syntax.pseudo_prefix) return validator.regularField(offered);
    return validator.pseudoField(offered);
}

fn pseudoField(validator: *MessageValidator, offered: *const Field) Error!void {
    assert(offered.name[0] == syntax.pseudo_prefix);

    // Section 8.3: "All pseudo-header fields MUST appear in a field block
    // before all regular field lines."
    if (validator.regular_seen) return error.PseudoAfterRegular;

    const which = pseudo_names.get(offered.name) orelse return error.UnknownPseudo;
    // RFC 8441's `:protocol` is defined only where it was negotiated. Section
    // 8.3 makes anything else an undefined pseudo-header rather than a
    // misplaced one, which is the distinction a consumer's log wants.
    if (which == .protocol and !validator.extended_connect) return error.UnknownPseudo;

    switch (validator.kind) {
        // Section 8.3: pseudo-header fields "MUST NOT appear in a trailer
        // section", both directions alike.
        .trailer => return error.MisplacedPseudo,
        .request => if (!which.forRequest()) return error.MisplacedPseudo,
        .response => if (which.forRequest()) return error.MisplacedPseudo,
    }

    // Section 8.3: "The same pseudo-header field name MUST NOT appear more than
    // once in a field block."
    if (validator.seen.contains(which)) return error.DuplicatePseudo;
    validator.seen.insert(which);
    assert(validator.seen.contains(which));
    // Nothing on this path may start the regular section, which is what makes
    // the ordering check above sound for every field after this one.
    assert(!validator.regular_seen);

    // The three bits later rules need, taken now because the slices they come
    // from are only good until the caller's next decode step.
    // Section 8.3.1: requests "MUST include exactly one valid value" for the
    // mandatory pseudo-header fields, and section 8.5 wants an `:authority`
    // that "contains the host and port to connect to". No value at all is not
    // a valid one, and this is the cheapest half of that rule — see the
    // "What is checked here" note above for the half left to a consumer.
    // `:path` is exempt because whether an empty one is legal depends on the
    // scheme, which is `finishOrdinary`'s question.
    if (which != .path and offered.value.len == 0) return error.EmptyPseudo;

    switch (which) {
        .method => validator.method_is_connect = std.mem.eql(u8, offered.value, connect_method),
        .scheme => validator.scheme_is_http = isPathBearingScheme(offered.value),
        .path => validator.path_is_empty = offered.value.len == 0,
        .authority, .status, .protocol => {},
    }
}

fn regularField(validator: *MessageValidator, offered: *const Field) Error!void {
    assert(offered.name.len >= 1);
    assert(offered.name[0] != syntax.pseudo_prefix);

    // Section 8.2.2. These apply to a trailer section too: the text forbids
    // generating "an HTTP/2 message containing connection-specific header
    // fields" without carving out trailers.
    if (connection_specific.has(offered.name)) return error.ConnectionSpecific;

    // Section 8.2.2's one exception: "the TE header field, which MAY be present
    // in an HTTP/2 request; when it is, it MUST NOT contain any value other
    // than 'trailers'." See `te_permitted_value` for why the direction is part
    // of the rule rather than only the value.
    if (std.mem.eql(u8, offered.name, te_field_name)) {
        if (validator.kind != .request) return error.ConnectionSpecific;
        // Case-insensitively: RFC 9110 section 10.1.4 defines the value through
        // ABNF, and RFC 5234 section 2.3 makes ABNF string literals
        // case-insensitive, so `TRAILERS` is a conforming spelling that this
        // package has no business refusing.
        if (!std.ascii.eqlIgnoreCase(offered.value, te_permitted_value)) return error.UnsupportedTe;
    }

    // Set last, so that a field this function refused cannot make a later
    // pseudo-header look out of order. A caller is meant to stop at the first
    // error either way — see `field` — but a rule that only holds when the
    // caller behaves is a rule with a hole in it.
    validator.regular_seen = true;
}

/// Whether a scheme is one section 8.3.1's non-empty-`:path` rule speaks about.
fn isPathBearingScheme(scheme: []const u8) bool {
    for (path_bearing_schemes) |candidate| {
        if (std.ascii.eqlIgnoreCase(scheme, candidate)) return true;
    }
    return false;
}

/// Check what only the end of a field block can decide: which pseudo-header
/// fields had to be there, and which had to not be.
///
/// Separate from `field` because presence is not decidable until the block is
/// over — pseudo-header fields may appear in any order among themselves, so a
/// CONNECT request's `:method` can arrive after the `:path` that its presence
/// makes illegal.
pub fn finish(validator: *MessageValidator) FinishError!void {
    assert(!validator.finished);
    validator.finished = true;
    // A trailer section reached `field` for every pseudo-header and refused it,
    // so there is nothing here for the presence rules to find.
    if (validator.kind == .trailer) assert(validator.seen.count() == 0);
    // Only a request can have carried a method, and only a method can have been
    // CONNECT.
    if (validator.method_is_connect) assert(validator.kind == .request);
    if (validator.method_is_connect) assert(validator.seen.contains(.method));

    switch (validator.kind) {
        // Section 8.3 constrains what a trailer section may not carry, and
        // `field` has already refused all of it. There is nothing a trailer
        // section is required to contain.
        .trailer => return,
        .request => return validator.finishRequest(),
        // Section 8.3.2: ":status" "MUST be included in all responses,
        // including interim responses; otherwise, the response is malformed".
        .response => if (!validator.seen.contains(.status)) return error.MissingPseudo,
    }
}

fn finishRequest(validator: *MessageValidator) FinishError!void {
    assert(validator.kind == .request);
    assert(validator.finished);

    // Three shapes, and which one applies is decided by `:protocol` first.
    // RFC 8441 section 4 *modifies* section 8.5 for a request that carries it,
    // so reading section 8.5's rules first — as this did — applies the classic
    // restrictions to an extended CONNECT and rejects every legal
    // WebSocket-over-HTTP/2 request.
    if (validator.seen.contains(.protocol)) return validator.finishExtendedConnect();
    if (validator.method_is_connect) return validator.finishConnect();
    return validator.finishOrdinary();
}

/// RFC 8441 section 4: CONNECT with a `:protocol`.
fn finishExtendedConnect(validator: *MessageValidator) FinishError!void {
    // `field` refuses `:protocol` outright when the extension was not
    // negotiated, so reaching here means it was.
    assert(validator.extended_connect);
    assert(validator.seen.contains(.protocol));

    // "A new pseudo-header field :protocol MAY be included on request HEADERS
    // indicating the desired protocol to be spoken on the tunnel created by
    // CONNECT" — so there has to be a CONNECT for it to modify.
    if (!validator.method_is_connect) return error.ForbiddenPseudo;
    assert(validator.seen.contains(.method));

    // "On requests that contain the :protocol pseudo-header field, the :scheme
    // and :path pseudo-header fields of the target URI MUST also be included."
    // This is the exact inverse of section 8.5, which is why it is checked
    // before section 8.5 rather than after.
    if (!validator.seen.contains(.scheme)) return error.MissingPseudo;
    if (!validator.seen.contains(.path)) return error.MissingPseudo;

    // `:authority` is not required: RFC 8441 has it "interpreted according to
    // Section 8.1.2.3 of [RFC7540] instead of Section 8.3", which is to say as
    // an ordinary request's authority rather than as a tunnel destination, and
    // section 8.3.1's mandatory list does not include it.
    return validator.checkPath();
}

/// RFC 9113 section 8.5: CONNECT without a `:protocol`.
fn finishConnect(validator: *MessageValidator) FinishError!void {
    assert(validator.method_is_connect);
    assert(validator.seen.contains(.method));
    assert(!validator.seen.contains(.protocol));

    // "The ':scheme' and ':path' pseudo-header fields MUST be omitted."
    if (validator.seen.contains(.scheme)) return error.ForbiddenPseudo;
    if (validator.seen.contains(.path)) return error.ForbiddenPseudo;

    // "The ':authority' pseudo-header field contains the host and port to
    // connect to." A CONNECT without one names no destination, and `field` has
    // already refused an empty one.
    if (!validator.seen.contains(.authority)) return error.MissingPseudo;
}

/// RFC 9113 section 8.3.1: everything that is not a CONNECT of either kind.
fn finishOrdinary(validator: *MessageValidator) FinishError!void {
    assert(!validator.method_is_connect);
    assert(!validator.seen.contains(.protocol));

    // "All HTTP/2 requests MUST include exactly one valid value for the
    // ':method', ':scheme', and ':path' pseudo-header fields, unless they are
    // CONNECT requests." `field` has already refused a second one of any and an
    // empty value on the first two, so what is left here is presence.
    if (!validator.seen.contains(.method)) return error.MissingPseudo;
    if (!validator.seen.contains(.scheme)) return error.MissingPseudo;
    if (!validator.seen.contains(.path)) return error.MissingPseudo;

    return validator.checkPath();
}

/// Section 8.3.1's rule on an empty `:path`, shared by the two shapes that
/// require a `:path` at all.
fn checkPath(validator: *const MessageValidator) FinishError!void {
    assert(validator.seen.contains(.path));

    // ":path" "MUST NOT be empty for 'http' or 'https' URIs". Restricted to
    // those two because the section is: ":scheme" is not limited to them, and a
    // translated request for some other scheme is not this rule's business.
    // Section 8.3.1's two exceptions need no code — asterisk-form OPTIONS sends
    // a ":path" of "*", which is not empty, and CONNECT omits ":path", which
    // never reaches here.
    if (validator.scheme_is_http and validator.path_is_empty) return error.EmptyPath;
}

const testing = std.testing;

/// Run a whole block through a fresh validator, which is how every case below
/// is stated: a list of fields and one verdict.
fn check(options: Options, block: []const Field) (Error || FinishError)!void {
    var validator: MessageValidator = .init(options);
    for (block) |offered| try validator.field(&offered);
    try validator.finish();
}

const request: Options = .{ .kind = .request, .rules = .strict };
const response: Options = .{ .kind = .response, .rules = .strict };
const trailer: Options = .{ .kind = .trailer, .rules = .strict };
const extended: Options = .{ .kind = .request, .rules = .strict, .extended_connect = true };

const minimal_request = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":path", .value = "/" },
};

test "an ordinary request and an ordinary response are accepted" {
    try check(request, &(minimal_request ++ [_]Field{
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "accept", .value = "*/*" },
    }));
    try check(response, &[_]Field{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/html" },
    });
}

test "a pseudo-header after a regular field is malformed" {
    try testing.expectError(error.PseudoAfterRegular, check(request, &[_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":path", .value = "/" },
    }));
    // The rule is about position, not about which pseudo-header: a repeat of
    // one already seen still reports the ordering violation, because that is
    // the check the octets reach first.
    try testing.expectError(error.PseudoAfterRegular, check(request, &[_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":method", .value = "GET" },
    }));
}

test "a refused regular field does not start the regular section" {
    // `regular_seen` is set only for a field this validator accepted, so a
    // caller that logged an error and carried on cannot be told a later
    // pseudo-header is out of order because of a field that never counted.
    var validator: MessageValidator = .init(request);
    try testing.expectError(error.ConnectionSpecific, validator.field(&.{
        .name = "connection",
        .value = "keep-alive",
    }));
    for (minimal_request) |offered| try validator.field(&offered);
    try validator.finish();
}

test "a repeated pseudo-header is malformed, a repeated regular field is not" {
    try testing.expectError(error.DuplicatePseudo, check(request, &[_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    }));
    // Section 8.3's rule is about pseudo-header fields alone; ordinary fields
    // repeat all the time and RFC 9110 section 5.2 says what that means.
    try check(request, &(minimal_request ++ [_]Field{
        .{ .name = "accept", .value = "text/html" },
        .{ .name = "accept", .value = "text/plain" },
    }));
}

test "each direction refuses the other's pseudo-headers" {
    try testing.expectError(error.MisplacedPseudo, check(request, &[_]Field{
        .{ .name = ":status", .value = "200" },
    }));
    for ([_][]const u8{ ":method", ":scheme", ":path", ":authority" }) |name| {
        try testing.expectError(error.MisplacedPseudo, check(response, &[_]Field{
            .{ .name = ":status", .value = "200" },
            .{ .name = name, .value = "x" },
        }));
    }
}

test "a trailer section carries no pseudo-header at all" {
    for ([_][]const u8{ ":method", ":scheme", ":path", ":authority", ":status" }) |name| {
        try testing.expectError(error.MisplacedPseudo, check(trailer, &[_]Field{
            .{ .name = name, .value = "x" },
        }));
    }
    // And is required to contain nothing.
    try check(trailer, &[_]Field{});
    try check(trailer, &[_]Field{.{ .name = "expires", .value = "0" }});
}

test "a pseudo-header this document does not define is malformed" {
    try testing.expectError(error.UnknownPseudo, check(request, &[_]Field{
        .{ .name = ":authorityy", .value = "x" },
    }));
    // `:Method` fails on the octets before it reaches the registry, and `:` is
    // an empty name — the point is only that neither is accepted.
    try testing.expectError(error.Character, check(request, &[_]Field{
        .{ .name = ":Method", .value = "x" },
    }));
    try testing.expectError(error.Empty, check(request, &[_]Field{
        .{ .name = ":", .value = "x" },
    }));
}

test "the mandatory pseudo-headers are required" {
    // One at a time, by leaving each out of an otherwise complete request.
    for (0..minimal_request.len) |omitted| {
        var block: [minimal_request.len - 1]Field = undefined;
        var next: usize = 0;
        for (minimal_request, 0..) |offered, index| {
            if (index == omitted) continue;
            block[next] = offered;
            next += 1;
        }
        try testing.expectError(error.MissingPseudo, check(request, &block));
    }
    try testing.expectError(error.MissingPseudo, check(response, &[_]Field{
        .{ .name = "content-type", .value = "text/html" },
    }));
    try testing.expectError(error.MissingPseudo, check(response, &[_]Field{}));
}

test "a pseudo-header that must carry a value may not be empty" {
    // Section 8.3.1 asks for "exactly one *valid* value", and no value is not
    // one. Presence alone would accept every block below.
    for ([_][]const u8{ ":method", ":scheme", ":authority", ":status" }) |name| {
        const kind: Options = if (std.mem.eql(u8, name, ":status")) response else request;
        try testing.expectError(error.EmptyPseudo, check(kind, &[_]Field{
            .{ .name = name, .value = "" },
        }));
    }
    // A CONNECT whose authority is empty names no destination either, which is
    // the case the section 8.5 branch's own comment claims to have covered.
    try testing.expectError(error.EmptyPseudo, check(request, &[_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "" },
    }));
    // `:path` is the exemption: whether an empty one is legal is the scheme's
    // question, not this one's.
    try check(request, &[_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "ftp" },
        .{ .name = ":path", .value = "" },
    });
}

test "CONNECT omits scheme and path and names an authority" {
    const connect: Field = .{ .name = ":method", .value = "CONNECT" };
    const authority: Field = .{ .name = ":authority", .value = "www.example.com:443" };
    try check(request, &[_]Field{ connect, authority });

    try testing.expectError(error.ForbiddenPseudo, check(request, &[_]Field{
        connect, authority, .{ .name = ":scheme", .value = "https" },
    }));
    try testing.expectError(error.ForbiddenPseudo, check(request, &[_]Field{
        connect, authority, .{ .name = ":path", .value = "/" },
    }));
    try testing.expectError(error.MissingPseudo, check(request, &[_]Field{connect}));
}

test "the CONNECT restrictions hold whatever order the method arrives in" {
    // The reason `finish` exists. Pseudo-header fields may appear in any order
    // among themselves, so `:path` can be offered before the `:method` whose
    // value makes it illegal — a validator deciding at `field` time would
    // accept this block.
    try testing.expectError(error.ForbiddenPseudo, check(request, &[_]Field{
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com:443" },
        .{ .name = ":method", .value = "CONNECT" },
    }));
}

test "extended CONNECT requires the scheme and path that plain CONNECT forbids" {
    // RFC 8441 section 4 modifies section 8.5 rather than living beside it, so
    // these two blocks differ only by `:protocol` and get opposite verdicts.
    // This is the WebSocket-over-HTTP/2 request a browser sends.
    try check(extended, &[_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/chat" },
    });
    // "On requests that contain the :protocol pseudo-header field, the :scheme
    // and :path pseudo-header fields of the target URI MUST also be included."
    for ([_][]const u8{ ":scheme", ":path" }) |omitted| {
        var block: [4]Field = .{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/chat" },
        };
        // Overwrite the omitted one with an authority, keeping the block legal
        // in every other respect.
        for (&block) |*offered| {
            if (std.mem.eql(u8, offered.name, omitted)) {
                offered.* = .{ .name = ":authority", .value = "example.com" };
            }
        }
        try testing.expectError(error.MissingPseudo, check(extended, &block));
    }
    // And `:authority` is not required of one, because RFC 8441 has it read as
    // an ordinary request's authority rather than as a tunnel destination.
    try check(extended, &[_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
    });
}

test "extended CONNECT is off until the connection says otherwise" {
    const block = [_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try check(extended, &block);
    // Without the setting, RFC 8441's pseudo-header was never negotiated and
    // section 8.3 makes it undefined rather than misplaced.
    try testing.expectError(error.UnknownPseudo, check(request, &block));
    // And with the setting, it still belongs only to CONNECT.
    try testing.expectError(error.ForbiddenPseudo, check(extended, &(minimal_request ++ [_]Field{
        .{ .name = ":protocol", .value = "websocket" },
    })));
}

test "an empty path is malformed under http and https whatever their case" {
    // RFC 3986 section 3.1: schemes are case-insensitive, and an implementation
    // "should accept uppercase letters as equivalent to lowercase in scheme
    // names". A case-sensitive comparison here would accept a malformed
    // message, which is the direction that matters.
    for ([_][]const u8{ "http", "https", "HTTPS", "HtTp" }) |scheme| {
        try testing.expectError(error.EmptyPath, check(request, &[_]Field{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = scheme },
            .{ .name = ":path", .value = "" },
        }));
    }
    // Section 8.3.1 restricts the rule to those two schemes, and says ":scheme"
    // is not restricted to them.
    try check(request, &[_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "ftp" },
        .{ .name = ":path", .value = "" },
    });
    // Asterisk-form OPTIONS, which section 8.3.1 names as an exception, sends a
    // ":path" of "*" and so needs no exception here.
    try check(request, &[_]Field{
        .{ .name = ":method", .value = "OPTIONS" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "*" },
    });
    // The rule reaches an extended CONNECT too, which is the other shape that
    // carries a ":path".
    try testing.expectError(error.EmptyPath, check(extended, &[_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "" },
    }));
}

test "the method is compared case-sensitively" {
    // RFC 9110 section 9.1: "the method token is case-sensitive". `connect` is
    // a different method, so section 8.5's restrictions do not apply to it and
    // section 8.3.1's do.
    try testing.expectError(error.MissingPseudo, check(request, &[_]Field{
        .{ .name = ":method", .value = "connect" },
        .{ .name = ":authority", .value = "www.example.com:443" },
    }));
    try check(request, &[_]Field{
        .{ .name = ":method", .value = "connect" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    });
}

test "connection-specific header fields are malformed in every kind of block" {
    for ([_][]const u8{ "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade" }) |name| {
        try testing.expectError(error.ConnectionSpecific, check(request, &(minimal_request ++ [_]Field{
            .{ .name = name, .value = "x" },
        })));
        try testing.expectError(error.ConnectionSpecific, check(trailer, &[_]Field{
            .{ .name = name, .value = "x" },
        }));
        try testing.expectError(error.ConnectionSpecific, check(response, &[_]Field{
            .{ .name = ":status", .value = "200" },
            .{ .name = name, .value = "x" },
        }));
    }
}

test "te carries trailers in any case, in a request, or nothing" {
    // RFC 5234 section 2.3 makes ABNF string literals case-insensitive, so
    // every spelling of the one permitted value is permitted.
    for ([_][]const u8{ "trailers", "TRAILERS", "Trailers" }) |value| {
        try check(request, &(minimal_request ++ [_]Field{
            .{ .name = "te", .value = value },
        }));
    }
    for ([_][]const u8{ "gzip", "trailers, deflate", "", "trailer", "trailerss" }) |value| {
        try testing.expectError(error.UnsupportedTe, check(request, &(minimal_request ++ [_]Field{
            .{ .name = "te", .value = value },
        })));
    }
    // Section 8.2.2's exception names a request and nothing else, so `te`
    // elsewhere is an ordinary connection-specific field even at the one value
    // a request may carry.
    try testing.expectError(error.ConnectionSpecific, check(response, &[_]Field{
        .{ .name = ":status", .value = "200" },
        .{ .name = "te", .value = "trailers" },
    }));
    try testing.expectError(error.ConnectionSpecific, check(trailer, &[_]Field{
        .{ .name = "te", .value = "trailers" },
    }));
}

test "the octet rules run before the message rules" {
    // A connection-specific name carrying a CR must report the CR: the field is
    // refused either way, but a consumer logging a smuggling attempt needs the
    // reason that names one.
    try testing.expectError(error.Delimiter, check(request, &(minimal_request ++ [_]Field{
        .{ .name = "transfer-encoding", .value = "chunked\r\nx: y" },
    })));
    try testing.expectError(error.Character, check(request, &(minimal_request ++ [_]Field{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    })));
}

test "no value is retained across a call" {
    // The lifetime rule this type is built around: a validator must survive its
    // caller overwriting every buffer between fields. Each field here is copied
    // into one scratch array that the next field then overwrites.
    var scratch: [64]u8 = undefined;
    var validator: MessageValidator = .init(request);
    for ([_][2][]const u8{
        .{ ":method", "CONNECT" },
        .{ ":authority", "www.example.com:443" },
    }) |pair| {
        @memcpy(scratch[0..pair[0].len], pair[0]);
        const name = scratch[0..pair[0].len];
        @memcpy(scratch[pair[0].len..][0..pair[1].len], pair[1]);
        const value = scratch[pair[0].len..][0..pair[1].len];
        try validator.field(&.{ .name = name, .value = value });
        @memset(&scratch, '?');
    }
    // The CONNECT-ness of the method has to have outlived the octets it came
    // from, or this would fail for want of `:scheme` and `:path`.
    try validator.finish();
}

test "both readings of section 8.2.1 are available to a message" {
    const lax: Options = .{ .kind = .request, .rules = .minimal };
    const block = minimal_request ++ [_]Field{.{ .name = "x/y", .value = "z" }};
    try check(lax, &block);
    try testing.expectError(error.Character, check(request, &block));
}
