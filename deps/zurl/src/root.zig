//! zurl — an experimental std.Io-native HTTP/1.1 client.
//!
//! Start with docs/DESIGN.md: eight rules, each traceable to an incident that
//! cost the zgix benchmark a real run. The short version:
//!
//!   * bodies go to a `Sink`; there is no way to forget one
//!   * framing (content-length / chunked / close-delimited, bodyless
//!     statuses, TE-beats-CL) is the library's job, never the caller's
//!   * the deadline is whole-request, enforced by Io cancellation, identical
//!     on `Io.Threaded` and zio
//!   * a `Connection` is a `*Io.Reader` + `*Io.Writer` — TLS and zio are
//!     transports and runtimes injected from outside, never dependencies
//!
//! Layers, bottom up:
//!   `parser`     — head + framed body delivery; zero-allocation
//!   `Connection` — request/response exchanges over an injected transport
//!   `tls`        — std.crypto.tls spliced into the transport, nothing more
//!   `fetch`      — URL in, deadline-bounded response out (http and https)

const std = @import("std");

pub const parser = @import("parser.zig");
pub const retry = @import("retry.zig");
pub const url = @import("url.zig");
pub const auth = @import("auth.zig");
pub const RetryAfter = retry.RetryAfter;
pub const Head = parser.Head;
pub const HeadOptions = parser.HeadOptions;

pub const LineSink = @import("sink.zig").LineSink;

const conn_mod = @import("connection.zig");
pub const Connection = conn_mod.Connection;
pub const Request = conn_mod.Request;
pub const Response = conn_mod.Response;
pub const StatusClass = conn_mod.StatusClass;
pub const Sink = conn_mod.Sink;
pub const Header = conn_mod.Header;
pub const writeRequest = conn_mod.writeRequest;
pub const RequestError = conn_mod.RequestError;
pub const default_user_agent = conn_mod.default_user_agent;
pub const validateTarget = conn_mod.validateTarget;

pub const tls = @import("tls.zig");

const client = @import("client.zig");
pub const session = @import("session.zig");
pub const Session = session.Session;

pub const fetch = client.fetch;
pub const FetchRequest = client.FetchRequest;
pub const default_deadline_ns = client.default_deadline_ns;

test {
    std.testing.refAllDecls(@This());
    // Not exported: test and fuzz infrastructure, reachable only so that
    // `zig build test` runs the fuzz oracle over its seed corpus.
    _ = @import("fuzz.zig");
}
