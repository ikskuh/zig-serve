const std = @import("std");
const serve = @import("serve");
const network = @import("network");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    defer _ = gpa.deinit();

    try network.init();
    defer network.deinit();

    const allocator = gpa.allocator();

    var listener = try serve.HttpListener.init(allocator);
    defer listener.deinit();

    try listener.addEndpoint(.{ .ipv4 = .{ 0, 0, 0, 0 } }, 8080);
    try listener.addSecureEndpoint(
        .{ .ipv4 = .{ 0, 0, 0, 0 } },
        8443,
        "examples/data/cert.pem",
        "examples/data/key.pem",
    );

    try listener.start();
    defer listener.stop();

    while (true) {
        var context = try listener.getContext();
        defer context.deinit();

        if (std.mem.eql(u8, context.request.url, "/favicon.ico")) {
            try context.response.setStatusCode(.ok);
            try context.response.setHeader("Content-Type", "image/vnd.microsoft.icon");

            const writer = try context.response.writer();
            try writer.writeAll(@embedFile("data/favicon.ico"));
        } else if (std.mem.eql(u8, context.request.url, "/source.zig")) {
            try context.response.setStatusCode(.ok);
            try context.response.setHeader("Content-Type", "text/zig");

            const writer = try context.response.writer();
            try writer.writeAll(@embedFile(@src().file));
        } else if (std.mem.eql(u8, context.request.url, "/cat")) {
            try context.response.setStatusCode(.ok);
            try context.response.setHeader("Content-Type", "image/gif");

            var stream = try context.response.writer();
            try stream.writeAll(@embedFile("data/cat.gif"));
        } else {
            try context.response.setStatusCode(.ok);
            try context.response.setHeader("Content-Type", "text/html");

            var stream = try context.response.writer();

            try stream.writeAll(
                \\<!doctype html>
                \\<html lang="en">
                \\<head>
                \\  <meta charset="UTF-8">
                \\  <title>Zig Demo Server</title>
                \\</head>
                \\<body>
                \\  <h1>zig-serve</h1>
                \\  <p>Hello, HTTP world!</p>
                \\  <p>This http(s) server was written in ⚡️Zig⚡️.</p>
                \\  <p>Request Info:</p>
                \\  <p>
                \\
            );

            try stream.print("  URL:     <code>{s}</code><br>\n", .{context.request.url});
            try stream.print("  Method:  <code>{?}</code>, <code>{s}</code><br>\n", .{ context.request.method, context.request.method_string });
            try stream.print("  Version: <code>{}</code><br>\n", .{context.request.version});
            try stream.writeAll(
                \\  </p>
                \\  <p>Other headers are:</p>
                \\  <ul>
            );

            var it = context.request.headers.iterator();
            while (it.next()) |header| {
                try stream.print("    <li><code>{s}</code>: <code>{s}</code></li>\n", .{ header.key_ptr.*, header.value_ptr.* });
            }
            try stream.writeAll(
                \\  </ul>
                \\  <p>Also, check out these awesome links:</p>
                \\  <ul>
                \\      <li><a href="/source.zig">Server Source Code</a></li>
                \\      <li><a href="https://ziglang.org/">Zig Project</a></li>
                \\  </ul>
                \\  <p>Also, look at this picture of a <a href="/cat">cat.gif</a>:</p>
                \\  <img src="/cat">
                \\</body>
            );
        }
    }
}
