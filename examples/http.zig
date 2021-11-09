const std = @import("std");
const serve = @import("serve");
const network = @import("network");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    defer _ = gpa.deinit();

    try network.init();
    defer network.deinit();

    const allocator = &gpa.allocator;

    var listener = try serve.HttpListener.init(allocator);
    defer listener.deinit();

    try listener.addEndpoint(.{ .ipv4 = .{ 0, 0, 0, 0 } }, 80);
    try listener.addSecureEndpoint(
        .{ .ipv4 = .{ 0, 0, 0, 0 } },
        443,
        "examples/data/cert.pem",
        "examples/data/key.pem",
        .{},
    );

    try listener.start();
    defer listener.stop();

    while (true) {
        var context = try listener.getContext();
        defer context.deinit();

        try context.response.setStatusCode(.ok);
        try context.response.setHeader("Content-Type", "text/plain");

        var stream = try context.response.writer();
        try stream.writeAll("Hello, World!\r\n");
        try stream.print("You requested the url {}", .{context.request.url});
        try stream.writeAll("Other headers are:\n");

        var it = context.response.headers.iterator();
        while (it.next()) |header| {
            try stream.print("{s}: {s}", .{ header.key_ptr.*, header.value_ptr.* });
        }
    }
}
