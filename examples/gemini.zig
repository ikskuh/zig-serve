const std = @import("std");
const serve = @import("serve");
const network = @import("network");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    defer _ = gpa.deinit();

    try network.init();
    defer network.deinit();

    try serve.initTls();
    defer serve.deinitTls();

    const allocator = &gpa.allocator;

    var listener = try serve.GeminiListener.init(allocator);
    defer listener.deinit();

    try listener.addEndpoint(
        .{ .ipv4 = .{ 0, 0, 0, 0 } },
        1965,
        "examples/data/cert.pem",
        "examples/data/key.pem",
    );

    try listener.start();
    defer listener.stop();

    std.log.info("gemini server ready.", .{});

    while (true) {
        var context = try listener.getContext();
        defer context.deinit();

        try context.response.setStatusCode(.success);

        if (std.mem.eql(u8, "/source.zig", context.request.url.path orelse "")) {
            try context.response.setMeta("text/zig");

            var stream = try context.response.writer();
            try stream.writeAll(@embedFile(@src().file));
        } else {
            try context.response.setMeta("text/gemini");

            var stream = try context.response.writer();
            try stream.writeAll("# zig-serve\n");

            try stream.writeAll(
                \\Hello, ⚡️Ziguanas⚡️!
                \\This is a zig-written gemini server that doesn't require a TLS proxy or anything.
                \\It uses 🐺WolfSSL🐺.
                \\
                \\Check out these projects:
                \\=> https://github.com/ziglang/zig ⚡️ Ziglang
                \\=> https://github.com/wolfSSL/wolfssl 🐺 WolfSSL
                \\
                \\
            );

            try stream.print("You requested a url that looks like this:\n", .{});
            inline for (std.meta.fields(serve.Url)) |fld| {
                const field_format = switch (fld.field_type) {
                    u16 => "{d}",
                    ?u16 => "{d}",
                    []const u8 => "{s}",
                    ?[]const u8 => "{s}",
                    else => @compileError("Unsupported field type: " ++ @typeName(fld.field_type)),
                };
                try stream.print("* {s}: " ++ field_format ++ "\n", .{ fld.name, @field(context.request.url, fld.name) });
            }

            try stream.writeAll(
                \\
                \\=> /source.zig Also, check out the source code of this!
                \\
            );
        }
    }
}
