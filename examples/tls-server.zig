const std = @import("std");
const serve = @import("serve");
const network = @import("network");

const logger = std.log;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    defer _ = gpa.deinit();

    try network.init();
    defer network.deinit();

    try serve.initTls();
    defer serve.deinitTls();

    var tls_server = try serve.TlsCore.init();
    defer tls_server.deinit();

    try tls_server.useCertifcateFile("examples/data/cert.pem");
    try tls_server.usePrivateKeyFile("examples/data/key.pem");

    const allocator = &gpa.allocator;

    var listener = try network.Socket.create(.ipv4, .tcp);
    defer listener.close();

    try listener.enablePortReuse(true);

    try listener.bindToPort(1337);

    try listener.listen();

    _ = allocator;

    logger.info("ready.", .{});

    while (true) {
        var child = try listener.accept();
        defer child.close();

        const remote = child.getRemoteEndPoint() catch undefined;
        logger.info("new client from {}.", .{remote});

        var tls_client = try tls_server.accept(&child);
        defer tls_client.close();

        var reader = tls_client.reader();
        var writer = tls_client.writer();

        var buffer: [1024]u8 = undefined;

        const read_len = try reader.read(&buffer);
        logger.info("client sends '{s}'", .{buffer[0..@intCast(usize, read_len)]});

        const response = "20 text/gemini\r\n" ++
            \\# zig-serve
            \\Hello, ⚡️Ziguanas⚡️!
            \\This is the first zig-written gemini server that doesn't require a TLS proxy or anything.
            \\It uses 🐺WolfSSL🐺.
            \\
            \\Check out these projects:
            \\=> https://github.com/ziglang/zig ⚡️ Ziglang
            \\=> https://github.com/wolfSSL/wolfssl 🐺 WolfSSL
            \\
        ;

        try writer.writeAll(response);
    }
}
