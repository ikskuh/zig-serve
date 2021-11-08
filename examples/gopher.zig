const std = @import("std");
const serve = @import("serve");
const network = @import("network");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    defer _ = gpa.deinit();

    try network.init();
    defer network.deinit();

    const allocator = &gpa.allocator;

    var listener = try serve.GopherListener.init(allocator);
    defer listener.deinit();

    try listener.addEndpoint(.{ .ipv4 = .{ 0, 0, 0, 0 } }, 7070);

    try listener.start();
    defer listener.stop();

    while (true) {
        var context = try listener.getContext();
        defer context.deinit();

        try context.response.setBinary(false);

        var stream = try context.response.writer();
        try stream.writeAll("Hello, World!\r\n");
        try stream.print("You requested the path {s}", .{context.request.path});
    }
}
