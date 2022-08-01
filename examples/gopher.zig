const std = @import("std");
const serve = @import("serve");
const network = @import("network");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    defer _ = gpa.deinit();

    try network.init();
    defer network.deinit();

    const allocator = gpa.allocator();

    var listener = try serve.GopherListener.init(allocator);
    defer listener.deinit();

    try listener.addEndpoint(.{ .ipv4 = .{ 0, 0, 0, 0 } }, 7070);

    try listener.start();
    defer listener.stop();

    std.log.info("gopher server ready.", .{});

    while (true) {
        var context = try listener.getContext();
        defer context.deinit();

        try context.response.setBinary(false);

        if (std.mem.eql(u8, context.request.path, "/source")) {
            var stream = try context.response.writer();
            try stream.writeAll(@embedFile(@src().file));
        } else if (std.mem.eql(u8, context.request.path, "/cat")) {
            try context.response.setBinary(true);

            var stream = try context.response.writer();
            try stream.writeAll(@embedFile("data/cat.gif"));
        } else if (std.mem.startsWith(u8, context.request.path, "URL:")) {
            const template =
                \\<!DOCTYPE html>
                \\<html>
                \\<head>
                \\    <title>Non-gopher link detected</title>
                \\</head>
                \\<body style="margin: 1em 2em 1em 2em; background-color: #D0E0FF; color: #101010;">
                \\    <table style="margin-left: auto; margin-right: auto; width: 70%; border: 1px solid black; padding: 1.5em 1.1em 1.5em 1.1em; background-color: #E0F0FF;">
                \\    <tr>
                \\        <td>
                \\        <p style="text-align: center; font-size: 1.3em; margin: 0 0 2em 0;">A non-gopher link has been detected.</p>
                \\        <p style="text-align: justify; margin: 0 0 0 0;">It appears that you clicked on a non-gopher link, which will make you use another protocol from now on (typically HTTP). Your gopher journey ends here.</p>
                \\        <p style="text-align: center; margin: 0.8em 0 0 0;">Click on the link below to continue:</p>
                \\        <p style="text-align: center; font-size: 1.1em; margin: 0.8em 0 0 0;"><a href="{[url]s}" style="color: #0000F0;">{[url]s}</a></p>
                \\        </td>
                \\    </tr>
                \\    </table>
                \\</body>
                \\</html>
            ;
            var stream = try context.response.writer();
            try stream.print(template, .{
                .url = context.request.path[4..],
            });
        } else {
            const writer = try context.response.writer();
            var map = serve.GopherMap(@TypeOf(writer)){
                .writer = writer,
                .hostname = "localhost",
                .port = 7070,
            };

            try map.info("Hello, Gopher!");
            try map.info("");
            try map.info("This gopher server was written in ⚡️Zig⚡️.");
            try map.info("");
            try map.print("You requested the path '{s}'", .{context.request.path});
            try map.info("");
            try map.info("Links:");
            try map.entry(.{
                .kind = .text,
                .display = "Server Source Code",
                .selector = "/source",
            });
            try map.entry(.{
                .kind = .html,
                .display = "Zig web presence",
                .selector = "URL:https://ziglang.org/",
            });
            try map.entry(.{
                .kind = .gif,
                .display = "Cat Picture",
                .selector = "/cat",
            });
        }
    }
}
