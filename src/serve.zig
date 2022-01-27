const std = @import("std");
const uri = @import("uri");
const network = @import("network");

pub const Url = uri.UriComponents;

pub const TlsCore = @import("TlsCore.zig");
pub const TlsClient = TlsCore.Client;

pub usingnamespace @import("gopher.zig");
pub usingnamespace @import("gemini.zig");
pub usingnamespace @import("http.zig");

pub const initTls = TlsCore.startup;
pub const deinitTls = TlsCore.shutdown;

pub const IP = union(enum) {
    pub const any_v4 = @This(){ .ipv4 = .{ 0, 0, 0, 0 } };

    ipv4: [4]u8,
    ipv6: void,
    // host: []const u8,

    pub fn convertToNetwork(self: IP) network.Address {
        return switch (self) {
            .ipv4 => |val| network.Address{ .ipv4 = network.Address.IPv4{ .value = val } },
            .ipv6 => @panic("not implemented yet!"),
        };
    }
};

pub const defaults = struct {
    pub const gopher_port = 70;
    pub const gemini_port = 1965;
    pub const http_port = 80;
    pub const https_port = 443;
};
