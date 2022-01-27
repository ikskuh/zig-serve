const std = @import("std");
const network = @import("network");
const serve = @import("serve.zig");
const logger = std.log.scoped(.serve_gopher);

pub const GopherListener = struct {
    const Binding = struct {
        address: network.Address,
        port: u16,
        socket: ?network.Socket,
    };

    allocator: std.mem.Allocator,
    bindings: std.ArrayList(Binding),

    /// Normalize incoming paths for the client, so a query to `"/"`, `"//"` and `""` are equivalent and will all receive
    /// `"/"` as the path.
    normalize_paths: bool = true,

    pub fn init(allocator: std.mem.Allocator) !GopherListener {
        return GopherListener{
            .allocator = allocator,
            .bindings = std.ArrayList(Binding).init(allocator),
        };
    }

    pub fn deinit(self: *GopherListener) void {
        for (self.bindings.items) |*bind| {
            if (bind.socket) |*sock| {
                sock.close();
            }
        }
        self.bindings.deinit();
        self.* = undefined;
    }

    const AddEndpointError = error{ AlreadyExists, AlreadyStarted, OutOfMemory };
    pub fn addEndpoint(self: *GopherListener, target_ip: serve.IP, port: u16) AddEndpointError!void {
        for (self.bindings.items) |*bind| {
            if (bind.socket != null)
                return error.AlreadyStarted;
        }

        var bind = Binding{
            .address = target_ip.convertToNetwork(),
            .port = port,
            .socket = null,
        };
        for (self.bindings.items) |*other| {
            if (std.meta.eql(other.*, bind))
                return error.AlreadyExists;
        }

        try self.bindings.append(bind);
    }

    pub const StartError = std.os.SocketError || std.os.BindError || std.os.ListenError || error{ NoBindings, AlreadyStarted };
    pub fn start(self: *GopherListener) StartError!void {
        if (self.bindings.items.len == 0) {
            return error.NoBindings;
        }
        for (self.bindings.items) |*bind| {
            if (bind.socket != null)
                return error.AlreadyStarted;
        }

        errdefer for (self.bindings.items) |*bind| {
            if (bind.socket) |*sock| {
                sock.close();
            }
            bind.socket = null;
        };
        for (self.bindings.items) |*bind| {
            var sock = try network.Socket.create(std.meta.activeTag(bind.address), .tcp);
            errdefer sock.close();

            sock.enablePortReuse(true) catch |e| logger.err("Failed to enable port reuse: {s}", .{@errorName(e)});

            try sock.bind(.{ .address = bind.address, .port = bind.port });

            try sock.listen();

            bind.socket = sock;
        }
    }

    pub fn stop(self: *GopherListener) void {
        for (self.bindings.items) |*bind| {
            if (bind.socket) |*sock| {
                sock.close();
            }
            bind.socket = null;
        }
    }

    const GetContextError = std.os.PollError || std.os.AcceptError || network.Socket.Reader.Error || error{ UnsupportedAddressFamily, NotStarted, OutOfMemory, EndOfStream, StreamTooLong };
    pub fn getContext(self: *GopherListener) GetContextError!*GopherContext {
        for (self.bindings.items) |*bind| {
            if (bind.socket == null)
                return error.NotStarted;
        }

        var set = try network.SocketSet.init(self.allocator);
        defer set.deinit();

        while (true) {
            for (self.bindings.items) |*bind| {
                try set.add(bind.socket.?, .{ .read = true, .write = false });
            }

            const events = try network.waitForSocketEvent(&set, null);
            std.debug.assert(events >= 1);

            var any_error = false;

            for (self.bindings.items) |*bind| {
                if (set.isReadyRead(bind.socket.?)) {
                    return self.acceptContext(bind.socket.?) catch |e| {
                        logger.warn("Invalid incoming connection: {s}", .{@errorName(e)});
                        any_error = true;
                        continue;
                    };
                }
            }

            // This means something very terrible has gone wrong
            std.debug.assert(any_error);
        }
    }

    fn acceptContext(self: *GopherListener, sock: network.Socket) !*GopherContext {
        var client_sock: network.Socket = try sock.accept();
        errdefer client_sock.close();

        var url_buffer: [4096]u8 = undefined;

        var reader = client_sock.reader();
        var path = try reader.readUntilDelimiter(&url_buffer, '\n');
        if (std.mem.endsWith(u8, path, "\r"))
            path = path[0 .. path.len - 1];

        logger.info("request for {s}", .{path});

        var temp_arena = std.heap.ArenaAllocator.init(self.allocator);

        const context = try temp_arena.allocator().create(GopherContext);

        context.* = GopherContext{
            .memory = temp_arena,
            .request = undefined,
            .response = undefined,
        };
        errdefer context.memory.deinit();

        context.request = GopherRequest{
            .path = try context.memory.allocator().dupeZ(u8, path),
        };

        context.response = GopherResponse{
            .socket = client_sock,
            .buffered_stream = GopherResponse.BufferedWriter{ .unbuffered_writer = context.response.socket.writer() },
        };

        return context;
    }
};

pub const GopherContext = struct {
    memory: std.heap.ArenaAllocator,

    request: GopherRequest,
    response: GopherResponse,

    fn finalize(self: *GopherContext) !void {
        if (self.response.is_binary) {
            var writer = self.response.buffered_stream.writer();
            try writer.writeAll("\r\n.\r\n");
        }
        try self.response.buffered_stream.flush();
    }

    pub fn deinit(self: *GopherContext) void {
        self.finalize() catch |e| logger.warn("Failed to finalize connection: {s}", .{@errorName(e)});

        self.response.socket.close();

        var copy = self.memory;
        copy.deinit();
    }
};

pub const GopherRequest = struct {
    path: [:0]const u8,
};

pub const GopherResponse = struct {
    pub const buffer_size = 1024;

    const BufferedWriter = std.io.BufferedWriter(buffer_size, network.Socket.Writer);

    socket: network.Socket,

    buffered_stream: BufferedWriter,

    is_writing: bool = false,
    is_binary: bool = false,

    pub fn setBinary(self: *GopherResponse, binary: bool) !void {
        std.debug.assert(!self.is_writing);
        self.is_binary = binary;
    }

    pub fn writer(self: *GopherResponse) !BufferedWriter.Writer {
        self.is_writing = true;
        return self.buffered_stream.writer();
    }
};

pub fn gopherMap(writer: anytype, hostname: []const u8, port: u16) GopherMap(@TypeOf(writer)) {
    return GopherMap(@TypeOf(writer)){
        .writer = writer,
        .hostname = hostname,
        .port = port,
    };
}

pub fn GopherMap(comptime Writer: type) type {
    return struct {
        const Self = @This();

        writer: Writer,
        hostname: []const u8,
        port: u16 = 70,

        pub fn entry(map: Self, data: Entry) !void {
            const hostname = data.hostname orelse map.hostname;
            const port = data.port orelse map.port;
            try map.writer.print("{c}{s}\t{s}\t{s}\t{d}\r\n", .{
                @enumToInt(data.kind),
                data.display,
                data.selector,
                hostname,
                port,
            });
        }

        pub fn info(self: Self, msg: []const u8) !void {
            try self.entry(Entry{
                .kind = .informational,
                .display = msg,
                .selector = "",
            });
        }

        pub fn print(map: Self, comptime fmt: []const u8, args: anytype) !void {
            try map.writer.writeAll("i");
            try map.writer.print(fmt, args);
            try map.writer.print("\t\t{s}\t{}\r\n", .{
                map.hostname,
                map.port,
            });
        }

        pub const Entry = GopherMapShared.Entry;
        pub const EntryKind = GopherMapShared.EntryKind;
    };
}

pub const GopherMapShared = struct {
    pub const Entry = struct {
        kind: EntryKind,
        display: []const u8,
        selector: []const u8,
        hostname: ?[]const u8 = null,
        port: ?u16 = null,
    };

    pub const EntryKind = enum(u8) {
        text = '0', // Text file
        submenu = '1', // Gopher submenu
        ccso_nameserver = '2', // CCSO Nameserver
        error_code = '3', // Error code returned by a Gopher server to indicate failure
        bin_hex = '4', // BinHex-encoded file (primarily for Macintosh computers)
        dos_file = '5', // DOS file
        uuencoded = '6', // uuencoded file
        full_text_search = '7', // Gopher full-text search
        telnet = '8', // Telnet
        binary = '9', // Binary file
        alternate_server = '+', // Mirror or alternate server (for load balancing or in case of primary server downtime)
        gif = 'g', // GIF file
        image = 'I', // Image file
        telnet_3270 = 'T', // Telnet 3270
        // gopher+ types
        bitmap = ':', // Bitmap image
        movie = ';', // Movie file
        sound = '<', // Sound file
        // Non-canonical types
        document = 'd', // Doc. Seen used alongside PDF's and .DOC's
        html = 'h', // HTML file
        informational = 'i', // Informational message, widely used.[23]
        wav = 's', // Sound file (especially the WAV format)
    };
};
