const std = @import("std");
const network = @import("network");
const serve = @import("serve.zig");
const logger = std.log.scoped(.gopher);

pub const GopherListener = struct {
    const Binding = struct {
        address: network.Address,
        port: u16,
        socket: ?network.Socket,
    };

    allocator: *std.mem.Allocator,
    bindings: std.ArrayList(Binding),

    /// Normalize incoming paths for the client, so a query to `"/"`, `"//"` and `""` are equivalent and will all receive
    /// `"/"` as the path.
    normalize_paths: bool = true,

    pub fn init(allocator: *std.mem.Allocator) !GopherListener {
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
    pub fn getContext(self: *GopherListener) GetContextError!GopherContext {
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

    fn acceptContext(self: *GopherListener, sock: network.Socket) !GopherContext {
        var client_sock: network.Socket = try sock.accept();
        errdefer client_sock.close();

        var url_buffer: [2048]u8 = undefined;

        var reader = client_sock.reader();
        var path = try reader.readUntilDelimiter(&url_buffer, '\n');
        if (std.mem.endsWith(u8, path, "\r"))
            path = path[0 .. path.len - 1];

        logger.info("request for {s}", .{path});

        var context = GopherContext{
            .memory = std.heap.ArenaAllocator.init(self.allocator),
            .request = undefined,
            .response = undefined,
        };
        errdefer context.memory.deinit();

        context.request = GopherRequest{
            .path = try context.memory.allocator.dupeZ(u8, path),
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
        var writer = self.response.buffered_stream.writer();
        try writer.writeAll("\r\n.\r\n");

        try self.response.buffered_stream.flush();
    }

    pub fn deinit(self: *GopherContext) void {
        self.finalize() catch |e| logger.warn("Failed to finalize connection: {s}", .{@errorName(e)});

        self.response.socket.close();
        self.memory.deinit();
        self.* = undefined;
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
