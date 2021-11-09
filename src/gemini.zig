const std = @import("std");
const network = @import("network");
const uri = @import("uri");
const serve = @import("serve.zig");
const logger = std.log.scoped(.serve_gemini);

pub const GeminiListener = struct {
    const Binding = struct {
        address: network.Address,
        port: u16,
        socket: ?network.Socket,
        tls: serve.TlsCore,
    };

    allocator: *std.mem.Allocator,
    bindings: std.ArrayList(Binding),

    /// Normalize incoming paths for the client, so a query to `"/"`, `"//"` and `""` are equivalent and will all receive
    /// `"/"` as the path.
    normalize_paths: bool = true,

    pub fn init(allocator: *std.mem.Allocator) !GeminiListener {
        return GeminiListener{
            .allocator = allocator,
            .bindings = std.ArrayList(Binding).init(allocator),
        };
    }

    pub fn deinit(self: *GeminiListener) void {
        for (self.bindings.items) |*bind| {
            bind.tls.deinit();
            if (bind.socket) |*sock| {
                sock.close();
            }
        }
        self.bindings.deinit();
        self.* = undefined;
    }

    const AddEndpointError = error{ AlreadyExists, AlreadyStarted, TlsError, InvalidCertificate, OutOfMemory };
    pub fn addEndpoint(
        self: *GeminiListener,
        target_ip: serve.IP,
        port: u16,
        certificate_file: []const u8,
        key_file: []const u8,
    ) AddEndpointError!void {
        for (self.bindings.items) |*bind| {
            if (bind.socket != null)
                return error.AlreadyStarted;
        }

        var tls = serve.TlsCore.init() catch return error.TlsError;
        errdefer tls.deinit();

        var temp = std.heap.ArenaAllocator.init(self.allocator);
        defer temp.deinit();

        tls.useCertifcateFile(try temp.allocator.dupeZ(u8, certificate_file)) catch return error.InvalidCertificate;
        tls.usePrivateKeyFile(try temp.allocator.dupeZ(u8, key_file)) catch return error.InvalidCertificate;

        var bind = Binding{
            .address = target_ip.convertToNetwork(),
            .port = port,
            .socket = null,
            .tls = tls,
        };
        for (self.bindings.items) |*other| {
            if (std.meta.eql(other.*, bind))
                return error.AlreadyExists;
        }

        try self.bindings.append(bind);
    }

    pub const StartError = std.os.SocketError || std.os.BindError || std.os.ListenError || error{ NoBindings, AlreadyStarted };
    pub fn start(self: *GeminiListener) StartError!void {
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

    pub fn stop(self: *GeminiListener) void {
        for (self.bindings.items) |*bind| {
            if (bind.socket) |*sock| {
                sock.close();
            }
            bind.socket = null;
        }
    }

    const GetContextError = std.os.PollError || std.os.AcceptError || network.Socket.Reader.Error || error{ UnsupportedAddressFamily, NotStarted, OutOfMemory, EndOfStream, StreamTooLong };
    pub fn getContext(self: *GeminiListener) GetContextError!*GeminiContext {
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
                    return self.acceptContext(bind.socket.?, &bind.tls) catch |e| {
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

    fn acceptContext(self: *GeminiListener, sock: network.Socket, tls: *serve.TlsCore) !*GeminiContext {
        var client_sock: network.Socket = try sock.accept();
        errdefer client_sock.close();

        logger.debug("accepted tcp connection from {}", .{client_sock.getRemoteEndPoint()});

        var temp_memory = std.heap.ArenaAllocator.init(self.allocator);
        errdefer temp_memory.deinit();

        const context = try temp_memory.allocator.create(GeminiContext);
        context.* = GeminiContext{
            .memory = temp_memory,
            .request = GeminiRequest{
                .url = undefined,
                .requested_server_name = null,
                .client_certificate = null,
            },
            .response = GeminiResponse{
                .socket = client_sock,
                .ssl = undefined,
            },
        };

        context.response.ssl = try tls.accept(&context.response.socket);
        errdefer context.response.ssl.close();

        logger.debug("accepted tls connection", .{});

        context.request.client_certificate = try context.response.ssl.getPeerCertificate();

        context.request.requested_server_name = try context.response.ssl.getServerNameIndication(&context.memory.allocator);

        var url_buffer: [2048]u8 = undefined;

        var reader = context.response.ssl.reader();
        var url_string = try reader.readUntilDelimiter(&url_buffer, '\n');
        if (std.mem.endsWith(u8, url_string, "\r")) {
            url_string = url_string[0 .. url_string.len - 1];
        }

        logger.info("request for {s}", .{url_string});

        const url_string_owned = try context.memory.allocator.dupeZ(u8, url_string);

        context.request.url = try uri.parse(url_string_owned);

        return context;
    }
};

pub const GeminiContext = struct {
    memory: std.heap.ArenaAllocator,

    request: GeminiRequest,
    response: GeminiResponse,

    fn finalize(self: *GeminiContext) !void {
        if (!self.response.is_writing) {
            try self.response.writeHeader();
        }
    }

    pub fn deinit(self: *GeminiContext) void {
        self.finalize() catch |e| logger.warn("Failed to finalize connection: {s}", .{@errorName(e)});

        logger.debug("closing tcp connection to {}", .{self.response.socket.getRemoteEndPoint()});

        self.response.ssl.close();
        self.response.socket.close();
        self.memory.deinit();
    }
};

pub const GeminiRequest = struct {
    url: uri.UriComponents,
    client_certificate: ?serve.TlsCore.Certificate,
    requested_server_name: ?[]const u8,
};

pub const GeminiResponse = struct {
    pub const buffer_size = 1024;

    const BufferedWriter = std.io.BufferedWriter(buffer_size, network.Socket.Writer);

    socket: network.Socket,

    ssl: serve.TlsClient,

    is_writing: bool = false,

    status_code: GeminiStatusCode = .success,
    meta: std.ArrayListUnmanaged(u8) = .{},

    fn getAllocator(self: *GeminiResponse) *std.mem.Allocator {
        return &@fieldParentPtr(GeminiContext, "response", self).memory.allocator;
    }

    pub fn setStatusCode(self: *GeminiResponse, status_code: GeminiStatusCode) !void {
        std.debug.assert(self.is_writing == false);
        self.status_code = status_code;
        if (self.meta.items.len == 0) {
            try self.meta.appendSlice(self.getAllocator(), switch (status_code) {
                .input => "input",
                .sensitive_input => "sensitive input",
                .success => "application/octet-stream",
                .temporary_redirect => "temporary redirect",
                .permanent_redirect => "permanent redirect",
                .temporary_failure => "temporary failure",
                .server_unavailable => "server unavailable",
                .cgi_error => "cgi error",
                .proxy_error => "proxy error",
                .slow_down => "slow down",
                .permanent_failure => "permanent failure",
                .not_found => "not found",
                .gone => "gone",
                .proxy_request_refused => "proxy request refused",
                .bad_request => "bad request",
                .client_certificate_required => "client certificate required",
                .certificate_not_authorised => "certificate not authorised",
                .certificate_not_valid => "certificate not valid",
                else => switch (@enumToInt(status_code) / 10) {
                    0 => "undefined",
                    1 => "input",
                    2 => "success",
                    3 => "redirect",
                    4 => "temporary failure",
                    5 => "permanent failure",
                    6 => "client certificate required",
                    7 => "undefined",
                    8 => "undefined",
                    9 => "undefined",
                    else => unreachable,
                },
            });
        }
    }

    pub fn setMeta(self: *GeminiResponse, text: []const u8) !void {
        std.debug.assert(self.is_writing == false);
        self.meta.shrinkRetainingCapacity(0);
        try self.meta.appendSlice(self.getAllocator(), text);
    }

    fn writeHeader(self: *GeminiResponse) !void {
        try self.ssl.writer().print("{}{} {s}\r\n", .{
            (@enumToInt(self.status_code) / 10) % 10,
            (@enumToInt(self.status_code) / 1) % 10,
            self.meta.items,
        });
    }

    pub fn writer(self: *GeminiResponse) !serve.TlsClient.Writer {
        std.debug.assert(self.status_code.class() == .success);
        if (!self.is_writing) {
            try self.writeHeader();
        }
        self.is_writing = true;
        return self.ssl.writer();
    }
};

pub const GeminiStatusClass = enum(u4) {
    input = 1,
    success = 2,
    redirect = 3,
    temporary_failure = 4,
    permanent_failure = 5,
    client_certificate_required = 6,
};

pub const GeminiStatusCode = enum(u8) {
    input = 10,
    sensitive_input = 11,
    success = 20,
    temporary_redirect = 30,
    permanent_redirect = 31,
    temporary_failure = 40,
    server_unavailable = 41,
    cgi_error = 42,
    proxy_error = 43,
    slow_down = 44,
    permanent_failure = 50,
    not_found = 51,
    gone = 52,
    proxy_request_refused = 53,
    bad_request = 59,
    client_certificate_required = 60,
    certificate_not_authorised = 61,
    certificate_not_valid = 62,

    _, // other status codes are legal as well

    pub fn class(self: GeminiStatusCode) GeminiStatusClass {
        return @intToEnum(GeminiStatusClass, @truncate(u4, @enumToInt(self) / 10));
    }
};
