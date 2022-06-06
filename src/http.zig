const std = @import("std");
const network = @import("network");
const uri = @import("uri");
const serve = @import("serve.zig");
const logger = std.log.scoped(.serve_http);

pub const HttpListener = struct {
    const Binding = struct {
        address: network.Address,
        port: u16,
        socket: ?network.Socket,
        tls: ?serve.TlsCore,
    };

    allocator: std.mem.Allocator,
    bindings: std.ArrayList(Binding),

    /// Normalize incoming paths for the client, so a query to `"/"`, `"//"` and `""` are equivalent and will all receive
    /// `"/"` as the path.
    normalize_paths: bool = true,

    pub fn init(allocator: std.mem.Allocator) !HttpListener {
        return HttpListener{
            .allocator = allocator,
            .bindings = std.ArrayList(Binding).init(allocator),
        };
    }

    pub fn deinit(self: *HttpListener) void {
        for (self.bindings.items) |*bind| {
            if (bind.tls) |*tls| {
                tls.deinit();
            }
            if (bind.socket) |*sock| {
                sock.close();
            }
        }
        self.bindings.deinit();
        self.* = undefined;
    }

    const AddEndpointError = error{ AlreadyExists, AlreadyStarted, TlsError, InvalidCertificate, OutOfMemory };
    pub fn addEndpoint(
        self: *HttpListener,
        target_ip: serve.IP,
        port: u16,
    ) AddEndpointError!void {
        for (self.bindings.items) |*bind| {
            if (bind.socket != null)
                return error.AlreadyStarted;
        }

        var bind = Binding{
            .address = target_ip.convertToNetwork(),
            .port = port,
            .socket = null,
            .tls = null,
        };
        for (self.bindings.items) |*other| {
            if (std.meta.eql(other.*, bind))
                return error.AlreadyExists;
        }

        try self.bindings.append(bind);
    }

    const AddSecureEndpointError = error{ AlreadyExists, AlreadyStarted, TlsError, InvalidCertificate, OutOfMemory };
    pub fn addSecureEndpoint(
        self: *HttpListener,
        target_ip: serve.IP,
        port: u16,
        certificate_file: []const u8,
        key_file: []const u8,
    ) AddSecureEndpointError!void {
        for (self.bindings.items) |*bind| {
            if (bind.socket != null)
                return error.AlreadyStarted;
        }

        var tls = serve.TlsCore.init() catch return error.TlsError;
        errdefer tls.deinit();

        var temp = std.heap.ArenaAllocator.init(self.allocator);
        defer temp.deinit();

        tls.useCertifcateFile(try temp.allocator().dupeZ(u8, certificate_file)) catch return error.InvalidCertificate;
        tls.usePrivateKeyFile(try temp.allocator().dupeZ(u8, key_file)) catch return error.InvalidCertificate;

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
    pub fn start(self: *HttpListener) StartError!void {
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

    pub fn stop(self: *HttpListener) void {
        for (self.bindings.items) |*bind| {
            if (bind.socket) |*sock| {
                sock.close();
            }
            bind.socket = null;
        }
    }

    const GetContextError = std.os.PollError || std.os.AcceptError || network.Socket.Reader.Error || error{ UnsupportedAddressFamily, NotStarted, OutOfMemory, EndOfStream, StreamTooLong };
    pub fn getContext(self: *HttpListener) GetContextError!*HttpContext {
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
                    return self.acceptContext(bind.socket.?, if (bind.tls) |*tls| tls else null) catch |e| {
                        logger.warn("Invalid incoming connection: {s}", .{@errorName(e)});

                        std.debug.dumpStackTrace((@errorReturnTrace() orelse unreachable).*);

                        any_error = true;
                        continue;
                    };
                }
            }

            // This means something very terrible has gone wrong
            std.debug.assert(any_error);
        }
    }

    fn acceptContext(self: *HttpListener, sock: network.Socket, maybe_tls: ?*serve.TlsCore) !*HttpContext {
        var client_sock: network.Socket = try sock.accept();
        errdefer client_sock.close();

        logger.debug("accepted tcp connection from {}", .{client_sock.getRemoteEndPoint()});

        var temp_memory = std.heap.ArenaAllocator.init(self.allocator);
        errdefer temp_memory.deinit();

        const context = try temp_memory.allocator().create(HttpContext);
        context.* = HttpContext{
            .memory = temp_memory,
            .socket = client_sock,
            .ssl = null,
            .request = HttpRequest{
                .version = undefined,
                .method = null,
                .method_string = undefined,
                .url = "",
                .requested_server_name = null,
                .client_certificate = null,
            },
            .response = HttpResponse{},
        };

        if (maybe_tls) |tls| {
            context.ssl = try tls.accept(&context.socket);
            errdefer context.ssl.close();
        }

        if (context.ssl) |ssl| {
            logger.debug("accepted tls connection", .{});
            context.request.client_certificate = try ssl.getPeerCertificate();
            context.request.requested_server_name = try ssl.getServerNameIndication(context.memory.allocator());

            try parseRequest(context, ssl.reader());
        } else {
            try parseRequest(context, context.socket.reader());
        }

        return context;
    }

    fn parseRequest(context: *HttpContext, reader: anytype) !void {
        var request_line = try reader.readUntilDelimiterAlloc(context.memory.allocator(), '\n', 65536); // allow long URLs
        if (std.mem.endsWith(u8, request_line, "\r")) {
            request_line = request_line[0 .. request_line.len - 1];
        }

        var tokens = std.mem.tokenize(u8, request_line, " \t");

        const method = tokens.next() orelse return error.MissingMethod;
        const url = tokens.next() orelse return error.MissingUrl;
        const maybe_version = tokens.next();

        std.log.info("{s} {s} {s}", .{ method, url, maybe_version });

        context.request.method = std.meta.stringToEnum(HttpMethod, method);
        context.request.method_string = method;
        context.request.url = url;

        if (maybe_version) |version| {
            // HTTP/1.0 or newer
            if (!std.mem.startsWith(u8, version, "HTTP/"))
                return error.UnexpectedToken;
            context.request.version = HttpVersion{
                .major = std.fmt.parseInt(u32, version[5..6], 10) catch return error.InvalidVersion,
                .minor = std.fmt.parseInt(u32, version[7..8], 10) catch return error.InvalidVersion,
            };
            if (!context.request.version.atLeast(HttpVersion.@"HTTP/1.0"))
                return error.InvalidVersion;

            // Read headers
            while (true) {
                var header_line = try reader.readUntilDelimiterAlloc(context.memory.allocator(), '\n', 65536); // allow long URLs
                if (std.mem.endsWith(u8, header_line, "\r")) {
                    header_line = header_line[0 .. header_line.len - 1];
                }
                if (header_line.len == 0)
                    break;

                const index = std.mem.indexOfScalar(u8, header_line, ':') orelse return error.InvalidHeader;

                const whitespace = " \t";
                const key = std.mem.trim(u8, header_line[0..index], whitespace);
                const value = std.mem.trim(u8, header_line[index + 1 ..], whitespace);

                try context.request.headers.put(context.memory.allocator(), key, value);
            }
        } else {
            // We're done parsing the request, this is everything available. We don't have headers
            context.request.version = HttpVersion.@"HTTP/0.9";
        }

        logger.info("request for {s}", .{url});
    }
};

pub const HttpContext = struct {
    memory: std.heap.ArenaAllocator,

    socket: network.Socket,
    ssl: ?serve.TlsClient,

    request: HttpRequest,
    response: HttpResponse,

    fn finalize(self: *HttpContext) !void {
        if (!self.response.is_writing_body) {
            try self.response.writeHeaders();
        }
    }

    pub fn deinit(self: *HttpContext) void {
        self.finalize() catch |e| logger.warn("Failed to finalize connection: {s}", .{@errorName(e)});

        logger.debug("closing tcp connection to {}", .{self.socket.getRemoteEndPoint()});

        if (self.ssl) |*ssl| {
            ssl.close();
        }
        self.socket.close();

        var copy = self.memory;
        copy.deinit();
    }
};

pub const HttpRequest = struct {
    version: HttpVersion,
    method: ?HttpMethod,
    method_string: []const u8,
    url: []const u8,
    client_certificate: ?serve.TlsCore.Certificate,
    requested_server_name: ?[]const u8,
    headers: CaseInsenitiveStringHashMapUnmanaged([]const u8) = .{},

    fn getContext(self: *HttpRequest) *HttpContext {
        return &@fieldParentPtr(HttpContext, "request", self);
    }

    pub const Reader = std.io.Reader(*HttpResponse, Reader, read);
    pub fn reader(self: *HttpResponse) !Reader {
        return Reader{ .context = self };
    }

    pub const ReadError = serve.TlsClient.Reader.Error || network.Socket.Reader.Error;
    fn read(self: *HttpResponse, buffer: []u8) ReadError!usize {
        const ctx = self.getContext();
        if (ctx.ssl) |*ssl| {
            return try ssl.read(buffer);
        } else {
            return ctx.socket.receive(buffer);
        }
    }
};

pub const HttpResponse = struct {
    pub const buffer_size = 1024;

    const BufferedWriter = std.io.BufferedWriter(buffer_size, network.Socket.Writer);

    is_writing_body: bool = false,

    status_code: HttpStatusCode = .ok,
    meta: std.ArrayListUnmanaged(u8) = .{},
    headers: std.StringHashMapUnmanaged([]const u8) = .{},

    pub fn setStatusCode(self: *HttpResponse, status_code: HttpStatusCode) !void {
        std.debug.assert(self.is_writing_body == false);
        self.status_code = status_code;
    }

    pub fn setMeta(self: *HttpResponse, text: []const u8) !void {
        std.debug.assert(self.is_writing_body == false);
        self.meta.shrinkRetainingCapacity(0);
        try self.meta.appendSlice(self.getAllocator(), text);
    }

    pub fn setHeader(self: *HttpResponse, header: []const u8, value: []const u8) !void {
        const allocator = self.getAllocator();

        // TODO: Use a non-casesensitive hash map!
        const gop = try self.headers.getOrPut(allocator, header);
        if (gop.found_existing) {
            const old_val = gop.value_ptr.*;
            gop.value_ptr.* = try allocator.dupe(u8, value);
            allocator.free(old_val);
        } else {
            errdefer _ = self.headers.remove(header);

            gop.key_ptr.* = try allocator.dupe(u8, header);
            errdefer allocator.free(gop.key_ptr.*);
            gop.value_ptr.* = try allocator.dupe(u8, value);
        }
    }

    pub const Writer = std.io.Writer(*HttpResponse, WriteError, write);
    pub fn writer(self: *HttpResponse) !Writer {
        if (!self.is_writing_body) {
            try self.writeHeaders();
        }
        self.is_writing_body = true;
        return Writer{ .context = self };
    }

    fn getContext(self: *HttpResponse) *HttpContext {
        return @fieldParentPtr(HttpContext, "response", self);
    }

    fn getAllocator(self: *HttpResponse) std.mem.Allocator {
        return self.getContext().memory.allocator();
    }

    fn writeHeaders(self: *HttpResponse) !void {
        var stream = HttpResponse.Writer{ .context = self };
        const ctx = self.getContext();

        if (ctx.request.version.eql(HttpVersion.@"HTTP/0.9")) {
            // No headers for HTTP/0.9
            return;
        }

        var reason_phrase: []const u8 = self.meta.items;
        if (reason_phrase.len == 0) {
            reason_phrase = @tagName(self.status_code);
        }

        try stream.print("HTTP/{}.{} {} {s}\r\n", .{
            ctx.request.version.major,
            ctx.request.version.minor,
            @enumToInt(self.status_code),
            reason_phrase,
        });

        var iter = self.headers.iterator();
        while (iter.next()) |kv| {
            try stream.print("{s}: {s}\r\n", .{
                kv.key_ptr.*,
                kv.value_ptr.*,
            });
        }

        try stream.writeAll("\r\n");
    }

    pub const WriteError = serve.TlsClient.Writer.Error || network.Socket.Writer.Error;
    fn write(self: *HttpResponse, buffer: []const u8) WriteError!usize {
        const ctx = self.getContext();
        if (ctx.ssl) |*ssl| {
            return try ssl.write(buffer);
        } else {
            return ctx.socket.send(buffer);
        }
    }
};

pub const HttpVersion = struct {
    minor: u32,
    major: u32,

    pub const @"HTTP/0.9" = HttpVersion{ .major = 0, .minor = 9 };
    pub const @"HTTP/1.0" = HttpVersion{ .major = 1, .minor = 0 };
    pub const @"HTTP/1.1" = HttpVersion{ .major = 1, .minor = 1 };

    pub fn eql(a: HttpVersion, b: HttpVersion) bool {
        return std.meta.eql(a, b);
    }

    pub fn atLeast(vers: HttpVersion, required: HttpVersion) bool {
        if (vers.major > required.major)
            return true;
        if (vers.major < required.major)
            return false;
        return (vers.minor >= required.minor);
    }
};

pub const HttpMethod = enum {
    OPTIONS,
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    TRACE,
    CONNECT,
};

pub const HttpStatusCode = enum(u16) {
    @"continue" = 100, // Continue
    switching_protocols = 101, // Switching Protocols
    ok = 200, // OK
    created = 201, // Created
    accepted = 202, // Accepted
    non_authoritative_information = 203, // Non-Authoritative Information
    no_content = 204, // No Content
    reset_content = 205, // Reset Content
    partial_content = 206, // Partial Content
    multiple_choices = 300, // Multiple Choices
    moved_permanently = 301, // Moved Permanently
    found = 302, // Found
    see_other = 303, // See Other
    not_modified = 304, // Not Modified
    use_proxy = 305, // Use Proxy
    temporary_redirect = 307, // Temporary Redirect
    bad_request = 400, // Bad Request
    unauthorized = 401, // Unauthorized
    payment_required = 402, // Payment Required
    forbidden = 403, // Forbidden
    not_found = 404, // Not Found
    method_not_allowed = 405, // Method Not Allowed
    not_acceptable = 406, // Not Acceptable
    proxy_authentication_required = 407, // Proxy Authentication Required
    request_timeout = 408, // Request Timeout
    conflict = 409, // Conflict
    gone = 410, // Gone
    length_required = 411, // Length Required
    precondition_failed = 412, // Precondition Failed
    payload_too_large = 413, // Payload Too Large
    uri_too_long = 414, // URI Too Long
    unsupported_media_type = 415, // Unsupported Media Type
    range_not_satisfiable = 416, // Range Not Satisfiable
    expectation_failed = 417, // Expectation Failed
    upgrade_required = 426, // Upgrade Required
    internal_server_error = 500, // Internal Server Error
    not_implemented = 501, // Not Implemented
    bad_gateway = 502, // Bad Gateway
    service_unavailable = 503, // Service Unavailable
    gateway_timeout = 504, // Gateway Timeout
    http_version_not_supported = 505, // HTTP Version Not Supported
    _,
};

pub const CaseInsensitiveStringContext = struct {
    pub fn hash(self: @This(), s: []const u8) u64 {
        _ = self;
        return hashString(s);
    }
    pub fn eql(self: @This(), a: []const u8, b: []const u8) bool {
        _ = self;
        return std.ascii.eqlIgnoreCase(a, b);
    }

    fn hashString(s: []const u8) u64 {
        var hasher = std.hash.Wyhash.init(0);
        var buffer: [128]u8 = undefined;
        var i: usize = 0;
        while (i < s.len) : (i += buffer.len) {
            const source = s[i..std.math.min(s.len, i + buffer.len)];
            std.mem.copy(u8, &buffer, s);
            for (buffer[0..source.len]) |*c| {
                c.* = std.ascii.toLower(c.*);
            }
            hasher.update(buffer[0..source.len]);
        }
        return hasher.final();
    }
};

pub fn CaseInsenitiveStringHashMapUnmanaged(comptime T: type) type {
    return std.HashMapUnmanaged([]const u8, T, CaseInsensitiveStringContext, std.hash_map.default_max_load_percentage);
}

test "CaseInsenitiveStringHashMapUnmanaged" {
    var hm = CaseInsenitiveStringHashMapUnmanaged(u32){};
    defer hm.deinit(std.testing.allocator);

    try hm.put(std.testing.allocator, "Host", 42);

    try std.testing.expectEqual(@as(?u32, 42), hm.get("Host"));
    try std.testing.expectEqual(@as(?u32, 42), hm.get("host"));
    try std.testing.expectEqual(@as(?u32, 42), hm.get("HOST"));
    try std.testing.expectEqual(@as(?u32, 42), hm.get("hOsT"));
}
