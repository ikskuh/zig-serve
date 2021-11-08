const std = @import("std");
const network = @import("network");
const logger = std.log.scoped(.serve_tls);

const c = @cImport({
    @cDefine("WOLFSSL_TLS13", "");
    @cInclude("wolfssl/ssl.h");
});

const TlsCore = @This();

pub fn startup() !void {
    try wolfCheck(c.wolfSSL_Init());

    // var cypher_buffer: [4096]u8 = undefined;
    // try wolfCheck(c.wolfSSL_get_ciphers(&cypher_buffer, cypher_buffer.len));
    // logger.info("{s}", .{cypher_buffer});
}

pub fn shutdown() void {
    _ = c.wolfSSL_Cleanup();
}

ctx: *c.WOLFSSL_CTX,

pub fn init() !TlsCore {
    var core = TlsCore{
        .ctx = c.wolfSSL_CTX_new(c.wolfTLSv1_2_server_method()) orelse return error.WolfSSL,
    };

    // Associate picoTCP callbacks to wolfSSL context */
    c.wolfSSL_CTX_SetIORecv(core.ctx, zigRecv);
    c.wolfSSL_CTX_SetIOSend(core.ctx, zigSend);

    return core;
}

pub fn deinit(self: *TlsCore) void {
    c.wolfSSL_CTX_free(self.ctx);
    self.* = undefined;
}

pub fn useCertifcateFile(self: *TlsCore, file_name: [:0]const u8) !void {
    try wolfCheck(c.wolfSSL_CTX_use_certificate_file(self.ctx, file_name.ptr, c.SSL_FILETYPE_PEM));
}

pub fn usePrivateKeyFile(self: *TlsCore, file_name: [:0]const u8) !void {
    try wolfCheck(c.wolfSSL_CTX_use_PrivateKey_file(self.ctx, file_name.ptr, c.SSL_FILETYPE_PEM));
}

pub fn accept(self: *TlsCore, socket: *network.Socket) !TlsClient {
    const ssl = c.wolfSSL_new(self.ctx) orelse return error.OutOfMemory;
    errdefer c.wolfSSL_free(ssl); // Free the wolfSSL object              */

    // Establish TLS connection */
    while (true) {
        c.wolfSSL_SetIOReadCtx(ssl, socket);
        c.wolfSSL_SetIOWriteCtx(ssl, socket);
        const ret = c.wolfSSL_accept(ssl);

        if (ret == c.SSL_SUCCESS)
            break;
        const error_code = c.wolfSSL_get_error(ssl, ret);
        if (error_code != c.SSL_ERROR_WANT_READ and error_code != c.SSL_ERROR_WANT_WRITE) {
            return makeWolfError(error_code);
        }
    }

    return TlsClient{
        .ssl = ssl,
    };
}

pub const TlsClient = struct {
    ssl: *c.WOLFSSL,

    pub fn close(self: *TlsClient) void {
        c.wolfSSL_free(self.ssl);
        self.* = undefined;
    }

    pub const ReadError = error{WolfSSL};
    pub const WriteError = error{WolfSSL};

    pub const Reader = std.io.Reader(TlsClient, ReadError, read);
    pub const Writer = std.io.Writer(TlsClient, WriteError, write);

    pub fn reader(self: TlsClient) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: TlsClient) Writer {
        return .{ .context = self };
    }

    pub fn read(self: TlsClient, buffer: []u8) ReadError!usize {
        const read_len = c.wolfSSL_read(self.ssl, buffer.ptr, @intCast(c_int, buffer.len));
        if (read_len < 0) {
            try wolfCheck(c.wolfSSL_get_error(self.ssl, read_len));
        }
        return @intCast(usize, read_len);
    }

    pub fn write(self: TlsClient, buffer: []const u8) WriteError!usize {
        const write_len = c.wolfSSL_write(self.ssl, buffer.ptr, @intCast(c_int, buffer.len));
        if (write_len < 0) {
            try wolfCheck(c.wolfSSL_get_error(self.ssl, write_len));
        }
        return @intCast(usize, write_len);
    }
};

fn makeWolfError(err_code: c_int) error{WolfSSL} {
    var name_buf: [c.WOLFSSL_MAX_ERROR_SZ + 1]u8 = undefined;
    const error_name = std.mem.sliceTo(
        @as(?[*:0]const u8, c.wolfSSL_ERR_error_string(@intCast(c_ulong, -err_code), &name_buf)) orelse "unknown",
        0,
    );
    const error_enum = std.meta.intToEnum(wolfSSL_ErrorCodes, err_code) catch @as(?wolfSSL_ErrorCodes, null);
    logger.err("WolfSSL Error {}/{}: {s}", .{
        err_code,
        error_enum,
        error_name,
    });
    return error.WolfSSL;
}

fn wolfCheck(err_code: c_int) error{WolfSSL}!void {
    if (err_code == c.SSL_SUCCESS)
        return;
    return makeWolfError(err_code);
}

/// PicoTCP send/receive callbacks */
fn zigSend(ssl: ?*c.WOLFSSL, buf: [*c]u8, len: c_int, ctx: ?*c_void) callconv(.C) c_int {
    _ = ssl;

    const sock = @ptrCast(*network.Socket, @alignCast(@alignOf(network.Socket), ctx.?));

    const actual_len = sock.send(buf[0..@intCast(usize, len)]) catch |err| {
        logger.err("socket: {}", .{err});
        return c.WOLFSSL_CBIO_ERR_WANT_WRITE;
    };

    return @intCast(c_int, actual_len);
}

fn zigRecv(ssl: ?*c.WOLFSSL, buf: [*c]u8, len: c_int, ctx: ?*c_void) callconv(.C) c_int {
    _ = ssl;

    const sock = @ptrCast(*network.Socket, @alignCast(@alignOf(network.Socket), ctx.?));

    const actual_len = sock.receive(buf[0..@intCast(usize, len)]) catch |err| {
        logger.err("socket: {}", .{err});
        return c.WOLFSSL_CBIO_ERR_WANT_READ;
    };

    return @intCast(c_int, actual_len);
}

const wolfSSL_ErrorCodes = enum(c_int) { INPUT_CASE_ERROR = -301, // process input state error */
PREFIX_ERROR = -302, // bad index to key rounds  */
MEMORY_ERROR = -303, // out of memory            */
VERIFY_FINISHED_ERROR = -304, // verify problem on finished */
VERIFY_MAC_ERROR = -305, // verify mac problem       */
PARSE_ERROR = -306, // parse error on header    */
UNKNOWN_HANDSHAKE_TYPE = -307, // weird handshake type     */
SOCKET_ERROR_E = -308, // error state on socket    */
SOCKET_NODATA = -309, // expected data, not there */
INCOMPLETE_DATA = -310, // don't have enough data to complete task            */
UNKNOWN_RECORD_TYPE = -311, // unknown type in record hdr */
DECRYPT_ERROR = -312, // error during decryption  */
FATAL_ERROR = -313, // recvd alert fatal error  */
ENCRYPT_ERROR = -314, // error during encryption  */
FREAD_ERROR = -315, // fread problem            */
NO_PEER_KEY = -316, // need peer's key          */
NO_PRIVATE_KEY = -317, // need the private key     */
RSA_PRIVATE_ERROR = -318, // error during rsa priv op */
NO_DH_PARAMS = -319, // server missing DH params */
BUILD_MSG_ERROR = -320, // build message failure    */
BAD_HELLO = -321, // client hello malformed   */
DOMAIN_NAME_MISMATCH = -322, // peer subject name mismatch */
WANT_READ = -323, // want read, call again    */
NOT_READY_ERROR = -324, // handshake layer not ready */
IPADDR_MISMATCH = -325, // peer ip address mismatch */
VERSION_ERROR = -326, // record layer version error */
WANT_WRITE = -327, // want write, call again   */
BUFFER_ERROR = -328, // malformed buffer input   */
VERIFY_CERT_ERROR = -329, // verify cert error        */
VERIFY_SIGN_ERROR = -330, // verify sign error        */
CLIENT_ID_ERROR = -331, // psk client identity error  */
SERVER_HINT_ERROR = -332, // psk server hint error  */
PSK_KEY_ERROR = -333, // psk key error  */

GETTIME_ERROR = -337, // gettimeofday failed ??? */
GETITIMER_ERROR = -338, // getitimer failed ??? */
SIGACT_ERROR = -339, // sigaction failed ??? */
SETITIMER_ERROR = -340, // setitimer failed ??? */
LENGTH_ERROR = -341, // record layer length error */
PEER_KEY_ERROR = -342, // can't decode peer key */
ZERO_RETURN = -343, // peer sent close notify */
SIDE_ERROR = -344, // wrong client/server type */
NO_PEER_CERT = -345, // peer didn't send key */
ECC_CURVETYPE_ERROR = -350, // Bad ECC Curve Type */
ECC_CURVE_ERROR = -351, // Bad ECC Curve */
ECC_PEERKEY_ERROR = -352, // Bad Peer ECC Key */
ECC_MAKEKEY_ERROR = -353, // Bad Make ECC Key */
ECC_EXPORT_ERROR = -354, // Bad ECC Export Key */
ECC_SHARED_ERROR = -355, // Bad ECC Shared Secret */
NOT_CA_ERROR = -357, // Not a CA cert error */

BAD_CERT_MANAGER_ERROR = -359, // Bad Cert Manager */
OCSP_CERT_REVOKED = -360, // OCSP Certificate revoked */
CRL_CERT_REVOKED = -361, // CRL Certificate revoked */
CRL_MISSING = -362, // CRL Not loaded */
MONITOR_SETUP_E = -363, // CRL Monitor setup error */
THREAD_CREATE_E = -364, // Thread Create Error */
OCSP_NEED_URL = -365, // OCSP need an URL for lookup */
OCSP_CERT_UNKNOWN = -366, // OCSP responder doesn't know */
OCSP_LOOKUP_FAIL = -367, // OCSP lookup not successful */
MAX_CHAIN_ERROR = -368, // max chain depth exceeded */
COOKIE_ERROR = -369, // dtls cookie error */
SEQUENCE_ERROR = -370, // dtls sequence error */
SUITES_ERROR = -371, // suites pointer error */

OUT_OF_ORDER_E = -373, // out of order message */
BAD_KEA_TYPE_E = -374, // bad KEA type found */
SANITY_CIPHER_E = -375, // sanity check on cipher error */
RECV_OVERFLOW_E = -376, // RXCB returned more than read */
GEN_COOKIE_E = -377, // Generate Cookie Error */
NO_PEER_VERIFY = -378, // Need peer cert verify Error */
FWRITE_ERROR = -379, // fwrite problem */
CACHE_MATCH_ERROR = -380, // Cache hdr match error */
UNKNOWN_SNI_HOST_NAME_E = -381, // Unrecognized host name Error */
UNKNOWN_MAX_FRAG_LEN_E = -382, // Unrecognized max frag len Error */
KEYUSE_SIGNATURE_E = -383, // KeyUse digSignature error */

KEYUSE_ENCIPHER_E = -385, // KeyUse keyEncipher error */
EXTKEYUSE_AUTH_E = -386, // ExtKeyUse server|client_auth */
SEND_OOB_READ_E = -387, // Send Cb out of bounds read */
SECURE_RENEGOTIATION_E = -388, // Invalid Renegotiation Info */
SESSION_TICKET_LEN_E = -389, // Session Ticket too large */
SESSION_TICKET_EXPECT_E = -390, // Session Ticket missing   */
SCR_DIFFERENT_CERT_E = -391, // SCR Different cert error  */
SESSION_SECRET_CB_E = -392, // Session secret Cb fcn failure */
NO_CHANGE_CIPHER_E = -393, // Finished before change cipher */
SANITY_MSG_E = -394, // Sanity check on msg order error */
DUPLICATE_MSG_E = -395, // Duplicate message error */
SNI_UNSUPPORTED = -396, // SSL 3.0 does not support SNI */
SOCKET_PEER_CLOSED_E = -397, // Underlying transport closed */
BAD_TICKET_KEY_CB_SZ = -398, // Bad session ticket key cb size */
BAD_TICKET_MSG_SZ = -399, // Bad session ticket msg size    */
BAD_TICKET_ENCRYPT = -400, // Bad user ticket encrypt        */
DH_KEY_SIZE_E = -401, // DH Key too small */
SNI_ABSENT_ERROR = -402, // No SNI request. */
RSA_SIGN_FAULT = -403, // RSA Sign fault */
HANDSHAKE_SIZE_ERROR = -404, // Handshake message too large */
UNKNOWN_ALPN_PROTOCOL_NAME_E = -405, // Unrecognized protocol name Error*/
BAD_CERTIFICATE_STATUS_ERROR = -406, // Bad certificate status message */
OCSP_INVALID_STATUS = -407, // Invalid OCSP Status */
OCSP_WANT_READ = -408, // OCSP callback response WOLFSSL_CBIO_ERR_WANT_READ */
RSA_KEY_SIZE_E = -409, // RSA key too small */
ECC_KEY_SIZE_E = -410, // ECC key too small */
DTLS_EXPORT_VER_E = -411, // export version error */
INPUT_SIZE_E = -412, // input size too big error */
CTX_INIT_MUTEX_E = -413, // initialize ctx mutex error */
EXT_MASTER_SECRET_NEEDED_E = -414, // need EMS enabled to resume */
DTLS_POOL_SZ_E = -415, // exceeded DTLS pool size */
DECODE_E = -416, // decode handshake message error */
HTTP_TIMEOUT = -417, // HTTP timeout for OCSP or CRL req */
WRITE_DUP_READ_E = -418, // Write dup write side can't read */
WRITE_DUP_WRITE_E = -419, // Write dup read side can't write */
INVALID_CERT_CTX_E = -420, // TLS cert ctx not matching */
BAD_KEY_SHARE_DATA = -421, // Key Share data invalid */
MISSING_HANDSHAKE_DATA = -422, // Handshake message missing data */
BAD_BINDER = -423, // Binder does not match */
EXT_NOT_ALLOWED = -424, // Extension not allowed in msg */
INVALID_PARAMETER = -425, // Security parameter invalid */
MCAST_HIGHWATER_CB_E = -426, // Multicast highwater cb err */
ALERT_COUNT_E = -427, // Alert Count exceeded err */
EXT_MISSING = -428, // Required extension not found */
UNSUPPORTED_EXTENSION = -429, // TLSX not requested by client */
PRF_MISSING = -430, // PRF not compiled in */
DTLS_RETX_OVER_TX = -431, // Retransmit DTLS flight over */
DH_PARAMS_NOT_FFDHE_E = -432, // DH params from server not FFDHE */
TCA_INVALID_ID_TYPE = -433, // TLSX TCA ID type invalid */
TCA_ABSENT_ERROR = -434, // TLSX TCA ID no response */
TSIP_MAC_DIGSZ_E = -435, // Invalid MAC size for TSIP */
CLIENT_CERT_CB_ERROR = -436, // Client cert callback error */
SSL_SHUTDOWN_ALREADY_DONE_E = -437, // Shutdown called redundantly */
TLS13_SECRET_CB_E = -438, // TLS1.3 secret Cb fcn failure */
DTLS_SIZE_ERROR = -439, // Trying to send too much data */
NO_CERT_ERROR = -440, // TLS1.3 - no cert set error */
APP_DATA_READY = -441, // DTLS1.2 application data ready for read */
TOO_MUCH_EARLY_DATA = -442, // Too much Early data */
SOCKET_FILTERED_E = -443, // Session stopped by network filter */
HTTP_RECV_ERR = -444, // HTTP Receive error */
HTTP_HEADER_ERR = -445, // HTTP Header error */
HTTP_PROTO_ERR = -446, // HTTP Protocol error */
HTTP_STATUS_ERR = -447, // HTTP Status error */
HTTP_VERSION_ERR = -448, // HTTP Version error */
HTTP_APPSTR_ERR = -449, // HTTP Application string error */
UNSUPPORTED_PROTO_VERSION = -450, // bad/unsupported protocol version*/
FALCON_KEY_SIZE_E = -451, // Wrong key size for Falcon. */

// add strings to wolfSSL_ERR_reason_error_string in internal.c !!!!! */

// begin negotiation parameter errors */
UNSUPPORTED_SUITE = -500, // unsupported cipher suite */
MATCH_SUITE_ERROR = -501, // can't match cipher suite */
COMPRESSION_ERROR = -502, // compression mismatch */
KEY_SHARE_ERROR = -503, // key share mismatch */
POST_HAND_AUTH_ERROR = -504, // client won't do post-hand auth */
HRR_COOKIE_ERROR = -505 // HRR msg cookie mismatch */
// end negotiation parameter errors only 10 for now */
// add strings to wolfSSL_ERR_reason_error_string in internal.c !!!!! */

// no error stings go down here, add above negotiation errors !!!! */
};
