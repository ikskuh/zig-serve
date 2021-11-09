const std = @import("std");
const network = @import("network");
const logger = std.log.scoped(.serve_tls);

const c = @cImport({
    @cDefine("WOLFSSL_TLS13", "");
    @cDefine("SESSION_INDEX", "");
    @cDefine("SESSION_CERTS", "");
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

    // c.wolfSSL_set_verify(ssl, c.SSL_VERIFY_PEER | c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, null);
    c.wolfSSL_set_verify(ssl, c.SSL_VERIFY_PEER, verifyFn);

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

fn verifyFn(some: c_int, certificate_store_ctx: [*c]c.WOLFSSL_X509_STORE_CTX) callconv(.C) c_int {
    _ = some;
    _ = certificate_store_ctx;
    // std.debug.print("{} {any}\n", .{ some, certificate_store_ctx });

    // const chain_stack = c.wolfSSL_X509_STORE_CTX_get_chain(certificate_store_ctx);
    // defer c.wolfSSL_sk_free(chain_stack);

    // std.debug.print("stack: {any}\n", .{chain_stack});

    return c.SSL_SUCCESS;
}

// static WC_INLINE int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
// {
//     char buffer[WOLFSSL_MAX_ERROR_SZ];
// #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
//     WOLFSSL_X509* peer;
// #if defined(SHOW_CERTS) && !defined(NO_FILESYSTEM)
//     WOLFSSL_BIO* bio = NULL;
//     WOLFSSL_STACK* sk = NULL;
//     X509* x509 = NULL;
//     int i = 0;
// #endif
// #endif
//     (void)preverify;

//     /* Verify Callback Arguments:
//      * preverify:           1=Verify Okay, 0=Failure
//      * store->error:        Failure error code (0 indicates no failure)
//      * store->current_cert: Current WOLFSSL_X509 object (only with OPENSSL_EXTRA)
//      * store->error_depth:  Current Index
//      * store->domain:       Subject CN as string (null term)
//      * store->totalCerts:   Number of certs presented by peer
//      * store->certs[i]:     A `WOLFSSL_BUFFER_INFO` with plain DER for each cert
//      * store->store:        WOLFSSL_X509_STORE with CA cert chain
//      * store->store->cm:    WOLFSSL_CERT_MANAGER
//      * store->ex_data:      The WOLFSSL object pointer
//      * store->discardSessionCerts: When set to non-zero value session certs
//         will be discarded (only with SESSION_CERTS)
//      */

//     printf("In verification callback, error = %d, %s\n", store->error,
//                                  wolfSSL_ERR_error_string(store->error, buffer));
// #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
//     peer = store->current_cert;
//     if (peer) {
//         char* issuer  = wolfSSL_X509_NAME_oneline(
//                                        wolfSSL_X509_get_issuer_name(peer), 0, 0);
//         char* subject = wolfSSL_X509_NAME_oneline(
//                                       wolfSSL_X509_get_subject_name(peer), 0, 0);
//         printf("\tPeer's cert info:\n issuer : %s\n subject: %s\n", issuer,
//                                                                   subject);
//         XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
//         XFREE(issuer,  0, DYNAMIC_TYPE_OPENSSL);
// #if defined(SHOW_CERTS) && !defined(NO_FILESYSTEM)
//         /* avoid printing duplicate certs */
//         if (store->depth == 1) {
//             /* retrieve x509 certs and display them on stdout */
//             sk = wolfSSL_X509_STORE_GetCerts(store);

//             for (i = 0; i < wolfSSL_sk_X509_num(sk); i++) {
//                 x509 = wolfSSL_sk_X509_value(sk, i);
//                 bio = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
//                 if (bio != NULL) {
//                     wolfSSL_BIO_set_fp(bio, stdout, BIO_NOCLOSE);
//                     wolfSSL_X509_print(bio, x509);
//                     wolfSSL_BIO_free(bio);
//                 }
//             }
//             wolfSSL_sk_X509_free(sk);
//         }
// #endif
//     }
//     else
//         printf("\tPeer has no cert!\n");
// #else
//     printf("\tPeer certs: %d\n", store->totalCerts);
//     #ifdef SHOW_CERTS
//     {   int i;
//         for (i=0; i<store->totalCerts; i++) {
//             WOLFSSL_BUFFER_INFO* cert = &store->certs[i];
//             printf("\t\tCert %d: Ptr %p, Len %u\n", i, cert->buffer, cert->length);
//         }
//     }
//     #endif /* SHOW_CERTS */
// #endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

//     printf("\tSubject's domain name at %d is %s\n", store->error_depth, store->domain);

//     /* Testing forced fail case by return zero */
//     if (myVerifyAction == VERIFY_FORCE_FAIL) {
//         return 0; /* test failure case */
//     }

//     if (myVerifyAction == VERIFY_OVERRIDE_DATE_ERR &&
//         (store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E)) {
//         printf("Overriding cert date error as example for bad clock testing\n");
//         return 1;
//     }

//     /* If error indicate we are overriding it for testing purposes */
//     if (store->error != 0 && myVerifyAction == VERIFY_OVERRIDE_ERROR) {
//         printf("\tAllowing failed certificate check, testing only "
//             "(shouldn't do this in production)\n");
//     }

//     /* A non-zero return code indicates failure override */
//     return (myVerifyAction == VERIFY_OVERRIDE_ERROR) ? 1 : preverify;
// }

pub const TlsClient = struct {
    ssl: *c.WOLFSSL,

    pub fn getSession(self: TlsClient) !*c.WOLFSSL_SESSION {
        return c.wolfSSL_get_session(self.ssl) orelse error.NoSession;
    }

    pub fn getPeerChain(self: TlsClient) !*c.WOLFSSL_X509_CHAIN {
        const sess = try self.getSession();
        return c.wolfSSL_SESSION_get_peer_chain(sess) orelse return error.NoChain;
    }

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

const wolfSSL_ErrorCodes = enum(c_int) {
    OPEN_RAN_E = -101, // opening random device error */
    READ_RAN_E = -102, // reading random device error */
    WINCRYPT_E = -103, // windows crypt init error */
    CRYPTGEN_E = -104, // windows crypt generation error */
    RAN_BLOCK_E = -105, // reading random device would block */
    BAD_MUTEX_E = -106, // Bad mutex operation */
    WC_TIMEOUT_E = -107, // timeout error */
    WC_PENDING_E = -108, // wolfCrypt operation pending (would block) */
    WC_NOT_PENDING_E = -109, // wolfCrypt operation not pending */

    MP_INIT_E = -110, // mp_init error state */
    MP_READ_E = -111, // mp_read error state */
    MP_EXPTMOD_E = -112, // mp_exptmod error state */
    MP_TO_E = -113, // mp_to_xxx error state, can't convert */
    MP_SUB_E = -114, // mp_sub error state, can't subtract */
    MP_ADD_E = -115, // mp_add error state, can't add */
    MP_MUL_E = -116, // mp_mul error state, can't multiply */
    MP_MULMOD_E = -117, // mp_mulmod error state, can't multiply mod */
    MP_MOD_E = -118, // mp_mod error state, can't mod */
    MP_INVMOD_E = -119, // mp_invmod error state, can't inv mod */
    MP_CMP_E = -120, // mp_cmp error state */
    MP_ZERO_E = -121, // got a mp zero result, not expected */

    MEMORY_E = -125, // out of memory error */
    VAR_STATE_CHANGE_E = -126, // var state modified by different thread */

    RSA_WRONG_TYPE_E = -130, // RSA wrong block type for RSA function */
    RSA_BUFFER_E = -131, // RSA buffer error, output too small or input too large */
    BUFFER_E = -132, // output buffer too small or input too large */
    ALGO_ID_E = -133, // setting algo id error */
    PUBLIC_KEY_E = -134, // setting public key error */
    DATE_E = -135, // setting date validity error */
    SUBJECT_E = -136, // setting subject name error */
    ISSUER_E = -137, // setting issuer  name error */
    CA_TRUE_E = -138, // setting CA basic constraint true error */
    EXTENSIONS_E = -139, // setting extensions error */

    ASN_PARSE_E = -140, // ASN parsing error, invalid input */
    ASN_VERSION_E = -141, // ASN version error, invalid number */
    ASN_GETINT_E = -142, // ASN get big int error, invalid data */
    ASN_RSA_KEY_E = -143, // ASN key init error, invalid input */
    ASN_OBJECT_ID_E = -144, // ASN object id error, invalid id */
    ASN_TAG_NULL_E = -145, // ASN tag error, not null */
    ASN_EXPECT_0_E = -146, // ASN expect error, not zero */
    ASN_BITSTR_E = -147, // ASN bit string error, wrong id */
    ASN_UNKNOWN_OID_E = -148, // ASN oid error, unknown sum id */
    ASN_DATE_SZ_E = -149, // ASN date error, bad size */
    ASN_BEFORE_DATE_E = -150, // ASN date error, current date before */
    ASN_AFTER_DATE_E = -151, // ASN date error, current date after */
    ASN_SIG_OID_E = -152, // ASN signature error, mismatched oid */
    ASN_TIME_E = -153, // ASN time error, unknown time type */
    ASN_INPUT_E = -154, // ASN input error, not enough data */
    ASN_SIG_CONFIRM_E = -155, // ASN sig error, confirm failure */
    ASN_SIG_HASH_E = -156, // ASN sig error, unsupported hash type */
    ASN_SIG_KEY_E = -157, // ASN sig error, unsupported key type */
    ASN_DH_KEY_E = -158, // ASN key init error, invalid input */
    ASN_CRIT_EXT_E = -160, // ASN unsupported critical extension */
    ASN_ALT_NAME_E = -161, // ASN alternate name error */
    ASN_NO_PEM_HEADER = -162, // ASN no PEM header found */

    ECC_BAD_ARG_E = -170, // ECC input argument of wrong type */
    ASN_ECC_KEY_E = -171, // ASN ECC bad input */
    ECC_CURVE_OID_E = -172, // Unsupported ECC OID curve type */
    BAD_FUNC_ARG = -173, // Bad function argument provided */
    NOT_COMPILED_IN = -174, // Feature not compiled in */
    UNICODE_SIZE_E = -175, // Unicode password too big */
    NO_PASSWORD = -176, // no password provided by user */
    ALT_NAME_E = -177, // alt name size problem, too big */
    BAD_OCSP_RESPONDER = -178, // missing key usage extensions */
    CRL_CERT_DATE_ERR = -179, // CRL date error */

    AES_GCM_AUTH_E = -180, // AES-GCM Authentication check failure */
    AES_CCM_AUTH_E = -181, // AES-CCM Authentication check failure */

    ASYNC_INIT_E = -182, // Async Init type error */

    COMPRESS_INIT_E = -183, // Compress init error */
    COMPRESS_E = -184, // Compress error */
    DECOMPRESS_INIT_E = -185, // DeCompress init error */
    DECOMPRESS_E = -186, // DeCompress error */

    BAD_ALIGN_E = -187, // Bad alignment for operation, no alloc */
    ASN_NO_SIGNER_E = -188, // ASN no signer to confirm failure */
    ASN_CRL_CONFIRM_E = -189, // ASN CRL signature confirm failure */
    ASN_CRL_NO_SIGNER_E = -190, // ASN CRL no signer to confirm failure */
    ASN_OCSP_CONFIRM_E = -191, // ASN OCSP signature confirm failure */

    BAD_STATE_E = -192, // Bad state operation */
    BAD_PADDING_E = -193, // Bad padding, msg not correct length  */

    REQ_ATTRIBUTE_E = -194, // setting cert request attributes error */

    PKCS7_OID_E = -195, // PKCS#7, mismatched OID error */
    PKCS7_RECIP_E = -196, // PKCS#7, recipient error */
    FIPS_NOT_ALLOWED_E = -197, // FIPS not allowed error */
    ASN_NAME_INVALID_E = -198, // ASN name constraint error */

    RNG_FAILURE_E = -199, // RNG Failed, Reinitialize */
    HMAC_MIN_KEYLEN_E = -200, // FIPS Mode HMAC Minimum Key Length error */
    RSA_PAD_E = -201, // RSA Padding Error */
    LENGTH_ONLY_E = -202, // Returning output length only */

    IN_CORE_FIPS_E = -203, // In Core Integrity check failure */
    AES_KAT_FIPS_E = -204, // AES KAT failure */
    DES3_KAT_FIPS_E = -205, // DES3 KAT failure */
    HMAC_KAT_FIPS_E = -206, // HMAC KAT failure */
    RSA_KAT_FIPS_E = -207, // RSA KAT failure */
    DRBG_KAT_FIPS_E = -208, // HASH DRBG KAT failure */
    DRBG_CONT_FIPS_E = -209, // HASH DRBG Continuous test failure */
    AESGCM_KAT_FIPS_E = -210, // AESGCM KAT failure */
    THREAD_STORE_KEY_E = -211, // Thread local storage key create failure */
    THREAD_STORE_SET_E = -212, // Thread local storage key set failure */

    MAC_CMP_FAILED_E = -213, // MAC comparison failed */
    IS_POINT_E = -214, // ECC is point on curve failed */
    ECC_INF_E = -215, // ECC point infinity error */
    ECC_PRIV_KEY_E = -216, // ECC private key not valid error */
    ECC_OUT_OF_RANGE_E = -217, // ECC key component out of range */

    SRP_CALL_ORDER_E = -218, // SRP function called in the wrong order. */
    SRP_VERIFY_E = -219, // SRP proof verification failed. */
    SRP_BAD_KEY_E = -220, // SRP bad ephemeral values. */

    ASN_NO_SKID = -221, // ASN no Subject Key Identifier found */
    ASN_NO_AKID = -222, // ASN no Authority Key Identifier found */
    ASN_NO_KEYUSAGE = -223, // ASN no Key Usage found */
    SKID_E = -224, // setting Subject Key Identifier error */
    AKID_E = -225, // setting Authority Key Identifier error */
    KEYUSAGE_E = -226, // Bad Key Usage value */
    CERTPOLICIES_E = -227, // setting Certificate Policies error */

    WC_INIT_E = -228, // wolfcrypt failed to initialize */
    SIG_VERIFY_E = -229, // wolfcrypt signature verify error */
    BAD_COND_E = -230, // Bad condition variable operation */
    SIG_TYPE_E = -231, // Signature Type not enabled/available */
    HASH_TYPE_E = -232, // Hash Type not enabled/available */

    WC_KEY_SIZE_E = -234, // Key size error, either too small or large */
    ASN_COUNTRY_SIZE_E = -235, // ASN Cert Gen, invalid country code size */
    MISSING_RNG_E = -236, // RNG required but not provided */
    ASN_PATHLEN_SIZE_E = -237, // ASN CA path length too large error */
    ASN_PATHLEN_INV_E = -238, // ASN CA path length inversion error */

    BAD_KEYWRAP_ALG_E = -239,
    BAD_KEYWRAP_IV_E = -240, // Decrypted AES key wrap IV incorrect */
    WC_CLEANUP_E = -241, // wolfcrypt cleanup failed */
    ECC_CDH_KAT_FIPS_E = -242, // ECC CDH Known Answer Test failure */
    DH_CHECK_PUB_E = -243, // DH Check Pub Key error */
    BAD_PATH_ERROR = -244, // Bad path for opendir */

    ASYNC_OP_E = -245, // Async operation error */

    ECC_PRIVATEONLY_E = -246, // Invalid use of private only ECC key*/
    EXTKEYUSAGE_E = -247, // Bad Extended Key Usage value */
    WC_HW_E = -248, // Error with hardware crypto use */
    WC_HW_WAIT_E = -249, // Hardware waiting on resource */

    PSS_SALTLEN_E = -250, // PSS length of salt is too long for hash */
    PRIME_GEN_E = -251, // Failure finding a prime. */
    BER_INDEF_E = -252, // Cannot decode indefinite length BER. */
    RSA_OUT_OF_RANGE_E = -253, // Ciphertext to decrypt out of range. */
    RSAPSS_PAT_FIPS_E = -254, // RSA-PSS PAT failure */
    ECDSA_PAT_FIPS_E = -255, // ECDSA PAT failure */
    DH_KAT_FIPS_E = -256, // DH KAT failure */
    AESCCM_KAT_FIPS_E = -257, // AESCCM KAT failure */
    SHA3_KAT_FIPS_E = -258, // SHA-3 KAT failure */
    ECDHE_KAT_FIPS_E = -259, // ECDHE KAT failure */
    AES_GCM_OVERFLOW_E = -260, // AES-GCM invocation counter overflow. */
    AES_CCM_OVERFLOW_E = -261, // AES-CCM invocation counter overflow. */
    RSA_KEY_PAIR_E = -262, // RSA Key Pair-Wise Consistency check fail. */
    DH_CHECK_PRIV_E = -263, // DH Check Priv Key error */

    WC_AFALG_SOCK_E = -264, // AF_ALG socket error */
    WC_DEVCRYPTO_E = -265, // /dev/crypto error */

    ZLIB_INIT_ERROR = -266, // zlib init error  */
    ZLIB_COMPRESS_ERROR = -267, // zlib compression error  */
    ZLIB_DECOMPRESS_ERROR = -268, // zlib decompression error  */

    PKCS7_NO_SIGNER_E = -269, // No signer in PKCS#7 signed data msg */
    WC_PKCS7_WANT_READ_E = -270, // PKCS7 operations wants more input */

    CRYPTOCB_UNAVAILABLE = -271, // Crypto callback unavailable */
    PKCS7_SIGNEEDS_CHECK = -272, // signature needs verified by caller */
    PSS_SALTLEN_RECOVER_E = -273, // PSS slat length not recoverable */
    CHACHA_POLY_OVERFLOW = -274, // ChaCha20Poly1305 limit overflow */
    ASN_SELF_SIGNED_E = -275, // ASN self-signed certificate error */
    SAKKE_VERIFY_FAIL_E = -276, // SAKKE derivation verification error */
    MISSING_IV = -277, // IV was not set */
    MISSING_KEY = -278, // Key was not set */
    BAD_LENGTH_E = -279, // Value of length parameter is invalid. */
    ECDSA_KAT_FIPS_E = -280, // ECDSA KAT failure */
    RSA_PAT_FIPS_E = -281, // RSA Pairwise failure */
    KDF_TLS12_KAT_FIPS_E = -282, // TLS12 KDF KAT failure */
    KDF_TLS13_KAT_FIPS_E = -283, // TLS13 KDF KAT failure */
    KDF_SSH_KAT_FIPS_E = -284, // SSH KDF KAT failure */
    DHE_PCT_E = -285, // DHE Pairwise Consistency Test failure */
    ECC_PCT_E = -286, // ECDHE Pairwise Consistency Test failure */
    FIPS_PRIVATE_KEY_LOCKED_E = -287, // Cannot export private key. */

    INPUT_CASE_ERROR = -301, // process input state error */
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
    HRR_COOKIE_ERROR = -505, // HRR msg cookie mismatch */
    // end negotiation parameter errors only 10 for now */
    // add strings to wolfSSL_ERR_reason_error_string in internal.c !!!!! */

    // no error stings go down here, add above negotiation errors !!!! */
};
