const std = @import("std");

fn sdkPath(comptime suffix: []const u8) []const u8 {
    if (suffix[0] != '/') @compileError("relToPath requires an absolute path!");
    return comptime blk: {
        const root_dir = std.fs.path.dirname(@src().file) orelse ".";
        break :blk root_dir ++ suffix;
    };
}

const pkgs = struct {
    const serve = std.build.Pkg{
        .name = "serve",
        .source = .{ .path = "src/serve.zig" },
        .dependencies = &.{ network, uri },
    };
    const network = std.build.Pkg{
        .name = "network",
        .source = .{ .path = "vendor/network/network.zig" },
    };
    const uri = std.build.Pkg{
        .name = "uri",
        .source = .{ .path = "vendor/uri/uri.zig" },
    };
};

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const wolfSSL = createWolfSSL(b, target);
    wolfSSL.install();

    const enable_gopher = b.option(bool, "enable-gopher", "Enables building the gopher example") orelse true;
    const enable_http = b.option(bool, "enable-http", "Enables building the http example") orelse true;
    const enable_gemini = b.option(bool, "enable-gemini", "Enables building the gemini example") orelse true;

    {
        const tls_server_exe = b.addExecutable("tls-server", "examples/tls-server.zig");
        tls_server_exe.setTarget(target);
        tls_server_exe.setBuildMode(mode);
        tls_server_exe.addPackage(pkgs.serve);
        tls_server_exe.addPackage(pkgs.network);
        tls_server_exe.linkLibrary(wolfSSL);
        tls_server_exe.addIncludeDir("vendor/wolfssl");
        tls_server_exe.linkLibC();
        tls_server_exe.install();
    }

    if (enable_gopher) {
        const gopher_exe = b.addExecutable("gopher-server", "examples/gopher.zig");
        gopher_exe.setTarget(target);
        gopher_exe.setBuildMode(mode);
        gopher_exe.addPackage(pkgs.serve);
        gopher_exe.addPackage(pkgs.network);
        gopher_exe.install();
    }

    if (enable_http) {
        const http_exe = b.addExecutable("http-server", "examples/http.zig");
        http_exe.setTarget(target);
        http_exe.setBuildMode(mode);
        http_exe.addPackage(pkgs.serve);
        http_exe.addPackage(pkgs.network);
        http_exe.linkLibrary(wolfSSL);
        http_exe.addIncludeDir("vendor/wolfssl");
        http_exe.install();
    }

    if (enable_gemini) {
        const gemini_exe = b.addExecutable("gemini-server", "examples/gemini.zig");
        gemini_exe.setTarget(target);
        gemini_exe.setBuildMode(mode);
        gemini_exe.addPackage(pkgs.serve);
        gemini_exe.addPackage(pkgs.network);
        gemini_exe.addIncludeDir("vendor/wolfssl");
        gemini_exe.linkLibrary(wolfSSL);
        gemini_exe.install();
    }
}

pub const include_dirs = [_][]const u8{
    sdkPath("/vendor/wolfssl"),
};

pub fn createWolfSSL(b: *std.build.Builder, target: std.zig.CrossTarget) *std.build.LibExeObjStep {
    const lib = b.addStaticLibrary("wolfSSL", null);
    lib.setBuildMode(.ReleaseSafe);
    lib.setTarget(target);
    lib.addCSourceFiles(&wolfssl_sources, &wolfssl_flags);
    lib.addCSourceFiles(&wolfcrypt_sources, &wolfcrypt_flags);
    lib.addIncludeDir(sdkPath("/vendor/wolfssl/"));

    lib.defineCMacro("TFM_TIMING_RESISTANT", null);
    lib.defineCMacro("ECC_TIMING_RESISTANT", null);
    lib.defineCMacro("WC_RSA_BLINDING", null);
    lib.defineCMacro("HAVE_PTHREAD", null);
    lib.defineCMacro("NO_INLINE", null);
    lib.defineCMacro("WOLFSSL_TLS13", null);
    lib.defineCMacro("WC_RSA_PSS", null);
    lib.defineCMacro("HAVE_TLS_EXTENSIONS", null);
    lib.defineCMacro("HAVE_SNI", null);
    lib.defineCMacro("HAVE_MAX_FRAGMENT", null);
    lib.defineCMacro("HAVE_TRUNCATED_HMAC", null);
    lib.defineCMacro("HAVE_ALPN", null);
    lib.defineCMacro("HAVE_TRUSTED_CA", null);
    lib.defineCMacro("HAVE_HKDF", null);
    lib.defineCMacro("BUILD_GCM", null);
    lib.defineCMacro("HAVE_AESCCM", null);
    lib.defineCMacro("HAVE_SESSION_TICKET", null);
    lib.defineCMacro("HAVE_CHACHA", null);
    lib.defineCMacro("HAVE_POLY1305", null);
    lib.defineCMacro("HAVE_ECC", null);
    lib.defineCMacro("HAVE_FFDHE_2048", null);
    lib.defineCMacro("HAVE_FFDHE_3072", null);
    lib.defineCMacro("HAVE_FFDHE_4096", null);
    lib.defineCMacro("HAVE_FFDHE_6144", null);
    lib.defineCMacro("HAVE_FFDHE_8192", null);
    lib.defineCMacro("HAVE_ONE_TIME_AUTH", null);
    lib.defineCMacro("HAVE_SYS_TIME_H", null);
    lib.defineCMacro("SESSION_INDEX", null);
    lib.defineCMacro("SESSION_CERTS", null);
    lib.defineCMacro("OPENSSL_EXTRA_X509", null);
    lib.defineCMacro("OPENSSL_EXTRA_X509_SMALL", null);
    lib.linkLibC();

    return lib;
}

const wolfssl_flags = [_][]const u8{
    "-std=c89",
};

const wolfssl_sources = [_][]const u8{
    sdkPath("/vendor/wolfssl/src/bio.c"),
    sdkPath("/vendor/wolfssl/src/crl.c"),
    sdkPath("/vendor/wolfssl/src/internal.c"),
    sdkPath("/vendor/wolfssl/src/keys.c"),
    sdkPath("/vendor/wolfssl/src/ocsp.c"),
    sdkPath("/vendor/wolfssl/src/sniffer.c"),
    sdkPath("/vendor/wolfssl/src/ssl.c"),
    sdkPath("/vendor/wolfssl/src/tls.c"),
    sdkPath("/vendor/wolfssl/src/tls13.c"),
    sdkPath("/vendor/wolfssl/src/wolfio.c"),
};

const wolfcrypt_flags = [_][]const u8{
    "-std=c89",
};
const wolfcrypt_sources = [_][]const u8{
    sdkPath("/vendor/wolfssl/wolfcrypt/src/aes.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/arc4.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/asm.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/asn.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/blake2b.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/blake2s.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/camellia.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/chacha.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/chacha20_poly1305.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/cmac.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/coding.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/compress.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/cpuid.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/cryptocb.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/curve448.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/curve25519.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/des3.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/dh.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/dsa.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/ecc.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/eccsi.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/ecc_fp.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/ed448.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/ed25519.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/error.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/evp.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/falcon.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/fe_448.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/fe_low_mem.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/fe_operations.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/ge_448.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/ge_low_mem.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/ge_operations.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/hash.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/hc128.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/hmac.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/idea.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/integer.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/kdf.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/logging.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/md2.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/md4.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/md5.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/memory.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/misc.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/pkcs7.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/pkcs12.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/poly1305.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/pwdbased.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/rabbit.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/random.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/rc2.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/ripemd.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/rsa.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sakke.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sha.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sha3.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sha256.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sha512.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/signature.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sp_arm32.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sp_arm64.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sp_armthumb.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sp_c32.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sp_c64.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sp_cortexm.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sp_dsp32.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sp_int.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/sp_x86_64.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/srp.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/tfm.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/wc_dsp.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/wc_encrypt.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/wc_pkcs11.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/wc_port.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/wolfevent.c"),
    sdkPath("/vendor/wolfssl/wolfcrypt/src/wolfmath.c"),
};
