/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * QUIC-TLS compatibility header for stock OpenSSL 3.0.
 *
 * Stock OpenSSL 3.0 does NOT include the QUIC API extensions
 * (SSL_QUIC_METHOD, SSL_set_quic_method, SSL_provide_quic_data, etc.)
 * that were introduced by BoringSSL and adopted by the quictls fork.
 *
 * This header provides the type definitions and function declarations
 * so that xquic can compile against stock OpenSSL 3.0.  The actual
 * function bodies are in xqc_ossl_quic_compat.c.
 *
 * If you are building against quictls/openssl (which does have the
 * QUIC API), this header is a no-op because the guards detect the
 * existing definitions.
 */

#ifndef XQC_OSSL_QUIC_COMPAT_H
#define XQC_OSSL_QUIC_COMPAT_H

#include <openssl/ssl.h>
#include <openssl/opensslv.h>

/*
 * Only activate if we are on OpenSSL 3.0+ **and** NOT BoringSSL,
 * **and** the QUIC API is not already provided by the SSL library.
 *
 * quictls provides <openssl/quic.h> and guards its QUIC API with
 * `#ifndef OPENSSL_NO_QUIC`.  We use __has_include to detect quictls.
 * Stock OpenSSL 3.0 has neither quic.h nor any QUIC API.
 */

/* Detect whether the SSL library already provides QUIC API */
#if defined(__has_include)
#  if __has_include(<openssl/quic.h>)
#    define XQC_SSL_HAS_QUIC_API 1
#  endif
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L   \
    && !defined(OPENSSL_IS_BORINGSSL)       \
    && !defined(XQC_SSL_HAS_QUIC_API)

#define XQC_OSSL_QUIC_COMPAT  1   /* flag: we are using the compat shim */

#include <stdint.h>
#include <stddef.h>

/* ─── encryption level enum (matches BoringSSL / quictls) ─── */
enum ssl_encryption_level_t {
    ssl_encryption_initial     = 0,
    ssl_encryption_early_data  = 1,
    ssl_encryption_handshake   = 2,
    ssl_encryption_application = 3,
};

/* ─── SSL_QUIC_METHOD structure ─── */
typedef struct ssl_quic_method_st {
    int (*set_read_secret)(SSL *ssl, enum ssl_encryption_level_t level,
                           const SSL_CIPHER *cipher,
                           const uint8_t *secret, size_t secret_len);
    int (*set_write_secret)(SSL *ssl, enum ssl_encryption_level_t level,
                            const SSL_CIPHER *cipher,
                            const uint8_t *secret, size_t secret_len);
    int (*add_handshake_data)(SSL *ssl, enum ssl_encryption_level_t level,
                              const uint8_t *data, size_t len);
    int (*flush_flight)(SSL *ssl);
    int (*send_alert)(SSL *ssl, enum ssl_encryption_level_t level,
                      uint8_t alert);
} SSL_QUIC_METHOD;


/* ─── Function stubs ─── */

/**
 * The stub implementations below always return success (1) or are
 * no-ops.  They allow xquic to **compile and link** against stock
 * OpenSSL 3.0, but QUIC-level TLS integration will NOT function
 * correctly at runtime without quictls or BoringSSL.
 *
 * If you need a working QUIC stack, build against quictls/openssl:
 *   https://github.com/quictls/openssl
 */

int  SSL_set_quic_method(SSL *ssl, const SSL_QUIC_METHOD *method);
int  SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params, size_t params_len);
void SSL_get_peer_quic_transport_params(const SSL *ssl, const uint8_t **out, size_t *out_len);
int  SSL_provide_quic_data(SSL *ssl, enum ssl_encryption_level_t level,
                           const uint8_t *data, size_t len);
int  SSL_process_quic_post_handshake(SSL *ssl);
enum ssl_encryption_level_t SSL_quic_read_level(const SSL *ssl);
enum ssl_encryption_level_t SSL_quic_write_level(const SSL *ssl);
void SSL_set_quic_use_legacy_codepoint(SSL *ssl, int use_legacy);
int  SSL_set_quic_early_data_context(SSL *ssl, const uint8_t *context, size_t context_len);

#endif /* stock OpenSSL 3.0 without QUIC API */

#endif /* XQC_OSSL_QUIC_COMPAT_H */
