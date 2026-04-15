/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * OpenSSL 3.0 SSL interface implementation.
 *
 * This file provides the platform-specific SSL helper functions that
 * abstract differences between OpenSSL 3.0, BabaSSL/Tongsuo, and
 * BoringSSL.
 *
 * The OpenSSL 3.0 backend closely follows the BabaSSL backend, since
 * BabaSSL is itself derived from OpenSSL.  The main differences are:
 *
 *   - SSL_set_quic_early_data_enabled() may not exist in stock
 *     OpenSSL 3.0 (it is a BoringSSL / QUIC-TLS extension).
 *     We wrap it with a feature check.
 *   - SSL_get_early_data_status() is the standard OpenSSL 3.0 API
 *     for checking 0-RTT acceptance.
 *   - Certificate chain iteration uses the X509_STORE_CTX API.
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/opensslv.h>

#include "src/tls/xqc_ssl_if.h"
#include "src/tls/xqc_tls_common.h"
#include "src/transport/xqc_conn.h"


/* ─────────────────── Session / timeout ─────────────────── */

void
xqc_ssl_ctx_set_timeout(SSL_CTX *ctx, uint32_t timeout)
{
    timeout = (timeout == 0 ? XQC_SESSION_DEFAULT_TIMEOUT : timeout);
    SSL_CTX_set_timeout(ctx, timeout);
}


/* ─────────────────── Early data (0-RTT) helpers ─────────────────── */

void
xqc_ssl_ctx_enable_max_early_data(SSL_CTX *ctx)
{
    /*
     * In stock OpenSSL 3.0 with the QUIC-TLS patches (ossl-quic or
     * compatible), SSL_CTX_set_max_early_data() is used.
     * If the symbol is not available the macro below becomes a no-op.
     */
#if defined(SSL_CTX_set_max_early_data)  \
    || OPENSSL_VERSION_NUMBER >= 0x30000000L
    SSL_CTX_set_max_early_data(ctx, XQC_UINT32_MAX);
#endif
}


xqc_int_t
xqc_ssl_ctx_set_cipher_suites(SSL_CTX *ctx, const char *ciphers)
{
    int ret = SSL_CTX_set_ciphersuites(ctx, ciphers);
    if (ret != XQC_SSL_SUCCESS) {
        return -XQC_TLS_INTERNAL;
    }
    return XQC_OK;
}


xqc_bool_t
xqc_ssl_session_is_early_data_enabled(SSL_SESSION *session)
{
#if defined(SSL_SESSION_get_max_early_data)     \
    || OPENSSL_VERSION_NUMBER >= 0x30000000L
    return SSL_SESSION_get_max_early_data(session) == XQC_UINT32_MAX;
#else
    (void)session;
    return XQC_FALSE;
#endif
}


void
xqc_ssl_enable_max_early_data(SSL *ssl)
{
    /*
     * SSL_set_quic_early_data_enabled() is available in the QUIC-TLS
     * fork of OpenSSL (and in BabaSSL).  If you build against stock
     * OpenSSL 3.0 + quictls patches it should be present.
     */
#if defined(SSL_set_quic_early_data_enabled) || defined(OPENSSL_IS_QUICTLS)
    SSL_set_quic_early_data_enabled(ssl, 1);
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
    /*
     * Fallback for stock OpenSSL 3.0 without QUIC-TLS patches:
     * attempt via generic max_early_data if the QUIC API is missing.
     * Note: stock OpenSSL 3.0 does NOT have QUIC support out-of-the-box;
     * users must build against quictls or a patched OpenSSL.
     */
    (void)ssl;
#endif
}


/* ─────────────────── Certificate chain ─────────────────── */

xqc_int_t
xqc_ssl_get_certs_array(SSL *ssl, X509_STORE_CTX *store_ctx,
    unsigned char **certs_array, size_t array_cap,
    size_t *certs_array_len, size_t *certs_len)
{
    unsigned char *cert_buf = NULL;
    X509 *cert = NULL;
    int cert_size = 0;
    const STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(store_ctx);

    (void)ssl;

    *certs_array_len = sk_X509_num(chain);
    if (*certs_array_len > XQC_MAX_VERIFY_DEPTH) {
        X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_CERT_CHAIN_TOO_LONG);
        return -XQC_TLS_INTERNAL;
    }

    for (int i = 0; i < (int)*certs_array_len; i++) {
        cert = sk_X509_value(chain, i);

        cert_size = i2d_X509(cert, NULL);
        if (cert_size <= 0) {
            return -XQC_TLS_INTERNAL;
        }

        /* caller must free via xqc_ssl_free_certs_array */
        certs_array[i] = xqc_malloc(cert_size);
        if (certs_array[i] == NULL) {
            return -XQC_TLS_INTERNAL;
        }

        cert_buf = certs_array[i];
        cert_size = i2d_X509(cert, &cert_buf);
        if (cert_size <= 0) {
            return -XQC_TLS_INTERNAL;
        }
        certs_len[i] = cert_size;
    }

    return XQC_OK;
}

void
xqc_ssl_free_certs_array(unsigned char **certs_array, size_t certs_array_len)
{
    for (size_t i = 0; i < certs_array_len; i++) {
        if (certs_array[i] != NULL) {
            xqc_free(certs_array[i]);
        }
    }
}


/* ─────────────────── Early data acceptance check ─────────────────── */

xqc_bool_t
xqc_ssl_is_early_data_accepted(SSL *ssl)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_ACCEPTED
               ? XQC_TRUE
               : XQC_FALSE;
#else
    (void)ssl;
    return XQC_FALSE;
#endif
}


/* ─────────────────── TLS handshake ─────────────────── */

xqc_ssl_handshake_res_t
xqc_ssl_do_handshake(SSL *ssl, xqc_connection_t *conn, xqc_log_t *log)
{
    int rv = SSL_do_handshake(ssl);

    xqc_log(log, XQC_LOG_DEBUG,
            "|ssl_do_handshake|SSL_quic_read_level:%d|"
            "SSL_quic_write_level:%d|rv:%d|",
            (int)SSL_quic_read_level(ssl),
            (int)SSL_quic_write_level(ssl),
            rv);

    /* check if ClientHello has been received completely */
    if (SSL_quic_read_level(ssl) > 0
        && conn != NULL
        && !(conn->conn_flag & XQC_CONN_FLAG_TLS_CH_RECVD))
    {
        conn->conn_flag |= XQC_CONN_FLAG_TLS_CH_RECVD;
    }

    if (rv <= 0) {
        int err = SSL_get_error(ssl, rv);
        switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return XQC_SSL_HSK_RES_WAIT;

        case SSL_ERROR_SSL:
        default:
            return XQC_SSL_HSK_RES_FAIL;
        }
    }

    return XQC_SSL_HSK_RES_FIN;
}
