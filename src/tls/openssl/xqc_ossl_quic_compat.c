/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * QUIC-TLS compatibility stub implementations for stock OpenSSL 3.0.
 *
 * These are no-op / minimal stubs that allow xquic to link against
 * stock OpenSSL 3.0 (which lacks the QUIC-TLS API).
 *
 * ┌──────────────────────────────────────────────────────────────┐
 * │ WARNING: These stubs allow compilation and linking ONLY.     │
 * │ For a fully functioning QUIC-TLS stack, you MUST build       │
 * │ against quictls/openssl or BoringSSL.                        │
 * └──────────────────────────────────────────────────────────────┘
 */

#include "xqc_ossl_quic_compat.h"

#ifdef XQC_OSSL_QUIC_COMPAT

#include <string.h>

/* Per-SSL storage for the QUIC method and transport params.
 * In a real implementation this would be stored inside the SSL object
 * via ex_data; here we use a simple global for link-time satisfaction. */

int
SSL_set_quic_method(SSL *ssl, const SSL_QUIC_METHOD *method)
{
    (void)ssl;
    (void)method;
    /* stub: always succeed */
    return 1;
}

int
SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params, size_t params_len)
{
    (void)ssl;
    (void)params;
    (void)params_len;
    return 1;
}

void
SSL_get_peer_quic_transport_params(const SSL *ssl, const uint8_t **out, size_t *out_len)
{
    (void)ssl;
    *out = NULL;
    *out_len = 0;
}

int
SSL_provide_quic_data(SSL *ssl, enum ssl_encryption_level_t level,
                      const uint8_t *data, size_t len)
{
    (void)ssl;
    (void)level;
    (void)data;
    (void)len;
    return 1;
}

int
SSL_process_quic_post_handshake(SSL *ssl)
{
    (void)ssl;
    return 1;
}

enum ssl_encryption_level_t
SSL_quic_read_level(const SSL *ssl)
{
    (void)ssl;
    return ssl_encryption_initial;
}

enum ssl_encryption_level_t
SSL_quic_write_level(const SSL *ssl)
{
    (void)ssl;
    return ssl_encryption_initial;
}

void
SSL_set_quic_use_legacy_codepoint(SSL *ssl, int use_legacy)
{
    (void)ssl;
    (void)use_legacy;
}

int
SSL_set_quic_early_data_context(SSL *ssl, const uint8_t *context, size_t context_len)
{
    (void)ssl;
    (void)context;
    (void)context_len;
    return 1;
}

#endif /* XQC_OSSL_QUIC_COMPAT */
