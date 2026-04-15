/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * OpenSSL 3.0 HKDF implementation.
 *
 * OpenSSL 3.0 introduces the EVP_KDF API as the preferred way to do
 * key derivation.  We provide two code paths:
 *
 *   1. OPENSSL_VERSION_NUMBER >= 0x30000000L  →  use EVP_KDF_*
 *   2. Fallback                               →  use EVP_PKEY_CTX HKDF
 *      (same pattern as the BabaSSL backend)
 *
 * Both paths implement the same two functions that the rest of xquic
 * expects: xqc_hkdf_extract() and xqc_hkdf_expand().
 */

#include "src/tls/xqc_hkdf.h"

#include <openssl/err.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/* ────────── OpenSSL 3.0+ preferred path: EVP_KDF ────────── */
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>


/**
 * @brief helper: look up the HKDF KDF provider once per call.
 *        In a real production build you may want to cache this.
 */
static EVP_KDF *
xqc_ossl3_kdf_fetch(void)
{
    return EVP_KDF_fetch(NULL, "HKDF", NULL);
}


xqc_int_t
xqc_hkdf_extract(uint8_t *dest, size_t destlen,
                  const uint8_t *secret, size_t secretlen,
                  const uint8_t *salt, size_t saltlen,
                  const xqc_digest_t *md)
{
    xqc_int_t       rc  = -XQC_TLS_DERIVE_KEY_ERROR;
    EVP_KDF        *kdf = NULL;
    EVP_KDF_CTX    *kctx = NULL;
    const char     *md_name = EVP_MD_get0_name(md->digest);

    kdf = xqc_ossl3_kdf_fetch();
    if (kdf == NULL) {
        goto end;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        goto end;
    }

    OSSL_PARAM params[5];
    int idx = 0;
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;

    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[idx++] = OSSL_PARAM_construct_utf8_string(
                        OSSL_KDF_PARAM_DIGEST, (char *)md_name, 0);
    params[idx++] = OSSL_PARAM_construct_octet_string(
                        OSSL_KDF_PARAM_KEY, (void *)secret, secretlen);
    params[idx++] = OSSL_PARAM_construct_octet_string(
                        OSSL_KDF_PARAM_SALT, (void *)salt, saltlen);
    params[idx]   = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, dest, destlen, params) != 1) {
        goto end;
    }

    rc = XQC_OK;

end:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return rc;
}


xqc_int_t
xqc_hkdf_expand(uint8_t *dest, size_t destlen,
                 const uint8_t *secret, size_t secretlen,
                 const uint8_t *info, size_t infolen,
                 const xqc_digest_t *md)
{
    xqc_int_t       rc  = -XQC_TLS_DERIVE_KEY_ERROR;
    EVP_KDF        *kdf = NULL;
    EVP_KDF_CTX    *kctx = NULL;
    const char     *md_name = EVP_MD_get0_name(md->digest);

    kdf = xqc_ossl3_kdf_fetch();
    if (kdf == NULL) {
        goto end;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        goto end;
    }

    OSSL_PARAM params[5];
    int idx = 0;
    int mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;

    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[idx++] = OSSL_PARAM_construct_utf8_string(
                        OSSL_KDF_PARAM_DIGEST, (char *)md_name, 0);
    params[idx++] = OSSL_PARAM_construct_octet_string(
                        OSSL_KDF_PARAM_KEY, (void *)secret, secretlen);
    params[idx++] = OSSL_PARAM_construct_octet_string(
                        OSSL_KDF_PARAM_INFO, (void *)info, infolen);
    params[idx]   = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, dest, destlen, params) != 1) {
        goto end;
    }

    rc = XQC_OK;

end:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return rc;
}


#else
/* ────────── Fallback: EVP_PKEY_CTX HKDF (same as BabaSSL) ────────── */
#include <openssl/kdf.h>


xqc_int_t
xqc_hkdf_expand(uint8_t *dest, size_t destlen,
                 const uint8_t *secret, size_t secretlen,
                 const uint8_t *info, size_t infolen,
                 const xqc_digest_t *ctx)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return -XQC_TLS_NOBUF;
    }

    if (EVP_PKEY_derive_init(pctx) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->digest) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_derive(pctx, dest, &destlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    EVP_PKEY_CTX_free(pctx);
    return XQC_OK;

err:
    EVP_PKEY_CTX_free(pctx);
    return -XQC_TLS_DERIVE_KEY_ERROR;
}


xqc_int_t
xqc_hkdf_extract(uint8_t *dest, size_t destlen,
                  const uint8_t *secret, size_t secretlen,
                  const uint8_t *salt, size_t saltlen,
                  const xqc_digest_t *ctx)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return -XQC_TLS_NOBUF;
    }

    if (EVP_PKEY_derive_init(pctx) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->digest) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    if (EVP_PKEY_derive(pctx, dest, &destlen) != XQC_SSL_SUCCESS) {
        goto err;
    }

    EVP_PKEY_CTX_free(pctx);
    return XQC_OK;

err:
    EVP_PKEY_CTX_free(pctx);
    return -XQC_TLS_DERIVE_KEY_ERROR;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
