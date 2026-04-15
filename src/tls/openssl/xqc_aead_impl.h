/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * OpenSSL 3.0 AEAD implementation header.
 * Adapted from babassl/xqc_aead_impl.h for OpenSSL >= 3.0.
 *
 * OpenSSL 3.0 uses EVP_CIPHER for both AEAD and stream ciphers,
 * same as BabaSSL/Tongsuo but with slightly different API details.
 */

#ifndef XQC_AEAD_IMPL_H_
#define XQC_AEAD_IMPL_H_

#include <openssl/evp.h>
#include <openssl/ssl.h>

#ifndef XQC_CRYPTO_PRIVATE
#error "Do not include this file directly, include xqc_crypto.h"
#endif


/*
 * Cipher id definition for TLS 1.3.
 * OpenSSL 3.0 defines TLS1_3_CK_* constants in <openssl/ssl.h>.
 * Fallback definitions are provided for older OpenSSL headers.
 */
#ifndef TLS1_3_CK_AES_128_GCM_SHA256
#define TLS1_3_CK_AES_128_GCM_SHA256           0x03001301
#endif
#ifndef TLS1_3_CK_AES_256_GCM_SHA384
#define TLS1_3_CK_AES_256_GCM_SHA384           0x03001302
#endif
#ifndef TLS1_3_CK_CHACHA20_POLY1305_SHA256
#define TLS1_3_CK_CHACHA20_POLY1305_SHA256     0x03001303
#endif

#define XQC_TLS13_AES_128_GCM_SHA256           TLS1_3_CK_AES_128_GCM_SHA256
#define XQC_TLS13_AES_256_GCM_SHA384           TLS1_3_CK_AES_256_GCM_SHA384
#define XQC_TLS13_CHACHA20_POLY1305_SHA256     TLS1_3_CK_CHACHA20_POLY1305_SHA256


/*
 * OpenSSL 3.0 uses EVP_CIPHER for both AEAD and stream cipher suites,
 * same as the BabaSSL/Tongsuo backend.
 */
#define XQC_CIPHER_SUITES_IMPL        const EVP_CIPHER *
#define XQC_AEAD_SUITES_IMPL          XQC_CIPHER_SUITES_IMPL

#define XQC_AEAD_OVERHEAD_IMPL(obj, cln)       (0) + (obj)->taglen

/* inner definition, MUST NOT be called directly */
#define DO_NOT_CALL_XQC_AEAD_INIT(obj, a, tgl) do {                          \
    obj->aead       = a;                                                     \
    obj->keylen     = EVP_CIPHER_key_length(obj->aead);                      \
    obj->noncelen   = EVP_CIPHER_iv_length(obj->aead);                       \
    obj->taglen     = (tgl);                                                 \
    obj->encrypt    = xqc_ossl3_aead_encrypt;                                \
    obj->decrypt    = xqc_ossl3_aead_decrypt;                                \
} while (0)

/* inner definition, MUST NOT be called directly */
#define DO_NOT_CALL_XQC_CIPHER_INIT(obj, c) do {                             \
    obj->cipher     = c;                                                     \
    obj->keylen     = EVP_CIPHER_key_length(obj->cipher);                    \
    obj->noncelen   = EVP_CIPHER_iv_length(obj->cipher);                     \
    obj->hp_mask    = xqc_ossl3_hp_mask;                                     \
} while (0)

/* AES-GCM initialization */
#define XQC_AEAD_INIT_AES_GCM_IMPL(obj, d) do {                             \
    xqc_pkt_protect_aead_t *___aead  = (obj);                                \
    DO_NOT_CALL_XQC_AEAD_INIT(___aead, EVP_aes_##d##_gcm(),                  \
                              EVP_GCM_TLS_TAG_LEN);                          \
} while (0)

/* ChaCha20-Poly1305 initialization */
#define XQC_AEAD_INIT_CHACHA20_POLY1305_IMPL(obj) do {                       \
    xqc_pkt_protect_aead_t *___aead = (obj);                                 \
    DO_NOT_CALL_XQC_AEAD_INIT(___aead, EVP_chacha20_poly1305(),              \
                              EVP_CHACHAPOLY_TLS_TAG_LEN);                   \
} while (0)

/* AES-CTR cipher initialization for header protection */
#define XQC_CIPHER_INIT_AES_CTR_IMPL(obj, d) do {                           \
    xqc_hdr_protect_cipher_t *___cipher = (obj);                             \
    DO_NOT_CALL_XQC_CIPHER_INIT(___cipher, EVP_aes_##d##_ctr());             \
} while (0)

/* ChaCha20 cipher initialization for header protection */
#define XQC_CIPHER_INIT_CHACHA20_IMPL(obj) do {                              \
    xqc_hdr_protect_cipher_t *___cipher = (obj);                             \
    DO_NOT_CALL_XQC_CIPHER_INIT(___cipher, EVP_chacha20());                  \
} while (0)


/* extern function declarations */

xqc_int_t xqc_ossl3_aead_encrypt(const xqc_pkt_protect_aead_t *pp_aead, void *aead_ctx,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen);

xqc_int_t xqc_ossl3_aead_decrypt(const xqc_pkt_protect_aead_t *pp_aead, void *aead_ctx,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *nonce, size_t noncelen,
    const uint8_t *ad, size_t adlen);

xqc_int_t xqc_ossl3_hp_mask(const xqc_hdr_protect_cipher_t *hp_cipher, void *hp_ctx,
    uint8_t *dest, size_t destcap, size_t *destlen,
    const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *key, size_t keylen,
    const uint8_t *sample, size_t samplelen);

#endif
