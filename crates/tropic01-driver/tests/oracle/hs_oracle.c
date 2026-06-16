// Handshake KAT oracle for the patina_key tropic01-driver.
// Reproduces libtropic's lt_in__session_start key derivation byte-for-byte
// using the REAL libtropic functions (lt_X25519, lt_hkdf, lt_sha256) with the
// openssl crypto backend, over PINNED test inputs. Emits golden kCMD/kRES/
// kAUTH/h and a valid t_tauth so the Rust handshake can be asserted against it.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "lt_sha256.h"
#include "lt_hmac_sha256.h"
#include "lt_x25519.h"
#include "lt_hkdf.h"
#include "libtropic_openssl.h"

static void hexln(const char *name, const uint8_t *p, int n)
{
    printf("%s = ", name);
    for (int i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

// Derive an X25519 public key from a raw private key via openssl.
static void x25519_pub(const uint8_t priv[32], uint8_t pub[32])
{
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    size_t len = 32;
    EVP_PKEY_get_raw_public_key(pk, pub, &len);
    EVP_PKEY_free(pk);
}

// AES-256-GCM tag over empty plaintext (the t_tauth computed by the chip side).
static void gcm_tag_empty(const uint8_t key[32], const uint8_t iv[12],
                          const uint8_t *aad, int aad_len, uint8_t tag[16])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int outl = 0;
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(c, NULL, NULL, key, iv);
    EVP_EncryptUpdate(c, NULL, &outl, aad, aad_len);
    EVP_EncryptFinal_ex(c, NULL, &outl);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(c);
}

int main(void)
{
    // Pinned test inputs (NOT production keys).
    uint8_t ehpriv[32], shipriv[32], etpriv[32], stpriv[32];
    for (int i = 0; i < 32; i++) {
        ehpriv[i]  = (uint8_t)(0x01 + i);
        shipriv[i] = (uint8_t)(0x21 + i);
        etpriv[i]  = (uint8_t)(0x41 + i);
        stpriv[i]  = (uint8_t)(0x61 + i);
    }
    uint8_t ehpub[32], shipub[32], etpub[32], stpub[32];
    x25519_pub(ehpriv, ehpub);
    x25519_pub(shipriv, shipub);
    x25519_pub(etpriv, etpub);
    x25519_pub(stpriv, stpub);
    uint8_t pkey_index = 0; // pairing slot 0

    // transcript hash (mirrors lt_in__session_start exactly)
    uint8_t protocol_name[32] = {'N','o','i','s','e','_','K','K','1','_','2',
                                 '5','5','1','9','_','A','E','S','G','C','M',
                                 '_','S','H','A','2','5','6',0x00,0x00,0x00};
    lt_ctx_openssl_t ctx; memset(&ctx, 0, sizeof(ctx));
    uint8_t h[32];
    lt_sha256_init(&ctx);
    lt_sha256_start(&ctx);  lt_sha256_update(&ctx, protocol_name, 32); lt_sha256_finish(&ctx, h);
    lt_sha256_start(&ctx);  lt_sha256_update(&ctx, h, 32); lt_sha256_update(&ctx, shipub, 32); lt_sha256_finish(&ctx, h);
    lt_sha256_start(&ctx);  lt_sha256_update(&ctx, h, 32); lt_sha256_update(&ctx, stpub, 32);  lt_sha256_finish(&ctx, h);
    lt_sha256_start(&ctx);  lt_sha256_update(&ctx, h, 32); lt_sha256_update(&ctx, ehpub, 32);  lt_sha256_finish(&ctx, h);
    lt_sha256_start(&ctx);  lt_sha256_update(&ctx, h, 32); lt_sha256_update(&ctx, &pkey_index, 1); lt_sha256_finish(&ctx, h);
    lt_sha256_start(&ctx);  lt_sha256_update(&ctx, h, 32); lt_sha256_update(&ctx, etpub, 32);  lt_sha256_finish(&ctx, h);
    lt_sha256_deinit(&ctx);

    // key schedule (exact call sequence + ck lengths 32 then 33)
    uint8_t output_1[33] = {0};
    uint8_t output_2[32] = {0};
    uint8_t shared[32];
    uint8_t kcmd[32], kres[32], kauth[32];

    lt_X25519(ehpriv, etpub, shared);
    lt_hkdf(protocol_name, 32, shared, 32, 1, output_1, output_2);   // ck_len = 32
    lt_X25519(shipriv, etpub, shared);
    lt_hkdf(output_1, 33, shared, 32, 1, output_1, output_2);        // ck_len = 33
    lt_X25519(ehpriv, stpub, shared);
    lt_hkdf(output_1, 33, shared, 32, 2, output_1, kauth);           // ck_len = 33 -> kauth
    lt_hkdf(output_1, 33, (uint8_t *)"", 0, 2, kcmd, kres);          // empty input -> kcmd,kres

    // t_tauth = chip's GCM tag over empty pt, key=kauth, iv=0, aad=h
    uint8_t iv0[12] = {0};
    uint8_t t_tauth[16];
    gcm_tag_empty(kauth, iv0, h, 32, t_tauth);

    // emit
    printf("// pinned test inputs\n");
    hexln("EHPRIV", ehpriv, 32); hexln("EHPUB", ehpub, 32);
    hexln("SHIPRIV", shipriv, 32); hexln("SHIPUB", shipub, 32);
    hexln("STPRIV", stpriv, 32); hexln("STPUB", stpub, 32);
    hexln("ETPRIV", etpriv, 32); hexln("ETPUB", etpub, 32);
    printf("PKEY_INDEX = %d\n", pkey_index);
    printf("// golden outputs\n");
    hexln("H_TRANSCRIPT", h, 32);
    hexln("KCMD", kcmd, 32);
    hexln("KRES", kres, 32);
    hexln("KAUTH", kauth, 32);
    hexln("T_TAUTH", t_tauth, 16);
    return 0;
}
