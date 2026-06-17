/**
 * @file main.c
 * @brief L2-frame transcript capture for the tropic01-driver golden KAT.
 *
 * Runs a real libtropic session against the TROPIC01 model and, with
 * LT_PRINT_SPI_DATA on, dumps every L1 SPI frame. The sequence is chosen to
 * exercise the L2 SEND multi-chunk path: a large Ping whose L3 ciphertext
 * spans several 252-byte L2 chunks, plus a small Random_Get command.
 *
 * This is a HOST test tool only. It validates protocol byte-exactness, not
 * physical security.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libtropic.h"
#include "libtropic_common.h"
#include "libtropic_mbedtls_v4.h"
#include "libtropic_port_posix_tcp.h"
#include "psa/crypto.h"

// Large Ping payload to force a multi-chunk L2 SEND (well over 252 bytes).
#define PING_MSG_SIZE 600
// Small number of random bytes for the second encrypted command.
#define RANDOM_SIZE 16

#define LT_EX_SH0_PRIV lt_sh0priv_prod0
#define LT_EX_SH0_PUB lt_sh0pub_prod0

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "PSA Crypto init failed, status=%d\n", status);
        return -1;
    }

    lt_handle_t lt_handle = {0};

    lt_dev_posix_tcp_t device;
    device.addr = inet_addr("127.0.0.1");
    device.port = 28992;
    lt_handle.l2.device = &device;

    unsigned int prng_seed;
    if (0 != getentropy(&prng_seed, sizeof(prng_seed))) {
        fprintf(stderr, "getentropy() failed (%s)!\n", strerror(errno));
        mbedtls_psa_crypto_free();
        return -1;
    }
    srand(prng_seed);

    lt_ctx_mbedtls_v4_t crypto_ctx;
    lt_handle.l3.crypto_ctx = &crypto_ctx;

    lt_ret_t ret = lt_init(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "lt_init failed, ret=%s\n", lt_ret_verbose(ret));
        mbedtls_psa_crypto_free();
        return -1;
    }

    ret = lt_reboot(&lt_handle, TR01_REBOOT);
    if (ret != LT_OK) {
        fprintf(stderr, "lt_reboot failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }

    printf("KAT-MARK handshake-begin\n");
    ret = lt_verify_chip_and_start_secure_session(&lt_handle, LT_EX_SH0_PRIV, LT_EX_SH0_PUB,
                                                  TR01_PAIRING_KEY_SLOT_INDEX_0);
    if (LT_OK != ret) {
        fprintf(stderr, "secure session failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("KAT-MARK handshake-end\n");

    uint8_t ping_tx[PING_MSG_SIZE];
    uint8_t ping_rx[PING_MSG_SIZE];
    for (int i = 0; i < PING_MSG_SIZE; i++) {
        ping_tx[i] = (uint8_t)(i & 0xFF);
    }
    printf("KAT-MARK ping-begin len=%d\n", PING_MSG_SIZE);
    ret = lt_ping(&lt_handle, ping_tx, ping_rx, PING_MSG_SIZE);
    if (LT_OK != ret) {
        fprintf(stderr, "ping failed, ret=%s\n", lt_ret_verbose(ret));
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    if (0 != memcmp(ping_tx, ping_rx, PING_MSG_SIZE)) {
        fprintf(stderr, "ping echo mismatch!\n");
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("KAT-MARK ping-end\n");

    uint8_t rnd[RANDOM_SIZE];
    printf("KAT-MARK random-begin len=%d\n", RANDOM_SIZE);
    ret = lt_random_value_get(&lt_handle, rnd, RANDOM_SIZE);
    if (LT_OK != ret) {
        fprintf(stderr, "random_value_get failed, ret=%s\n", lt_ret_verbose(ret));
        lt_session_abort(&lt_handle);
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }
    printf("KAT-MARK random-end\n");

    ret = lt_session_abort(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "session abort failed, ret=%s\n", lt_ret_verbose(ret));
        lt_deinit(&lt_handle);
        mbedtls_psa_crypto_free();
        return -1;
    }

    ret = lt_deinit(&lt_handle);
    if (LT_OK != ret) {
        fprintf(stderr, "lt_deinit failed, ret=%s\n", lt_ret_verbose(ret));
        mbedtls_psa_crypto_free();
        return -1;
    }

    mbedtls_psa_crypto_free();
    printf("KAT-MARK done\n");
    return 0;
}
