/*
* Author: Christian Huitema
* Copyright (c) 2026, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "picoquictest_internal.h"

/* Concurrency test of the public random generator.
*
* The public random generator is a process global. It is used from
* arbitrary threads: the packet sender path uses it for packet number
* obfuscation, pacing and spin bit randomization, connection ID and
* ticket generation use it on server threads, and
* picoquic_public_random_seed runs on whatever thread creates a QUIC
* context. The generator state must therefore be synchronized.
*
* The test starts several generator threads and one seeding thread, all
* released together by a start barrier, so seeding and generation run
* concurrently. The test is expected to run under thread sanitizer in
* the CI; without synchronization in the generator it reports data races
* on the generator state. The functional check is intentionally minimal:
* the threads must terminate and report success.
*/

#define PRNG_TEST_NB_GEN_THREADS 3
#define PRNG_TEST_NB_ROUNDS 2000

typedef struct st_prng_test_ctx_t {
    volatile int start_flag;
    picoquic_quic_t* quic;
} prng_test_ctx_t;

static void prng_test_flag_set(volatile int* flag, int value)
{
#ifdef _WINDOWS
    (void)InterlockedExchange((volatile LONG*)flag, (LONG)value);
#else
    __atomic_store_n(flag, value, __ATOMIC_RELEASE);
#endif
}

static int prng_test_flag_get(volatile int const* flag)
{
#ifdef _WINDOWS
    return (int)InterlockedCompareExchange((volatile LONG*)flag, 0, 0);
#else
    return __atomic_load_n(flag, __ATOMIC_ACQUIRE);
#endif
}

static void prng_test_wait_start(prng_test_ctx_t* ctx)
{
    while (!prng_test_flag_get(&ctx->start_flag)) {
        /* busy wait until the main thread releases all workers */
    }
}

static picoquic_thread_return_t prng_test_generate_thread(void* v_ctx)
{
    prng_test_ctx_t* ctx = (prng_test_ctx_t*)v_ctx;
    uint8_t buf[24];
    uint64_t sum = 0;

    prng_test_wait_start(ctx);

    for (int i = 0; i < PRNG_TEST_NB_ROUNDS; i++) {
        sum += picoquic_public_random_64();
        picoquic_public_random(buf, sizeof(buf));
        sum += picoquic_public_uniform_random(1000000007ull);
    }
    /* Consume the sum so the loop is not optimized out. */
    if (sum == 0x5555555555555555ull) {
        DBG_PRINTF("%s", "Unlikely sum");
    }
    picoquic_thread_do_return;
}


/* Join a test thread and release its OS resources. picoquic_wait_thread
 * joins but, on Windows, never closes the thread HANDLE -- the handle
 * would leak once per joined thread. POSIX pthread_join already reclaims
 * the thread, so no further action is needed there. (Windows branch by
 * inspection; this test battery runs on POSIX.) */
static int prng_test_join_thread(picoquic_thread_t thread)
{
    int ret = picoquic_wait_thread(thread);
#ifdef _WINDOWS
    if (thread != NULL) {
        (void)CloseHandle(thread);
    }
#endif
    return ret;
}

static picoquic_thread_return_t prng_test_seed_thread(void* v_ctx)
{
    prng_test_ctx_t* ctx = (prng_test_ctx_t*)v_ctx;

    prng_test_wait_start(ctx);

    for (int i = 0; i < PRNG_TEST_NB_ROUNDS; i++) {
        picoquic_public_random_seed(ctx->quic);
        picoquic_public_random_seed_64((uint64_t)i, 0);
    }
    picoquic_thread_do_return;
}

int public_random_thread_test(void)
{
    int ret = 0;
    prng_test_ctx_t ctx;
    picoquic_thread_t gen_threads[PRNG_TEST_NB_GEN_THREADS];
    picoquic_thread_t seed_thread;
    int nb_gen_started = 0;
    int seed_started = 0;

    memset(&ctx, 0, sizeof(ctx));
    /* A pro-forma QUIC context provides the crypto random entropy source
     * used by picoquic_public_random_seed. It is only used from the
     * seeding thread. */
    ctx.quic = picoquic_create(8,
        NULL, NULL, NULL,
        PICOQUIC_TEST_ALPN, NULL, NULL, NULL, NULL, NULL,
        0, NULL, NULL, NULL, 0);

    if (ctx.quic == NULL) {
        ret = -1;
    }

    for (int i = 0; ret == 0 && i < PRNG_TEST_NB_GEN_THREADS; i++) {
        if (picoquic_create_thread(&gen_threads[i], prng_test_generate_thread, &ctx) != 0) {
            ret = -1;
        }
        else {
            nb_gen_started++;
        }
    }
    if (ret == 0) {
        if (picoquic_create_thread(&seed_thread, prng_test_seed_thread, &ctx) != 0) {
            ret = -1;
        }
        else {
            seed_started = 1;
        }
    }

    /* Release all workers together. */
    prng_test_flag_set(&ctx.start_flag, 1);

    for (int i = 0; i < nb_gen_started; i++) {
        if (prng_test_join_thread(gen_threads[i]) != 0) {
            ret = -1;
        }
    }
    if (seed_started && prng_test_join_thread(seed_thread) != 0) {
        ret = -1;
    }

    if (ctx.quic != NULL) {
        picoquic_free(ctx.quic);
    }

    return ret;
}
