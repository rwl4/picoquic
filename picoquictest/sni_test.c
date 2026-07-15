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

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#pragma warning(disable:4204)
#endif
#include <picotls.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "picoquictest.h"

/* Tests of server-side SNI virtual hosts: identity selection during
 * ClientHello processing, driven by the built-in name registry or by an
 * application selector callback.
 *
 * The fixtures in certs/sni/ hold a dedicated test CA and three leaf
 * certificates signed by it:
 * - default.crt: SAN default.example.com, used as the server's default
 *   (fallback) certificate,
 * - alpha.crt: SAN alpha.example.com,
 * - beta.crt: SAN beta.example.com and *.wild.example.com.
 * When a test needs real hostname verification, the client is created
 * with certs/sni/ca.crt as its root store; when the test asserts
 * selection details that on purpose do not line up with certificate
 * names, the client uses the null verifier and the test asserts the
 * per-vhost context observed on the server connection instead.
 */

#define SNI_TEST_NAME_ALPHA "alpha.example.com"
#define SNI_TEST_NAME_BETA "beta.example.com"
#define SNI_TEST_NAME_OMEGA "omega.example.com" /* same length as alpha, see resumption test */
#define SNI_TEST_NAME_DEFAULT "default.example.com"
#define SNI_TEST_NAME_WILDCARD "*.wild.example.com"
#define SNI_TEST_NAME_IN_WILDCARD "one.wild.example.com"
#define SNI_TEST_NAME_TWO_LABELS "a.one.wild.example.com"
#define SNI_TEST_NAME_UNKNOWN "unknown.example.com"

#define SNI_TEST_ALERT_UNRECOGNIZED_NAME (0x100 + 112)
#define SNI_TEST_ALERT_INTERNAL_ERROR (0x100 + 80)
#define SNI_TEST_ALERT_ILLEGAL_PARAMETER (0x100 + 47)
#define SNI_TEST_NAME_LEGACY "my_host.example.com"
#define SNI_TEST_NAME_IPV4 "192.0.2.1"

static const uint8_t sni_test_ticket_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

/* Distinct per-vhost application contexts; only the addresses matter. */
static int sni_test_vhost_alpha;
static int sni_test_vhost_beta;
static int sni_test_vhost_callback;

static int sni_test_start_client(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* p_simulated_time, char const* sni);

/* Create a client+server pair over the simulated link. The server uses
 * the SNI fixture default certificate. If client_root_file is NULL, the
 * client uses the null verifier. If start_client is 0, no client
 * connection is created; the test creates one later with
 * sni_test_start_client(), e.g. after doctoring the ticket store. */
static int sni_test_ctx_create(picoquic_test_tls_api_ctx_t** pctx, uint64_t* p_simulated_time,
    char const* sni, char const* client_root_file, int force_zero_share,
    char const* ticket_file, int start_client)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char server_cert_path[512];
    char server_key_path[512];
    char client_root_path[512];

    *pctx = NULL;

    ret = picoquic_get_input_path(server_cert_path, sizeof(server_cert_path),
        picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_CERT_DEFAULT);
    if (ret == 0) {
        ret = picoquic_get_input_path(server_key_path, sizeof(server_key_path),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_KEY_DEFAULT);
    }
    if (ret == 0 && client_root_file != NULL) {
        ret = picoquic_get_input_path(client_root_path, sizeof(client_root_path),
            picoquic_solution_dir, client_root_file);
    }

    if (ret == 0) {
        test_ctx = (picoquic_test_tls_api_ctx_t*)malloc(sizeof(picoquic_test_tls_api_ctx_t));
        if (test_ctx == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        memset(test_ctx, 0, sizeof(picoquic_test_tls_api_ctx_t));
        test_ctx->client_callback.client_mode = 1;

        picoquic_set_test_address(&test_ctx->client_addr, 0x0A000002, 1234);
        picoquic_set_test_address(&test_ctx->server_addr, 0x0A000001, 4321);

        test_ctx->qclient = picoquic_create(8, NULL, NULL,
            (client_root_file != NULL) ? client_root_path : NULL, NULL, test_api_callback,
            (void*)&test_ctx->client_callback, NULL, NULL, NULL, *p_simulated_time,
            p_simulated_time, ticket_file, NULL, 0);

        test_ctx->qserver = picoquic_create(8,
            server_cert_path, server_key_path,
            (client_root_file != NULL) ? client_root_path : NULL, PICOQUIC_TEST_ALPN,
            test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL,
            *p_simulated_time, p_simulated_time, NULL,
            sni_test_ticket_key, sizeof(sni_test_ticket_key));

        if (test_ctx->qclient == NULL || test_ctx->qserver == NULL) {
            ret = -1;
        }
        else {
            if (client_root_file == NULL) {
                picoquic_set_null_verifier(test_ctx->qclient);
            }
            if (force_zero_share) {
                test_ctx->qclient->client_zero_share = 1;
            }
        }
    }

    if (ret == 0) {
        test_ctx->c_to_s_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
        test_ctx->s_to_c_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);

        if (test_ctx->c_to_s_link == NULL || test_ctx->s_to_c_link == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        test_ctx->send_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
        test_ctx->send_buffer = (uint8_t*)malloc(test_ctx->send_buffer_size);
        if (test_ctx->send_buffer == NULL) {
            ret = -1;
        }
    }

    if (ret != 0 && test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    *pctx = test_ctx;

    if (ret == 0 && start_client) {
        ret = sni_test_start_client(test_ctx, p_simulated_time, sni);
    }

    return ret;
}

static int sni_test_start_client(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* p_simulated_time,
    char const* sni)
{
    int ret = 0;

    test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, picoquic_null_connection_id,
        picoquic_null_connection_id, (struct sockaddr*)&test_ctx->server_addr,
        *p_simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, sni, PICOQUIC_TEST_ALPN, 1);

    if (test_ctx->cnx_client == NULL) {
        ret = -1;
    }
    else {
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    return ret;
}

/* Create an identity from fixture files and register it under a name
 * pattern. On success the caller owns the creation reference in
 * *p_identity (may pass NULL to have it released immediately, leaving
 * only the registry's reference). */
static int sni_test_register(picoquic_quic_t* qserver, char const* pattern,
    char const* cert_file, char const* key_file, void* vhost_ctx,
    picoquic_server_identity_t** p_identity)
{
    int ret = 0;
    char cert_path[512];
    char key_path[512];
    picoquic_server_identity_t* identity = NULL;

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir, cert_file);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir, key_file);
    }
    if (ret == 0) {
        ret = picoquic_server_identity_create(qserver, cert_path, key_path, &identity);
    }
    if (ret == 0) {
        ret = picoquic_set_server_identity(qserver, pattern, identity, vhost_ctx);
        if (ret != 0 || p_identity == NULL) {
            picoquic_server_identity_release(identity);
            identity = NULL;
        }
    }
    if (p_identity != NULL) {
        *p_identity = identity;
    }

    return ret;
}

static int sni_test_register_alpha_beta(picoquic_quic_t* qserver)
{
    int ret = sni_test_register(qserver, SNI_TEST_NAME_ALPHA,
        PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
        (void*)&sni_test_vhost_alpha, NULL);
    if (ret == 0) {
        ret = sni_test_register(qserver, SNI_TEST_NAME_BETA,
            PICOQUIC_TEST_FILE_SNI_CERT_BETA, PICOQUIC_TEST_FILE_SNI_KEY_BETA,
            (void*)&sni_test_vhost_beta, NULL);
    }
    return ret;
}

/* Stable scopes used by the resumption tests; opaque values, only
 * equality matters. */
static const picoquic_server_resumption_scope_t sni_scope_stable = {
    { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }
};
static const picoquic_server_resumption_scope_t sni_scope_other = {
    { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 }
};

/* Create an identity and register it with an explicit scope, releasing
 * the creation reference. */
static int sni_scope_register_ex(picoquic_quic_t* qserver, char const* pattern,
    char const* cert_file, char const* key_file, void* vhost_ctx,
    const picoquic_server_resumption_scope_t* scope)
{
    int ret = 0;
    char cert_path[512];
    char key_path[512];
    picoquic_server_identity_t* identity = NULL;

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir, cert_file);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir, key_file);
    }
    if (ret == 0) {
        ret = picoquic_server_identity_create(qserver, cert_path, key_path, &identity);
    }
    if (ret == 0) {
        ret = picoquic_set_server_identity_ex(qserver, pattern, identity, vhost_ctx, scope);
        picoquic_server_identity_release(identity);
    }

    return ret;
}

/* Run the connection loop and verify the outcome. If expect_success,
 * both sides must be ready and the server connection must carry the
 * expected server name context; otherwise the client must end up
 * disconnected, with the expected remote error if expected_error != 0. */
static int sni_test_connect(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* p_simulated_time,
    int expect_success, void* expected_server_name_ctx, uint64_t expected_error)
{
    int ret = 0;
    int c_ret = tls_api_connection_loop(test_ctx, NULL, 0, p_simulated_time);

    if (expect_success) {
        if (c_ret != 0 || !(TEST_CLIENT_READY && TEST_SERVER_READY)) {
            DBG_PRINTF("Connection loop returns %d, expected success", c_ret);
            ret = -1;
        }
        else if (picoquic_get_server_name_context(test_ctx->cnx_server) != expected_server_name_ctx) {
            DBG_PRINTF("%s", "Server name context does not match expectation");
            ret = -1;
        }
    }
    else {
        if (c_ret == 0 && TEST_CLIENT_READY && TEST_SERVER_READY) {
            DBG_PRINTF("%s", "Connection succeeded, expected reject");
            ret = -1;
        }
        else if (expected_error != 0 &&
            test_ctx->cnx_client->remote_error != expected_error) {
            DBG_PRINTF("Client remote error 0x%" PRIx64 ", expected 0x%" PRIx64,
                test_ctx->cnx_client->remote_error, expected_error);
            ret = -1;
        }
    }

    return ret;
}

/* Run one registry-driven scenario end to end. */
static int sni_test_one_registry(char const* sni, char const* client_root_file,
    int force_zero_share, int expect_success, void* expected_server_name_ctx,
    int register_precedence_entry)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = sni_test_ctx_create(&test_ctx, &simulated_time, sni, client_root_file,
        force_zero_share, NULL, 1);

    if (ret == 0) {
        ret = sni_test_register_alpha_beta(test_ctx->qserver);
    }
    if (ret == 0) {
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_WILDCARD,
            PICOQUIC_TEST_FILE_SNI_CERT_BETA, PICOQUIC_TEST_FILE_SNI_KEY_BETA,
            (void*)&sni_test_vhost_beta, NULL);
    }
    if (ret == 0 && register_precedence_entry) {
        /* An exact entry for a name that the wildcard also covers. */
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_IN_WILDCARD,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, NULL);
    }
    if (ret == 0) {
        ret = sni_test_connect(test_ctx, &simulated_time, expect_success,
            expected_server_name_ctx, 0);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

/* Exact hostname A selects and verifies certificate A. The client only
 * trusts the SNI test CA, so the handshake succeeding proves that the
 * certificate presented for alpha.example.com carries that name. */
int sni_exact_first_test(void)
{
    return sni_test_one_registry(SNI_TEST_NAME_ALPHA, PICOQUIC_TEST_FILE_SNI_CERT_STORE,
        0, 1, (void*)&sni_test_vhost_alpha, 0);
}

/* Exact hostname B selects and verifies certificate B. */
int sni_exact_second_test(void)
{
    return sni_test_one_registry(SNI_TEST_NAME_BETA, PICOQUIC_TEST_FILE_SNI_CERT_STORE,
        0, 1, (void*)&sni_test_vhost_beta, 0);
}

/* Matching is ASCII case insensitive; certificate verification of the
 * mixed-case name still succeeds since DNS names compare case
 * insensitively there too. */
int sni_case_insensitive_test(void)
{
    return sni_test_one_registry("AlPhA.eXaMpLe.CoM", PICOQUIC_TEST_FILE_SNI_CERT_STORE,
        0, 1, (void*)&sni_test_vhost_alpha, 0);
}

/* A wildcard entry matches one leftmost label; the beta certificate
 * carries the matching *.wild.example.com SAN so full verification
 * applies. */
int sni_wildcard_test(void)
{
    return sni_test_one_registry(SNI_TEST_NAME_IN_WILDCARD, PICOQUIC_TEST_FILE_SNI_CERT_STORE,
        0, 1, (void*)&sni_test_vhost_beta, 0);
}

/* The wildcard must not match more than one label, nor the bare suffix:
 * both fall back to the default certificate (server name context NULL).
 * The client uses the null verifier because the default certificate
 * does not carry these names. */
int sni_wildcard_one_label_test(void)
{
    int ret = sni_test_one_registry(SNI_TEST_NAME_TWO_LABELS, NULL, 0, 1, NULL, 0);
    if (ret == 0) {
        ret = sni_test_one_registry("wild.example.com", NULL, 0, 1, NULL, 0);
    }
    return ret;
}

/* When both an exact entry and a wildcard entry cover a name, the exact
 * entry wins regardless of registration order. */
int sni_exact_precedence_test(void)
{
    return sni_test_one_registry(SNI_TEST_NAME_IN_WILDCARD, NULL, 0, 1,
        (void*)&sni_test_vhost_alpha, 1);
}

/* An SNI matching no entry falls back to the default certificate. Run
 * once with a name the default certificate carries (full verification
 * proves the default chain was presented) and once with an unknown name
 * under the null verifier (selection must be default, context NULL). */
int sni_unknown_fallback_test(void)
{
    int ret = sni_test_one_registry(SNI_TEST_NAME_DEFAULT, PICOQUIC_TEST_FILE_SNI_CERT_STORE,
        0, 1, NULL, 0);
    if (ret == 0) {
        ret = sni_test_one_registry(SNI_TEST_NAME_UNKNOWN, NULL, 0, 1, NULL, 0);
    }
    return ret;
}

/* A client that does not send an SNI gets the default certificate even
 * when the registry is populated. */
int sni_absent_fallback_test(void)
{
    return sni_test_one_registry(NULL, PICOQUIC_TEST_FILE_SNI_CERT_STORE, 0, 1, NULL, 0);
}

/* Selector scaffolding. The callback copies what it saw and reacts
 * according to the configured behavior. */
typedef struct st_sni_test_selector_state_t {
    picoquic_server_identity_result_t behavior;
    picoquic_server_identity_t* identity_out; /* for behavior == selected */
    void* server_name_ctx_out;
    const picoquic_server_resumption_scope_t* scope_out; /* NULL: leave all-zero */
    int was_called;
    int saw_server_name;
    char server_name_seen[256];
    size_t alpn_count_seen;
    size_t signature_algorithms_count_seen;
} sni_test_selector_state_t;

static picoquic_server_identity_result_t sni_test_selector(picoquic_cnx_t* cnx,
    const picoquic_client_hello_info_t* hello, picoquic_server_identity_t** identity,
    void** server_name_ctx, picoquic_server_resumption_scope_t* resumption_scope,
    void* select_ctx)
{
    sni_test_selector_state_t* state = (sni_test_selector_state_t*)select_ctx;

    state->was_called = 1;
    state->alpn_count_seen = hello->alpn_count;
    state->signature_algorithms_count_seen = hello->signature_algorithms_count;
    if (hello->server_name != NULL && hello->server_name_length < sizeof(state->server_name_seen)) {
        state->saw_server_name = 1;
        memcpy(state->server_name_seen, hello->server_name, hello->server_name_length);
        state->server_name_seen[hello->server_name_length] = 0;
    }

    if (state->behavior == picoquic_server_identity_result_selected) {
        *identity = state->identity_out;
    }
    if (state->server_name_ctx_out != NULL) {
        *server_name_ctx = state->server_name_ctx_out;
    }
    if (state->scope_out != NULL) {
        *resumption_scope = *state->scope_out;
    }

    (void)cnx;
    return state->behavior;
}

/* Run one selector-driven scenario. The registry maps the beta name to
 * the ALPHA identity on purpose, so registry vs. selector precedence is
 * observable through which certificate gets verified. */
static int sni_test_one_selector(sni_test_selector_state_t* state, char const* sni,
    char const* client_root_file, int expect_success, void* expected_server_name_ctx,
    uint64_t expected_error, int select_beta_identity)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_server_identity_t* beta_identity = NULL;
    uint64_t simulated_time = 0;
    int ret = sni_test_ctx_create(&test_ctx, &simulated_time, sni, client_root_file, 0, NULL, 1);

    if (ret == 0) {
        /* Registry: beta.example.com -> alpha identity (deliberate mismatch). */
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_BETA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, NULL);
    }
    if (ret == 0 && select_beta_identity) {
        char cert_path[512];
        char key_path[512];
        ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_CERT_BETA);
        if (ret == 0) {
            ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
                PICOQUIC_TEST_FILE_SNI_KEY_BETA);
        }
        if (ret == 0) {
            ret = picoquic_server_identity_create(test_ctx->qserver, cert_path, key_path,
                &beta_identity);
        }
        if (ret == 0) {
            state->identity_out = beta_identity;
        }
    }
    if (ret == 0) {
        picoquic_set_server_identity_select_fn(test_ctx->qserver, sni_test_selector, state);
        ret = sni_test_connect(test_ctx, &simulated_time, expect_success,
            expected_server_name_ctx, expected_error);
    }
    if (ret == 0 && !state->was_called) {
        DBG_PRINTF("%s", "Selector was not called");
        ret = -1;
    }

    if (beta_identity != NULL) {
        picoquic_server_identity_release(beta_identity);
    }
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

/* use_default bypasses a matching registry entry: the client asks for
 * beta.example.com, the registry would answer with the alpha identity,
 * but the server presents the default certificate. The callback's
 * server name context is retained since the registry was bypassed. */
int sni_selector_use_default_test(void)
{
    sni_test_selector_state_t state;
    memset(&state, 0, sizeof(state));
    state.behavior = picoquic_server_identity_result_use_default;
    state.server_name_ctx_out = (void*)&sni_test_vhost_callback;

    return sni_test_one_selector(&state, SNI_TEST_NAME_BETA, NULL, 1,
        (void*)&sni_test_vhost_callback, 0, 0);
}

/* selected overrides the registry: the registry maps beta.example.com
 * to the alpha identity (whose certificate would fail verification for
 * that name), the selector picks the beta identity, and the client
 * fully verifies the beta certificate against its trust root. */
int sni_selector_selected_test(void)
{
    int ret;
    sni_test_selector_state_t state;
    memset(&state, 0, sizeof(state));
    state.behavior = picoquic_server_identity_result_selected;
    state.server_name_ctx_out = (void*)&sni_test_vhost_callback;

    ret = sni_test_one_selector(&state, SNI_TEST_NAME_BETA,
        PICOQUIC_TEST_FILE_SNI_CERT_STORE, 1, (void*)&sni_test_vhost_callback, 0, 1);

    if (ret == 0 && (!state.saw_server_name ||
        strcmp(state.server_name_seen, SNI_TEST_NAME_BETA) != 0)) {
        DBG_PRINTF("Selector saw server name '%s', expected '%s'",
            state.saw_server_name ? state.server_name_seen : "(none)", SNI_TEST_NAME_BETA);
        ret = -1;
    }
    if (ret == 0 && (state.alpn_count_seen == 0 || state.signature_algorithms_count_seen == 0)) {
        DBG_PRINTF("%s", "Selector did not see ALPN or signature algorithm lists");
        ret = -1;
    }

    if (ret == 0) {
        /* Returning selected while leaving *identity NULL is an
         * application error; it must fail the handshake with a TLS
         * internal_error alert, not dereference the missing identity. */
        memset(&state, 0, sizeof(state));
        state.behavior = picoquic_server_identity_result_selected;
        ret = sni_test_one_selector(&state, SNI_TEST_NAME_BETA, NULL, 0, NULL,
            SNI_TEST_ALERT_INTERNAL_ERROR, 0);
    }

    return ret;
}

/* fallthrough reaches the registry; the registry match overwrites the
 * server name context provided by the callback. The registry entry maps
 * beta.example.com to the alpha identity, so the client runs under the
 * null verifier and the test asserts the entry's context. */
int sni_selector_fallthrough_test(void)
{
    int ret;
    sni_test_selector_state_t state;
    memset(&state, 0, sizeof(state));
    state.behavior = picoquic_server_identity_result_fallthrough;
    state.server_name_ctx_out = (void*)&sni_test_vhost_callback;

    ret = sni_test_one_selector(&state, SNI_TEST_NAME_BETA, NULL, 1,
        (void*)&sni_test_vhost_alpha, 0, 0);

    if (ret == 0) {
        /* When the ClientHello carries no SNI the selector still runs
         * and must see a NULL server name; fallthrough then finds no
         * registry match, so the default certificate is presented and
         * the callback's routing context is retained. */
        memset(&state, 0, sizeof(state));
        state.behavior = picoquic_server_identity_result_fallthrough;
        state.server_name_ctx_out = (void*)&sni_test_vhost_callback;
        ret = sni_test_one_selector(&state, NULL, NULL, 1,
            (void*)&sni_test_vhost_callback, 0, 0);
        if (ret == 0 && state.saw_server_name) {
            DBG_PRINTF("Selector saw server name '%s', expected none",
                state.server_name_seen);
            ret = -1;
        }
    }

    return ret;
}

/* reject fails the handshake with a TLS unrecognized_name alert. */
int sni_selector_reject_test(void)
{
    sni_test_selector_state_t state;
    memset(&state, 0, sizeof(state));
    state.behavior = picoquic_server_identity_result_reject;

    return sni_test_one_selector(&state, SNI_TEST_NAME_BETA, NULL, 0, NULL,
        SNI_TEST_ALERT_UNRECOGNIZED_NAME, 0);
}

/* Selecting an identity that belongs to a different QUIC context must
 * fail the handshake safely with a TLS internal_error alert. */
int sni_cross_quic_test(void)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_quic_t* other_quic = NULL;
    picoquic_server_identity_t* foreign_identity = NULL;
    sni_test_selector_state_t state;
    uint64_t simulated_time = 0;
    char cert_path[512];
    char key_path[512];

    memset(&state, 0, sizeof(state));

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SNI_CERT_ALPHA);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_ALPHA);
    }
    if (ret == 0) {
        ret = sni_test_ctx_create(&test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA, NULL, 0, NULL, 1);
    }
    if (ret == 0) {
        other_quic = picoquic_create(8, cert_path, key_path, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, simulated_time, &simulated_time, NULL, NULL, 0);
        if (other_quic == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = picoquic_server_identity_create(other_quic, cert_path, key_path, &foreign_identity);
    }
    if (ret == 0) {
        /* Registering a foreign identity must be refused. */
        if (picoquic_set_server_identity(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
            foreign_identity, NULL) == 0) {
            DBG_PRINTF("%s", "Registry accepted a foreign identity");
            ret = -1;
        }
    }
    if (ret == 0) {
        /* A selector returning a foreign identity must fail the handshake. */
        state.behavior = picoquic_server_identity_result_selected;
        state.identity_out = foreign_identity;
        picoquic_set_server_identity_select_fn(test_ctx->qserver, sni_test_selector, &state);
        ret = sni_test_connect(test_ctx, &simulated_time, 0, NULL,
            SNI_TEST_ALERT_INTERNAL_ERROR);
    }

    if (foreign_identity != NULL) {
        picoquic_server_identity_release(foreign_identity);
    }
    if (other_quic != NULL) {
        picoquic_free(other_quic);
    }
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

/* Malformed names: the validation helper must classify anything that is
 * not a well-formed DNS host name as invalid without overreading, and
 * the registry must refuse invalid patterns. */
int sni_malformed_name_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_server_identity_t* identity = NULL;
    uint64_t simulated_time = 0;
    char cert_path[512];
    char key_path[512];
    /* Building blocks for the total-length boundary: labels at the
     * 63-octet limit, plus a 61-octet one so that four labels and three
     * dots come to exactly 253 octets. */
#define SNI_TEST_LABEL_63 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SNI_TEST_LABEL_61 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    /* Well-formed DNS names: registering each as an exact pattern must
     * succeed. */
    static char const* valid_names[] = {
        "alpha.example.com", "a.b", "9started.example.com", "x-y.example.com", "localhost",
        "1.2.3.4.example.com", "example.123a", "9started", "x-y.example",
        /* 253 octets, the largest well-formed host name. */
        SNI_TEST_LABEL_63 "." SNI_TEST_LABEL_63 "." SNI_TEST_LABEL_63 "." SNI_TEST_LABEL_61
    };
    /* Not well-formed: registering each must be refused. */
    static char const* invalid_names[] = {
        "a..example.com", ".example.com", "example.com.",
        "caf\xc3\xa9.example.com", "a b.example.com", "a\texample.com",
        "-a.example.com", "a-.example.com", "a_b.example.com",
        "192.0.2.1", "999.999.999.999", "example.123", "123",
        /* 255 octets: every label is valid but the name as a whole
         * exceeds the 253-octet limit. */
        SNI_TEST_LABEL_63 "." SNI_TEST_LABEL_63 "." SNI_TEST_LABEL_63 "." SNI_TEST_LABEL_63
    };
    /* Invalid registration patterns, including wildcard-specific forms. */
    static char const* bad_patterns[] = {
        "", "*", "*.", "a.*.example.com", "*x.example.com", "x*.example.com", "*.*.com",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
        "*.-a.example.com", "*.example.123", "*.192.0.2.1"
    };

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SNI_CERT_ALPHA);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_ALPHA);
    }
    if (ret == 0) {
        quic = picoquic_create(8, cert_path, key_path, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, simulated_time, &simulated_time, NULL, NULL, 0);
        if (quic == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = picoquic_server_identity_create(quic, cert_path, key_path, &identity);
    }

    /* Name validation, exercised through the public registration API so
     * it is covered in every build. Every C-string-representable valid
     * and invalid case runs here. */
    for (size_t i = 0; ret == 0 && i < sizeof(valid_names) / sizeof(char const*); i++) {
        if (picoquic_set_server_identity(quic, valid_names[i], identity, NULL) != 0) {
            DBG_PRINTF("Valid name '%s' refused by registration", valid_names[i]);
            ret = -1;
        }
    }
    for (size_t i = 0; ret == 0 && i < sizeof(invalid_names) / sizeof(char const*); i++) {
        if (picoquic_set_server_identity(quic, invalid_names[i], identity, NULL) == 0) {
            DBG_PRINTF("Invalid name '%s' accepted by registration", invalid_names[i]);
            ret = -1;
        }
    }
    for (size_t i = 0; ret == 0 && i < sizeof(bad_patterns) / sizeof(char const*); i++) {
        if (picoquic_set_server_identity(quic, bad_patterns[i], identity, NULL) == 0) {
            DBG_PRINTF("Invalid pattern '%s' accepted", bad_patterns[i]);
            ret = -1;
        }
    }
    if (ret == 0 && picoquic_remove_server_identity(quic, "not.registered.example") == 0) {
        DBG_PRINTF("%s", "Removing an unregistered pattern succeeded");
        ret = -1;
    }

    if (identity != NULL) {
        picoquic_server_identity_release(identity);
    }
    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

/* Replacing a registry entry affects new handshakes only. A first
 * connection selects the alpha identity and stays alive across the
 * replacement (exercising the reference counting under ASan); a second
 * server then presents the replacement identity for the same name. */
int sni_replace_entry_test(void)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_server_identity_t* alpha_identity = NULL;
    uint64_t simulated_time = 0;

    ret = sni_test_ctx_create(&test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA,
        PICOQUIC_TEST_FILE_SNI_CERT_STORE, 0, NULL, 1);
    if (ret == 0) {
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, &alpha_identity);
    }
    if (ret == 0) {
        ret = sni_test_connect(test_ctx, &simulated_time, 1, (void*)&sni_test_vhost_alpha, 0);
    }
    if (ret == 0) {
        /* Replace the entry while the first connection is still alive,
         * and drop every application reference to the old identity. */
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_BETA, PICOQUIC_TEST_FILE_SNI_KEY_BETA,
            (void*)&sni_test_vhost_beta, NULL);
    }
    if (ret == 0) {
        picoquic_server_identity_release(alpha_identity);
        alpha_identity = NULL;

        /* The established connection must remain usable. */
        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 100000);
    }
    if (ret == 0 &&
        picoquic_get_cnx_state(test_ctx->cnx_client) > picoquic_state_ready) {
        DBG_PRINTF("%s", "First connection did not survive the replacement");
        ret = -1;
    }
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    /* A new handshake for the same name now gets the beta identity. The
     * client runs under the null verifier since the beta certificate
     * does not carry the alpha name; selection is observed through the
     * server name context. */
    if (ret == 0) {
        ret = sni_test_ctx_create(&test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA, NULL, 0, NULL, 1);
        if (ret == 0) {
            ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
                PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
                (void*)&sni_test_vhost_alpha, &alpha_identity);
        }
        if (ret == 0) {
            ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
                PICOQUIC_TEST_FILE_SNI_CERT_BETA, PICOQUIC_TEST_FILE_SNI_KEY_BETA,
                (void*)&sni_test_vhost_beta, NULL);
        }
        if (ret == 0) {
            picoquic_server_identity_release(alpha_identity);
            alpha_identity = NULL;
            ret = sni_test_connect(test_ctx, &simulated_time, 1, (void*)&sni_test_vhost_beta, 0);
        }
        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
        }
    }

    if (alpha_identity != NULL) {
        picoquic_server_identity_release(alpha_identity);
    }

    return ret;
}

/* Removing an entry releases only the registry's reference; the
 * established connection survives and later handshakes fall back to the
 * default certificate. */
int sni_remove_entry_test(void)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;

    ret = sni_test_ctx_create(&test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA,
        PICOQUIC_TEST_FILE_SNI_CERT_STORE, 0, NULL, 1);
    if (ret == 0) {
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, NULL);
    }
    if (ret == 0) {
        ret = sni_test_connect(test_ctx, &simulated_time, 1, (void*)&sni_test_vhost_alpha, 0);
    }
    if (ret == 0) {
        ret = picoquic_remove_server_identity(test_ctx->qserver, SNI_TEST_NAME_ALPHA);
    }
    if (ret == 0) {
        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 100000);
    }
    if (ret == 0 &&
        picoquic_get_cnx_state(test_ctx->cnx_client) > picoquic_state_ready) {
        DBG_PRINTF("%s", "Connection did not survive the removal");
        ret = -1;
    }
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    if (ret == 0) {
        ret = sni_test_one_registry(SNI_TEST_NAME_UNKNOWN, NULL, 0, 1, NULL, 0);
    }

    return ret;
}

/* Session resumption must not cross SNI boundaries. A first connection
 * to alpha.example.com yields a session ticket. Resuming with the same
 * name is a PSK handshake. Presenting the alpha ticket for another name
 * (forced by editing the client's ticket store, which a well-behaved
 * client would never do) must be refused by the server: the handshake
 * completes as a full handshake, not PSK. */
int sni_resumption_boundary_test(void)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    char const* ticket_file = "sni_resume_tickets.bin";

    /* Start from an empty ticket store. */
    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file);

    for (int round = 0; ret == 0 && round < 3; round++) {
        picoquic_test_tls_api_ctx_t* test_ctx = NULL;
        char const* sni = SNI_TEST_NAME_ALPHA;
        int expect_psk = (round == 1);

        ret = sni_test_ctx_create(&test_ctx, &simulated_time, NULL, NULL, 0, ticket_file, 0);
        if (ret == 0) {
            /* Servers are recreated each round, so resumption across
             * rounds needs explicit stable scopes. The omega entry gets
             * the SAME scope as alpha on purpose: the cross-SNI ticket
             * offer in the last round is then rejected by picotls'
             * server-name binding alone, which is what this test is
             * about (scope isolation has its own tests). */
            ret = sni_scope_register_ex(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
                PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
                (void*)&sni_test_vhost_alpha, &sni_scope_stable);
        }
        if (ret == 0) {
            ret = sni_scope_register_ex(test_ctx->qserver, SNI_TEST_NAME_OMEGA,
                PICOQUIC_TEST_FILE_SNI_CERT_BETA, PICOQUIC_TEST_FILE_SNI_KEY_BETA,
                (void*)&sni_test_vhost_beta, &sni_scope_stable);
        }
        if (ret == 0 && round == 2) {
            /* Rewrite the stored ticket's SNI in place (same length) so
             * the client offers the alpha ticket for omega.example.com. */
            picoquic_stored_ticket_t* stored = test_ctx->qclient->p_first_ticket;
            if (stored == NULL || stored->sni == NULL ||
                stored->sni_length != strlen(SNI_TEST_NAME_OMEGA) ||
                strcmp(stored->sni, SNI_TEST_NAME_ALPHA) != 0) {
                DBG_PRINTF("%s", "Ticket store does not hold the expected alpha ticket");
                ret = -1;
            }
            else {
                memcpy(stored->sni, SNI_TEST_NAME_OMEGA, stored->sni_length);
                sni = SNI_TEST_NAME_OMEGA;
            }
        }
        if (ret == 0) {
            ret = sni_test_start_client(test_ctx, &simulated_time, sni);
        }
        if (ret == 0) {
            void* expected_ctx = (round == 2) ?
                (void*)&sni_test_vhost_beta : (void*)&sni_test_vhost_alpha;
            ret = sni_test_connect(test_ctx, &simulated_time, 1, expected_ctx, 0);
        }
        if (ret == 0) {
            int is_psk = picoquic_tls_is_psk_handshake(test_ctx->cnx_client);
            if (is_psk != expect_psk) {
                DBG_PRINTF("Round %d: PSK handshake %d, expected %d", round, is_psk, expect_psk);
                ret = -1;
            }
        }
        if (ret == 0 && round == 0) {
            /* Wait for the session ticket to arrive, then persist it. */
            uint64_t target_time = simulated_time + 2000000;
            while (ret == 0 && test_ctx->qclient->p_first_ticket == NULL &&
                simulated_time < target_time) {
                ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 100000);
            }
            if (ret == 0 && test_ctx->qclient->p_first_ticket == NULL) {
                DBG_PRINTF("%s", "No session ticket received");
                ret = -1;
            }
        }
        if (ret == 0 && round < 2) {
            ret = picoquic_save_tickets(test_ctx->qclient->p_first_ticket, simulated_time,
                ticket_file);
        }
        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
        }
    }

    (void)picoquic_file_delete(ticket_file, NULL);

    return ret;
}

/* Resumption scope tests. Each test runs two connection phases against
 * freshly created servers that share the ticket encryption key, with
 * the client's tickets carried across through a store file. Phase 0
 * issues a session ticket under one server configuration; phase 1
 * reconstructs a configuration, reconnects with the same SNI and 0-RTT
 * data queued, and checks whether the ticket resumes (PSK handshake,
 * early data accepted) and which virtual host context the connection
 * lands on. Cross-phase resumption relies on explicit scopes, which is
 * exactly the documented persistence model. */

typedef enum {
    sni_scope_case_control = 0, /* same entry, same explicit scope: resumes */
    sni_scope_case_remove, /* entry removed: falls back, no resumption */
    sni_scope_case_replace_simple, /* replaced via simple API: fresh scope, no resumption */
    sni_scope_case_replace_same_scope, /* replaced via _ex, same scope: certificate-only rotation, resumes */
    sni_scope_case_replace_new_scope, /* replaced via _ex, different scope: no resumption */
    sni_scope_case_readd, /* removed then re-added via simple API: fresh scope, no resumption */
    sni_scope_case_selector_stable, /* selector supplies the same stable scope: resumes */
    sni_scope_case_selector_changed, /* selector changes its scope: no resumption */
    sni_scope_case_selector_no_scope, /* selector never supplies a scope: no resumption */
    sni_scope_case_legacy, /* no selector or registry: legacy ticket binding, resumes */
    sni_scope_case_legacy_then_scoped, /* legacy ticket, then scoping enabled: no resumption */
    sni_scope_case_wildcard, /* wildcard entry keeps its scope: resumes */
    sni_scope_case_wildcard_exact_override, /* exact entry added over the wildcard: no resumption */
    sni_scope_case_default_fallback /* unmatched name on a scope-enabled server: the default scope is process-local, no cross-instance resumption */
} sni_scope_case_enum;

static sni_test_selector_state_t sni_scope_selector_state;

/* Install the shared test selector returning the alpha identity, with
 * the given stable scope (NULL: none). The identity is left for
 * picoquic_free() to release. */
static int sni_scope_install_selector(picoquic_quic_t* qserver,
    const picoquic_server_resumption_scope_t* scope)
{
    int ret = 0;
    char cert_path[512];
    char key_path[512];
    picoquic_server_identity_t* identity = NULL;

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SNI_CERT_ALPHA);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_ALPHA);
    }
    if (ret == 0) {
        ret = picoquic_server_identity_create(qserver, cert_path, key_path, &identity);
    }
    if (ret == 0) {
        memset(&sni_scope_selector_state, 0, sizeof(sni_scope_selector_state));
        sni_scope_selector_state.behavior = picoquic_server_identity_result_selected;
        sni_scope_selector_state.identity_out = identity;
        sni_scope_selector_state.server_name_ctx_out = (void*)&sni_test_vhost_callback;
        sni_scope_selector_state.scope_out = scope;
        picoquic_set_server_identity_select_fn(qserver, sni_test_selector,
            &sni_scope_selector_state);
    }

    return ret;
}

/* Configure the phase's server for the given case. */
static int sni_scope_server_setup(picoquic_quic_t* qserver, sni_scope_case_enum which, int phase)
{
    int ret = 0;

    switch (which) {
    case sni_scope_case_control:
    case sni_scope_case_default_fallback:
        ret = sni_scope_register_ex(qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, &sni_scope_stable);
        break;
    case sni_scope_case_remove:
        ret = sni_scope_register_ex(qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, &sni_scope_stable);
        if (ret == 0 && phase == 1) {
            ret = picoquic_remove_server_identity(qserver, SNI_TEST_NAME_ALPHA);
        }
        break;
    case sni_scope_case_replace_simple:
    case sni_scope_case_replace_same_scope:
    case sni_scope_case_replace_new_scope:
        ret = sni_scope_register_ex(qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, &sni_scope_stable);
        if (ret == 0 && phase == 1) {
            const picoquic_server_resumption_scope_t* scope = NULL;
            if (which == sni_scope_case_replace_same_scope) {
                scope = &sni_scope_stable;
            }
            else if (which == sni_scope_case_replace_new_scope) {
                scope = &sni_scope_other;
            }
            ret = sni_scope_register_ex(qserver, SNI_TEST_NAME_ALPHA,
                PICOQUIC_TEST_FILE_SNI_CERT_BETA, PICOQUIC_TEST_FILE_SNI_KEY_BETA,
                (void*)&sni_test_vhost_beta, scope);
        }
        break;
    case sni_scope_case_readd:
        ret = sni_scope_register_ex(qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, &sni_scope_stable);
        if (ret == 0 && phase == 1) {
            ret = picoquic_remove_server_identity(qserver, SNI_TEST_NAME_ALPHA);
            if (ret == 0) {
                ret = sni_scope_register_ex(qserver, SNI_TEST_NAME_ALPHA,
                    PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
                    (void*)&sni_test_vhost_alpha, NULL);
            }
        }
        break;
    case sni_scope_case_selector_stable:
        ret = sni_scope_install_selector(qserver, &sni_scope_stable);
        break;
    case sni_scope_case_selector_changed:
        ret = sni_scope_install_selector(qserver,
            (phase == 0) ? &sni_scope_stable : &sni_scope_other);
        break;
    case sni_scope_case_selector_no_scope:
        ret = sni_scope_install_selector(qserver, NULL);
        break;
    case sni_scope_case_legacy:
        break;
    case sni_scope_case_legacy_then_scoped:
        if (phase == 1) {
            ret = sni_scope_register_ex(qserver, SNI_TEST_NAME_ALPHA,
                PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
                (void*)&sni_test_vhost_alpha, &sni_scope_stable);
        }
        break;
    case sni_scope_case_wildcard:
    case sni_scope_case_wildcard_exact_override:
        ret = sni_scope_register_ex(qserver, SNI_TEST_NAME_WILDCARD,
            PICOQUIC_TEST_FILE_SNI_CERT_BETA, PICOQUIC_TEST_FILE_SNI_KEY_BETA,
            (void*)&sni_test_vhost_beta, &sni_scope_stable);
        if (ret == 0 && which == sni_scope_case_wildcard_exact_override && phase == 1) {
            ret = sni_scope_register_ex(qserver, SNI_TEST_NAME_IN_WILDCARD,
                PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
                (void*)&sni_test_vhost_alpha, NULL);
        }
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}

static int sni_scope_test_one(sni_scope_case_enum which, char const* sni,
    int expect_resume, void* expected_ctx)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    char const* ticket_file = "sni_scope_tickets.bin";
    static const uint8_t early_data[] = { 't', 'e', 's', 't', '0', 'r', 't', 't' };

    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file);

    for (int phase = 0; ret == 0 && phase < 2; phase++) {
        picoquic_test_tls_api_ctx_t* test_ctx = NULL;

        ret = sni_test_ctx_create(&test_ctx, &simulated_time, NULL, NULL, 0, ticket_file, 0);
        if (ret == 0) {
            ret = sni_scope_server_setup(test_ctx->qserver, which, phase);
        }
        if (ret == 0) {
            ret = sni_test_start_client(test_ctx, &simulated_time, sni);
        }
        if (ret == 0 && phase == 1) {
            /* Queue stream data before the handshake so it is sent as
             * 0-RTT whenever the client holds a usable ticket. */
            ret = picoquic_add_to_stream(test_ctx->cnx_client, 0, early_data,
                sizeof(early_data), 1);
        }
        if (ret == 0) {
            ret = tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);
            if (ret == 0 && !(TEST_CLIENT_READY && TEST_SERVER_READY)) {
                DBG_PRINTF("Case %d phase %d: connection failed", (int)which, phase);
                ret = -1;
            }
        }
        if (ret == 0 && phase == 1) {
            int is_psk;
            void* observed_ctx;

            /* Let the early data acknowledgments drain before checking
             * the 0-RTT counters. */
            ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, 0, 1);

            is_psk = picoquic_tls_is_psk_handshake(test_ctx->cnx_client);
            observed_ctx = picoquic_get_server_name_context(test_ctx->cnx_server);

            if (ret != 0) {
                DBG_PRINTF("Case %d: post-handshake loop failed", (int)which);
            }
            else if (is_psk != expect_resume) {
                DBG_PRINTF("Case %d: PSK handshake %d, expected %d", (int)which,
                    is_psk, expect_resume);
                ret = -1;
            }
            else if (observed_ctx != expected_ctx) {
                DBG_PRINTF("Case %d: unexpected server name context", (int)which);
                ret = -1;
            }
            else if (test_ctx->cnx_client->nb_zero_rtt_sent == 0) {
                DBG_PRINTF("Case %d: client did not send 0-RTT data", (int)which);
                ret = -1;
            }
            else if (expect_resume &&
                (test_ctx->cnx_server->nb_zero_rtt_received == 0 ||
                    test_ctx->cnx_client->nb_zero_rtt_acked == 0)) {
                DBG_PRINTF("Case %d: 0-RTT data not accepted", (int)which);
                ret = -1;
            }
            else if (!expect_resume &&
                (test_ctx->cnx_server->nb_zero_rtt_received != 0 ||
                    test_ctx->cnx_client->nb_zero_rtt_acked != 0)) {
                DBG_PRINTF("Case %d: 0-RTT data accepted across scopes", (int)which);
                ret = -1;
            }
        }
        if (ret == 0 && phase == 0) {
            uint64_t target_time = simulated_time + 2000000;
            while (ret == 0 && test_ctx->qclient->p_first_ticket == NULL &&
                simulated_time < target_time) {
                ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 100000);
            }
            if (ret == 0 && test_ctx->qclient->p_first_ticket == NULL) {
                DBG_PRINTF("Case %d: no session ticket received", (int)which);
                ret = -1;
            }
            if (ret == 0) {
                ret = picoquic_save_tickets(test_ctx->qclient->p_first_ticket,
                    simulated_time, ticket_file);
            }
        }
        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
        }
    }

    (void)picoquic_file_delete(ticket_file, NULL);

    return ret;
}

/* Same SNI and unchanged registry scope: resumption and 0-RTT work.
 * By contrast, a ticket issued to an unmatched name is bound to the
 * server's process-local default scope, so it must not resume on a
 * recreated server even when the registry is configured identically. */
int sni_scope_resume_test(void)
{
    int ret = sni_scope_test_one(sni_scope_case_control, SNI_TEST_NAME_ALPHA, 1,
        (void*)&sni_test_vhost_alpha);
    if (ret == 0) {
        ret = sni_scope_test_one(sni_scope_case_default_fallback,
            SNI_TEST_NAME_UNKNOWN, 0, NULL);
    }
    return ret;
}

/* Removing the entry invalidates its tickets: the reconnection falls
 * back to the default certificate, the old ticket is not accepted as a
 * PSK, and the early data is rejected. */
int sni_scope_remove_test(void)
{
    return sni_scope_test_one(sni_scope_case_remove, SNI_TEST_NAME_ALPHA, 0, NULL);
}

/* Replacement semantics: plain replacement and re-adding invalidate
 * tickets; replacing with the same explicit scope (certificate-only
 * rotation) keeps them; replacing with a different explicit scope
 * invalidates them. */
int sni_scope_replace_test(void)
{
    int ret = sni_scope_test_one(sni_scope_case_replace_simple, SNI_TEST_NAME_ALPHA, 0,
        (void*)&sni_test_vhost_beta);
    if (ret == 0) {
        ret = sni_scope_test_one(sni_scope_case_replace_same_scope, SNI_TEST_NAME_ALPHA, 1,
            (void*)&sni_test_vhost_beta);
    }
    if (ret == 0) {
        ret = sni_scope_test_one(sni_scope_case_replace_new_scope, SNI_TEST_NAME_ALPHA, 0,
            (void*)&sni_test_vhost_beta);
    }
    if (ret == 0) {
        ret = sni_scope_test_one(sni_scope_case_readd, SNI_TEST_NAME_ALPHA, 0,
            (void*)&sni_test_vhost_alpha);
    }
    return ret;
}

/* Selector scope semantics: a stable scope resumes, a changed scope
 * does not, and a selector that never supplies a scope never gets a
 * later resumption. */
int sni_scope_selector_test(void)
{
    int ret = sni_scope_test_one(sni_scope_case_selector_stable, SNI_TEST_NAME_ALPHA, 1,
        (void*)&sni_test_vhost_callback);
    if (ret == 0) {
        ret = sni_scope_test_one(sni_scope_case_selector_changed, SNI_TEST_NAME_ALPHA, 0,
            (void*)&sni_test_vhost_callback);
    }
    if (ret == 0) {
        ret = sni_scope_test_one(sni_scope_case_selector_no_scope, SNI_TEST_NAME_ALPHA, 0,
            (void*)&sni_test_vhost_callback);
    }
    return ret;
}

/* Legacy compatibility: a server that never configures SNI selection
 * keeps the original ticket binding and resumption; a ticket issued in
 * legacy mode stops working once scoping is enabled. */
int sni_scope_legacy_test(void)
{
    int ret = sni_scope_test_one(sni_scope_case_legacy, SNI_TEST_NAME_ALPHA, 1, NULL);
    if (ret == 0) {
        ret = sni_scope_test_one(sni_scope_case_legacy_then_scoped, SNI_TEST_NAME_ALPHA, 0,
            (void*)&sni_test_vhost_alpha);
    }
    return ret;
}

/* Wildcard entries carry their own scope, and an exact entry added
 * over a wildcard has an independent one. */
int sni_scope_wildcard_test(void)
{
    int ret = sni_scope_test_one(sni_scope_case_wildcard, SNI_TEST_NAME_IN_WILDCARD, 1,
        (void*)&sni_test_vhost_beta);
    if (ret == 0) {
        ret = sni_scope_test_one(sni_scope_case_wildcard_exact_override,
            SNI_TEST_NAME_IN_WILDCARD, 0, (void*)&sni_test_vhost_alpha);
    }
    return ret;
}

/* Selector routing across connections on the SAME live QUIC context:
 * when the selector routes a name through use_default or through
 * fallthrough without a registry match, its routing context can change
 * between connections while the SNI stays the same. A ticket issued
 * under the old routing must not resume into the new one unless the
 * selector supplies the same stable scope on both connections. */

typedef struct st_sni_scope_routing_case_t {
    picoquic_server_identity_result_t behavior;
    int register_other_entry; /* non-matching registry entry, for the fallthrough-miss path */
    void* ctx_round[2];
    const picoquic_server_resumption_scope_t* scope_round[2];
    int expect_resume;
} sni_scope_routing_case_t;

static int sni_scope_routing_one(const sni_scope_routing_case_t* rc)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char const* ticket_file = "sni_scope_routing_tickets.bin";
    static const uint8_t early_data[] = { 't', 'e', 's', 't', '0', 'r', 't', 't' };

    /* The ticket store file is only needed so that the client installs
     * its ticket callbacks; both connections share one client. */
    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file);
    if (ret == 0) {
        ret = sni_test_ctx_create(&test_ctx, &simulated_time, NULL, NULL, 0, ticket_file, 0);
    }
    if (ret == 0 && rc->register_other_entry) {
        ret = sni_scope_register_ex(test_ctx->qserver, SNI_TEST_NAME_BETA,
            PICOQUIC_TEST_FILE_SNI_CERT_BETA, PICOQUIC_TEST_FILE_SNI_KEY_BETA,
            (void*)&sni_test_vhost_beta, &sni_scope_stable);
    }
    if (ret == 0) {
        memset(&sni_scope_selector_state, 0, sizeof(sni_scope_selector_state));
        sni_scope_selector_state.behavior = rc->behavior;
        picoquic_set_server_identity_select_fn(test_ctx->qserver, sni_test_selector,
            &sni_scope_selector_state);
    }

    for (int round = 0; ret == 0 && round < 2; round++) {
        sni_scope_selector_state.server_name_ctx_out = rc->ctx_round[round];
        sni_scope_selector_state.scope_out = rc->scope_round[round];

        ret = sni_test_start_client(test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA);
        if (ret == 0 && round == 1) {
            ret = picoquic_add_to_stream(test_ctx->cnx_client, 0, early_data,
                sizeof(early_data), 1);
        }
        if (ret == 0) {
            ret = tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);
            if (ret == 0 && !(TEST_CLIENT_READY && TEST_SERVER_READY)) {
                DBG_PRINTF("Routing case: connection %d failed", round);
                ret = -1;
            }
        }
        if (ret == 0 &&
            picoquic_get_server_name_context(test_ctx->cnx_server) != rc->ctx_round[round]) {
            DBG_PRINTF("Routing case: unexpected server name context in round %d", round);
            ret = -1;
        }
        if (ret == 0 && round == 0) {
            /* Wait for the session ticket, then tear the connection
             * down while keeping the QUIC contexts alive. */
            uint64_t target_time = simulated_time + 2000000;
            while (ret == 0 && test_ctx->qclient->p_first_ticket == NULL &&
                simulated_time < target_time) {
                ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 100000);
            }
            if (ret == 0 && test_ctx->qclient->p_first_ticket == NULL) {
                DBG_PRINTF("%s", "Routing case: no session ticket received");
                ret = -1;
            }
            if (ret == 0) {
                picoquic_delete_cnx(test_ctx->cnx_client);
                test_ctx->cnx_client = NULL;
                if (test_ctx->cnx_server != NULL) {
                    picoquic_delete_cnx(test_ctx->cnx_server);
                    test_ctx->cnx_server = NULL;
                }
            }
        }
        if (ret == 0 && round == 1) {
            int is_psk;

            ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, 0, 1);
            is_psk = picoquic_tls_is_psk_handshake(test_ctx->cnx_client);

            if (ret != 0) {
                DBG_PRINTF("%s", "Routing case: post-handshake loop failed");
            }
            else if (is_psk != rc->expect_resume) {
                DBG_PRINTF("Routing case: PSK handshake %d, expected %d", is_psk,
                    rc->expect_resume);
                ret = -1;
            }
            else if (test_ctx->cnx_client->nb_zero_rtt_sent == 0) {
                DBG_PRINTF("%s", "Routing case: client did not send 0-RTT data");
                ret = -1;
            }
            else if (rc->expect_resume &&
                (test_ctx->cnx_server->nb_zero_rtt_received == 0 ||
                    test_ctx->cnx_client->nb_zero_rtt_acked == 0)) {
                DBG_PRINTF("%s", "Routing case: 0-RTT data not accepted");
                ret = -1;
            }
            else if (!rc->expect_resume &&
                (test_ctx->cnx_server->nb_zero_rtt_received != 0 ||
                    test_ctx->cnx_client->nb_zero_rtt_acked != 0)) {
                DBG_PRINTF("%s", "Routing case: 0-RTT data accepted across routings");
                ret = -1;
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    (void)picoquic_file_delete(ticket_file, NULL);

    return ret;
}

int sni_scope_selector_routing_test(void)
{
    int ret = 0;
    sni_scope_routing_case_t rc;

    /* use_default routing changed from A to B with no stable scope:
     * the old ticket must not resume into B. */
    memset(&rc, 0, sizeof(rc));
    rc.behavior = picoquic_server_identity_result_use_default;
    rc.ctx_round[0] = (void*)&sni_test_vhost_alpha;
    rc.ctx_round[1] = (void*)&sni_test_vhost_beta;
    rc.expect_resume = 0;
    ret = sni_scope_routing_one(&rc);

    /* Same, with the selector changing its stable scope. */
    if (ret == 0) {
        rc.scope_round[0] = &sni_scope_stable;
        rc.scope_round[1] = &sni_scope_other;
        ret = sni_scope_routing_one(&rc);
    }

    /* Stable routing and stable scope through use_default resumes. */
    if (ret == 0) {
        rc.ctx_round[1] = rc.ctx_round[0];
        rc.scope_round[1] = rc.scope_round[0];
        rc.expect_resume = 1;
        ret = sni_scope_routing_one(&rc);
    }

    /* fallthrough with no matching registry entry, routing changed with
     * no stable scope: no resumption. */
    if (ret == 0) {
        memset(&rc, 0, sizeof(rc));
        rc.behavior = picoquic_server_identity_result_fallthrough;
        rc.register_other_entry = 1;
        rc.ctx_round[0] = (void*)&sni_test_vhost_alpha;
        rc.ctx_round[1] = (void*)&sni_test_vhost_beta;
        rc.expect_resume = 0;
        ret = sni_scope_routing_one(&rc);
    }

    /* Pure fallthrough with no routing context and no scope: default
     * fallback resumption keeps working. */
    if (ret == 0) {
        memset(&rc, 0, sizeof(rc));
        rc.behavior = picoquic_server_identity_result_fallthrough;
        rc.register_other_entry = 1;
        rc.expect_resume = 1;
        ret = sni_scope_routing_one(&rc);
    }

    return ret;
}

/* The all-zero scope is a sentinel meaning "no stable scope": explicit
 * registration with it must be refused, and the random helper must
 * never produce it. */
int sni_scope_zero_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_server_identity_t* identity = NULL;
    picoquic_server_resumption_scope_t zero_scope;
    picoquic_server_resumption_scope_t random_scope;
    uint64_t simulated_time = 0;
    char cert_path[512];
    char key_path[512];
    int is_zero = 1;

    memset(&zero_scope, 0, sizeof(zero_scope));

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SNI_CERT_ALPHA);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_ALPHA);
    }
    if (ret == 0) {
        quic = picoquic_create(8, cert_path, key_path, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, simulated_time, &simulated_time, NULL, NULL, 0);
        if (quic == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = picoquic_server_identity_create(quic, cert_path, key_path, &identity);
    }
    if (ret == 0 && picoquic_set_server_identity_ex(quic, SNI_TEST_NAME_ALPHA,
        identity, NULL, &zero_scope) == 0) {
        DBG_PRINTF("%s", "Explicit all-zero scope accepted");
        ret = -1;
    }
    if (ret == 0) {
        picoquic_server_resumption_scope_random(quic, &random_scope);
        for (size_t i = 0; is_zero && i < sizeof(random_scope.id); i++) {
            is_zero = (random_scope.id[i] == 0);
        }
        if (is_zero) {
            DBG_PRINTF("%s", "Random scope is all-zero");
            ret = -1;
        }
    }

    if (identity != NULL) {
        picoquic_server_identity_release(identity);
    }
    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

/* Certificate-verification policy inheritance: every SNI identity must
 * apply exactly the master context's verification policy (custom
 * verifiers installed with a cleanup callback, and provider verifiers
 * whose trust store was extended with in-memory roots), and an owned
 * verifier must be cleaned up exactly once, after the last TLS context
 * that references it is gone. These tests enable client authentication
 * so the SERVER's verifier is exercised; the client presents
 * certs/sni/client.crt, signed by the SNI test CA. */

typedef struct st_sni_verifier_t {
    ptls_verify_certificate_t super;
    int call_count;
    int reject;
    int cleaned;
} sni_verifier_t;

static int sni_verifier_cleanup_count;

static int sni_verifier_sign(void* verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign)
{
    (void)verify_ctx;
    (void)algo;
    (void)data;
    (void)sign;
    return 0;
}

static int sni_verifier_cb(struct st_ptls_verify_certificate_t* self, ptls_t* tls,
    const char* server_name,
    int (**verify_sign)(void* verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign),
    void** verify_data, ptls_iovec_t* certs, size_t num_certs)
{
    sni_verifier_t* verifier = (sni_verifier_t*)((char*)self - offsetof(sni_verifier_t, super));

    (void)tls;
    (void)server_name;
    (void)certs;
    (void)num_certs;

    verifier->call_count++;
    if (verifier->reject) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    *verify_sign = sni_verifier_sign;
    *verify_data = NULL;
    return 0;
}

static void sni_verifier_cleanup(ptls_verify_certificate_t* verifier)
{
    sni_verifier_t* self = (sni_verifier_t*)((char*)verifier - offsetof(sni_verifier_t, super));

    self->cleaned++;
    sni_verifier_cleanup_count++;
}

static const uint16_t sni_verifier_algos[] = {
    PTLS_SIGNATURE_ED25519, PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PTLS_SIGNATURE_RSA_PKCS1_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA1, UINT16_MAX };

static void sni_verifier_init(sni_verifier_t* verifier, int reject)
{
    memset(verifier, 0, sizeof(*verifier));
    verifier->super.cb = sni_verifier_cb;
    verifier->super.algos = sni_verifier_algos;
    verifier->reject = reject;
    sni_verifier_cleanup_count = 0;
}

/* Client+server pair for client-authentication tests: the client holds
 * the SNI test client certificate and trusts the SNI test CA; the
 * server uses the fixture default certificate, with or without the SNI
 * test CA as its file-based root store. No client connection yet. */
static int sni_verifier_ctx_create(picoquic_test_tls_api_ctx_t** pctx, uint64_t* p_simulated_time,
    int server_with_root_file)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char server_cert_path[512];
    char server_key_path[512];
    char client_cert_path[512];
    char client_key_path[512];
    char root_path[512];

    *pctx = NULL;

    ret = picoquic_get_input_path(server_cert_path, sizeof(server_cert_path),
        picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_CERT_DEFAULT);
    if (ret == 0) {
        ret = picoquic_get_input_path(server_key_path, sizeof(server_key_path),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_KEY_DEFAULT);
    }
    if (ret == 0) {
        ret = picoquic_get_input_path(client_cert_path, sizeof(client_cert_path),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_CLIENT_CERT);
    }
    if (ret == 0) {
        ret = picoquic_get_input_path(client_key_path, sizeof(client_key_path),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_CLIENT_KEY);
    }
    if (ret == 0) {
        ret = picoquic_get_input_path(root_path, sizeof(root_path),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_CERT_STORE);
    }

    if (ret == 0) {
        test_ctx = (picoquic_test_tls_api_ctx_t*)malloc(sizeof(picoquic_test_tls_api_ctx_t));
        if (test_ctx == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        memset(test_ctx, 0, sizeof(picoquic_test_tls_api_ctx_t));
        test_ctx->client_callback.client_mode = 1;

        picoquic_set_test_address(&test_ctx->client_addr, 0x0A000002, 1234);
        picoquic_set_test_address(&test_ctx->server_addr, 0x0A000001, 4321);

        test_ctx->qclient = picoquic_create(8, client_cert_path, client_key_path,
            root_path, NULL, test_api_callback,
            (void*)&test_ctx->client_callback, NULL, NULL, NULL, *p_simulated_time,
            p_simulated_time, NULL, NULL, 0);

        test_ctx->qserver = picoquic_create(8,
            server_cert_path, server_key_path,
            (server_with_root_file) ? root_path : NULL, PICOQUIC_TEST_ALPN,
            test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL,
            *p_simulated_time, p_simulated_time, NULL,
            sni_test_ticket_key, sizeof(sni_test_ticket_key));

        if (test_ctx->qclient == NULL || test_ctx->qserver == NULL) {
            ret = -1;
        }
        else {
            picoquic_enforce_client_only(test_ctx->qclient, 1);
        }
    }

    if (ret == 0) {
        test_ctx->c_to_s_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
        test_ctx->s_to_c_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);

        if (test_ctx->c_to_s_link == NULL || test_ctx->s_to_c_link == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        test_ctx->send_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
        test_ctx->send_buffer = (uint8_t*)malloc(test_ctx->send_buffer_size);
        if (test_ctx->send_buffer == NULL) {
            ret = -1;
        }
    }

    if (ret != 0 && test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    *pctx = test_ctx;

    return ret;
}

/* An SNI-selected identity must invoke a custom verifier installed with
 * a cleanup callback, and enforce its verdict. */
int sni_verifier_custom_test(void)
{
    int ret = 0;

    for (int reject = 0; ret == 0 && reject < 2; reject++) {
        picoquic_test_tls_api_ctx_t* test_ctx = NULL;
        sni_verifier_t verifier;
        uint64_t simulated_time = 0;

        sni_verifier_init(&verifier, reject);

        ret = sni_verifier_ctx_create(&test_ctx, &simulated_time, 1);
        if (ret == 0) {
            picoquic_set_verify_certificate_callback(test_ctx->qserver, &verifier.super,
                sni_verifier_cleanup);
            picoquic_set_client_authentication(test_ctx->qserver, 1);
            ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
                PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
                (void*)&sni_test_vhost_alpha, NULL);
        }
        if (ret == 0) {
            ret = sni_test_start_client(test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA);
        }
        if (ret == 0) {
            int c_ret = tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);
            int connected = (c_ret == 0 && TEST_CLIENT_READY && TEST_SERVER_READY);

            if (reject == 0) {
                if (!connected) {
                    DBG_PRINTF("%s", "Connection with accepting custom verifier failed");
                    ret = -1;
                }
                else if (picoquic_get_server_name_context(test_ctx->cnx_server) !=
                    (void*)&sni_test_vhost_alpha) {
                    DBG_PRINTF("%s", "Custom verifier: unexpected server name context");
                    ret = -1;
                }
            }
            else if (connected) {
                DBG_PRINTF("%s", "Connection succeeded although the custom verifier rejects");
                ret = -1;
            }
            if (ret == 0 && verifier.call_count == 0) {
                DBG_PRINTF("Custom verifier not invoked (reject=%d)", reject);
                ret = -1;
            }
        }
        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
            test_ctx = NULL;
        }
        if (ret == 0 && sni_verifier_cleanup_count != 1) {
            DBG_PRINTF("Custom verifier cleaned up %d times, expected 1",
                sni_verifier_cleanup_count);
            ret = -1;
        }
    }

    return ret;
}

/* Roots added with picoquic_set_tls_root_certificates() must be part of
 * the trust store applied by SNI identities as well as by the fallback
 * context. The server has no file-based root store at all. */
int sni_verifier_roots_test(void)
{
    int ret = 0;

    for (int use_identity = 1; ret == 0 && use_identity >= 0; use_identity--) {
        picoquic_test_tls_api_ctx_t* test_ctx = NULL;
        uint64_t simulated_time = 0;
        char root_path[512];

        ret = picoquic_get_input_path(root_path, sizeof(root_path),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_CERT_STORE);
        if (ret == 0) {
            ret = sni_verifier_ctx_create(&test_ctx, &simulated_time, 0);
        }
        if (ret == 0) {
            size_t count = 0;
            ptls_iovec_t* chain = picoquic_get_certs_from_file(root_path, &count);
            if (chain == NULL) {
                ret = -1;
            }
            else {
                ret = picoquic_set_tls_root_certificates(test_ctx->qserver, chain, count);
                for (size_t i = 0; i < count; i++) {
                    free(chain[i].base);
                }
                free(chain);
            }
        }
        if (ret == 0) {
            picoquic_set_client_authentication(test_ctx->qserver, 1);
            ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
                PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
                (void*)&sni_test_vhost_alpha, NULL);
        }
        if (ret == 0) {
            /* The fallback control uses the name carried by the default
             * certificate, since this client fully verifies the server. */
            ret = sni_test_start_client(test_ctx, &simulated_time,
                (use_identity) ? SNI_TEST_NAME_ALPHA : SNI_TEST_NAME_DEFAULT);
        }
        if (ret == 0) {
            int c_ret = tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);

            if (c_ret != 0 || !(TEST_CLIENT_READY && TEST_SERVER_READY)) {
                DBG_PRINTF("Connection with in-memory roots failed (identity=%d)", use_identity);
                ret = -1;
            }
            else if (picoquic_get_server_name_context(test_ctx->cnx_server) !=
                ((use_identity) ? (void*)&sni_test_vhost_alpha : NULL)) {
                DBG_PRINTF("%s", "In-memory roots: unexpected server name context");
                ret = -1;
            }
        }
        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
        }
    }

    return ret;
}

/* Owned-verifier lifetime: the cleanup callback runs exactly once, when
 * the last TLS context that references the verifier is gone, across
 * identity creation, release, registry replacement and removal, failed
 * identity creation, live connections, and QUIC context teardown. */
int sni_verifier_lifetime_test(void)
{
    int ret = 0;
    sni_verifier_t verifier;
    uint64_t simulated_time = 0;
    char cert_path[512];
    char key_path[512];

    /* Phase A: registry churn without connections. */
    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SNI_CERT_ALPHA);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_ALPHA);
    }
    if (ret == 0) {
        picoquic_quic_t* quic = picoquic_create(8, cert_path, key_path, NULL, NULL,
            NULL, NULL, NULL, NULL, NULL, simulated_time, &simulated_time, NULL, NULL, 0);
        if (quic == NULL) {
            ret = -1;
        }
        else {
            picoquic_server_identity_t* identity = NULL;
            picoquic_server_identity_t* identity2 = NULL;

            sni_verifier_init(&verifier, 0);
            picoquic_set_verify_certificate_callback(quic, &verifier.super,
                sni_verifier_cleanup);

            ret = picoquic_server_identity_create(quic, cert_path, key_path, &identity);
            if (ret == 0) {
                ret = picoquic_set_server_identity(quic, SNI_TEST_NAME_ALPHA, identity,
                    NULL);
            }
            if (ret == 0) {
                picoquic_server_identity_release(identity);
                ret = picoquic_server_identity_create(quic, cert_path, key_path, &identity2);
            }
            if (ret == 0) {
                /* Replace, then remove. */
                ret = picoquic_set_server_identity(quic, SNI_TEST_NAME_ALPHA, identity2,
                    NULL);
            }
            if (ret == 0) {
                ret = picoquic_remove_server_identity(quic, SNI_TEST_NAME_ALPHA);
            }
            if (ret == 0) {
                /* Failed identity creation must unwind cleanly. */
                picoquic_server_identity_t* failed = NULL;
                if (picoquic_server_identity_create(quic, "no/such/cert.pem",
                    "no/such/key.pem", &failed) == 0) {
                    DBG_PRINTF("%s", "Identity creation with bad files succeeded");
                    ret = -1;
                }
            }
            if (ret == 0 && sni_verifier_cleanup_count != 0) {
                DBG_PRINTF("Verifier cleaned up %d times before teardown",
                    sni_verifier_cleanup_count);
                ret = -1;
            }
            /* identity2 is deliberately not released: picoquic_free
             * takes care of it. */
            picoquic_free(quic);
            if (ret == 0 && sni_verifier_cleanup_count != 1) {
                DBG_PRINTF("Verifier cleaned up %d times after teardown, expected 1",
                    sni_verifier_cleanup_count);
                ret = -1;
            }
        }
    }

    /* Phase B: a live connection through an identity whose registry
     * entry is removed while the connection is established. */
    if (ret == 0) {
        picoquic_test_tls_api_ctx_t* test_ctx = NULL;

        simulated_time = 0;
        ret = sni_verifier_ctx_create(&test_ctx, &simulated_time, 1);
        if (ret == 0) {
            sni_verifier_init(&verifier, 0);
            picoquic_set_verify_certificate_callback(test_ctx->qserver, &verifier.super,
                sni_verifier_cleanup);
            picoquic_set_client_authentication(test_ctx->qserver, 1);
            ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
                PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
                (void*)&sni_test_vhost_alpha, NULL);
        }
        if (ret == 0) {
            ret = sni_test_start_client(test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA);
        }
        if (ret == 0) {
            int c_ret = tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);
            if (c_ret != 0 || !(TEST_CLIENT_READY && TEST_SERVER_READY)) {
                DBG_PRINTF("%s", "Lifetime phase B connection failed");
                ret = -1;
            }
            else if (verifier.call_count == 0) {
                DBG_PRINTF("%s", "Lifetime phase B custom verifier not invoked");
                ret = -1;
            }
        }
        if (ret == 0) {
            ret = picoquic_remove_server_identity(test_ctx->qserver, SNI_TEST_NAME_ALPHA);
        }
        if (ret == 0) {
            ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 100000);
        }
        if (ret == 0 && sni_verifier_cleanup_count != 0) {
            DBG_PRINTF("%s", "Verifier cleaned up while contexts are alive");
            ret = -1;
        }
        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
        }
        if (ret == 0 && sni_verifier_cleanup_count != 1) {
            DBG_PRINTF("Verifier cleaned up %d times after phase B, expected 1",
                sni_verifier_cleanup_count);
            ret = -1;
        }
    }

    return ret;
}

/* Refreshing the fallback certificate after identities exist must keep
 * the shared verifier policy valid, on the refreshed fallback context
 * as well as on identities, without premature cleanup. */
int sni_verifier_refresh_test(void)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    sni_verifier_t verifier;
    uint64_t simulated_time = 0;
    int calls_before_refresh = 0;
    char cert_path[512];
    char key_path[512];

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SNI_CERT_DEFAULT);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_DEFAULT);
    }
    if (ret == 0) {
        ret = sni_verifier_ctx_create(&test_ctx, &simulated_time, 1);
    }
    if (ret == 0) {
        sni_verifier_init(&verifier, 0);
        picoquic_set_verify_certificate_callback(test_ctx->qserver, &verifier.super,
            sni_verifier_cleanup);
        picoquic_set_client_authentication(test_ctx->qserver, 1);
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, NULL);
    }

    /* Three connections on the same live context: identity, then
     * refresh, then identity again, then fallback. */
    for (int round = 0; ret == 0 && round < 3; round++) {
        /* The last round exercises the refreshed fallback context, with
         * the name the default certificate carries. */
        char const* sni = (round < 2) ? SNI_TEST_NAME_ALPHA : SNI_TEST_NAME_DEFAULT;

        if (round == 1) {
            ret = picoquic_refresh_tls_certificate(test_ctx->qserver, cert_path, key_path);
            if (ret != 0) {
                DBG_PRINTF("%s", "Certificate refresh failed");
            }
            else if (sni_verifier_cleanup_count != 0) {
                DBG_PRINTF("%s", "Verifier cleaned up by certificate refresh");
                ret = -1;
            }
        }
        if (ret == 0 && round > 0) {
            picoquic_delete_cnx(test_ctx->cnx_client);
            test_ctx->cnx_client = NULL;
            if (test_ctx->cnx_server != NULL) {
                picoquic_delete_cnx(test_ctx->cnx_server);
                test_ctx->cnx_server = NULL;
            }
        }
        if (ret == 0) {
            ret = sni_test_start_client(test_ctx, &simulated_time, sni);
        }
        if (ret == 0) {
            int c_ret = tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);
            if (c_ret != 0 || !(TEST_CLIENT_READY && TEST_SERVER_READY)) {
                DBG_PRINTF("Refresh test round %d connection failed", round);
                ret = -1;
            }
            else if (verifier.call_count <= calls_before_refresh) {
                DBG_PRINTF("Custom verifier not invoked in round %d", round);
                ret = -1;
            }
            else {
                calls_before_refresh = verifier.call_count;
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }
    if (ret == 0 && sni_verifier_cleanup_count != 1) {
        DBG_PRINTF("Verifier cleaned up %d times, expected 1", sni_verifier_cleanup_count);
        ret = -1;
    }

    return ret;
}

static int sni_heap_cleanup_count;
static int sni_alt_cleanup_count;

static void sni_verifier_cleanup_heap(ptls_verify_certificate_t* verifier)
{
    sni_verifier_t* self = (sni_verifier_t*)((char*)verifier - offsetof(sni_verifier_t, super));

    sni_heap_cleanup_count++;
    free(self);
}

static void sni_verifier_cleanup_alt(ptls_verify_certificate_t* verifier)
{
    (void)verifier;
    sni_alt_cleanup_count++;
}


/* Reinstalling a verifier must be safe: installing the callback that is
 * already active with the same cleanup function is an idempotent no-op
 * (no ownership change, no cleanup), and attempting to change only the
 * cleanup function of the installed callback is refused without
 * touching anything. Without these rules a reinstall would release the
 * only reference to the active verifier, freeing it while installed. */
int sni_verifier_reinstall_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    sni_verifier_t* verifier = NULL;
    uint64_t simulated_time = 0;
    char cert_path[512];
    char key_path[512];

    sni_heap_cleanup_count = 0;
    sni_alt_cleanup_count = 0;

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SNI_CERT_DEFAULT);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_DEFAULT);
    }
    if (ret == 0) {
        quic = picoquic_create(8, cert_path, key_path, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, simulated_time, &simulated_time, NULL, NULL, 0);
        verifier = (sni_verifier_t*)malloc(sizeof(sni_verifier_t));
        if (quic == NULL || verifier == NULL) {
            free(verifier);
            verifier = NULL;
            ret = -1;
        }
    }
    if (ret == 0) {
        /* Source compatibility: the historical setter keeps its exact
         * void signature. */
        void (*legacy_setter)(picoquic_quic_t*, ptls_verify_certificate_t*,
            picoquic_free_verify_certificate_ctx) = picoquic_set_verify_certificate_callback;

        memset(verifier, 0, sizeof(*verifier));
        verifier->super.cb = sni_verifier_cb;
        verifier->super.algos = sni_verifier_algos;

        legacy_setter(quic, &verifier->super, sni_verifier_cleanup_heap);
        if (((ptls_context_t*)quic->tls_master_ctx)->verify_certificate != &verifier->super) {
            DBG_PRINTF("%s", "Initial heap verifier installation failed");
            ret = -1;
        }
    }
    if (ret == 0) {
        /* Idempotent reinstall: same callback, same cleanup. */
        if (picoquic_set_verify_certificate_callback_ex(quic, &verifier->super,
            sni_verifier_cleanup_heap) != 0) {
            DBG_PRINTF("%s", "Idempotent verifier reinstall failed");
            ret = -1;
        }
        else if (sni_heap_cleanup_count != 0) {
            DBG_PRINTF("%s", "Idempotent verifier reinstall ran the cleanup");
            ret = -1;
        }
        else if (((ptls_context_t*)quic->tls_master_ctx)->verify_certificate !=
            &verifier->super) {
            DBG_PRINTF("%s", "Idempotent verifier reinstall changed the verifier");
            ret = -1;
        }
    }
    if (ret == 0) {
        /* Same callback with a different cleanup function is refused. */
        if (picoquic_set_verify_certificate_callback_ex(quic, &verifier->super,
            sni_verifier_cleanup_alt) != PICOQUIC_ERROR_UNEXPECTED_ERROR) {
            DBG_PRINTF("%s", "Cleanup change on installed verifier was not refused");
            ret = -1;
        }
        else if (sni_heap_cleanup_count != 0 || sni_alt_cleanup_count != 0) {
            DBG_PRINTF("%s", "Refused verifier reinstall ran a cleanup");
            ret = -1;
        }
        else if (((ptls_context_t*)quic->tls_master_ctx)->verify_certificate !=
            &verifier->super) {
            DBG_PRINTF("%s", "Refused verifier reinstall changed the verifier");
            ret = -1;
        }
    }
    if (ret == 0) {
        /* The historical void setter must never dispose the currently
         * active callback, even though it disposes other incoming
         * callbacks on failure. */
        picoquic_set_verify_certificate_callback(quic, &verifier->super,
            sni_verifier_cleanup_alt);
        if (sni_heap_cleanup_count != 0 || sni_alt_cleanup_count != 0) {
            DBG_PRINTF("%s", "Legacy setter disposed the active verifier");
            ret = -1;
        }
        else if (((ptls_context_t*)quic->tls_master_ctx)->verify_certificate !=
            &verifier->super) {
            DBG_PRINTF("%s", "Legacy setter failure changed the verifier");
            ret = -1;
        }
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }
    if (ret == 0 && (sni_heap_cleanup_count != 1 || sni_alt_cleanup_count != 0)) {
        DBG_PRINTF("Cleanup counts after teardown: heap %d, alt %d",
            sni_heap_cleanup_count, sni_alt_cleanup_count);
        ret = -1;
    }

    return ret;
}

/* A -> B -> A verifier rollback across retained TLS contexts: while an
 * old (pre-refresh) context still references verifier A, replacing A
 * with B on the refreshed master and then reinstalling A must reuse
 * A's live ownership record. A second independent record would run
 * A's cleanup twice and free it while installed. B's record must still
 * be cleaned up promptly when it becomes unused. */
int sni_verifier_rollback_test(void)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    sni_verifier_t* verifier_a = NULL;
    sni_verifier_t* verifier_b = NULL;
    uint64_t simulated_time = 0;
    int calls_before = 0;
    char cert_path[512];
    char key_path[512];

    sni_heap_cleanup_count = 0;
    sni_alt_cleanup_count = 0;

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SNI_CERT_DEFAULT);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_DEFAULT);
    }
    if (ret == 0) {
        ret = sni_verifier_ctx_create(&test_ctx, &simulated_time, 1);
    }
    if (ret == 0) {
        verifier_a = (sni_verifier_t*)malloc(sizeof(sni_verifier_t));
        verifier_b = (sni_verifier_t*)malloc(sizeof(sni_verifier_t));
        if (verifier_a == NULL || verifier_b == NULL) {
            free(verifier_a);
            free(verifier_b);
            verifier_a = NULL;
            verifier_b = NULL;
            ret = -1;
        }
        else {
            memset(verifier_a, 0, sizeof(*verifier_a));
            verifier_a->super.cb = sni_verifier_cb;
            verifier_a->super.algos = sni_verifier_algos;
            memset(verifier_b, 0, sizeof(*verifier_b));
            verifier_b->super.cb = sni_verifier_cb;
            verifier_b->super.algos = sni_verifier_algos;
        }
    }
    if (ret == 0) {
        if (picoquic_set_verify_certificate_callback_ex(test_ctx->qserver,
            &verifier_a->super, sni_verifier_cleanup_heap) != 0) {
            DBG_PRINTF("%s", "Rollback: installing A failed");
            ret = -1;
        }
        else {
            picoquic_set_client_authentication(test_ctx->qserver, 1);
        }
    }
    if (ret == 0) {
        /* Connection 1 uses A's original context and stays alive. */
        ret = sni_test_start_client(test_ctx, &simulated_time, SNI_TEST_NAME_DEFAULT);
        if (ret == 0) {
            ret = tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);
        }
        if (ret == 0 && (!(TEST_CLIENT_READY && TEST_SERVER_READY) ||
            verifier_a->call_count == 0)) {
            DBG_PRINTF("%s", "Rollback: first connection failed or A not invoked");
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = picoquic_refresh_tls_certificate(test_ctx->qserver, cert_path, key_path);
    }
    if (ret == 0) {
        /* Replace A with B on the refreshed master, then roll back to
         * A while the old connection still retains A's context. */
        if (picoquic_set_verify_certificate_callback_ex(test_ctx->qserver,
            &verifier_b->super, sni_verifier_cleanup_heap) != 0 ||
            picoquic_set_verify_certificate_callback_ex(test_ctx->qserver,
                &verifier_a->super, sni_verifier_cleanup_heap) != 0) {
            DBG_PRINTF("%s", "Rollback: replace or reinstall failed");
            ret = -1;
        }
        else if (sni_heap_cleanup_count != 1) {
            DBG_PRINTF("Rollback: %d cleanups after B became unused, expected 1 (B)",
                sni_heap_cleanup_count);
            ret = -1;
        }
    }
    if (ret == 0) {
        /* Legacy setter with a conflicting cleanup function while A is
         * retained by both the old context and the master: nothing may
         * be disposed. */
        picoquic_set_verify_certificate_callback(test_ctx->qserver, &verifier_a->super,
            sni_verifier_cleanup_alt);
        if (sni_heap_cleanup_count != 1 || sni_alt_cleanup_count != 0) {
            DBG_PRINTF("%s", "Rollback: legacy conflicting reinstall ran a cleanup");
            ret = -1;
        }
    }
    if (ret == 0) {
        /* Delete the old connection: A must remain installed, callable
         * and uncleaned. */
        picoquic_delete_cnx(test_ctx->cnx_client);
        test_ctx->cnx_client = NULL;
        if (test_ctx->cnx_server != NULL) {
            picoquic_delete_cnx(test_ctx->cnx_server);
            test_ctx->cnx_server = NULL;
        }
        if (sni_heap_cleanup_count != 1) {
            DBG_PRINTF("Rollback: %d cleanups after old connection deletion, expected 1",
                sni_heap_cleanup_count);
            ret = -1;
        }
        else if (((ptls_context_t*)test_ctx->qserver->tls_master_ctx)->verify_certificate !=
            &verifier_a->super) {
            DBG_PRINTF("%s", "Rollback: A no longer installed");
            ret = -1;
        }
    }
    if (ret == 0) {
        calls_before = verifier_a->call_count;
        ret = sni_test_start_client(test_ctx, &simulated_time, SNI_TEST_NAME_DEFAULT);
        if (ret == 0) {
            ret = tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);
        }
        if (ret == 0 && (!(TEST_CLIENT_READY && TEST_SERVER_READY) ||
            verifier_a->call_count <= calls_before)) {
            DBG_PRINTF("%s", "Rollback: reinstalled A not invoked on a new connection");
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }
    if (ret == 0 && (sni_heap_cleanup_count != 2 || sni_alt_cleanup_count != 0)) {
        DBG_PRINTF("Rollback: final cleanups %d/%d, expected 2/0",
            sni_heap_cleanup_count, sni_alt_cleanup_count);
        ret = -1;
    }

    return ret;
}

/* Legacy wire compatibility: a server that never configured SNI
 * selection accepts arbitrary SNI values exactly as before this
 * feature, including names that are not well-formed host names. The
 * name remains visible through picoquic_tls_get_sni() (picotls state),
 * but the C-string convenience copy on the connection is only made for
 * validated names. Note that a conformant client never sends an IP
 * literal in the SNI extension at all (picotls suppresses it per RFC
 * 6066), so dialing an IP literal reaches the server as an absent SNI:
 * expected_seen is NULL for that case. */
static int sni_legacy_names_one(char const* sni, char const* expected_seen)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = sni_test_ctx_create(&test_ctx, &simulated_time, sni, NULL, 0, NULL, 1);

    if (ret == 0) {
        ret = sni_test_connect(test_ctx, &simulated_time, 1, NULL, 0);
    }
    if (ret == 0) {
        char const* seen = picoquic_tls_get_sni(test_ctx->cnx_server);
        if ((expected_seen == NULL) ? (seen != NULL) :
            (seen == NULL || strcmp(seen, expected_seen) != 0)) {
            DBG_PRINTF("Legacy server sees SNI '%s', expected '%s'",
                (seen == NULL) ? "(null)" : seen,
                (expected_seen == NULL) ? "(null)" : expected_seen);
            ret = -1;
        }
        else if (test_ctx->cnx_server->sni != NULL) {
            DBG_PRINTF("Non-validated legacy SNI '%s' was copied to cnx->sni", sni);
            ret = -1;
        }
    }
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int sni_legacy_names_test(void)
{
    int ret = sni_legacy_names_one(SNI_TEST_NAME_LEGACY, SNI_TEST_NAME_LEGACY);
    if (ret == 0) {
        ret = sni_legacy_names_one(SNI_TEST_NAME_IPV4, NULL);
    }
    return ret;
}

/* Strict wire validation: once SNI selection has been enabled, a
 * malformed SNI fails the handshake with illegal_parameter, and it
 * stays rejected after the registry entry is removed, since strict
 * mode is sticky. */
static int sni_strict_names_one(char const* sni, int remove_entry)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = sni_test_ctx_create(&test_ctx, &simulated_time, sni, NULL, 0, NULL, 1);

    if (ret == 0) {
        /* An unrelated entry activates strict validation. */
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, NULL);
    }
    if (ret == 0 && remove_entry) {
        ret = picoquic_remove_server_identity(test_ctx->qserver, SNI_TEST_NAME_ALPHA);
    }
    if (ret == 0) {
        ret = sni_test_connect(test_ctx, &simulated_time, 0, NULL,
            SNI_TEST_ALERT_ILLEGAL_PARAMETER);
    }
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int sni_strict_names_test(void)
{
    int ret = sni_strict_names_one(SNI_TEST_NAME_LEGACY, 0);
    if (ret == 0) {
        /* Sticky: still rejected after the registry is emptied. */
        ret = sni_strict_names_one(SNI_TEST_NAME_LEGACY, 1);
    }
    if (ret == 0) {
        /* A conformant client never sends an IP-literal SNI (picotls
         * suppresses the extension per RFC 6066), so dialing an IP
         * literal reaches a strict server as an absent SNI and falls
         * back to the default identity. The server-side rejection of
         * numeric final labels shares its code path with the malformed
         * name above and is covered by the validator and registration
         * tests. */
        picoquic_test_tls_api_ctx_t* test_ctx = NULL;
        uint64_t simulated_time = 0;

        ret = sni_test_ctx_create(&test_ctx, &simulated_time, SNI_TEST_NAME_IPV4,
            NULL, 0, NULL, 1);
        if (ret == 0) {
            ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
                PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
                (void*)&sni_test_vhost_alpha, NULL);
        }
        if (ret == 0) {
            ret = sni_test_connect(test_ctx, &simulated_time, 1, NULL, 0);
        }
        if (ret == 0 && picoquic_tls_get_sni(test_ctx->cnx_server) != NULL) {
            DBG_PRINTF("%s", "Client sent an IP literal SNI");
            ret = -1;
        }
        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
        }
    }
    return ret;
}

/* SSL key logging must cover every TLS context of the QUIC context:
 * the fallback (master) context, SNI-selected identity contexts --
 * including identities created BEFORE the key log file is configured --
 * and refreshed fallback contexts. Each handshake is matched to its
 * key-log records through the client-random value: connections run one
 * at a time, so the records appearing after a handshake belong to it. */

/* Collect the distinct client-random values (second token of each
 * line) from the key log file. Returns the count, at most max_randoms. */
static size_t sni_keylog_count_randoms(char const* filename, char randoms[][2 * 32 + 1],
    size_t max_randoms)
{
    size_t count = 0;
    char line[1024];
    FILE* F = picoquic_file_open(filename, "r");

    while (F != NULL && fgets(line, sizeof(line), F) != NULL) {
        char* first_space = strchr(line, ' ');
        if (first_space != NULL) {
            char* random_hex = first_space + 1;
            char* second_space = strchr(random_hex, ' ');
            if (second_space != NULL && (size_t)(second_space - random_hex) < 2 * 32 + 1) {
                size_t len = (size_t)(second_space - random_hex);
                int is_new = 1;
                for (size_t i = 0; is_new && i < count; i++) {
                    is_new = (strncmp(randoms[i], random_hex, len) != 0 ||
                        randoms[i][len] != 0);
                }
                if (is_new && count < max_randoms) {
                    memcpy(randoms[count], random_hex, len);
                    randoms[count][len] = 0;
                    count++;
                }
            }
        }
    }
    if (F != NULL) {
        (void)picoquic_file_close(F);
    }

    return count;
}

int sni_keylog_test(void)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    char const* keylog_file = "sni_keylog.log";
    char randoms[8][2 * 32 + 1];
    char cert_path[512];
    char key_path[512];

    (void)picoquic_file_delete(keylog_file, NULL);

    /* Failed QUIC context creation (bad certificate path) must release
     * the key log sink it allocated; observable as a leak under LSan
     * on platforms that support it. */
    if (picoquic_create(8, "no/such/cert.pem", "no/such/key.pem", NULL, NULL,
        NULL, NULL, NULL, NULL, NULL, simulated_time, &simulated_time,
        NULL, NULL, 0) != NULL) {
        DBG_PRINTF("%s", "QUIC creation with bad certificate succeeded");
        ret = -1;
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_CERT_DEFAULT);
    }
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_DEFAULT);
    }
    if (ret == 0) {
        ret = sni_test_ctx_create(&test_ctx, &simulated_time, NULL, NULL, 0, NULL, 0);
    }
    if (ret == 0) {
        /* The identity exists BEFORE the key log file is configured. */
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, NULL);
    }
    if (ret == 0) {
        picoquic_set_key_log_file(test_ctx->qserver, keylog_file);
    }

    /* Three connections on one live QUIC context: fallback, identity,
     * then refreshed fallback. Each must add its own client-random to
     * the key log. */
    for (int round = 0; ret == 0 && round < 3; round++) {
        char const* sni = (round == 1) ? SNI_TEST_NAME_ALPHA : SNI_TEST_NAME_DEFAULT;
        void* expected_ctx = (round == 1) ? (void*)&sni_test_vhost_alpha : NULL;

        if (round == 2) {
            ret = picoquic_refresh_tls_certificate(test_ctx->qserver, cert_path, key_path);
        }
        if (ret == 0 && round > 0) {
            picoquic_delete_cnx(test_ctx->cnx_client);
            test_ctx->cnx_client = NULL;
            if (test_ctx->cnx_server != NULL) {
                picoquic_delete_cnx(test_ctx->cnx_server);
                test_ctx->cnx_server = NULL;
            }
        }
        if (ret == 0) {
            ret = sni_test_start_client(test_ctx, &simulated_time, sni);
        }
        if (ret == 0) {
            ret = sni_test_connect(test_ctx, &simulated_time, 1, expected_ctx, 0);
        }
        if (ret == 0) {
            size_t nb_randoms = sni_keylog_count_randoms(keylog_file, randoms, 8);
            if (nb_randoms != (size_t)(round + 1)) {
                DBG_PRINTF("Round %d: %d distinct client randoms in key log, expected %d",
                    round, (int)nb_randoms, round + 1);
                ret = -1;
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }
    (void)picoquic_file_delete(keylog_file, NULL);

    return ret;
}

/* A QUIC context is not restricted to one role. When a context has no
 * root store, its client connections adopt the null verifier lazily at
 * connection creation. Creating a server identity on that same context
 * freezes the TLS configuration, which used to block that lazy setup,
 * leaving a later client connection with the empty-store verifier that
 * rejects every peer. Creating an identity must finalize the null
 * verifier first, so the client connection still succeeds. */
int sni_client_from_server_ctx_test(void)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_server_identity_t* identity = NULL;
    uint64_t simulated_time = 0;
    char server_cert_path[512];
    char server_key_path[512];
    char id_cert_path[512];
    char id_key_path[512];

    ret = picoquic_get_input_path(server_cert_path, sizeof(server_cert_path),
        picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_CERT_DEFAULT);
    if (ret == 0) {
        ret = picoquic_get_input_path(server_key_path, sizeof(server_key_path),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_KEY_DEFAULT);
    }
    if (ret == 0) {
        ret = picoquic_get_input_path(id_cert_path, sizeof(id_cert_path),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_CERT_ALPHA);
    }
    if (ret == 0) {
        ret = picoquic_get_input_path(id_key_path, sizeof(id_key_path),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA);
    }

    if (ret == 0) {
        test_ctx = (picoquic_test_tls_api_ctx_t*)malloc(sizeof(picoquic_test_tls_api_ctx_t));
        if (test_ctx == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        memset(test_ctx, 0, sizeof(picoquic_test_tls_api_ctx_t));
        test_ctx->client_callback.client_mode = 1;
        picoquic_set_test_address(&test_ctx->client_addr, 0x0A000002, 1234);
        picoquic_set_test_address(&test_ctx->server_addr, 0x0A000001, 4321);

        /* Client context: no root store and, deliberately, no explicit
         * null verifier, so it relies on the lazy setup. */
        test_ctx->qclient = picoquic_create(8, NULL, NULL, NULL, NULL, test_api_callback,
            (void*)&test_ctx->client_callback, NULL, NULL, NULL, simulated_time,
            &simulated_time, NULL, NULL, 0);
        test_ctx->qserver = picoquic_create(8, server_cert_path, server_key_path, NULL,
            PICOQUIC_TEST_ALPN, test_api_callback, (void*)&test_ctx->server_callback,
            NULL, NULL, NULL, simulated_time, &simulated_time, NULL,
            sni_test_ticket_key, sizeof(sni_test_ticket_key));
        if (test_ctx->qclient == NULL || test_ctx->qserver == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        /* Give the client context a server identity (mixed role), which
         * freezes its TLS configuration before the first connection. */
        ret = picoquic_server_identity_create(test_ctx->qclient, id_cert_path, id_key_path,
            &identity);
        if (ret == 0) {
            ret = picoquic_set_server_identity(test_ctx->qclient, SNI_TEST_NAME_ALPHA,
                identity, NULL);
            picoquic_server_identity_release(identity);
        }
    }
    if (ret == 0) {
        test_ctx->c_to_s_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
        test_ctx->s_to_c_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
        if (test_ctx->c_to_s_link == NULL || test_ctx->s_to_c_link == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        test_ctx->send_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
        test_ctx->send_buffer = (uint8_t*)malloc(test_ctx->send_buffer_size);
        if (test_ctx->send_buffer == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = sni_test_start_client(test_ctx, &simulated_time, SNI_TEST_NAME_DEFAULT);
    }
    if (ret == 0) {
        int c_ret = tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);
        if (c_ret != 0 || !(TEST_CLIENT_READY && TEST_SERVER_READY)) {
            DBG_PRINTF("%s", "Client connection from a server-identity context failed");
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

/* Server identity contexts shallow-copy the master context, including
 * its ECH opener. The public ECH release must not free that opener out
 * from under the identity contexts once the configuration is frozen,
 * and teardown must free it exactly once. Configure ECH, register an
 * identity, complete an SNI handshake that selects it, then exercise
 * the public release and teardown. Run under ASan to catch a dangling
 * opener or double free. */
int sni_ech_identity_test(void)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    char ech_key_path[512];
    char ech_config_path[512];

    ret = picoquic_get_input_path(ech_key_path, sizeof(ech_key_path),
        picoquic_solution_dir, PICOQUIC_TEST_ECH_PRIVATE_KEY);
    if (ret == 0) {
        ret = picoquic_get_input_path(ech_config_path, sizeof(ech_config_path),
            picoquic_solution_dir, PICOQUIC_TEST_ECH_CONFIG);
    }
    if (ret == 0) {
        ret = sni_test_ctx_create(&test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_STORE, 0, NULL, 0);
    }
    if (ret == 0) {
        /* Configure ECH before creating identities (configuration is
         * frozen afterwards). */
        ret = picoquic_ech_configure_quic_ctx(test_ctx->qserver, ech_key_path, ech_config_path);
        if (ret != 0) {
            DBG_PRINTF("Cannot configure ECH, ret = 0x%x", ret);
        }
    }
    if (ret == 0) {
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, NULL);
    }
    if (ret == 0) {
        /* The public release is now a no-op on a frozen context; the
         * shared opener must stay valid for the identity contexts. */
        if (picoquic_ech_configure_quic_ctx(test_ctx->qserver, ech_key_path, ech_config_path) !=
            PICOQUIC_ERROR_TLS_CONFIG_FROZEN) {
            DBG_PRINTF("%s", "ECH reconfiguration not frozen after identities");
            ret = -1;
        }
        picoquic_release_quic_ech_ctx(test_ctx->qserver);
    }
    if (ret == 0) {
        ret = sni_test_start_client(test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA);
    }
    if (ret == 0) {
        ret = sni_test_connect(test_ctx, &simulated_time, 1, (void*)&sni_test_vhost_alpha, 0);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

/* The identity selected for the connection survives a Hello Retry
 * Round-trip: force the client to omit its key share so the server
 * requests a second ClientHello. */
int sni_hrr_test(void)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = sni_test_ctx_create(&test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA,
        PICOQUIC_TEST_FILE_SNI_CERT_STORE, 1, NULL, 1);

    if (ret == 0) {
        ret = sni_test_register_alpha_beta(test_ctx->qserver);
    }
    if (ret == 0) {
        ret = sni_test_connect(test_ctx, &simulated_time, 1, (void*)&sni_test_vhost_alpha, 0);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

/* Once an identity exists, context-wide TLS configuration is frozen:
 * int setters fail with PICOQUIC_ERROR_TLS_CONFIG_FROZEN, void setters
 * leave the master context unchanged. Shared runtime state (ticket
 * keys) and the fallback certificate refresh remain allowed. */
int sni_config_freeze_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_server_identity_t* identity = NULL;
    uint64_t simulated_time = 0;
    char cert_path[512];
    char key_path[512];

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SNI_CERT_DEFAULT);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_DEFAULT);
    }
    if (ret == 0) {
        quic = picoquic_create(8, cert_path, key_path, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, simulated_time, &simulated_time, NULL, NULL, 0);
        if (quic == NULL) {
            ret = -1;
        }
    }

    /* Before any identity exists, configuration is open. */
    if (ret == 0 && picoquic_set_cipher_suite(quic, 0) != 0) {
        DBG_PRINTF("%s", "Cipher suite setter failed before freeze");
        ret = -1;
    }
    if (ret == 0 && picoquic_set_key_exchange(quic, 0) != 0) {
        DBG_PRINTF("%s", "Key exchange setter failed before freeze");
        ret = -1;
    }
    if (ret == 0 && picoquic_set_low_memory_mode(quic, 1) != 0) {
        DBG_PRINTF("%s", "Low memory setter failed before freeze");
        ret = -1;
    }

    if (ret == 0) {
        ret = picoquic_server_identity_create(quic, cert_path, key_path, &identity);
    }

    /* After: int setters report the freeze... */
    if (ret == 0 && picoquic_set_cipher_suite(quic, 0) != PICOQUIC_ERROR_TLS_CONFIG_FROZEN) {
        DBG_PRINTF("%s", "Cipher suite setter not frozen");
        ret = -1;
    }
    if (ret == 0 && picoquic_set_key_exchange(quic, 0) != PICOQUIC_ERROR_TLS_CONFIG_FROZEN) {
        DBG_PRINTF("%s", "Key exchange setter not frozen");
        ret = -1;
    }
    if (ret == 0 &&
        picoquic_set_tls_root_certificates(quic, NULL, 0) != PICOQUIC_ERROR_TLS_CONFIG_FROZEN) {
        DBG_PRINTF("%s", "Root certificates setter not frozen");
        ret = -1;
    }
    if (ret == 0 &&
        (picoquic_set_low_memory_mode(quic, 0) != PICOQUIC_ERROR_TLS_CONFIG_FROZEN ||
            quic->use_low_memory != 1)) {
        DBG_PRINTF("%s", "Low memory mode changed after freeze");
        ret = -1;
    }
    if (ret == 0 && picoquic_set_verify_certificate_callback_ex(quic, NULL, NULL) !=
        PICOQUIC_ERROR_TLS_CONFIG_FROZEN) {
        DBG_PRINTF("%s", "Verify certificate callback setter not frozen");
        ret = -1;
    }
    /* ...void setters are ignored... */
    if (ret == 0) {
        ptls_context_t* master = (ptls_context_t*)quic->tls_master_ctx;
        unsigned int before = master->require_client_authentication;
        picoquic_set_client_authentication(quic, !before);
        if (master->require_client_authentication != before) {
            DBG_PRINTF("%s", "Client authentication setter not ignored after freeze");
            ret = -1;
        }
        before = master->use_exporter;
        picoquic_set_use_exporter(quic, !before);
        if (master->use_exporter != before) {
            DBG_PRINTF("%s", "Exporter setter not ignored after freeze");
            ret = -1;
        }
    }
    /* ...while shared runtime state and the fallback refresh still work. */
    if (ret == 0 &&
        picoquic_set_ticket_key(quic, sni_test_ticket_key, sizeof(sni_test_ticket_key)) != 0) {
        DBG_PRINTF("%s", "Ticket key setter blocked by freeze");
        ret = -1;
    }
    if (ret == 0 && picoquic_refresh_tls_certificate(quic, cert_path, key_path) != 0) {
        DBG_PRINTF("%s", "Fallback certificate refresh blocked by freeze");
        ret = -1;
    }

    if (identity != NULL) {
        picoquic_server_identity_release(identity);
    }
    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

/* Teardown safety: a QUIC context with registered, replaced, removed,
 * still-held and in-use identities must be freed without leaks or
 * use-after-free (run under ASan). picoquic_free() releases whatever
 * the application did not. */
int sni_teardown_test(void)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_server_identity_t* held_identity = NULL;
    picoquic_server_identity_t* leaked_identity = NULL;
    uint64_t simulated_time = 0;
    char cert_path[512];
    char key_path[512];

    ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SNI_CERT_ALPHA);
    if (ret == 0) {
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SNI_KEY_ALPHA);
    }
    if (ret == 0) {
        ret = sni_test_ctx_create(&test_ctx, &simulated_time, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_STORE, 0, NULL, 1);
    }
    if (ret == 0) {
        /* Registered and released by the app: only the registry holds it. */
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_ALPHA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA,
            (void*)&sni_test_vhost_alpha, NULL);
    }
    if (ret == 0) {
        /* Registered, then replaced, then removed. */
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_BETA,
            PICOQUIC_TEST_FILE_SNI_CERT_ALPHA, PICOQUIC_TEST_FILE_SNI_KEY_ALPHA, NULL, NULL);
    }
    if (ret == 0) {
        ret = sni_test_register(test_ctx->qserver, SNI_TEST_NAME_BETA,
            PICOQUIC_TEST_FILE_SNI_CERT_BETA, PICOQUIC_TEST_FILE_SNI_KEY_BETA, NULL, NULL);
    }
    if (ret == 0) {
        ret = picoquic_remove_server_identity(test_ctx->qserver, SNI_TEST_NAME_BETA);
    }
    if (ret == 0) {
        /* Held by the app across picoquic_free (released by it). */
        ret = picoquic_server_identity_create(test_ctx->qserver, cert_path, key_path,
            &held_identity);
    }
    if (ret == 0) {
        /* Never registered, never released: picoquic_free cleans up. */
        ret = picoquic_server_identity_create(test_ctx->qserver, cert_path, key_path,
            &leaked_identity);
    }
    if (ret == 0) {
        /* An in-use identity: complete a handshake and keep it open. */
        ret = sni_test_connect(test_ctx, &simulated_time, 1, (void*)&sni_test_vhost_alpha, 0);
    }
    if (ret == 0 && held_identity != NULL) {
        picoquic_server_identity_release(held_identity);
        held_identity = NULL;
    }

    /* Free everything with the connection still established; the
     * leaked_identity handle is intentionally not released. */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}
