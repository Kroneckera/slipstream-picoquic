/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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
#include "picoquictest_internal.h"
#include <stdlib.h>
#ifdef _WINDOWS
#include <malloc.h>
#endif
#include <string.h>

/* 
 * Cnx creation unit test
 * - Create QUIC context
 * - Create a set of connections, with variations:
 * - IPv4 or IPv6 address
 * - Different ports
 * - either no connection ID or a connection ID.
 *
 *  - Verify that all these connections can be retrieved using their
 *    registered attributes.
 *  - Verify that a non registered connection can be retrieved.
 *
 *  - Delete connections first-middle-last.
 *  - Verify that deleted connections cannot be retrieved, and the others can.
 *
 *  - delete QUIC context.
 */

#define TEST_CNX_COUNT 7
#define TEST_CNX_ID(x) {{ x, x, x, x, x, x, x, x, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} , 8 }

int create_cnx_test()
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* test_cnx[TEST_CNX_COUNT] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    struct sockaddr_in test4[5];
    struct sockaddr_in6 test6[3];
    const uint8_t test_ipv4[4] = { 192, 0, 2, 0 };
    const uint8_t test_ipv6[16] = { 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    const uint8_t test_ipv4l[4] = { 127, 0, 0, 1 };
    const uint8_t test_ipv6l[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    picoquic_connection_id_t test_cid[TEST_CNX_COUNT];

    const picoquic_connection_id_t test_cnx_id[TEST_CNX_COUNT] = {
        TEST_CNX_ID(1), TEST_CNX_ID(2), TEST_CNX_ID(3), TEST_CNX_ID(4),
        TEST_CNX_ID(5), TEST_CNX_ID(6), TEST_CNX_ID(7) };

    struct sockaddr* test_cnx_addr[TEST_CNX_COUNT] = {
        (struct sockaddr*)&test4[0],
        (struct sockaddr*)&test4[1],
        (struct sockaddr*)&test4[2],
        (struct sockaddr*)&test4[4],
        (struct sockaddr*)&test6[0],
        (struct sockaddr*)&test6[1],
        (struct sockaddr*)&test6[2]
    };

    /*
     * Initialize the sockaddr values
     */
    for (int i = 0; i < 5; i++) {
        uint8_t* addr = (uint8_t*)&test4[i].sin_addr;
        memset(&test4[i], 0, sizeof(test4[i]));
        test4[i].sin_family = AF_INET;
        if (i < 4) {
            addr[0] = test_ipv4[0];
            addr[1] = test_ipv4[1];
            addr[2] = test_ipv4[2];
            addr[3] = (i == 0) ? 1 : 2;
        }
        else {
            addr[0] = test_ipv4l[0];
            addr[1] = test_ipv4l[1];
            addr[2] = test_ipv4l[2];
            addr[3] = test_ipv4l[3];
        }
        test4[i].sin_port = 1000 + i;
    }

    for (int i = 0; i < 3; i++) {
        uint8_t* addr = (uint8_t*)&test6[i].sin6_addr;
        memset(&test6[i], 0, sizeof(test6[i]));
        test6[i].sin6_family = AF_INET6;
        for (int j = 0; j < 16; j++) {
            if (i < 2) {
                addr[j] = test_ipv6[j];
            }
            else {
                addr[j] = test_ipv6l[j];
            }
        }
        if (i < 2) {
            addr[15] = i + 1;
        }
        test6[i].sin6_port = 1000 + i;
    }

    for (int l = 0; ret == 0 && l < 2; l++) {
        /* Create QUIC context */
        quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        if (quic == NULL) {
            ret = -1;
        }
        else if (l == 0) {
            quic->local_cnxid_length = 0;
        }
        /*
        * Create a set of connections, with variations :
        * -IPv4 or IPv6 address
        * -Different ports
        * -either no connection ID or a connection ID.
        */

        for (int i = 0; ret == 0 && i < TEST_CNX_COUNT; i++) {
            test_cnx[i] = picoquic_create_cnx(quic,
                (quic->local_cnxid_length == 0) ? picoquic_null_connection_id : test_cnx_id[i],
                picoquic_null_connection_id, test_cnx_addr[i], 0, 0, NULL, NULL, 1);
            if (test_cnx[i] == NULL) {
                ret = -1;
            }
            else {
                test_cid[i] = test_cnx[i]->path[0]->p_local_cnxid->cnx_id;
            }
        }

        /*
         *  -Verify that all these connections can be retrieved using their
         *    registered attributes.
         */
        if (quic->local_cnxid_length == 0) {
            for (int i = 0; ret == 0 && i < TEST_CNX_COUNT; i++) {
                picoquic_cnx_t* cnx = picoquic_cnx_by_net(quic, test_cnx_addr[i]);

                if (cnx == NULL) {
                    ret = -1;
                }
            }
        }

        /*
         * Verify that the iterator returns all connections.
         */
        if (ret == 0) {
            int counter = 0;
            for (picoquic_cnx_t* cnx = picoquic_get_first_cnx(quic); cnx != NULL; cnx = picoquic_get_next_cnx(cnx)) {
                counter += 1;
            }

            if (counter != TEST_CNX_COUNT) {
                ret = -1;
            }
        }

        /* TODO: cannot retrieve connections by initial ID yet, should work on it */
        /*
        *  -Verify that a non registered connection cannot be retrieved.
        */

        if (ret == 0) {
            if (quic->local_cnxid_length == 0) {
                picoquic_cnx_t* cnx = picoquic_cnx_by_net(quic, (struct sockaddr*)&test4[3]);
                if (cnx != NULL) {
                    ret = -1;
                }
            }
            else {
                picoquic_connection_id_t bad_target = { { 1,2,3,4,5,6,7,8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 8 };
                picoquic_cnx_t* cnx = picoquic_cnx_by_id(quic, bad_target, NULL);
                if (cnx != NULL) {
                    ret = -1;
                }
            }
        }


        /* Delete connections first - middle - last. */
        for (int i = 0; ret == 0 && i < TEST_CNX_COUNT; i += 2) {
            picoquic_delete_cnx(test_cnx[i]);
            test_cnx[i] = NULL;
        }

        /* Verify that deleted connections cannot be retrieved, and the others can. */
        if (quic->local_cnxid_length == 0) {
            for (int i = 0; ret == 0 && i < TEST_CNX_COUNT; i++) {
                picoquic_cnx_t* cnx = picoquic_cnx_by_net(quic, test_cnx_addr[i]);

                if (cnx != NULL && (i & 1) == 0) {
                    ret = -1;
                }
                else if (cnx == NULL && (i & 1) != 0) {
                    ret = -1;
                }
            }
        }
        else {
            for (int i = 0; ret == 0 && i < TEST_CNX_COUNT; i++) {
                picoquic_cnx_t* cnx = picoquic_cnx_by_id(quic, test_cid[i], NULL);

                if (cnx != NULL && (i & 1) == 0) {
                    ret = -1;
                }
                else if (cnx == NULL && (i & 1) != 0) {
                    ret = -1;
                }
            }
        }

        /* delete QUIC context. */
        if (quic != NULL) {
            picoquic_free(quic);
        }
    }

    return ret;
}

static picoquic_cnx_t* cnx_handle_create_connection(
    picoquic_quic_t* quic,
    uint8_t address_suffix)
{
    struct sockaddr_in addr = { 0 };
    uint8_t* address_bytes = (uint8_t*)&addr.sin_addr;

    addr.sin_family = AF_INET;
    addr.sin_port = 4433;
    address_bytes[0] = 192;
    address_bytes[1] = 0;
    address_bytes[2] = 2;
    address_bytes[3] = address_suffix;
    return picoquic_create_cnx(
        quic, picoquic_null_connection_id, picoquic_null_connection_id,
        (const struct sockaddr*)&addr, 0, 0, NULL, NULL, 1);
}

static picoquic_cnx_t* cnx_handle_create_server_connection(
    picoquic_quic_t* quic,
    picoquic_connection_id_t initial_cid,
    uint8_t address_suffix)
{
    struct sockaddr_in addr = { 0 };
    uint8_t* address_bytes = (uint8_t*)&addr.sin_addr;

    addr.sin_family = AF_INET;
    addr.sin_port = 4433;
    address_bytes[0] = 192;
    address_bytes[1] = 0;
    address_bytes[2] = 2;
    address_bytes[3] = address_suffix;
    return picoquic_create_cnx(
        quic, initial_cid, picoquic_null_connection_id,
        (const struct sockaddr*)&addr, 0, PICOQUIC_V1_VERSION,
        NULL, NULL, 0);
}

static void cnx_failure_fixed_cid_callback(
    picoquic_quic_t* quic,
    picoquic_connection_id_t cnx_id_local,
    picoquic_connection_id_t cnx_id_remote,
    void* callback_context,
    picoquic_connection_id_t* cnx_id_returned)
{
    (void)quic;
    (void)cnx_id_local;
    (void)cnx_id_remote;
    *cnx_id_returned = *(const picoquic_connection_id_t*)callback_context;
}

static int cnx_failure_survivor_is_intact(
    picoquic_quic_t* quic,
    picoquic_cnx_t* survivor,
    picoquic_cnx_handle_t survivor_handle,
    int* state_result)
{
    picoquic_state_enum state = picoquic_state_disconnected;

    *state_result = picoquic_get_cnx_state_by_handle(
        quic, survivor_handle, &state);
    return *state_result == 0 && state == picoquic_get_cnx_state(survivor) &&
        quic->cnx_list == survivor && quic->cnx_last == survivor &&
        quic->current_number_connections == 1 &&
        quic->cnx_wake_tree.size == 1 &&
        picoquic_get_earliest_cnx_to_wake(quic, UINT64_MAX) == survivor;
}

static void cnx_failure_restore_survivor_for_cleanup(
    picoquic_quic_t* quic,
    picoquic_cnx_t* survivor)
{
    quic->cnx_list = survivor;
    quic->cnx_last = survivor;
    quic->current_number_connections = 1;
    survivor->next_in_table = NULL;
    survivor->previous_in_table = NULL;
    survivor->is_in_cnx_list = 1;
    if (quic->cnx_wake_tree.root != &survivor->cnx_wake_node ||
        quic->cnx_wake_tree.size != 1) {
        quic->cnx_wake_tree.root = NULL;
        quic->cnx_wake_tree.size = 0;
        (void)picosplay_insert(&quic->cnx_wake_tree, survivor);
    }
    survivor->is_in_wake_tree = 1;
}

static int cnx_failure_check_expected_create_failure(
    picoquic_quic_t* quic,
    picoquic_cnx_t* survivor,
    picoquic_cnx_handle_t survivor_handle,
    picoquic_cnx_t** failed,
    int* state_result,
    const char* diagnostic)
{
    int failed_was_null = *failed == NULL;
    int survivor_is_intact;

    if (!failed_was_null) {
        picoquic_delete_cnx(*failed);
        *failed = NULL;
    }
    survivor_is_intact = cnx_failure_survivor_is_intact(
        quic, survivor, survivor_handle, state_result);

    if (!failed_was_null || !survivor_is_intact) {
        if (diagnostic != NULL) {
            fprintf(stderr,
                "%s: failed_null=%d state_ret=%d first=%d last=%d "
                "count=%u wake_size=%d earliest=%d\n",
                diagnostic, failed_was_null, *state_result,
                quic->cnx_list == survivor, quic->cnx_last == survivor,
                quic->current_number_connections, quic->cnx_wake_tree.size,
                picoquic_get_earliest_cnx_to_wake(quic, UINT64_MAX) == survivor);
        }
        cnx_failure_restore_survivor_for_cleanup(quic, survivor);
        return -1;
    }
    return 0;
}

static int cnx_failure_unexpected_success_cleanup_case()
{
    int ret = 0;
    int branch_result = 0;
    int state_result = -1;
    int unexpected_state_result = 0;
    picoquic_state_enum state = picoquic_state_disconnected;
    picoquic_quic_t* quic = picoquic_create(
        4, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        0, NULL, NULL, NULL, 0);
    picoquic_cnx_t* survivor = NULL;
    picoquic_cnx_t* unexpected = NULL;
    picoquic_cnx_handle_t survivor_handle = PICOQUIC_CNX_HANDLE_INVALID;
    picoquic_cnx_handle_t unexpected_handle = PICOQUIC_CNX_HANDLE_INVALID;

    if (quic == NULL) {
        return -1;
    }
    survivor = cnx_handle_create_connection(quic, 21);
    unexpected = cnx_handle_create_connection(quic, 22);
    if (survivor == NULL || unexpected == NULL) {
        ret = -1;
    }
    else {
        survivor_handle = picoquic_get_cnx_handle(survivor);
        unexpected_handle = picoquic_get_cnx_handle(unexpected);
        survivor->is_in_cnx_list = 0;
        survivor->is_in_wake_tree = 0;
        branch_result = cnx_failure_check_expected_create_failure(
            quic, survivor, survivor_handle, &unexpected, &state_result,
            NULL);
        unexpected_state_result = picoquic_get_cnx_state_by_handle(
            quic, unexpected_handle, &state);
        if (branch_result == 0 || unexpected != NULL ||
            unexpected_state_result != -1 ||
            !cnx_failure_survivor_is_intact(
                quic, survivor, survivor_handle, &state_result) ||
            !survivor->is_in_cnx_list || !survivor->is_in_wake_tree) {
            fprintf(stderr,
                "Unexpected-success ownership: branch_ret=%d released=%d "
                "unexpected_state_ret=%d state_ret=%d list_member=%u "
                "wake_member=%u\n",
                branch_result, unexpected == NULL, unexpected_state_result,
                state_result, survivor->is_in_cnx_list,
                survivor->is_in_wake_tree);
            ret = -1;
        }
    }
    picoquic_free(quic);
    return ret;
}

int cnx_preinsert_failure_test()
{
    int ret = cnx_failure_unexpected_success_cleanup_case();
    int state_result = -1;
    const picoquic_connection_id_t fixed_cid = TEST_CNX_ID(0x55);
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* survivor = NULL;
    picoquic_cnx_t* failed = NULL;
    picoquic_cnx_handle_t survivor_handle = PICOQUIC_CNX_HANDLE_INVALID;

    if (ret != 0) {
        return ret;
    }
    quic = picoquic_create(
        4, NULL, NULL, NULL, NULL, NULL, NULL,
        cnx_failure_fixed_cid_callback, (void*)&fixed_cid, NULL,
        0, NULL, NULL, NULL, 0);
    if (quic == NULL) {
        return -1;
    }
    survivor = cnx_handle_create_connection(quic, 11);
    if (survivor == NULL) {
        ret = -1;
    }
    else {
        survivor_handle = picoquic_get_cnx_handle(survivor);
        failed = cnx_handle_create_connection(quic, 12);
        if (cnx_failure_check_expected_create_failure(
                quic, survivor, survivor_handle, &failed, &state_result,
                "Pre-insertion create failure") != 0) {
            ret = -1;
        }
    }
    picoquic_free(quic);
    return ret;
}

int cnx_unique_log_failure_test()
{
    int ret = 0;
    int state_result = -1;
    const picoquic_connection_id_t duplicate_icid = TEST_CNX_ID(0x66);
    picoquic_quic_t* quic = picoquic_create(
        4, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        0, NULL, NULL, NULL, 0);
    picoquic_cnx_t* survivor = NULL;
    picoquic_cnx_t* failed = NULL;
    picoquic_cnx_handle_t survivor_handle = PICOQUIC_CNX_HANDLE_INVALID;

    if (quic == NULL) {
        return -1;
    }
    survivor = cnx_handle_create_server_connection(
        quic, duplicate_icid, 13);
    if (survivor == NULL) {
        ret = -1;
    }
    else {
        survivor_handle = picoquic_get_cnx_handle(survivor);
        picoquic_use_unique_log_names(quic, 1);
        failed = cnx_handle_create_server_connection(
            quic, duplicate_icid, 13);
        if (failed != NULL ||
            !cnx_failure_survivor_is_intact(
                quic, survivor, survivor_handle, &state_result)) {
            fprintf(stderr,
                "Unique-log create failure: failed_null=%d state_ret=%d "
                "first=%d last=%d count=%u wake_size=%d earliest=%d\n",
                failed == NULL, state_result, quic->cnx_list == survivor,
                quic->cnx_last == survivor,
                quic->current_number_connections,
                quic->cnx_wake_tree.size,
                picoquic_get_earliest_cnx_to_wake(quic, UINT64_MAX) == survivor);
            ret = -1;
        }
    }
    picoquic_free(quic);
    return ret;
}

int cnx_handle_test()
{
    int ret = 0;
    picoquic_quic_t* quic = picoquic_create(
        8, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        0, NULL, NULL, NULL, 0);
    picoquic_cnx_t* cnx1 = NULL;
    picoquic_cnx_t* cnx2 = NULL;
    picoquic_cnx_t* replacement = NULL;
    picoquic_cnx_handle_t handle1 = PICOQUIC_CNX_HANDLE_INVALID;
    picoquic_cnx_handle_t handle2 = PICOQUIC_CNX_HANDLE_INVALID;
    picoquic_cnx_handle_t replacement_handle = PICOQUIC_CNX_HANDLE_INVALID;
    picoquic_state_enum state = picoquic_state_disconnected;

    if (quic == NULL) {
        return -1;
    }
    cnx1 = cnx_handle_create_connection(quic, 1);
    cnx2 = cnx_handle_create_connection(quic, 2);
    if (cnx1 == NULL || cnx2 == NULL) {
        ret = -1;
    }
    else {
        handle1 = picoquic_get_cnx_handle(cnx1);
        handle2 = picoquic_get_cnx_handle(cnx2);
        if (handle1 != 1 || handle2 != 2 || handle1 == handle2 ||
            picoquic_get_cnx_state_by_handle(quic, handle1, &state) != 0 ||
            state != picoquic_get_cnx_state(cnx1)) {
            ret = -1;
        }
    }

    if (ret == 0) {
        picoquic_local_cnxid_t* retired = cnx1->path[0]->p_local_cnxid;
        picoquic_local_cnxid_t* alternate = picoquic_create_local_cnxid(
            cnx1, retired->path_id, NULL, 1);
        picoquic_connection_id_t retired_id = retired->cnx_id;
        uint64_t retired_path_id = retired->path_id;
        uint64_t retired_sequence = retired->sequence;

        if (alternate == NULL || alternate->registered_cnx != cnx1) {
            ret = -1;
        }
        else {
            picoquic_connection_id_t alternate_id = alternate->cnx_id;
            picoquic_retire_local_cnxid(
                cnx1, retired_path_id, retired_sequence);
            if (picoquic_cnx_by_id_(quic, retired_id) != NULL ||
                picoquic_cnx_by_id_(quic, alternate_id) != cnx1 ||
                picoquic_get_cnx_state_by_handle(quic, handle1, &state) != 0 ||
                state != picoquic_get_cnx_state(cnx1)) {
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        cnx1->cnx_state = picoquic_state_ready;
        if (picoquic_close(cnx1, 0) != 0 ||
            picoquic_get_cnx_state_by_handle(quic, handle1, &state) != 0 ||
            state != picoquic_state_disconnecting) {
            ret = -1;
        }
    }

    if (ret == 0) {
        picoquic_delete_cnx(cnx1);
        cnx1 = NULL;
        state = picoquic_state_ready;
        if (picoquic_get_cnx_state_by_handle(quic, handle1, &state) != -1 ||
            state != picoquic_state_ready) {
            ret = -1;
        }
    }

    if (ret == 0) {
        replacement = cnx_handle_create_connection(quic, 3);
        replacement_handle = picoquic_get_cnx_handle(replacement);
        if (replacement == NULL || replacement_handle != 3 ||
            replacement_handle == handle1 || replacement_handle == handle2 ||
            picoquic_get_cnx_state_by_handle(quic, handle1, &state) != -1 ||
            picoquic_get_cnx_state_by_handle(
                quic, replacement_handle, &state) != 0 ||
            state != picoquic_get_cnx_state(replacement)) {
            ret = -1;
        }
    }

    if (ret == 0) {
        state = picoquic_state_ready;
        if (picoquic_get_cnx_handle(NULL) != PICOQUIC_CNX_HANDLE_INVALID ||
            picoquic_get_cnx_state_by_handle(
                quic, PICOQUIC_CNX_HANDLE_INVALID, &state) != -1 ||
            state != picoquic_state_ready ||
            picoquic_get_cnx_state_by_handle(quic, 42, &state) != -1 ||
            state != picoquic_state_ready ||
            picoquic_get_cnx_state_by_handle(NULL, handle2, &state) != -1 ||
            state != picoquic_state_ready ||
            picoquic_get_cnx_state_by_handle(quic, handle2, NULL) != -1) {
            ret = -1;
        }
    }

    picoquic_free(quic);

    if (ret == 0) {
        const picoquic_connection_id_t duplicate_icid = TEST_CNX_ID(0x44);
        picoquic_cnx_t* registered_server;
        picoquic_cnx_t* failed_duplicate;
        picoquic_cnx_t* after_failure;

        quic = picoquic_create(
            4, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            0, NULL, NULL, NULL, 0);
        if (quic == NULL) {
            ret = -1;
        }
        else {
            registered_server = cnx_handle_create_server_connection(
                quic, duplicate_icid, 9);
            failed_duplicate = cnx_handle_create_server_connection(
                quic, duplicate_icid, 9);
            after_failure = cnx_handle_create_connection(quic, 10);
            if (registered_server == NULL ||
                picoquic_get_cnx_handle(registered_server) != 1 ||
                failed_duplicate != NULL || quic->next_cnx_handle != 4 ||
                after_failure == NULL ||
                picoquic_get_cnx_handle(after_failure) != 3 ||
                picoquic_get_cnx_state_by_handle(quic, 2, &state) != -1 ||
                picoquic_get_cnx_state_by_handle(quic, 3, &state) != 0 ||
                state != picoquic_get_cnx_state(after_failure)) {
                ret = -1;
            }
            picoquic_free(quic);
        }
    }

    if (ret == 0) {
        picoquic_cnx_t* max_cnx;
        quic = picoquic_create(
            4, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            0, NULL, NULL, NULL, 0);
        if (quic == NULL) {
            ret = -1;
        }
        else {
            quic->next_cnx_handle = UINT64_MAX;
            max_cnx = cnx_handle_create_connection(quic, 4);
            if (max_cnx == NULL ||
                picoquic_get_cnx_handle(max_cnx) != UINT64_MAX ||
                quic->next_cnx_handle != PICOQUIC_CNX_HANDLE_INVALID) {
                ret = -1;
            }
            else {
                picoquic_delete_cnx(max_cnx);
                for (int i = 0; ret == 0 && i < 3; i++) {
                    if (cnx_handle_create_connection(
                            quic, (uint8_t)(5 + i)) != NULL ||
                        quic->next_cnx_handle != PICOQUIC_CNX_HANDLE_INVALID) {
                        ret = -1;
                    }
                }
            }
            picoquic_free(quic);
        }
    }

    return ret;
}

static void prepare_by_unique_path_id_clear_misc_frames(picoquic_cnx_t* cnx)
{
    while (cnx->first_misc_frame != NULL) {
        picoquic_delete_misc_or_dg(
            &cnx->first_misc_frame, &cnx->last_misc_frame,
            cnx->first_misc_frame);
    }
}

static void prepare_by_unique_path_id_clear_datagrams(picoquic_cnx_t* cnx)
{
    while (cnx->first_datagram != NULL) {
        picoquic_delete_misc_or_dg(
            &cnx->first_datagram, &cnx->last_datagram,
            cnx->first_datagram);
    }
}

static int prepare_by_unique_path_id_has_abandon_frame(
    picoquic_cnx_t* cnx, uint64_t unique_path_id)
{
    int has_abandon_frame = 0;

    if (cnx->first_misc_frame != NULL) {
        const uint8_t* frame_bytes =
            ((const uint8_t*)cnx->first_misc_frame) +
            sizeof(picoquic_misc_frame_header_t);
        const uint8_t* frame_bytes_max = frame_bytes +
            cnx->first_misc_frame->length;
        uint64_t frame_type = 0;
        uint64_t frame_path_id = UINT64_MAX;
        frame_bytes = picoquic_frames_varint_decode(
            frame_bytes, frame_bytes_max, &frame_type);
        if (frame_bytes != NULL) {
            frame_bytes = picoquic_frames_varint_decode(
                frame_bytes, frame_bytes_max, &frame_path_id);
        }
        has_abandon_frame = frame_bytes != NULL &&
            frame_type == picoquic_frame_type_path_abandon &&
            frame_path_id == unique_path_id;
    }

    return has_abandon_frame;
}

typedef enum {
    prepare_unique_callback_queue_datagram = 0,
    prepare_unique_callback_set_app_wake,
    prepare_unique_callback_reinsert
} prepare_unique_callback_action_t;

typedef struct st_prepare_unique_callback_ctx_t {
    picoquic_stream_data_cb_fn previous_callback;
    void* previous_callback_ctx;
    prepare_unique_callback_action_t action;
    uint64_t wake_time;
    int path_deleted_count;
    int action_ret;
    uint64_t generation_before_action;
    uint64_t generation_after_action;
} prepare_unique_callback_ctx_t;

typedef struct st_prepare_unique_fixture_t {
    picoquic_test_tls_api_ctx_t* test_ctx;
    picoquic_cnx_t* cnx;
    uint64_t simulated_time;
    uint64_t path_id;
    prepare_unique_callback_ctx_t callback_ctx;
    int callbacks_installed;
    int path_callbacks_were_enabled;
} prepare_unique_fixture_t;

static int prepare_unique_path_deleted_callback(
    picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes,
    size_t length, picoquic_call_back_event_t fin_or_event,
    void* callback_ctx, void* stream_ctx)
{
    prepare_unique_callback_ctx_t* ctx =
        (prepare_unique_callback_ctx_t*)callback_ctx;

    if (fin_or_event == picoquic_callback_path_deleted) {
        const uint8_t datagram_bytes[4] = { 0xd0, 0xd1, 0xd2, 0xd3 };

        ctx->path_deleted_count++;
        ctx->generation_before_action = cnx->wake_generation;
        switch (ctx->action) {
        case prepare_unique_callback_queue_datagram:
            ctx->action_ret = picoquic_queue_datagram_frame(
                cnx, sizeof(datagram_bytes), datagram_bytes);
            break;
        case prepare_unique_callback_set_app_wake:
            picoquic_set_app_wake_time(cnx, ctx->wake_time);
            ctx->action_ret = 0;
            break;
        case prepare_unique_callback_reinsert:
            picoquic_reinsert_by_wake_time(
                cnx->quic, cnx, ctx->wake_time);
            ctx->action_ret = 0;
            break;
        default:
            ctx->action_ret = -1;
            break;
        }
        ctx->generation_after_action = cnx->wake_generation;
        return ctx->action_ret;
    }

    if (ctx->previous_callback != NULL) {
        return ctx->previous_callback(
            cnx, stream_id, bytes, length, fin_or_event,
            ctx->previous_callback_ctx, stream_ctx);
    }
    return 0;
}

static int prepare_unique_fixture_init(prepare_unique_fixture_t* fixture)
{
    uint64_t loss_mask = 0;
    int ret;

    memset(fixture, 0, sizeof(*fixture));
    ret = tls_api_init_ctx(
        &fixture->test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN,
        &fixture->simulated_time, NULL, NULL, 0, 0, 0);
    if (ret == 0) {
        ret = tls_api_connection_loop(
            fixture->test_ctx, &loss_mask, 0,
            &fixture->simulated_time);
    }
    if (ret == 0) {
        fixture->cnx = fixture->test_ctx->cnx_client;
        if (fixture->cnx == NULL ||
            (fixture->cnx->cnx_state != picoquic_state_ready &&
             fixture->cnx->cnx_state != picoquic_state_client_ready_start)) {
            ret = -1;
        }
    }
    if (ret == 0) {
        fixture->cnx->is_multipath_enabled = 1;
        fixture->cnx->remote_parameters.max_datagram_frame_size =
            PICOQUIC_MAX_PACKET_SIZE;
        fixture->cnx->app_wake_time = 0;
        fixture->cnx->is_lost_feedback_notification_required = 0;
        prepare_by_unique_path_id_clear_misc_frames(fixture->cnx);
        prepare_by_unique_path_id_clear_datagrams(fixture->cnx);
    }
    return ret;
}

static int prepare_unique_fixture_create_path(
    prepare_unique_fixture_t* fixture)
{
    struct sockaddr_in peer;
    struct sockaddr_in local;
    int path_index;

    memset(&peer, 0, sizeof(peer));
    memset(&local, 0, sizeof(local));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(7301);
    peer.sin_addr.s_addr = htonl(0x7f000081u);
    local.sin_family = AF_INET;
    local.sin_port = htons(47001);
    local.sin_addr.s_addr = htonl(0x7f000082u);
    path_index = picoquic_create_path(
        fixture->cnx, fixture->simulated_time,
        (const struct sockaddr*)&local,
        (const struct sockaddr*)&peer, 31);
    if (path_index != 1) {
        DBG_PRINTF("Wake fixture path index is %d, expected 1",
            path_index);
        return -1;
    }
    fixture->path_id =
        fixture->cnx->path[path_index]->unique_path_id;
    return 0;
}

static void prepare_unique_fixture_delete(
    prepare_unique_fixture_t* fixture)
{
    if (fixture->callbacks_installed && fixture->cnx != NULL) {
        picoquic_set_callback(
            fixture->cnx, fixture->callback_ctx.previous_callback,
            fixture->callback_ctx.previous_callback_ctx);
        picoquic_enable_path_callbacks(
            fixture->cnx, fixture->path_callbacks_were_enabled);
    }
    if (fixture->test_ctx != NULL) {
        tls_api_delete_ctx(fixture->test_ctx);
    }
}

static void prepare_unique_fixture_install_callback(
    prepare_unique_fixture_t* fixture,
    prepare_unique_callback_action_t action, uint64_t wake_time)
{
    fixture->callback_ctx.previous_callback =
        picoquic_get_callback_function(fixture->cnx);
    fixture->callback_ctx.previous_callback_ctx =
        picoquic_get_callback_context(fixture->cnx);
    fixture->callback_ctx.action = action;
    fixture->callback_ctx.wake_time = wake_time;
    fixture->callback_ctx.path_deleted_count = 0;
    fixture->callback_ctx.action_ret = 0;
    fixture->callback_ctx.generation_before_action = 0;
    fixture->callback_ctx.generation_after_action = 0;
    fixture->path_callbacks_were_enabled =
        fixture->cnx->are_path_callbacks_enabled;
    picoquic_set_callback(
        fixture->cnx, prepare_unique_path_deleted_callback,
        &fixture->callback_ctx);
    picoquic_enable_path_callbacks(fixture->cnx, 1);
    fixture->callbacks_installed = 1;
}

static int prepare_unique_fixture_arm_path_delete(
    prepare_unique_fixture_t* fixture)
{
    int path_index = picoquic_find_path_by_unique_id(
        fixture->cnx, fixture->path_id);

    if (path_index <= 0 || path_index >= fixture->cnx->nb_paths) {
        return -1;
    }
    fixture->cnx->path[path_index]->path_is_demoted = 1;
    fixture->cnx->path[path_index]->demotion_time =
        fixture->simulated_time;
    fixture->cnx->path_demotion_needed = 1;
    return 0;
}

static int prepare_unique_fixture_prepare(
    prepare_unique_fixture_t* fixture, uint64_t unique_path_id,
    size_t* send_length)
{
    struct sockaddr_storage addr_to;
    struct sockaddr_storage addr_from;
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    size_t send_msg_size = 0;
    int if_index = 0;

    *send_length = 17;
    return picoquic_prepare_packet_by_unique_path_id(
        fixture->cnx, unique_path_id, fixture->simulated_time,
        send_buffer, sizeof(send_buffer), send_length,
        &addr_to, &addr_from, &if_index, &send_msg_size);
}

static int prepare_unique_fixture_prepare_ordinary(
    prepare_unique_fixture_t* fixture, size_t* send_length)
{
    struct sockaddr_storage addr_to;
    struct sockaddr_storage addr_from;
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    int if_index = 0;

    *send_length = 17;
    return picoquic_prepare_packet(
        fixture->cnx, fixture->simulated_time,
        send_buffer, sizeof(send_buffer), send_length,
        &addr_to, &addr_from, &if_index);
}

static int prepare_unique_fixture_settle_initial_output(
    prepare_unique_fixture_t* fixture)
{
    size_t send_length = 0;
    int ret = 0;

    for (int i = 0; ret == 0 && i < 8; i++) {
        ret = prepare_unique_fixture_prepare_ordinary(
            fixture, &send_length);
        if (ret == 0 && send_length == 0 &&
            fixture->cnx->next_wake_time > fixture->simulated_time) {
            return 0;
        }
    }
    DBG_PRINTF("Could not settle initial output: ret=%d, length=%zu, wake=%" PRIu64 "/%" PRIu64,
        ret, send_length, fixture->cnx->next_wake_time,
        fixture->simulated_time);
    return -1;
}

static int prepare_unique_fixture_consume_due_wake(
    prepare_unique_fixture_t* fixture)
{
    const uint8_t datagram_bytes[3] = { 0xc0, 0xc1, 0xc2 };
    size_t send_length = 0;
    int ret = prepare_unique_fixture_settle_initial_output(fixture);

    if (ret == 0) {
        ret = picoquic_queue_datagram_frame(
            fixture->cnx, sizeof(datagram_bytes), datagram_bytes);
    }

    if (ret == 0) {
        ret = prepare_unique_fixture_prepare_ordinary(
            fixture, &send_length);
    }
    if (ret != 0 || send_length == 0 ||
        fixture->cnx->first_datagram != NULL ||
        fixture->cnx->last_datagram != NULL ||
        fixture->cnx->next_wake_time != fixture->simulated_time) {
        DBG_PRINTF("Could not consume fixture wake: ret=%d, length=%zu, queue=%d/%d, wake=%" PRIu64 "/%" PRIu64,
            ret, send_length, fixture->cnx->first_datagram != NULL,
            fixture->cnx->last_datagram != NULL,
            fixture->cnx->next_wake_time, fixture->simulated_time);
        ret = -1;
    }
    return ret;
}

static int prepare_unique_callback_datagram_case()
{
    prepare_unique_fixture_t fixture;
    size_t reject_length = 0;
    size_t drain_length = 0;
    size_t settle_length = 0;
    uint64_t reject_wake = 0;
    int reject_misc = 0;
    int reject_datagram = 0;
    int reject_earliest = 0;
    int reject_ret = 0;
    int drain_ret = 0;
    int settle_ret = 0;
    int ret = prepare_unique_fixture_init(&fixture);

    if (ret == 0) {
        ret = prepare_unique_fixture_consume_due_wake(&fixture);
    }
    if (ret == 0) {
        ret = prepare_unique_fixture_create_path(&fixture);
    }
    if (ret == 0) {
        prepare_unique_fixture_install_callback(
            &fixture, prepare_unique_callback_queue_datagram, 0);
        ret = prepare_unique_fixture_arm_path_delete(&fixture);
    }
    if (ret == 0) {
        reject_ret = prepare_unique_fixture_prepare(
            &fixture, fixture.path_id, &reject_length);
        reject_wake = fixture.cnx->next_wake_time;
        reject_misc = fixture.cnx->first_misc_frame != NULL;
        reject_datagram = fixture.cnx->first_datagram != NULL;
        reject_earliest = picoquic_get_earliest_cnx_to_wake(
            fixture.cnx->quic, fixture.simulated_time) == fixture.cnx;
        drain_ret = prepare_unique_fixture_prepare_ordinary(
            &fixture, &drain_length);
        settle_ret = prepare_unique_fixture_prepare_ordinary(
            &fixture, &settle_length);
        if (reject_ret != PICOQUIC_ERROR_PATH_ID_INVALID ||
            reject_length != 0 ||
            fixture.callback_ctx.path_deleted_count != 1 ||
            fixture.callback_ctx.action_ret != 0 ||
            fixture.callback_ctx.generation_before_action ==
                fixture.callback_ctx.generation_after_action ||
            reject_misc || !reject_datagram ||
            reject_wake != fixture.simulated_time || !reject_earliest ||
            drain_ret != 0 || drain_length == 0 ||
            fixture.cnx->first_datagram != NULL ||
            settle_ret != 0 || settle_length != 0 ||
            fixture.cnx->next_wake_time <= fixture.simulated_time) {
            DBG_PRINTF("Deleted-path datagram drain invalid: reject=%d/%zu/%" PRIu64 "/%d/%d/%d, callback=%d/%d/%" PRIu64 "/%" PRIu64 ", drain=%d/%zu, settle=%d/%zu, datagram=%d, final_wake=%" PRIu64 "/%" PRIu64,
                reject_ret, reject_length,
                reject_wake, reject_misc, reject_datagram,
                reject_earliest,
                fixture.callback_ctx.path_deleted_count,
                fixture.callback_ctx.action_ret,
                fixture.callback_ctx.generation_before_action,
                fixture.callback_ctx.generation_after_action,
                drain_ret, drain_length, settle_ret, settle_length,
                fixture.cnx->first_datagram != NULL,
                fixture.cnx->next_wake_time, fixture.simulated_time);
            ret = -1;
        }
    }
    prepare_unique_fixture_delete(&fixture);
    return ret;
}

static int prepare_unique_callback_reinsert_case(uint64_t wake_delta)
{
    prepare_unique_fixture_t fixture;
    size_t send_length = 0;
    int prepare_ret = 0;
    int ret = prepare_unique_fixture_init(&fixture);

    if (ret == 0) {
        ret = prepare_unique_fixture_consume_due_wake(&fixture);
    }
    if (ret == 0) {
        ret = prepare_unique_fixture_create_path(&fixture);
    }
    if (ret == 0) {
        uint64_t callback_wake = fixture.simulated_time + wake_delta;
        prepare_unique_fixture_install_callback(
            &fixture, prepare_unique_callback_reinsert, callback_wake);
        ret = prepare_unique_fixture_arm_path_delete(&fixture);
        if (ret == 0) {
            prepare_ret = prepare_unique_fixture_prepare(
                &fixture, fixture.path_id, &send_length);
            if (prepare_ret != PICOQUIC_ERROR_PATH_ID_INVALID ||
                send_length != 0 ||
                fixture.callback_ctx.path_deleted_count != 1 ||
                fixture.callback_ctx.action_ret != 0 ||
                fixture.callback_ctx.generation_before_action ==
                    fixture.callback_ctx.generation_after_action ||
                fixture.cnx->first_misc_frame != NULL ||
                fixture.cnx->first_datagram != NULL ||
                fixture.cnx->next_wake_time != callback_wake ||
                picoquic_get_earliest_cnx_to_wake(
                    fixture.cnx->quic, callback_wake) != fixture.cnx) {
                DBG_PRINTF("Deleted-path reinsert delayed: delta=%" PRIu64 ", ret=%d/%zu, callback=%d/%d/%" PRIu64 "/%" PRIu64 ", wake=%" PRIu64 "/%" PRIu64 ", queue=%d/%d",
                    wake_delta, prepare_ret, send_length,
                    fixture.callback_ctx.path_deleted_count,
                    fixture.callback_ctx.action_ret,
                    fixture.callback_ctx.generation_before_action,
                    fixture.callback_ctx.generation_after_action,
                    fixture.cnx->next_wake_time, callback_wake,
                    fixture.cnx->first_misc_frame != NULL,
                    fixture.cnx->first_datagram != NULL);
                ret = -1;
            }
        }
    }
    prepare_unique_fixture_delete(&fixture);
    return ret;
}

static int prepare_unique_callback_app_wake_case()
{
    prepare_unique_fixture_t fixture;
    size_t send_length = 0;
    int prepare_ret = 0;
    int ret = prepare_unique_fixture_init(&fixture);

    if (ret == 0) {
        ret = prepare_unique_fixture_consume_due_wake(&fixture);
    }
    if (ret == 0) {
        ret = prepare_unique_fixture_create_path(&fixture);
    }
    if (ret == 0) {
        uint64_t app_wake = fixture.simulated_time + 10000;
        prepare_unique_fixture_install_callback(
            &fixture, prepare_unique_callback_set_app_wake, app_wake);
        ret = prepare_unique_fixture_arm_path_delete(&fixture);
        if (ret == 0) {
            prepare_ret = prepare_unique_fixture_prepare(
                &fixture, fixture.path_id, &send_length);
            if (prepare_ret != PICOQUIC_ERROR_PATH_ID_INVALID ||
                send_length != 0 ||
                fixture.callback_ctx.path_deleted_count != 1 ||
                fixture.callback_ctx.action_ret != 0 ||
                fixture.callback_ctx.generation_before_action !=
                    fixture.callback_ctx.generation_after_action ||
                fixture.cnx->app_wake_time != app_wake ||
                fixture.cnx->next_wake_time != app_wake ||
                picoquic_get_earliest_cnx_to_wake(
                    fixture.cnx->quic, app_wake) != fixture.cnx ||
                fixture.cnx->first_misc_frame != NULL ||
                fixture.cnx->first_datagram != NULL ||
                fixture.cnx->wake_generation_at_last_prepare !=
                    fixture.cnx->wake_generation) {
                DBG_PRINTF("Deleted-path app wake delayed: ret=%d/%zu, callback=%d/%d/%" PRIu64 "/%" PRIu64 ", app=%" PRIu64 "/%" PRIu64 ", wake=%" PRIu64 ", queue=%d/%d, generation=%" PRIu64 "/%" PRIu64,
                    prepare_ret, send_length,
                    fixture.callback_ctx.path_deleted_count,
                    fixture.callback_ctx.action_ret,
                    fixture.callback_ctx.generation_before_action,
                    fixture.callback_ctx.generation_after_action,
                    fixture.cnx->app_wake_time, app_wake,
                    fixture.cnx->next_wake_time,
                    fixture.cnx->first_misc_frame != NULL,
                    fixture.cnx->first_datagram != NULL,
                    fixture.cnx->wake_generation_at_last_prepare,
                    fixture.cnx->wake_generation);
                ret = -1;
            }
        }
    }
    prepare_unique_fixture_delete(&fixture);
    return ret;
}

static int prepare_unique_future_entry_wake_case()
{
    prepare_unique_fixture_t fixture;
    size_t send_length = 0;
    int prepare_ret = 0;
    int ret = prepare_unique_fixture_init(&fixture);

    if (ret == 0) {
        ret = prepare_unique_fixture_consume_due_wake(&fixture);
    }
    if (ret == 0) {
        ret = prepare_unique_fixture_create_path(&fixture);
    }
    if (ret == 0) {
        uint64_t future_wake = fixture.simulated_time + 20000;
        picoquic_enable_path_callbacks(fixture.cnx, 0);
        picoquic_reinsert_by_wake_time(
            fixture.cnx->quic, fixture.cnx, future_wake);
        ret = prepare_unique_fixture_arm_path_delete(&fixture);
        if (ret == 0) {
            prepare_ret = prepare_unique_fixture_prepare(
                &fixture, fixture.path_id, &send_length);
            if (prepare_ret != PICOQUIC_ERROR_PATH_ID_INVALID ||
                send_length != 0 ||
                fixture.cnx->next_wake_time != future_wake ||
                picoquic_get_earliest_cnx_to_wake(
                    fixture.cnx->quic, future_wake) != fixture.cnx ||
                fixture.cnx->first_misc_frame != NULL ||
                fixture.cnx->first_datagram != NULL ||
                fixture.cnx->wake_generation_at_last_prepare !=
                    fixture.cnx->wake_generation) {
                DBG_PRINTF("Future entry wake lost: ret=%d/%zu, wake=%" PRIu64 "/%" PRIu64 ", queue=%d/%d, generation=%" PRIu64 "/%" PRIu64,
                    prepare_ret, send_length,
                    fixture.cnx->next_wake_time, future_wake,
                    fixture.cnx->first_misc_frame != NULL,
                    fixture.cnx->first_datagram != NULL,
                    fixture.cnx->wake_generation_at_last_prepare,
                    fixture.cnx->wake_generation);
                ret = -1;
            }
        }
    }
    prepare_unique_fixture_delete(&fixture);
    return ret;
}

static int prepare_unique_preentry_abandon_case()
{
    const uint8_t remote_cid_bytes[8] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7
    };
    const uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE] = { 4 };
    prepare_unique_fixture_t fixture;
    picoquic_remote_cnxid_t* remote_cnxid = NULL;
    size_t reject_length = 0;
    size_t drain_length = 0;
    size_t settle_length = 0;
    int reject_ret = 0;
    int drain_ret = 0;
    int settle_ret = 0;
    int ret = prepare_unique_fixture_init(&fixture);

    if (ret == 0) {
        ret = prepare_unique_fixture_consume_due_wake(&fixture);
    }
    if (ret == 0) {
        ret = prepare_unique_fixture_create_path(&fixture);
    }
    if (ret == 0) {
        int path_index = picoquic_find_path_by_unique_id(
            fixture.cnx, fixture.path_id);
        if (path_index != 1 || picoquic_stash_remote_cnxid(
                fixture.cnx, 0, fixture.path_id, 0,
                sizeof(remote_cid_bytes), remote_cid_bytes,
                reset_secret, &remote_cnxid) != 0 ||
            remote_cnxid == NULL) {
            ret = -1;
        }
        else {
            fixture.cnx->path[path_index]->p_remote_cnxid = remote_cnxid;
            remote_cnxid->nb_path_references++;
            picoquic_demote_path(
                fixture.cnx, path_index, fixture.simulated_time, 0, NULL);
            fixture.cnx->path[path_index]->demotion_time =
                fixture.simulated_time;
            if (!prepare_by_unique_path_id_has_abandon_frame(
                    fixture.cnx, fixture.path_id) ||
                fixture.cnx->next_wake_time != fixture.simulated_time) {
                ret = -1;
            }
        }
    }
    if (ret == 0) {
        reject_ret = prepare_unique_fixture_prepare(
            &fixture, fixture.path_id, &reject_length);
        int reject_wake_ok =
            fixture.cnx->next_wake_time == fixture.simulated_time &&
            picoquic_get_earliest_cnx_to_wake(
                fixture.cnx->quic, fixture.simulated_time) == fixture.cnx;
        drain_ret = prepare_unique_fixture_prepare_ordinary(
            &fixture, &drain_length);
        int abandon_drained = fixture.cnx->first_misc_frame == NULL;
        settle_ret = prepare_unique_fixture_prepare_ordinary(
            &fixture, &settle_length);
        if (reject_ret != PICOQUIC_ERROR_PATH_ID_INVALID ||
            reject_length != 0 || !reject_wake_ok ||
            drain_ret != 0 || drain_length == 0 || !abandon_drained ||
            settle_ret != 0 || settle_length != 0 ||
            fixture.cnx->next_wake_time <= fixture.simulated_time) {
            DBG_PRINTF("Pre-entry abandon replay invalid: reject=%d/%zu/%d, drain=%d/%zu/%d, settle=%d/%zu, wake=%" PRIu64 "/%" PRIu64,
                reject_ret, reject_length, reject_wake_ok,
                drain_ret, drain_length, abandon_drained,
                settle_ret, settle_length,
                fixture.cnx->next_wake_time, fixture.simulated_time);
            ret = -1;
        }
    }
    prepare_unique_fixture_delete(&fixture);
    return ret;
}

static int prepare_unique_two_connection_wake_tree_case()
{
    picoquic_connection_id_t cid[2] = {
        { { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 }, 8 },
        { { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 }, 8 }
    };
    struct sockaddr_in addr[2];
    picoquic_quic_t* quic = picoquic_create(
        8, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        0, NULL, NULL, NULL, 0);
    picoquic_cnx_t* cnx[2] = { NULL, NULL };
    int ret = quic == NULL ? -1 : 0;

    memset(addr, 0, sizeof(addr));
    for (int i = 0; i < 2; i++) {
        addr[i].sin_family = AF_INET;
        addr[i].sin_port = htons((uint16_t)(7400 + i));
        addr[i].sin_addr.s_addr = htonl(0x7f000091u + (uint32_t)i);
        if (ret == 0) {
            cnx[i] = picoquic_create_cnx(
                quic, cid[i], picoquic_null_connection_id,
                (const struct sockaddr*)&addr[i],
                (uint64_t)(100 + i), 0, NULL, NULL, 1);
            if (cnx[i] == NULL) {
                ret = -1;
            }
        }
    }
    if (ret == 0) {
        uint64_t generation_0 = cnx[0]->wake_generation;
        uint64_t generation_1 = cnx[1]->wake_generation;
        picoquic_reinsert_by_wake_time(quic, cnx[0], 200);
        picoquic_reinsert_by_wake_time(quic, cnx[1], 100);
        if (quic->cnx_wake_tree.size != 2 ||
            picoquic_get_earliest_cnx_to_wake(quic, 0) != cnx[1] ||
            cnx[0]->wake_generation != generation_0 + 1 ||
            cnx[1]->wake_generation != generation_1 + 1) {
            ret = -1;
        }
    }
    if (ret == 0) {
        picoquic_reinsert_by_wake_time(quic, cnx[0], 50);
        if (quic->cnx_wake_tree.size != 2 ||
            picoquic_get_earliest_cnx_to_wake(quic, 0) != cnx[0]) {
            ret = -1;
        }
    }
    if (ret != 0 && quic != NULL) {
        DBG_PRINTF("Two-connection wake tree invalid: size=%d, earliest=%p, cnx=%p/%p",
            quic->cnx_wake_tree.size,
            (void*)picoquic_get_earliest_cnx_to_wake(quic, 0),
            (void*)cnx[0], (void*)cnx[1]);
    }
    if (quic != NULL) {
        picoquic_free(quic);
    }
    return ret;
}

static int prepare_unique_generation_wrap_case()
{
    prepare_unique_fixture_t fixture;
    size_t send_length = 0;
    int prepare_ret = 0;
    int ret = prepare_unique_fixture_init(&fixture);

    if (ret == 0) {
        ret = prepare_unique_fixture_consume_due_wake(&fixture);
    }
    if (ret == 0) {
        ret = prepare_unique_fixture_create_path(&fixture);
    }
    if (ret == 0) {
        prepare_unique_fixture_install_callback(
            &fixture, prepare_unique_callback_reinsert,
            fixture.simulated_time);
        ret = prepare_unique_fixture_arm_path_delete(&fixture);
    }
    if (ret == 0) {
        fixture.cnx->wake_generation = UINT64_MAX;
        fixture.cnx->wake_generation_at_last_prepare = UINT64_MAX;
        prepare_ret = prepare_unique_fixture_prepare(
            &fixture, fixture.path_id, &send_length);
        if (prepare_ret != PICOQUIC_ERROR_PATH_ID_INVALID ||
            send_length != 0 ||
            fixture.callback_ctx.path_deleted_count != 1 ||
            fixture.callback_ctx.action_ret != 0 ||
            fixture.callback_ctx.generation_before_action != UINT64_MAX ||
            fixture.callback_ctx.generation_after_action != 0 ||
            fixture.cnx->next_wake_time != fixture.simulated_time ||
            fixture.cnx->wake_generation != 1 ||
            fixture.cnx->wake_generation_at_last_prepare != 1) {
            DBG_PRINTF("Wake generation wrap invalid: ret=%d/%zu, callback=%d/%d, callback_generation=%" PRIu64 "/%" PRIu64 ", final=%" PRIu64 "/%" PRIu64 ", wake=%" PRIu64 "/%" PRIu64,
                prepare_ret, send_length,
                fixture.callback_ctx.path_deleted_count,
                fixture.callback_ctx.action_ret,
                fixture.callback_ctx.generation_before_action,
                fixture.callback_ctx.generation_after_action,
                fixture.cnx->wake_generation,
                fixture.cnx->wake_generation_at_last_prepare,
                fixture.cnx->next_wake_time, fixture.simulated_time);
            ret = -1;
        }
    }
    prepare_unique_fixture_delete(&fixture);
    return ret;
}

static int prepare_unique_wake_reconciliation_cases()
{
    int ret = 0;

    if (prepare_unique_callback_datagram_case() != 0) {
        ret = -1;
    }
    if (prepare_unique_callback_reinsert_case(0) != 0) {
        ret = -1;
    }
    if (prepare_unique_callback_reinsert_case(1000) != 0) {
        ret = -1;
    }
    if (prepare_unique_callback_app_wake_case() != 0) {
        ret = -1;
    }
    if (prepare_unique_future_entry_wake_case() != 0) {
        ret = -1;
    }
    if (prepare_unique_preentry_abandon_case() != 0) {
        ret = -1;
    }
    if (prepare_unique_two_connection_wake_tree_case() != 0) {
        ret = -1;
    }
    if (prepare_unique_generation_wrap_case() != 0) {
        ret = -1;
    }
    return ret;
}

static int prepare_by_unique_path_id_case(int probe_nat)
{
    const uint8_t normal_remote_cid[8] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    const uint8_t nat_remote_cid[8] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    };
    const uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE] = { 0 };
    const uint8_t nat_reset_secret[PICOQUIC_RESET_SECRET_SIZE] = { 1 };
    picoquic_connection_id_t local_cid = {
        { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 }, 8
    };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_cnx_t* cnx = NULL;
    picoquic_path_t* default_path = NULL;
    picoquic_path_t* target_path = NULL;
    picoquic_remote_cnxid_t* remote_cnxid = NULL;
    picoquic_remote_cnxid_t* remote_nat_cnxid = NULL;
    struct sockaddr_in peer[3];
    struct sockaddr_in local[3];
    struct sockaddr_in nat_peer;
    struct sockaddr_in nat_local;
    struct sockaddr_storage addr_to;
    struct sockaddr_storage addr_from;
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t target_path_id = UINT64_MAX;
    size_t send_length = 0;
    size_t send_msg_size = 0;
    int if_index = 0;
    int obsolete_index = -1;
    int target_index = -1;
    int ret = tls_api_init_ctx(
        &test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI,
        PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(
            test_ctx, &loss_mask, 0, &simulated_time);
    }
    if (ret == 0 && (test_ctx == NULL || !TEST_CLIENT_READY)) {
        DBG_PRINTF("TLS fixture not ready, ret=%d", ret);
        ret = -1;
    }
    memset(peer, 0, sizeof(peer));
    memset(local, 0, sizeof(local));
    memset(&nat_peer, 0, sizeof(nat_peer));
    memset(&nat_local, 0, sizeof(nat_local));
    for (int i = 0; i < 3; i++) {
        peer[i].sin_family = AF_INET;
        peer[i].sin_port = htons((uint16_t)(5300 + i));
        peer[i].sin_addr.s_addr = htonl(0x7f000001u + (uint32_t)i);
        local[i].sin_family = AF_INET;
        local[i].sin_port = htons((uint16_t)(45000 + i));
        local[i].sin_addr.s_addr = htonl(0x7f00002au + (uint32_t)i);
    }
    nat_peer.sin_family = AF_INET;
    nat_peer.sin_port = htons(6302);
    nat_peer.sin_addr.s_addr = htonl(0x7f000062u);
    nat_local.sin_family = AF_INET;
    nat_local.sin_port = htons(46002);
    nat_local.sin_addr.s_addr = htonl(0x7f000072u);

    if (ret == 0) {
        cnx = test_ctx->cnx_client;
        default_path = cnx->path[0];
        cnx->is_multipath_enabled = 1;
        obsolete_index = picoquic_create_path(
            cnx, simulated_time, (const struct sockaddr*)&local[1],
            (const struct sockaddr*)&peer[1], 1);
        target_index = picoquic_create_path(
            cnx, simulated_time, (const struct sockaddr*)&local[2],
            (const struct sockaddr*)&peer[2], 2);
        if (obsolete_index != 1 || target_index != 2) {
            DBG_PRINTF("Could not create paths: obsolete=%d, target=%d, count=%d",
                obsolete_index, target_index, cnx->nb_paths);
            ret = -1;
        }
    }
    if (ret == 0) {
        target_path = cnx->path[2];
        target_path_id = target_path->unique_path_id;
        target_path->if_index_dest = 22;
        target_path->p_local_cnxid = picoquic_create_local_cnxid(
            cnx, target_path_id, &local_cid, simulated_time);
        if (target_path->p_local_cnxid == NULL ||
            picoquic_stash_remote_cnxid(
                cnx, 0, target_path_id, 0, sizeof(normal_remote_cid),
                normal_remote_cid, reset_secret, &remote_cnxid) != 0 ||
            remote_cnxid == NULL) {
            DBG_PRINTF("%s", "Could not assign target path CIDs");
            ret = -1;
        }
        else {
            target_path->p_remote_cnxid = remote_cnxid;
            remote_cnxid->nb_path_references++;
        }
    }
    if (ret == 0 && probe_nat) {
        picoquic_store_addr(
            &target_path->nat_peer_addr,
            (const struct sockaddr*)&nat_peer);
        picoquic_store_addr(
            &target_path->nat_local_addr,
            (const struct sockaddr*)&nat_local);
        target_path->if_index_nat_dest = 44;
        target_path->challenge_repeat_count = 1;
        target_path->challenge_time = simulated_time;
        target_path->nat_challenge_repeat_count = 0;
        target_path->nat_challenge[0] = 0x0123456789abcdefull;
        if (picoquic_stash_remote_cnxid(
                cnx, 0, target_path_id, 1, sizeof(nat_remote_cid),
                nat_remote_cid, nat_reset_secret, &remote_nat_cnxid) != 0 ||
            remote_nat_cnxid == NULL) {
            DBG_PRINTF("%s", "Could not assign target NAT CID");
            ret = -1;
        }
        else {
            target_path->p_remote_nat_cnxid = remote_nat_cnxid;
            remote_nat_cnxid->nb_path_references++;
        }
    }
    if (ret == 0) {
        cnx->path[1]->path_is_demoted = 1;
        cnx->path[1]->demotion_time = simulated_time;
        cnx->path_demotion_needed = 1;
    }
    if (ret == 0) {
        const struct sockaddr* expected_to = probe_nat ?
            (const struct sockaddr*)&nat_peer :
            (const struct sockaddr*)&peer[2];
        const struct sockaddr* expected_from = probe_nat ?
            (const struct sockaddr*)&nat_local :
            (const struct sockaddr*)&local[2];
        const uint8_t* expected_cid = probe_nat ?
            nat_remote_cid : normal_remote_cid;
        int expected_if_index = probe_nat ? 44 : 22;

        ret = picoquic_prepare_packet_by_unique_path_id(
            cnx, target_path_id, simulated_time, send_buffer,
            sizeof(send_buffer), &send_length, &addr_to, &addr_from,
            &if_index, &send_msg_size);
        if (ret != 0) {
            DBG_PRINTF("Target stable path returned %d, nat=%d", ret,
                probe_nat);
        }
        if (ret == 0 &&
            (send_length <= 1 + sizeof(normal_remote_cid) ||
             (send_buffer[0] & 0x80) != 0 ||
             memcmp(send_buffer + 1, expected_cid,
                 sizeof(normal_remote_cid)) != 0 ||
             cnx->path[0] != default_path || cnx->nb_paths != 2 ||
             cnx->path[1] != target_path ||
             picoquic_compare_addr(
                 (const struct sockaddr*)&addr_to, expected_to) != 0 ||
             picoquic_compare_addr(
                 (const struct sockaddr*)&addr_from, expected_from) != 0 ||
             if_index != expected_if_index)) {
            DBG_PRINTF("Unique path route mismatch, nat=%d, length=%zu, if=%d/%d, cid=%d, to=%d, from=%d",
                probe_nat, send_length, if_index, expected_if_index,
                send_length > 1 + sizeof(normal_remote_cid) ?
                    memcmp(send_buffer + 1, expected_cid,
                        sizeof(normal_remote_cid)) : -1,
                picoquic_compare_addr(
                    (const struct sockaddr*)&addr_to, expected_to),
                picoquic_compare_addr(
                    (const struct sockaddr*)&addr_from, expected_from));
            ret = -1;
        }
    }
    if (ret == 0) {
        send_length = 17;
        ret = picoquic_prepare_packet_by_unique_path_id(
            cnx, target_path_id, simulated_time, send_buffer,
            sizeof(send_buffer), &send_length, &addr_to, &addr_from,
            &if_index, &send_msg_size);
        if (ret != 0 || send_length != 0) {
            DBG_PRINTF("Unique path zero output returned %d, length=%zu, nat=%d",
                ret, send_length, probe_nat);
            ret = -1;
        }
    }
    if (ret == 0) {
        const uint8_t consumed_datagram[3] = { 0xe0, 0xe1, 0xe2 };
        int disappearing_index = -1;
        uint64_t due_wake_time = picoquic_get_quic_time(cnx->quic);
        uint64_t expected_future_wake = cnx->start_time +
            cnx->local_parameters.max_idle_timeout * 1000ull;
        int missing_ret[3] = { 0, 0, 0 };
        size_t missing_length[3] = { 0, 0, 0 };
        uint64_t missing_wake[3] = { 0, 0, 0 };
        int missing_queue[3] = { 0, 0, 0 };

        cnx->app_wake_time = 0;
        cnx->is_lost_feedback_notification_required = 0;
        prepare_by_unique_path_id_clear_misc_frames(cnx);
        prepare_by_unique_path_id_clear_datagrams(cnx);
        ret = picoquic_queue_datagram_frame(
            cnx, sizeof(consumed_datagram), consumed_datagram);
        if (ret == 0) {
            send_length = 17;
            ret = picoquic_prepare_packet(
                cnx, simulated_time, send_buffer, sizeof(send_buffer),
                &send_length, &addr_to, &addr_from, &if_index);
        }
        if (ret != 0 || send_length == 0 ||
            cnx->first_datagram != NULL ||
            cnx->last_datagram != NULL ||
            cnx->next_wake_time != due_wake_time) {
            DBG_PRINTF("Could not consume disappearing-path wake: ret=%d, length=%zu, queue=%d/%d, wake=%" PRIu64 "/%" PRIu64,
                ret, send_length, cnx->first_datagram != NULL,
                cnx->last_datagram != NULL, cnx->next_wake_time,
                due_wake_time);
            ret = -1;
        }
        if (ret == 0) {
            disappearing_index = picoquic_create_path(
                cnx, simulated_time, (const struct sockaddr*)&local[1],
                (const struct sockaddr*)&peer[1], 3);
        }
        if (ret == 0 && (disappearing_index != 2 ||
            cnx->first_misc_frame != NULL ||
            cnx->last_misc_frame != NULL ||
            cnx->cnx_state >= picoquic_state_ready ||
            cnx->quic->default_handshake_timeout != 0 ||
            cnx->local_parameters.max_idle_timeout == 0 ||
            expected_future_wake <= due_wake_time)) {
            DBG_PRINTF("Disappearing path fixture invalid: index=%d, queue=%d/%d, state=%d, timeout=%" PRIu64 "/%" PRIu64 ", wake=%" PRIu64 "/%" PRIu64,
                disappearing_index, cnx->first_misc_frame != NULL,
                cnx->last_misc_frame != NULL, cnx->cnx_state,
                cnx->quic->default_handshake_timeout,
                cnx->local_parameters.max_idle_timeout,
                due_wake_time, expected_future_wake);
            ret = -1;
        }
        else if (ret == 0) {
            uint64_t disappearing_path_id =
                cnx->path[disappearing_index]->unique_path_id;
            cnx->path[disappearing_index]->path_is_demoted = 1;
            cnx->path[disappearing_index]->demotion_time = simulated_time;
            cnx->path_demotion_needed = 1;
            for (int i = 0; i < 3; i++) {
                send_length = 17;
                missing_ret[i] = picoquic_prepare_packet_by_unique_path_id(
                    cnx, disappearing_path_id, simulated_time, send_buffer,
                    sizeof(send_buffer), &send_length, &addr_to, &addr_from,
                    &if_index, &send_msg_size);
                missing_length[i] = send_length;
                missing_wake[i] = cnx->next_wake_time;
                missing_queue[i] = cnx->first_misc_frame != NULL ||
                    cnx->last_misc_frame != NULL;
            }
            for (int i = 0; ret == 0 && i < 3; i++) {
                if (missing_ret[i] != PICOQUIC_ERROR_PATH_ID_INVALID ||
                    missing_length[i] != 0 ||
                    missing_wake[i] != expected_future_wake ||
                    missing_queue[i]) {
                    ret = -1;
                }
            }
            if (ret != 0) {
                DBG_PRINTF("Repeated missing stable path: ret=%d/%d/%d, length=%zu/%zu/%zu, wake=%" PRIu64 "/%" PRIu64 "/%" PRIu64 ", expected=%" PRIu64 ", due=%" PRIu64 ", queue=%d/%d/%d",
                    missing_ret[0], missing_ret[1], missing_ret[2],
                    missing_length[0], missing_length[1], missing_length[2],
                    missing_wake[0], missing_wake[1], missing_wake[2],
                    expected_future_wake, due_wake_time,
                    missing_queue[0], missing_queue[1], missing_queue[2]);
            }
        }
    }
    if (ret == 0) {
        const uint8_t queued_remote_cid[8] = {
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67
        };
        const uint8_t queued_reset_secret[PICOQUIC_RESET_SECRET_SIZE] = {
            3
        };
        picoquic_remote_cnxid_t* queued_remote_cnxid = NULL;
        int queued_index;
        uint64_t expected_wake_time = picoquic_get_quic_time(cnx->quic);

        prepare_by_unique_path_id_clear_misc_frames(cnx);
        picoquic_reinsert_by_wake_time(cnx->quic, cnx, UINT64_MAX);
        queued_index = picoquic_create_path(
            cnx, simulated_time, (const struct sockaddr*)&local[1],
            (const struct sockaddr*)&peer[1], 5);
        if (queued_index != 2) {
            DBG_PRINTF("Queued disappearing path index is %d, expected 2",
                queued_index);
            ret = -1;
        }
        else {
            uint64_t queued_path_id =
                cnx->path[queued_index]->unique_path_id;
            if (picoquic_stash_remote_cnxid(
                    cnx, 0, queued_path_id, 0,
                    sizeof(queued_remote_cid), queued_remote_cid,
                    queued_reset_secret, &queued_remote_cnxid) != 0 ||
                queued_remote_cnxid == NULL) {
                DBG_PRINTF("Could not assign queued path CID, index=%d",
                    queued_index);
                ret = -1;
            }
            else {
                cnx->path[queued_index]->p_remote_cnxid =
                    queued_remote_cnxid;
                queued_remote_cnxid->nb_path_references++;
                picoquic_demote_path(
                    cnx, queued_index, simulated_time, 0, NULL);
            }
            int queued_path_abandon =
                prepare_by_unique_path_id_has_abandon_frame(
                    cnx, queued_path_id);
            unsigned int path_abandon_sent =
                cnx->path[queued_index]->path_abandon_sent;
            cnx->path[queued_index]->demotion_time = simulated_time;
            send_length = 17;
            int queued_ret = ret == 0 ?
                picoquic_prepare_packet_by_unique_path_id(
                    cnx, queued_path_id, simulated_time, send_buffer,
                    sizeof(send_buffer), &send_length, &addr_to, &addr_from,
                    &if_index, &send_msg_size) : ret;
            int resolved_index = picoquic_find_path_by_unique_id(
                cnx, queued_path_id);
            if (queued_ret != PICOQUIC_ERROR_PATH_ID_INVALID ||
                send_length != 0 || resolved_index >= 0 ||
                !queued_path_abandon || !path_abandon_sent ||
                cnx->first_misc_frame == NULL ||
                cnx->next_wake_time != expected_wake_time ||
                picoquic_get_earliest_cnx_to_wake(
                    cnx->quic, expected_wake_time) != cnx) {
                DBG_PRINTF("Queued missing stable path returned %d, length=%zu, index=%d, wake=%" PRIu64 "/%" PRIu64 ", queue=%d, abandon=%d/%u",
                    queued_ret, send_length, resolved_index,
                    cnx->next_wake_time, expected_wake_time,
                    cnx->first_misc_frame != NULL, queued_path_abandon,
                    path_abandon_sent);
                ret = -1;
            }
        }
    }
    if (ret == 0 && !probe_nat) {
        uint64_t expected_wake_time = picoquic_get_quic_time(cnx->quic);
        prepare_by_unique_path_id_clear_misc_frames(cnx);
        picoquic_reinsert_by_wake_time(cnx->quic, cnx, UINT64_MAX);
        picoquic_demote_path(cnx, 1, simulated_time, 0, NULL);
        int demoted_index = picoquic_find_path_by_unique_id(
            cnx, target_path_id);
        unsigned int path_abandon_sent =
            demoted_index >= 0 && demoted_index < cnx->nb_paths ?
            cnx->path[demoted_index]->path_abandon_sent : 0;
        int queued_path_abandon =
            prepare_by_unique_path_id_has_abandon_frame(
                cnx, target_path_id);
        if (demoted_index != 1 || !cnx->path[demoted_index]->path_is_demoted ||
            cnx->path[demoted_index]->demotion_time <= simulated_time ||
            cnx->path[demoted_index]->p_remote_cnxid != NULL ||
            !path_abandon_sent || !queued_path_abandon ||
            cnx->next_wake_time != expected_wake_time ||
            picoquic_get_earliest_cnx_to_wake(
                cnx->quic, expected_wake_time) != cnx) {
            DBG_PRINTF("Demoted path fixture invalid: index=%d, count=%d, wake=%" PRIu64 "/%" PRIu64 ", abandon=%d/%u",
                demoted_index, cnx->nb_paths, cnx->next_wake_time,
                expected_wake_time, queued_path_abandon,
                path_abandon_sent);
            ret = -1;
        }
        else {
            send_length = 17;
            ret = picoquic_prepare_packet_by_unique_path_id(
                cnx, target_path_id, simulated_time, send_buffer,
                sizeof(send_buffer), &send_length, &addr_to, &addr_from,
                &if_index, &send_msg_size);
            if (ret != PICOQUIC_ERROR_PATH_ID_INVALID || send_length != 0 ||
                cnx->next_wake_time != expected_wake_time ||
                picoquic_get_earliest_cnx_to_wake(
                    cnx->quic, expected_wake_time) != cnx) {
                DBG_PRINTF("Demoted stable path returned %d, length=%zu, wake=%" PRIu64 "/%" PRIu64 ", abandon=%d/%u",
                    ret, send_length, cnx->next_wake_time,
                    expected_wake_time, queued_path_abandon,
                    path_abandon_sent);
                ret = -1;
            }
            else {
                ret = 0;
            }
        }
    }
    if (ret == 0 && !probe_nat) {
        const uint8_t selector_remote_cid[8] = {
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
        };
        const uint8_t selector_reset_secret[PICOQUIC_RESET_SECRET_SIZE] = {
            2
        };
        picoquic_connection_id_t selector_local_cid = {
            { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57 }, 8
        };
        picoquic_remote_cnxid_t* selector_remote_cnxid = NULL;
        uint64_t selector_time = cnx->path[1]->demotion_time;
        uint64_t next_wake_time = UINT64_MAX;

        picoquic_delete_abandoned_paths(
            cnx, selector_time, &next_wake_time);
        next_wake_time = UINT64_MAX;
        picoquic_delete_abandoned_paths(
            cnx, selector_time, &next_wake_time);
        prepare_by_unique_path_id_clear_misc_frames(cnx);
        int selector_index = picoquic_create_path(
            cnx, selector_time, (const struct sockaddr*)&local[1],
            (const struct sockaddr*)&peer[1], 4);
        if (cnx->nb_paths != 2 || selector_index != 1 ||
            cnx->path[0] != default_path || cnx->path_demotion_needed ||
            cnx->first_misc_frame != NULL || cnx->last_misc_frame != NULL) {
            DBG_PRINTF("Selector-demoted path index is %d, count=%d, unsettled=%u",
                selector_index, cnx->nb_paths, cnx->path_demotion_needed);
            ret = -1;
        }
        else {
            picoquic_path_t* selector_path = cnx->path[selector_index];
            uint64_t selector_path_id = selector_path->unique_path_id;
            selector_path->p_local_cnxid = picoquic_create_local_cnxid(
                cnx, selector_path_id, &selector_local_cid, selector_time);
            if (selector_path->p_local_cnxid == NULL ||
                picoquic_stash_remote_cnxid(
                    cnx, 0, selector_path_id, 0,
                    sizeof(selector_remote_cid), selector_remote_cid,
                    selector_reset_secret, &selector_remote_cnxid) != 0 ||
                selector_remote_cnxid == NULL) {
                DBG_PRINTF("%s", "Could not assign selector-demoted path CIDs");
                ret = -1;
            }
            else {
                size_t unprepared_msg_size = (size_t)-1;
                uint64_t expected_wake_time = picoquic_get_quic_time(cnx->quic);
                selector_path->p_remote_cnxid = selector_remote_cnxid;
                selector_remote_cnxid->nb_path_references++;
                picoquic_store_addr(
                    &selector_path->nat_peer_addr,
                    (const struct sockaddr*)&nat_peer);
                picoquic_store_addr(
                    &selector_path->nat_local_addr,
                    (const struct sockaddr*)&nat_local);
                selector_path->challenge_required = 1;
                selector_path->challenge_verified = 0;
                selector_path->response_required = 0;
                selector_path->retransmit_timer = 1;
                selector_path->nat_challenge_time = 0;
                selector_path->nat_challenge_repeat_count =
                    PICOQUIC_CHALLENGE_REPEAT_MAX;
                selector_path->challenge_failed = 1;
                send_length = 17;
                send_msg_size = unprepared_msg_size;
                memset(&addr_to, 0, sizeof(addr_to));
                memset(&addr_from, 0, sizeof(addr_from));
                if_index = -1;
                picoquic_reinsert_by_wake_time(cnx->quic, cnx, UINT64_MAX);
                ret = picoquic_prepare_packet_by_unique_path_id(
                    cnx, selector_path_id, selector_time, send_buffer,
                    sizeof(send_buffer), &send_length, &addr_to, &addr_from,
                    &if_index, &send_msg_size);
                int resolved_index = picoquic_find_path_by_unique_id(
                    cnx, selector_path_id);
                int queued_path_abandon =
                    prepare_by_unique_path_id_has_abandon_frame(
                        cnx, selector_path_id);
                int selector_route_ok = picoquic_compare_addr(
                        (const struct sockaddr*)&addr_to,
                        (const struct sockaddr*)&default_path->peer_addr) == 0 &&
                    picoquic_compare_addr(
                        (const struct sockaddr*)&addr_from,
                        (const struct sockaddr*)&default_path->local_addr) == 0 &&
                    if_index == default_path->if_index_dest;
                int forced_challenge_skipped =
                    selector_path->nat_local_addr.ss_family == AF_INET &&
                    picoquic_compare_addr(
                        (const struct sockaddr*)&selector_path->nat_local_addr,
                        (const struct sockaddr*)&nat_local) == 0 &&
                    picoquic_compare_addr(
                        (const struct sockaddr*)&selector_path->nat_peer_addr,
                        (const struct sockaddr*)&nat_peer) == 0 &&
                    cnx->is_multipath_enabled &&
                    selector_path->challenge_required &&
                    !selector_path->challenge_verified &&
                    !selector_path->response_required &&
                    selector_path->nat_challenge_time == 0 &&
                    selector_time > selector_path->nat_challenge_time +
                        selector_path->retransmit_timer &&
                    selector_path->nat_challenge_repeat_count ==
                        PICOQUIC_CHALLENGE_REPEAT_MAX;
                unsigned int requested_path_abandon_sent =
                    resolved_index >= 0 && resolved_index < cnx->nb_paths ?
                    cnx->path[resolved_index]->path_abandon_sent : 0;
                if (ret != PICOQUIC_ERROR_PATH_ID_INVALID ||
                    send_length != 0 || resolved_index != 1 ||
                    !cnx->path[resolved_index]->path_is_demoted ||
                    cnx->path[resolved_index]->demotion_time <= selector_time ||
                    cnx->path[resolved_index]->p_remote_cnxid != NULL ||
                    !cnx->path[resolved_index]->path_abandon_sent ||
                    !queued_path_abandon ||
                    cnx->next_wake_time != expected_wake_time ||
                    picoquic_get_earliest_cnx_to_wake(
                        cnx->quic, expected_wake_time) != cnx ||
                    !selector_route_ok ||
                    !forced_challenge_skipped ||
                    send_msg_size != unprepared_msg_size) {
                    DBG_PRINTF("Selector-demoted stable path returned %d, length=%zu, index=%d, msg=%zu, wake=%" PRIu64 "/%" PRIu64 ", abandon=%d/%u, route=%d, nat=%d/%u/%" PRIu64,
                        ret, send_length, resolved_index, send_msg_size,
                        cnx->next_wake_time, expected_wake_time,
                        queued_path_abandon,
                        requested_path_abandon_sent,
                        selector_route_ok, forced_challenge_skipped,
                        selector_path->nat_challenge_repeat_count,
                        selector_path->nat_challenge_time);
                    ret = -1;
                }
                else {
                    ret = 0;
                }
            }
        }
    }
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }
    return ret;
}

int prepare_by_unique_path_id_test()
{
    int ret = prepare_by_unique_path_id_case(0);
    int wake_ret;

    if (ret != 0) {
        DBG_PRINTF("%s", "Normal unique path preparation failed");
    }
    if (ret == 0) {
        ret = prepare_by_unique_path_id_case(1);
        if (ret != 0) {
            DBG_PRINTF("%s", "NAT unique path preparation failed");
        }
    }
    wake_ret = prepare_unique_wake_reconciliation_cases();
    if (wake_ret != 0) {
        DBG_PRINTF("%s", "Unique path wake reconciliation failed");
        ret = -1;
    }
    return ret;
}

int create_quic_test()
{
    int ret = 0;
    char const* bad_dir = "..";
    char const* bad_file = "no_such_file_should_exist.pem";
    picoquic_quic_t* quic = NULL;

    /* Check that 0 connection == 1 */
    if (ret == 0) {
        quic = picoquic_create(0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        if (quic == NULL || quic->max_number_connections != 1) {
            ret = -1;
        }
        picoquic_free(quic);
        quic = NULL;
    }

    /* Check that bad context, bad key or bad store crashes connection */
    if (ret == 0) {
        char test_server_cert_file[512];
        char test_server_key_file[512];

        ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_CERT);

        if (ret == 0) {
            ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
                PICOQUIC_TEST_FILE_SERVER_KEY);
        }

        if (ret == 0) {
            if ((quic = picoquic_create(8, bad_file, test_server_key_file, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0)) != NULL ||
                (quic = picoquic_create(8, test_server_cert_file, bad_file, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0)) != NULL) {
                ret = -1;
                picoquic_free(quic);
                quic = NULL;
            }
        }
    }

    /* Check that bad ticket store does not crash a client connection */
    if (ret == 0) {
        if ((quic = picoquic_create(0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, bad_file, NULL, 0)) == NULL) {
            ret = -1;
        }
        else {
            picoquic_free(quic);
            if ((quic = picoquic_create(0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, bad_dir, NULL, 0)) == NULL) {
                ret = -1;
            }
            else {
                picoquic_free(quic);
                quic = NULL;
            }
        }
    }

    /* Check loading of token file (always work) and not a valid file name (always fail).
    * However, this test is not very portable, because reading a bad directory only
    * fails on Windows.
     */
    if (ret == 0) {
        if ((quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0)) == NULL) {
            ret = -1;
        }
        else
        {
            int rbf = 0;
            int rbd = 0;
            if ((rbf = picoquic_load_token_file(quic, bad_file)) != 0 &&
                (rbd = picoquic_load_token_file(quic, bad_dir)) == 0) {
                ret = -1;
            }
            DBG_PRINTF("Load token %s %s",
                bad_file, (rbf == 0) ? "Succeeds" : "Fails");
            DBG_PRINTF("Load token %s %s",
                bad_dir, (rbd == 0) ? "Succeeds" : "Fails");
            picoquic_free(quic);
            quic = NULL;
        }
    }

    /* Check that loading a NULL TP loads the default */
    if (ret == 0) {
        if ((quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0)) == NULL) {
            ret = -1;
        }
        else
        {
            if (picoquic_set_default_tp(quic, NULL) != 0) {
                ret = -1;
            }
            picoquic_free(quic);
            quic = NULL;
        }
    }

    return ret;
}
