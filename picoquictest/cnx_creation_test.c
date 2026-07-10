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

static void prepare_by_unique_path_id_clear_misc_frames(picoquic_cnx_t* cnx)
{
    while (cnx->first_misc_frame != NULL) {
        picoquic_delete_misc_or_dg(
            &cnx->first_misc_frame, &cnx->last_misc_frame,
            cnx->first_misc_frame);
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
        int disappearing_index;
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
        picoquic_reinsert_by_wake_time(
            cnx->quic, cnx, due_wake_time);
        disappearing_index = picoquic_create_path(
            cnx, simulated_time, (const struct sockaddr*)&local[1],
            (const struct sockaddr*)&peer[1], 3);
        if (disappearing_index != 2 || cnx->first_misc_frame != NULL ||
            cnx->last_misc_frame != NULL ||
            cnx->cnx_state >= picoquic_state_ready ||
            cnx->quic->default_handshake_timeout != 0 ||
            cnx->local_parameters.max_idle_timeout == 0 ||
            expected_future_wake <= due_wake_time) {
            DBG_PRINTF("Disappearing path fixture invalid: index=%d, queue=%d/%d, state=%d, timeout=%" PRIu64 "/%" PRIu64 ", wake=%" PRIu64 "/%" PRIu64,
                disappearing_index, cnx->first_misc_frame != NULL,
                cnx->last_misc_frame != NULL, cnx->cnx_state,
                cnx->quic->default_handshake_timeout,
                cnx->local_parameters.max_idle_timeout,
                due_wake_time, expected_future_wake);
            ret = -1;
        }
        else {
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

    if (ret != 0) {
        DBG_PRINTF("%s", "Normal unique path preparation failed");
    }
    if (ret == 0) {
        ret = prepare_by_unique_path_id_case(1);
        if (ret != 0) {
            DBG_PRINTF("%s", "NAT unique path preparation failed");
        }
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
