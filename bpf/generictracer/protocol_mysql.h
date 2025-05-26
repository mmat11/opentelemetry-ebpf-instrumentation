#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/http_types.h>
#include <common/pin_internal.h>
#include <common/ringbuf.h>
#include <common/runtime.h>
#include <common/sql.h>
#include <common/tp_info.h>
#include <common/trace_common.h>

#include <generictracer/protocol_common.h>

#include <maps/active_ssl_connections.h>

// Every mysql command packet is prefixed by an header
// https://mariadb.com/kb/en/0-packet/
struct mysql_hdr {
    uint32_t payload_length : 24;
    uint8_t sequence_id;
    uint8_t command_id;

    // Metadata
    bool hdr_arrived; // Signals whether to skip or not the first 4 bytes in the current buffer as
                      // they arrived in a previous packet.
} __attribute__((packed));

struct mysql_state_data {
    uint32_t payload_length : 24;
    uint8_t sequence_id;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, struct mysql_state_data);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} mysql_state SEC(".maps");

#define MYSQL_HDR_SIZE 5
#define MYSQL_HDR_COMMAND_ID_SIZE 1
#define MYSQL_HDR_SEQUENCE_ID_SIZE 1
#define MYSQL_HDR_PAYLOAD_LENGTH_SIZE 3
#define MYSQL_HDR_WITHOUT_COMMAND_SIZE 4
#define MYSQL_ERR_PACKET_MIN_SIZE 9

// MySQL Client
#define MYSQL_COM_QUERY 0x3
#define MYSQL_COM_STMT_PREPARE 0x16
#define MYSQL_COM_STMT_EXECUTE 0x17
// MySQL Server
#define MYSQL_OK 0x0
#define MYSQL_OK_EOF_DEPRECATED 0xfe
#define MYSQL_ERR 0xff

#define MYSQL_STATE_MARKER '#'

static inline void mysql_store_state_data(connection_info_t *conn_info, const unsigned char *data) {
    struct mysql_state_data *state_data = bpf_map_lookup_elem(&mysql_state, conn_info);
    if (state_data == NULL) {
        struct mysql_state_data new_state_data = {};
        bpf_probe_read(&new_state_data, MYSQL_HDR_PAYLOAD_LENGTH_SIZE, (void *)data);
        bpf_probe_read(&new_state_data.sequence_id, MYSQL_HDR_SEQUENCE_ID_SIZE, (void *)(data + 3));
        bpf_map_update_elem(&mysql_state, conn_info, &new_state_data, BPF_ANY);
    } else {
        bpf_probe_read(state_data, MYSQL_HDR_WITHOUT_COMMAND_SIZE, (void *)data);
        bpf_map_update_elem(&mysql_state, conn_info, state_data, BPF_ANY);
    }
}

static inline int mysql_parse_fixup_header(connection_info_t *conn_info,
                                           struct mysql_hdr *hdr,
                                           const unsigned char *data,
                                           size_t data_len,
                                           bool delete_data) {
    struct mysql_state_data *state_data = bpf_map_lookup_elem(&mysql_state, conn_info);
    if (state_data != NULL) {
        bpf_dbg_printk("mysql_parse_fixup_header: state data found");

        hdr->payload_length = state_data->payload_length;
        hdr->sequence_id = state_data->sequence_id;
        bpf_probe_read(&hdr->command_id, MYSQL_HDR_COMMAND_ID_SIZE, (void *)data);
        hdr->hdr_arrived = true;

        if (delete_data) {
            bpf_dbg_printk("mysql_parse_fixup_header: deleting state data");
            // Reset state data
            bpf_map_delete_elem(&mysql_state, conn_info);
        } else {
            bpf_dbg_printk("mysql_parse_fixup_header: protocol check, not deleting state data");
        }
    } else {
        bpf_dbg_printk("mysql_parse_fixup_header: state data not found");
        if (data_len < MYSQL_HDR_SIZE) {
            bpf_dbg_printk("mysql_parse_fixup_header: data_len is too short: %d", data_len);
            return -1;
        }
        if (bpf_probe_read(hdr, MYSQL_HDR_SIZE, (void *)data)) {
            bpf_dbg_printk("mysql_parse_fixup_header: failed to read into mysql_hdr");
            return -1;
        }
    }
    return 0;
}

static inline void
mysql_set_trace_info(connection_info_t *conn, tp_info_t *tp, uint32_t pid, uint8_t ssl) {
    tp_info_pid_t *tp_p = tp_buf();
    if (!tp_p) {
        return;
    }

    tp_p->tp = *tp;
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->pid = pid; // used for avoiding finding stale server requests with client port reuse
    tp_p->req_type = EVENT_MYSQL_REQUEST;

    set_trace_info_for_connection(conn, TRACE_TYPE_CLIENT, tp_p);
    bpf_dbg_printk("mysql_set_trace_info: set traceinfo for conn");
    dbg_print_http_connection_info(conn);

    server_or_client_trace(TRACE_TYPE_CLIENT, conn, tp_p, ssl);
}

static inline void
mysql_fill_trace_info(pid_connection_info_t *pid_conn, tp_info_t *tp, uint8_t ssl) {
    uint8_t found = find_trace_for_client_request(pid_conn, tp);
    bpf_dbg_printk("mysql_fill_trace_info: looking up client trace info, found: %d", found);
    if (found) {
        urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
    } else {
        init_new_trace(tp);
    }
    mysql_set_trace_info(&pid_conn->conn, tp, pid_conn->pid, ssl);
}

static inline void mysql_cleanup_trace_info(pid_connection_info_t *pid_conn) {
    delete_client_trace_info(pid_conn);
}

static inline uint32_t data_offset(struct mysql_hdr *hdr) {
    return hdr->hdr_arrived ? MYSQL_HDR_SIZE - MYSQL_HDR_WITHOUT_COMMAND_SIZE : MYSQL_HDR_SIZE;
}

static inline uint32_t mysql_command_offset(struct mysql_hdr *hdr) {
    return data_offset(hdr) - MYSQL_HDR_COMMAND_ID_SIZE;
}

static void mysql_request_handle(struct mysql_hdr *hdr,
                                 const unsigned char *data,
                                 size_t data_len,
                                 connection_info_t *conn_info,
                                 uint8_t ssl,
                                 tp_info_t *tp) {
    int sql_query_offset;

    pid_info pid = {};
    task_pid(&pid);

    mysql_request_event_t *e = (mysql_request_event_t *)bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e == NULL) {
        bpf_dbg_printk("mysql_request_handle: couldn't reserve ringbuf event");
        return;
    }
    e->type = EVENT_MYSQL_REQUEST;
    e->conn_info = *conn_info;
    e->pid = pid;
    e->ssl = ssl;
    e->start_monotime_ns = bpf_ktime_get_ns();
    e->end_monotime_ns = 0;
    e->command_id = hdr->command_id;
    e->query_len = hdr->payload_length - MYSQL_HDR_COMMAND_ID_SIZE;
    e->tp = *tp;

    switch (hdr->command_id) {
    case MYSQL_COM_QUERY:
        // TODO(matt): prepared statements
        // case MYSQL_COM_STMT_PREPARE:
        sql_query_offset = is_sql_query((void *)(data + data_offset(hdr)));
        if (sql_query_offset == -1) {
            bpf_dbg_printk("mysql_request_handle: COM_QUERY or COM_PREPARE found, but buf doesn't "
                           "contain a sql query");
            bpf_ringbuf_discard(e, 0);
            return;
        }
        e->query_len -= sql_query_offset;
        if (bpf_probe_read(&e->buf,
                           e->query_len & MYSQL_QUERY_MAX_MASK,
                           data + (data_offset(hdr) + sql_query_offset))) {
            bpf_dbg_printk("mysql_request_handle: failed to read query");
            bpf_ringbuf_discard(e, 0);
            return;
        }
        e->buf[e->query_len & MYSQL_QUERY_MAX_MASK] = '\0';

        bpf_dbg_printk("mysql request event sent! command_id=COM_QUERY/COM_STMT_PREPARE "
                       "command_id=%d query_len=%d",
                       hdr->command_id,
                       e->query_len);
        break;
        // TODO(matt): prepared statements
        //case MYSQL_COM_STMT_EXECUTE:
        // if (bpf_probe_read(&e->stmt_id, 4, data + data_offset(hdr))) {
        // 	bpf_dbg_printk("mysql_request_handle: failed to read statement id");
        // 	bpf_ringbuf_discard(e, 0);
        // 	return;
        // }
        // bpf_dbg_printk("mysql request event sent! command_id=COM_STMT_EXECUTE stmt_id=%d", e->stmt_id);
        break;
    default:
        bpf_dbg_printk("mysql_request_handle: unhandled command 0x%x", hdr->command_id);
        bpf_ringbuf_discard(e, 0);
        return;
    }

    bpf_ringbuf_submit(e, 0);
}

static int mysql_err__fill(struct mysql_hdr *hdr,
                           struct mysql_response_err *err,
                           void *data,
                           size_t data_len) {
    size_t offset = data_offset(hdr); // response header
    uint8_t min_data_len = offset + MYSQL_ERR_PACKET_MIN_SIZE;

    if (data_len < min_data_len) {
        bpf_dbg_printk("mysql_err__fill: data_len is too short: %d", data_len);
        return -1;
    }

    if (bpf_probe_read(&err->error_code, 2, data + offset)) {
        bpf_dbg_printk("mysql_err__fill: failed to read error code");
        return -1;
    }
    offset += 2;

    if (err->error_code == 0xffff) { // progress reporting
        bpf_dbg_printk("mysql_err__fill: progress reporting...");
        err->sql_state[0] = '\0';
        err->error_message[0] = '\0';
    } else {
        if (bpf_probe_read(&err->sql_state, 1, data + offset)) {
            bpf_dbg_printk("mysql_err__fill: failed to read state marker");
            return -1;
        }
        offset += 1;

        if (err->sql_state[0] == MYSQL_STATE_MARKER) {
            if (bpf_probe_read(&err->sql_state[1], 5, data + offset)) {
                bpf_dbg_printk("mysql_err__fill: failed to read sql state");
                return -1;
            }
            err->sql_state[6] = '\0';
            offset += 5;
        } else {
            err->sql_state[0] = '\0';
            offset -= 1;
        }

        size_t error_message_len = (data_len - offset + 1) & MYSQL_ERROR_MESSAGE_MAX_MASK;
        bpf_probe_read_str(&err->error_message, error_message_len, data + offset);
        err->error_message[error_message_len] = '\0';
        offset += error_message_len;
    }

    bpf_dbg_printk("mysql_err__fill: code=%d state=%s", err->error_code, err->sql_state);
    bpf_dbg_printk("mysql_err__fill: error_message=%s", err->error_message);

    return 0;
}

/**
 * https://mariadb.com/kb/en/err_packet/
 */
static bool is_err_packet(struct mysql_hdr *hdr, uint8_t command_id, size_t data_len) {
    uint8_t min_data_len = hdr->hdr_arrived
                               ? MYSQL_ERR_PACKET_MIN_SIZE - MYSQL_HDR_WITHOUT_COMMAND_SIZE
                               : MYSQL_ERR_PACKET_MIN_SIZE;

    if (data_len < min_data_len) {
        bpf_dbg_printk("is_err_packet: data_len is too short: %d", data_len);
        return false;
    }

    return command_id == MYSQL_ERR;
}

/**
 * https://mariadb.com/kb/en/eof_packet/
 */
static bool is_eof_packet(uint8_t command_id, size_t data_len) {
    return command_id == MYSQL_OK_EOF_DEPRECATED;
}

/**
 * https://mariadb.com/kb/en/protocol-data-types/#length-encoded-integers
 * returns the length of the encoded integer, or -1 if invalid
 */
static int parse_length_encoded_integer(const uint8_t *data, size_t data_len) {
    // If it is < 0xfb, treat it as a 1-byte integer.
    // If it is 0xfc, it is followed by a 2-byte integer.
    // If it is 0xfd, it is followed by a 3-byte integer.
    // If it is 0xfe, it is followed by a 8-byte integer.
    uint8_t first_byte;
    bpf_probe_read(&first_byte, 1, data);
    int offset = -1;
    // either 1 byte integer or null
    if (first_byte <= 0xfb) {
        offset = 1;
    }
    // 2 byte integer
    if (first_byte == 0xfc) {
        offset = 3;
    }
    // 3 byte integer
    if (first_byte == 0xfd) {
        offset = 4;
    }
    // 8 byte integer
    if (first_byte == 0xfe) {
        offset = 9;
    }

    if (offset == -1) {
        bpf_dbg_printk("is_length_encoded_integer: invalid first byte: %d", first_byte);
        return -1;
    }

    if (data_len < offset) {
        bpf_dbg_printk(
            "is_length_encoded_integer: data_len: %d is too short to contain integer of size: %d",
            data_len,
            offset);
        return -1;
    }

    return offset;
}

/**
 * Assume CLIENT_PROTOCOL_41 is set.
 * https://mariadb.com/kb/en/ok_packet/
 * int<1> 0x00 : OK_Packet header or (0xFE if CLIENT_DEPRECATE_EOF is set)
 * int<lenenc> affected rows
 * int<lenenc> last insert id
 * int<2> server status
 * int<2> warning count
 */
static bool
is_ok_packet(struct mysql_hdr *hdr, const uint8_t *data, size_t data_len, uint8_t command_id) {
    int offset = data_offset(hdr);

    // parse affected rows
    int res = parse_length_encoded_integer(data + offset, data_len - offset);
    if (res == -1) {
        bpf_dbg_printk("is_ok_packet: failed to get affected rows");
        return false;
    }
    offset += res;
    // parse last insert id
    res = parse_length_encoded_integer(data + offset, data_len - offset);
    if (res == -1) {
        bpf_dbg_printk("is_ok_packet: failed to parse last insert id");
        return false;
    }
    // parse server status and warning count
    offset += res;
    if (data_len < offset + 4) {
        bpf_dbg_printk(
            "is_ok_packet: remaining data_len is too short for server status and warning count: %d",
            data_len - offset);
        return false;
    }

    return (command_id == MYSQL_OK || command_id == MYSQL_OK_EOF_DEPRECATED);
}

static inline bool is_last_packet_eof(struct mysql_hdr *hdr, const uint8_t *data, size_t data_len) {
    const uint8_t eof;
    bpf_probe_read((void *)&eof, 1, data + data_len - data_offset(hdr));
    return is_eof_packet(eof, data_offset(hdr));
}

/*
 * try to check if the last packet is an ok packet
 * since an OK packet has int<lenenc> fields, we need to try each combination of an ok packet
 * a int<lenenc> can be of length 1, 3, 4, 9, so a combination of 2 of them is
 * 1+1=2, 1+3=4, 1+4=5, 3+3=6, 3+4=7, 4+4=8, 1+9=10, 3+9=12, 4+9=13, 9+9=18
 * if we add 4 for header length, 1 for the first byte of header and 4 bytes for server status and warning count (5 total), we get either
 * 11, 13, 14, 15, 16, 17, 19, 21, 25
 */
#define CHECK_OK_PACKET_FROM_OFFSET(offset)                                                        \
    ok = data + data_len - offset;                                                                 \
    bpf_probe_read(&command_id, 1, ok + command_offset);                                           \
    if (is_ok_packet(hdr, ok, offset, command_id)) {                                               \
        return true;                                                                               \
    }

static bool is_last_packet_ok(struct mysql_hdr *hdr, const uint8_t *data, size_t data_len) {
    const uint8_t *ok;
    uint8_t command_id;
    uint8_t command_offset = mysql_command_offset(hdr);
    CHECK_OK_PACKET_FROM_OFFSET(11);
    CHECK_OK_PACKET_FROM_OFFSET(13);
    CHECK_OK_PACKET_FROM_OFFSET(14);
    CHECK_OK_PACKET_FROM_OFFSET(15);
    CHECK_OK_PACKET_FROM_OFFSET(16);
    CHECK_OK_PACKET_FROM_OFFSET(17);
    CHECK_OK_PACKET_FROM_OFFSET(19);
    CHECK_OK_PACKET_FROM_OFFSET(21);
    CHECK_OK_PACKET_FROM_OFFSET(25);
    return false;
}

static int parse_response_packet_type(struct mysql_hdr *hdr, const uint8_t *data, size_t data_len) {
    uint8_t offset = data_offset(hdr);

    if (data_len < offset) {
        bpf_dbg_printk("parse_response_packet_type: data_len is too short: %d", data_len);
        return -1;
    }

    uint8_t command_id;
    bpf_probe_read(&command_id, MYSQL_HDR_COMMAND_ID_SIZE, data + mysql_command_offset(hdr));

    int ret = -1;
    if (is_ok_packet(hdr, data, data_len, command_id)) {
        ret = MYSQL_OK;
    } else if (is_err_packet(hdr, command_id, data_len)) {
        ret = MYSQL_ERR;
    } else if (is_eof_packet(command_id, data_len)) {
        ret = MYSQL_OK_EOF_DEPRECATED;
    } else if (is_last_packet_eof(hdr, data, data_len)) {
        ret = MYSQL_OK_EOF_DEPRECATED;
    } else if (is_last_packet_ok(hdr, data, data_len)) {
        ret = MYSQL_OK;
    }

    bpf_dbg_printk("parse_response_packet_type: command_id=%d packet_type=%d", command_id, ret);
    return ret;
}

static void mysql_response_handle(struct mysql_hdr *hdr,
                                  const unsigned char *data,
                                  size_t data_len,
                                  connection_info_t *conn_info,
                                  uint8_t ssl,
                                  tp_info_t *tp) {
    uint8_t packet_type;
    int packet_type_response = parse_response_packet_type(hdr, data, data_len);
    // do this to avoid underflow, as parse_response_packet_type returns -1 on error and 256 - 1 = 255 which is error packet
    if (packet_type_response == -1) {
        bpf_dbg_printk("mysql_response_handle: couldn't parse response packet type");
        return;
    }
    packet_type = (uint8_t)packet_type_response;
    bpf_dbg_printk("mysql_response_handle: packet_type=%d", packet_type);

    switch (packet_type) {
    case MYSQL_OK:
    case MYSQL_OK_EOF_DEPRECATED:
    case MYSQL_ERR:
        break;
    default:
        bpf_dbg_printk("mysql_response_handle: unknown mysql response packet");
        return;
    }

    pid_info pid = {};
    task_pid(&pid);

    mysql_response_event_t *e =
        (mysql_response_event_t *)bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e == NULL) {
        bpf_dbg_printk("mysql_response_handle: couldn't reserve ringbuf event");
        return;
    }
    e->type = EVENT_MYSQL_RESPONSE;
    e->conn_info = *conn_info;
    e->pid = pid;
    e->ssl = ssl;
    e->start_monotime_ns = 0;
    e->end_monotime_ns = bpf_ktime_get_ns();
    e->command_id = packet_type;
    e->tp = *tp;

    switch (packet_type) {
    case MYSQL_ERR:
        e->response_status = MYSQL_RESP_ERR;
        if (mysql_err__fill(hdr, &e->err, (void *)data, data_len)) {
            bpf_dbg_printk("mysql_response_handle: couldn't fill error response");
            bpf_ringbuf_discard(e, 0);
            return;
        }
        break;
    case MYSQL_OK:
    case MYSQL_OK_EOF_DEPRECATED:
        e->response_status = MYSQL_RESP_OK;
        // TODO(matt): prepared statements
        // if (state_data->request_command_id == MYSQL_COM_STMT_PREPARE) {
        // 	if (bpf_probe_read(&e->ok.stmt_id, 4, data + MYSQL_HDR_SIZE)) {
        // 		bpf_dbg_printk("mysql_response_handle: couldn't read statement id for COM_STMT_PREPARE");
        // 		bpf_ringbuf_discard(e, 0);
        // 		return;
        // 	}
        // }
    }

    bpf_ringbuf_submit(e, 0);
    bpf_dbg_printk("mysql response event sent with status %d!", packet_type);
}

// k_tail_protocol_mysql
SEC("kprobe/mysql")
int beyla_protocol_mysql(void *ctx) {
    call_protocol_args_t *args = protocol_args();
    if (!args) {
        return 0;
    }

    bpf_dbg_printk("=== tcp_mysql_event len=%d pid=%d ===",
                   args->bytes_len,
                   pid_from_pid_tgid(bpf_get_current_pid_tgid()));

    if (args->bytes_len == MYSQL_HDR_WITHOUT_COMMAND_SIZE) {
        // This packet only contains the first 4 bytes of the header, which is the payload length and sequence id.
        // We store this state data to be able to parse the full header later.
        bpf_dbg_printk("mysql: 4 bytes packet, storing state data");
        mysql_store_state_data(&args->pid_conn.conn, (const unsigned char *)args->u_buf);
        return 0;
    }

    struct mysql_hdr hdr = {};
    if (mysql_parse_fixup_header(&args->pid_conn.conn,
                                 &hdr,
                                 (const unsigned char *)args->u_buf,
                                 args->bytes_len,
                                 true) != 0) {
        bpf_dbg_printk("mysql: failed to parse mysql header");
        return 0;
    }

    tp_info_pid_t *tp_p = tp_buf();
    if (tp_p == NULL) {
        bpf_dbg_printk("mysql: failed to get tp_info");
        return 0;
    }
    mysql_fill_trace_info(&args->pid_conn, &tp_p->tp, args->ssl);

    switch (args->packet_type) {
    case PACKET_TYPE_REQUEST:
        mysql_request_handle(&hdr,
                             (const unsigned char *)args->u_buf,
                             args->bytes_len,
                             &args->pid_conn.conn,
                             args->ssl,
                             &tp_p->tp);
        break;
    case PACKET_TYPE_RESPONSE:
        mysql_response_handle(&hdr,
                              (const unsigned char *)args->u_buf,
                              args->bytes_len,
                              &args->pid_conn.conn,
                              args->ssl,
                              &tp_p->tp);
        mysql_cleanup_trace_info(&args->pid_conn);
        break;
    }

    return 0;
}

static inline uint8_t is_mysql(connection_info_t *conn_info,
                               const unsigned char *data,
                               size_t data_len,
                               uint8_t *packet_type) {
    size_t offset;
    uint8_t response_packet_type;
    int packet_type_response;

    bpf_dbg_printk("is_mysql: buf=%s data_len=%d", data, data_len);

    if (data_len == MYSQL_HDR_WITHOUT_COMMAND_SIZE) {
        bpf_dbg_printk("is_mysql: 4 bytes packet, storing state data");
        mysql_store_state_data(conn_info, data);
        return 0;
    }

    struct mysql_hdr hdr = {};
    if (mysql_parse_fixup_header(conn_info, &hdr, data, data_len, false) != 0) {
        bpf_dbg_printk("is_mysql: failed to parse mysql header");
        return 0;
    }

    bpf_dbg_printk("is_mysql: payload_length=%d sequence_id=%d command_id=%d",
                   hdr.payload_length,
                   hdr.sequence_id,
                   hdr.command_id);

    switch (hdr.command_id) {
    case MYSQL_COM_QUERY:
        //case MYSQL_COM_STMT_PREPARE:
        // COM_QUERY packet structure:
        // +------------+-------------+------------------+
        // | payload_len| sequence_id | command_id | SQL |
        // +------------+-------------+------------------+
        // |    3B      |     1B      |     1B     | ... |
        // +------------+-------------+------------------+
        // COM_STMT_PREPARE packet structure:
        // +------------+-------------+----------------------+
        // | payload_len| sequence_id | command_id | SQL     |
        // +------------+-------------+----------------------+
        // |    3B      |     1B      |     1B     | ...     |
        // +------------+-------------+----------------------+
        offset = is_sql_query((void *)(data + data_offset(&hdr)));
        if (offset == -1) {
            bpf_dbg_printk(
                "is_mysql: COM_QUERY or COM_PREPARE found, but buf doesn't contain a sql query");
            return 0;
        }
        *packet_type = PACKET_TYPE_REQUEST;
        break;
    case MYSQL_COM_STMT_EXECUTE:
        // COM_STMT_EXECUTE packet structure:
        // +------------+-------------+----------------------+
        // | payload_len| sequence_id | command_id | stmt_id |
        // +------------+-------------+----------------------+
        // |    3B      |     1B      |     1B     | 4B      |
        // +------------+-------------+----------------------+
        *packet_type = PACKET_TYPE_REQUEST;
        break;
    default:
        packet_type_response = parse_response_packet_type(&hdr, data, data_len);
        // do this to avoid underflow, as parse_response_packet_type returns -1 on error and 256 - 1 = 255 which is error packet
        if (packet_type_response == -1) {
            bpf_dbg_printk("is_mysql: couldn't parse response packet type");
            return 0;
        }
        response_packet_type = (uint8_t)packet_type_response;

        switch (response_packet_type) {
        case MYSQL_OK:
        case MYSQL_OK_EOF_DEPRECATED:
        case MYSQL_ERR:
            *packet_type = PACKET_TYPE_RESPONSE;
            goto ok;
        default:
            bpf_dbg_printk("is_mysql: unknown mysql response packet");
            return 0;
        }

        bpf_dbg_printk("is_mysql: unhandled mysql command_id: %d", hdr.command_id);
        return 0;
    }

ok:
    bpf_dbg_printk("is_mysql: mysql! command_id=%d packet_type=%d", hdr.command_id, *packet_type);
    return 1;
}
