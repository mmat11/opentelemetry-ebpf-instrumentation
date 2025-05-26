// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <bpfcore/utils.h>

#include <pid/pid_helpers.h>

#include <common/http_types.h>

#define PATH_MAX_LEN 100
#define METHOD_MAX_LEN 7 // Longest method: OPTIONS
#define REMOTE_ADDR_MAX_LEN                                                                        \
    50 // We need 48: 39(ip v6 max) + 1(: separator) + 7(port length max value 65535) + 1(null terminator)
#define HOST_LEN 64 // can be a fully qualified DNS name
#define TRACEPARENT_LEN 55
#define SQL_MAX_LEN 500
#define KAFKA_MAX_LEN 256
#define REDIS_MAX_LEN 256
#define MAX_TOPIC_NAME_LEN 64
#define HOST_MAX_LEN 100
#define SCHEME_MAX_LEN 10

#define MYSQL_QUERY_MAX 8192 // Maximum tracked query length. Give up if it's longer.
#define MYSQL_QUERY_MAX_MASK MYSQL_QUERY_MAX - 1
#define MYSQL_ERROR_MESSAGE_MAX 512 // MYSQL_ERRMSG_SIZE
#define MYSQL_ERROR_MESSAGE_MAX_MASK MYSQL_ERROR_MESSAGE_MAX - 1

enum mysql_response_status { MYSQL_RESP_OK = 0, MYSQL_RESP_ERR = 1 };

// Trace of an HTTP call invocation. It is instantiated by the return uprobe and forwarded to the
// user space through the events ringbuffer.
// TODO(matt): fix naming
typedef struct http_request_trace_t {
    u8 type; // Must be first
    u8 _pad0[1];
    u16 status;
    u8 method[METHOD_MAX_LEN];
    u8 scheme[SCHEME_MAX_LEN];
    u8 _pad1[11];
    u64 go_start_monotime_ns;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    s64 content_length;
    s64 response_length;
    u8 path[PATH_MAX_LEN];
    u8 host[HOST_MAX_LEN];
    tp_info_t tp;
    connection_info_t conn;
    pid_info pid;
} http_request_trace;

// TODO(matt): fix naming
typedef struct sql_request_trace_t {
    u8 type; // Must be first
    u8 _pad[1];
    u16 status;
    pid_info pid;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    tp_info_t tp;
    connection_info_t conn;
    u8 sql[SQL_MAX_LEN];
} sql_request_trace;

typedef struct kafka_client_req {
    u8 type; // Must be first
    u8 _pad[7];
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8 buf[KAFKA_MAX_LEN];
    connection_info_t conn;
    pid_info pid;
} kafka_client_req_t;

typedef struct kafka_go_req {
    u8 type; // Must be first
    u8 op;
    u8 _pad0[2];
    pid_info pid;
    connection_info_t conn;
    u8 _pad1[4];
    tp_info_t tp;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8 topic[MAX_TOPIC_NAME_LEN];
} kafka_go_req_t;

typedef struct redis_client_req {
    u8 type; // Must be first
    u8 err;
    u8 _pad[6];
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    pid_info pid;
    u8 buf[REDIS_MAX_LEN];
    connection_info_t conn;
    tp_info_t tp;
} redis_client_req_t;

// https://mariadb.com/kb/en/ok_packet/
struct mysql_response_ok {
    // Empty; will be used for prepared statements support
};

// https://mariadb.com/kb/en/err_packet/
//
// int<1> ERR_Packet header = 0xFF
// int<2> error code. see error list
// if (errorcode == 0xFFFF) /* progress reporting */
//     int<1> stage
//     int<1> max_stage
//     int<3> progress
//     string<lenenc> progress_info
// else
//     if (next byte = '#')
//         string<1> sql state marker '#'
//         string<5>sql state
//         string<EOF> human-readable error message
//     else
//         string<EOF> human-readable error message
struct mysql_response_err {
    // https://mariadb.com/kb/en/mariadb-error-code-reference/
    uint16_t error_code;
    uint8_t sql_state[7];
    char _pad;
    uint8_t error_message[MYSQL_ERROR_MESSAGE_MAX];
};

typedef struct mysql_request_event {
    uint8_t type; // Must be first
    char _pad1[7];
    connection_info_t conn_info;
    pid_info pid;
    uint8_t ssl;
    char _pad2[7];
    uint64_t start_monotime_ns;
    uint64_t end_monotime_ns;
    uint8_t command_id;
    char _pad3[3];
    uint32_t query_len;
    uint8_t buf[MYSQL_QUERY_MAX];
    tp_info_t tp;
} mysql_request_event_t;

typedef struct mysql_response_event {
    uint8_t type; // Must be first
    char _pad1[7];
    connection_info_t conn_info;
    pid_info pid;
    uint8_t ssl;
    char _pad2[7];
    uint64_t start_monotime_ns;
    uint64_t end_monotime_ns;
    uint8_t command_id;
    char _pad3[3];
    enum mysql_response_status response_status;
    struct mysql_response_err err;
    struct mysql_response_ok ok;
    char _pad4[6];
    tp_info_t tp;
} mysql_response_event_t;
