#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#define MAX_QUERY_OFFSET 4

static inline char lowercase(char c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static inline bool case_insensitive_strncmp(const char *s1, const char *s2, int n) {
    for (int i = 0; i < n && s1[i] && s2[i]; i++) {
        if (lowercase(s1[i]) != lowercase(s2[i])) {
            return false;
        }
    }
    return true;
}

static inline bool is_nullbyte(void *data) {
    char c;
    if (bpf_probe_read(&c, 1, data)) {
        return false;
    }
    return c == '\0';
}

static inline bool is_sql_query_stmt(void *data) {
    if (is_nullbyte(data)) {
        return false;
    }
    char stmt[6];
    if (bpf_probe_read(&stmt, 6, data)) {
        return false;
    }
    return case_insensitive_strncmp(stmt, "SELECT", 6) ||
           case_insensitive_strncmp(stmt, "INSERT", 6) ||
           case_insensitive_strncmp(stmt, "UPDATE", 6) ||
           case_insensitive_strncmp(stmt, "DELETE", 6) ||
           case_insensitive_strncmp(stmt, "CREATE", 6) ||
           case_insensitive_strncmp(stmt, "DROP", 4) ||
           case_insensitive_strncmp(stmt, "ALTER", 5) || case_insensitive_strncmp(stmt, "WITH", 4);
}

// Returns the index of the first character of the SQL query in the buffer.
// Some SQL packets contain some flags which are not a part of the SQL query.
// Returns -1 if the buffer doesn't contain an SQL query.
static inline int is_sql_query(void *data) {
    for (int i = 0; i < MAX_QUERY_OFFSET; i++) {
        if (is_sql_query_stmt(data + i)) {
            return i;
        }
    }
    return -1;
}
