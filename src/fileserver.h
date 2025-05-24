// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 File Server Kernel Processing */
#ifndef __FILESERVER_H
#define __FILESERVER_H

#define MAX_FILENAME_LEN 256
#define MAX_PACKET_SIZE 1024
#define MAX_HTTP_HEADER_SIZE 256

/* HTTP request types */
enum http_method {
    HTTP_GET = 1,
    HTTP_POST = 2,
    HTTP_PUT = 3,
    HTTP_DELETE = 4,
    HTTP_UNKNOWN = 0
};

/* File operation result codes */
enum file_op_result {
    FILE_OP_SUCCESS = 0,
    FILE_OP_NOT_FOUND = 1,
    FILE_OP_ACCESS_DENIED = 2,
    FILE_OP_TOO_LARGE = 3,
    FILE_OP_FORWARD_TO_USER = 4,
    FILE_OP_ERROR = 5
};

/* Network event structure for packet capture */
struct net_event {
    __u32 src_addr;
    __u32 dst_addr;
    __u16 src_port;
    __u16 dst_port;
    __u32 seq_num;
    __u32 ack_num;
    __u8 tcp_flags;
    __u16 payload_len;
    __u8 payload[MAX_PACKET_SIZE];
};

/* HTTP request event */
struct http_request {
    __u32 src_addr;
    __u16 src_port;
    __u8 method;  /* http_method enum */
    __u8 processed_in_kernel;  /* 1 if handled in kernel, 0 if forwarded */
    char filename[MAX_FILENAME_LEN];
    __u16 content_length;
    __u8 headers[MAX_HTTP_HEADER_SIZE];
};

/* File operation event */
struct file_event {
    __u32 client_addr;
    __u16 client_port;
    __u8 operation;  /* file_op_result enum */
    char filename[MAX_FILENAME_LEN];
    __u32 file_size;
    __u64 timestamp;
    __u8 forwarded_to_user;
};

/* File cache entry structure */
struct file_cache_entry {
    char filename[MAX_FILENAME_LEN];
    __u32 file_size;
    __u64 last_modified;
    __u8 cached_data[MAX_PACKET_SIZE];
    __u32 cache_hits;
    __u8 valid;
};

#endif /* __FILESERVER_H */
