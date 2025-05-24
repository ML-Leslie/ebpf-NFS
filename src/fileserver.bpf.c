// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023 File Server Kernel Processing */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "fileserver.h"

/* TC action definitions - if not available in vmlinux.h */
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

/* Network protocol definitions */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Maps for storing data and communication */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* File cache map for frequently accessed files */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, struct file_cache_entry);
} file_cache SEC(".maps");

/* Connection tracking map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);  /* client IP */
    __type(value, __u64); /* last request timestamp */
} conn_track SEC(".maps");

/* Statistics map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* Configuration - can be set from user space */
const volatile unsigned int enable_kernel_processing = 1;
const volatile unsigned int max_file_size = 4096;  /* Max file size to handle in kernel */
const volatile unsigned int cache_ttl_seconds = 300;  /* Cache TTL */

/* Helper function to parse HTTP method with proper bounds checking */
static inline __u8 parse_http_method(void *data, void *data_end, __u16 len)
{
    char *payload = (char *)data;
    
    /* Ensure we have at least 3 bytes for GET */
    if (payload + 3 > (char *)data_end || len < 3)
        return HTTP_UNKNOWN;
    
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T')
        return HTTP_GET;
    
    /* Check for POST (4 bytes) */
    if (payload + 4 <= (char *)data_end && len >= 4 &&
        payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T')
        return HTTP_POST;
    
    /* Check for PUT (3 bytes) */
    if (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T')
        return HTTP_PUT;
    
    /* Check for DELETE (6 bytes) */
    if (payload + 6 <= (char *)data_end && len >= 6 &&
        payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && 
        payload[3] == 'E' && payload[4] == 'T' && payload[5] == 'E')
        return HTTP_DELETE;
    
    return HTTP_UNKNOWN;
}

/* Helper function to extract filename from HTTP request - ultra-simple version */
static inline int extract_filename(void *data, void *data_end, __u16 len, char *filename)
{
    char *payload = (char *)data;
    
    /* Ultra-simple: just check for "GET /" pattern at the beginning */
    if (len < 5 || payload + 5 > (char *)data_end) {
        filename[0] = '\0';
        return 0;
    }
    
    /* Check for "GET /" */
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && 
        payload[3] == ' ' && payload[4] == '/') {
        
        /* Extract up to 8 characters only to avoid loops */
        int j = 0;
        for (int i = 5; i < 13 && i < len && j < 8; i++) {
            if (payload + i >= (char *)data_end)
                break;
            if (payload[i] == ' ' || payload[i] == '?' || 
                payload[i] == '\r' || payload[i] == '\n')
                break;
            filename[j++] = payload[i];
        }
        filename[j] = '\0';
        return j;
    }
    
    filename[0] = '\0';
    return 0;
}

/* Simple file existence check - in real implementation, this would check actual filesystem */
static inline int check_file_exists(const char *filename)
{
    /* For demonstration, assume files with certain patterns exist */
    if (filename[0] == 'i' && filename[1] == 'n' && filename[2] == 'd') {
        return 1; /* index.html exists */
    }
    if (filename[0] == 's' && filename[1] == 't' && filename[2] == 'a') {
        return 1; /* static files exist */
    }
    if (filename[0] == 't' && filename[1] == 'e' && filename[2] == 's') {
        return 1; /* test files exist */
    }
    return 0;
}

/* Update statistics */
static inline void update_stats(__u32 stat_type, __u64 value)
{
    __u64 *counter = bpf_map_lookup_elem(&stats, &stat_type);
    if (counter) {
        __sync_fetch_and_add(counter, value);
    }
}

/* TC ingress handler for intercepting HTTP requests */
SEC("tc")
int fileserver_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    char *http_payload;
    __u16 payload_len;
    struct http_request *req_event;
    struct file_event *file_event;
    char filename[MAX_FILENAME_LEN] = {0};
    __u8 method;
    __u32 client_ip;
    __u16 client_port;
    
    /* Basic packet validation */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;
    
    /* Check if this is HTTP traffic (port 80 or 8080) */
    if (tcp->dest != bpf_htons(80) && tcp->dest != bpf_htons(8080))
        return TC_ACT_OK;
    
    /* Extract HTTP payload */
    http_payload = (char *)tcp + (tcp->doff * 4);
    if (http_payload >= (char *)data_end)
        return TC_ACT_OK;
    
    payload_len = data_end - (void *)http_payload;
    if (payload_len < 4)  /* Minimum HTTP request size */
        return TC_ACT_OK;
    
    /* Parse HTTP method */
    method = parse_http_method(http_payload, data_end, payload_len);
    if (method == HTTP_UNKNOWN)
        return TC_ACT_OK;
    
    client_ip = ip->saddr;
    client_port = tcp->source;
    
    /* Extract filename from request */
    int filename_len = extract_filename(http_payload, data_end, payload_len, filename);
    if (filename_len == 0) {
        /* Default to index.html for root requests */
        __builtin_memcpy(filename, "index.html", 11);
    }
    
    /* Update statistics */
    update_stats(0, 1); /* Total requests */
    
    /* Create HTTP request event */
    req_event = bpf_ringbuf_reserve(&events, sizeof(*req_event), 0);
    if (!req_event)
        return TC_ACT_OK;
    
    req_event->src_addr = client_ip;
    req_event->src_port = client_port;
    req_event->method = method;
    req_event->processed_in_kernel = 0;
    __builtin_memcpy(req_event->filename, filename, MAX_FILENAME_LEN);
    req_event->content_length = 0;
    
    /* Simple kernel-space file handling for GET requests */
    if (enable_kernel_processing && method == HTTP_GET) {
        /* Check if file exists and is cacheable */
        if (check_file_exists(filename)) {
            /* Check cache first */
            struct file_cache_entry *cache_entry = bpf_map_lookup_elem(&file_cache, filename);
            
            if (cache_entry && cache_entry->valid) {
                /* Cache hit - we could respond directly here */
                req_event->processed_in_kernel = 1;
                cache_entry->cache_hits++;
                update_stats(1, 1); /* Kernel processed requests */
                
                /* Create file event */
                file_event = bpf_ringbuf_reserve(&events, sizeof(*file_event), 0);
                if (file_event) {
                    file_event->client_addr = client_ip;
                    file_event->client_port = client_port;
                    file_event->operation = FILE_OP_SUCCESS;
                    __builtin_memcpy(file_event->filename, filename, MAX_FILENAME_LEN);
                    file_event->file_size = cache_entry->file_size;
                    file_event->timestamp = bpf_ktime_get_ns();
                    file_event->forwarded_to_user = 0;
                    bpf_ringbuf_submit(file_event, 0);
                }
            } else {
                /* File exists but not cached - forward to user space for caching */
                req_event->processed_in_kernel = 0;
                update_stats(2, 1); /* Forwarded to user space */
                
                file_event = bpf_ringbuf_reserve(&events, sizeof(*file_event), 0);
                if (file_event) {
                    file_event->client_addr = client_ip;
                    file_event->client_port = client_port;
                    file_event->operation = FILE_OP_FORWARD_TO_USER;
                    __builtin_memcpy(file_event->filename, filename, MAX_FILENAME_LEN);
                    file_event->file_size = 0;
                    file_event->timestamp = bpf_ktime_get_ns();
                    file_event->forwarded_to_user = 1;
                    bpf_ringbuf_submit(file_event, 0);
                }
            }
        } else {
            /* File not found */
            file_event = bpf_ringbuf_reserve(&events, sizeof(*file_event), 0);
            if (file_event) {
                file_event->client_addr = client_ip;
                file_event->client_port = client_port;
                file_event->operation = FILE_OP_NOT_FOUND;
                __builtin_memcpy(file_event->filename, filename, MAX_FILENAME_LEN);
                file_event->file_size = 0;
                file_event->timestamp = bpf_ktime_get_ns();
                file_event->forwarded_to_user = 1;
                bpf_ringbuf_submit(file_event, 0);
            }
            update_stats(3, 1); /* File not found */
        }
    } else {
        /* POST/PUT/DELETE or kernel processing disabled - forward to user space */
        update_stats(2, 1); /* Forwarded to user space */
    }
    
    /* Update connection tracking */
    __u64 timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&conn_track, &client_ip, &timestamp, BPF_ANY);
    
    bpf_ringbuf_submit(req_event, 0);
    return TC_ACT_OK;
}

/* File operation tracing using fentry */
SEC("fentry/vfs_open")
int BPF_PROG(trace_file_open, struct path *path, struct file *file, const struct cred *cred)
{
    struct file_event *event;
    const char *filename;
    
    if (!enable_kernel_processing)
        return 0;
    
    /* Get filename from dentry */
    filename = (const char *)BPF_CORE_READ(path, dentry, d_name.name);
    if (!filename)
        return 0;
    
    /* Create file operation event */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->client_addr = 0;  /* Not available in this context */
    event->client_port = 0;
    event->operation = FILE_OP_SUCCESS;
    bpf_probe_read_str(event->filename, MAX_FILENAME_LEN, filename);
    event->file_size = 0;  /* Could be read from inode if needed */
    event->timestamp = bpf_ktime_get_ns();
    event->forwarded_to_user = 0;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Network statistics and monitoring using XDP */
SEC("xdp")
int fileserver_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    
    /* Basic packet validation */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    /* Update packet statistics */
    update_stats(4, 1); /* Total packets processed */
    
    return XDP_PASS;
}
