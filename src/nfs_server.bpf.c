// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2024 NFS Server Kernel Processing */
#define __KERNEL__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "nfs_server.h"

/* TC action definitions */
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
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
} nfs_events SEC(".maps");

/* NFS file cache map for frequently accessed files */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, struct nfs_file_cache_entry);
} nfs_file_cache SEC(".maps");

/* NFS file handle to filename mapping */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct nfs_fh);
    __type(value, char[MAX_FILENAME_LEN]);
} fh_to_name SEC(".maps");

/* Client connection tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  /* client IP */
    __type(value, struct nfs_client_state);
} client_track SEC(".maps");

/* Statistics map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} nfs_stats SEC(".maps");

/* Configuration - can be set from user space */
const volatile unsigned int enable_kernel_processing = 1;
const volatile unsigned int max_cached_file_size = 4096;
const volatile unsigned int cache_ttl_seconds = 300;

/* Helper function to extract 32-bit big-endian value */
static inline __u32 extract_be32(void *data, void *data_end, int offset)
{
    if ((char *)data + offset + 4 > (char *)data_end)
        return 0;
    return bpf_ntohl(*(__u32 *)((char *)data + offset));
}

/* Helper function to parse RPC header */
static inline int parse_rpc_header(void *data, void *data_end, int payload_len, 
                                   struct rpc_header *rpc)
{
    if (payload_len < sizeof(struct rpc_header))
        return -1;
    
    if ((char *)data + sizeof(struct rpc_header) > (char *)data_end)
        return -1;
    
    rpc->xid = extract_be32(data, data_end, 0);
    rpc->msg_type = extract_be32(data, data_end, 4);
    rpc->rpc_version = extract_be32(data, data_end, 8);
    rpc->program = extract_be32(data, data_end, 12);
    rpc->version = extract_be32(data, data_end, 16);
    rpc->procedure = extract_be32(data, data_end, 20);
    rpc->auth_flavor = extract_be32(data, data_end, 24);
    rpc->auth_len = extract_be32(data, data_end, 28);
    
    return 0;
}

/* Helper function to check if file exists in cache */
static inline struct nfs_file_cache_entry *
lookup_file_cache(const char *filename)
{
    return bpf_map_lookup_elem(&nfs_file_cache, filename);
}

/* Helper function to generate simple file handle from filename */
static inline void generate_file_handle(const char *filename, struct nfs_fh *fh)
{
    fh->len = 8;  /* Simple 8-byte handle */
    
    /* Simple hash of filename - in real implementation would be more robust */
    __u32 hash = 0;
    for (int i = 0; i < MAX_FILENAME_LEN && filename[i] != '\0'; i++) {
        hash = hash * 31 + filename[i];
        if (i >= 3) break;  /* Limit loop to prevent verifier issues */
    }
    
    *(__u32 *)&fh->data[0] = hash;
    *(__u32 *)&fh->data[4] = hash ^ 0xdeadbeef;
}

/* Update statistics */
static inline void update_nfs_stats(__u32 stat_type, __u64 value)
{
    __u64 *counter = bpf_map_lookup_elem(&nfs_stats, &stat_type);
    if (counter) {
        __sync_fetch_and_add(counter, value);
    }
}

/* Handle NFS GETATTR procedure in kernel */
static inline int handle_nfs_getattr(struct nfs_request *req, 
                                     struct nfs_event *event)
{
    struct nfs_file_cache_entry *cache_entry;
    char filename[MAX_FILENAME_LEN];
    
    /* Look up filename from file handle */
    char *cached_name = bpf_map_lookup_elem(&fh_to_name, &req->fh);
    if (!cached_name) {
        event->result = NFS_OP_FORWARD_TO_USER;
        event->forwarded_to_user = 1;
        return 0;
    }
    
    /* Copy filename with bounds checking */
    for (int i = 0; i < MAX_FILENAME_LEN - 1; i++) {
        filename[i] = cached_name[i];
        if (cached_name[i] == '\0')
            break;
    }
    filename[MAX_FILENAME_LEN - 1] = '\0';
    
    /* Check cache for file attributes */
    cache_entry = lookup_file_cache(filename);
    if (!cache_entry || !cache_entry->valid) {
        event->result = NFS_OP_FORWARD_TO_USER;
        event->forwarded_to_user = 1;
        __builtin_memcpy(event->filename, filename, MAX_FILENAME_LEN);
        return 0;
    }
    
    /* Check cache TTL */
    __u64 current_time = bpf_ktime_get_ns();
    if (current_time - cache_entry->cache_time > (cache_ttl_seconds * 1000000000ULL)) {
        event->result = NFS_OP_FORWARD_TO_USER;
        event->forwarded_to_user = 1;
        __builtin_memcpy(event->filename, filename, MAX_FILENAME_LEN);
        return 0;
    }
    
    /* Cache hit - attributes available in kernel */
    cache_entry->cache_hits++;
    event->result = NFS_OP_SUCCESS;
    event->forwarded_to_user = 0;
    event->from_cache = 1;
    event->file_size = cache_entry->attr.size;
    __builtin_memcpy(event->filename, filename, MAX_FILENAME_LEN);
    
    update_nfs_stats(1, 1); /* Kernel processed */
    return 1; /* Handled in kernel */
}

/* Handle NFS READ procedure in kernel */
static inline int handle_nfs_read(struct nfs_request *req, 
                                 struct nfs_event *event)
{
    struct nfs_file_cache_entry *cache_entry;
    char filename[MAX_FILENAME_LEN];
    
    /* Look up filename from file handle */
    char *cached_name = bpf_map_lookup_elem(&fh_to_name, &req->fh);
    if (!cached_name) {
        event->result = NFS_OP_FORWARD_TO_USER;
        event->forwarded_to_user = 1;
        return 0;
    }
    
    /* Copy filename */
    for (int i = 0; i < MAX_FILENAME_LEN - 1; i++) {
        filename[i] = cached_name[i];
        if (cached_name[i] == '\0')
            break;
    }
    filename[MAX_FILENAME_LEN - 1] = '\0';
    
    /* Check if file is cached and small enough for kernel processing */
    cache_entry = lookup_file_cache(filename);
    if (!cache_entry || !cache_entry->valid || !cache_entry->data_valid) {
        event->result = NFS_OP_FORWARD_TO_USER;
        event->forwarded_to_user = 1;
        __builtin_memcpy(event->filename, filename, MAX_FILENAME_LEN);
        return 0;
    }
    
    /* Check if read request is within cached data bounds */
    if (req->offset >= cache_entry->data_size || 
        req->count > MAX_NFS_DATA_SIZE ||
        req->offset + req->count > cache_entry->data_size) {
        event->result = NFS_OP_FORWARD_TO_USER;
        event->forwarded_to_user = 1;
        __builtin_memcpy(event->filename, filename, MAX_FILENAME_LEN);
        return 0;
    }
    
    /* Can handle in kernel - data is cached */
    cache_entry->cache_hits++;
    event->result = NFS_OP_SUCCESS;
    event->forwarded_to_user = 0;
    event->from_cache = 1;
    event->file_size = req->count;
    __builtin_memcpy(event->filename, filename, MAX_FILENAME_LEN);
    
    update_nfs_stats(1, 1); /* Kernel processed */
    return 1; /* Handled in kernel */
}

/* Main TC handler for NFS packets */
SEC("tc")
int nfs_server_tc(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    void *nfs_payload;
    __u16 payload_len;
    struct rpc_header rpc;
    struct nfs_request *req_event;
    struct nfs_event *nfs_event;
    __u32 client_ip;
    __u16 client_port;
    struct nfs_client_state *client_state;
    int handled_in_kernel = 0;
    
    /* Basic packet validation */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    /* Check if this is NFS traffic (port 2049) */
    if (udp->dest != bpf_htons(NFS_PORT))
        return TC_ACT_OK;
    
    /* Extract NFS payload */
    nfs_payload = (void *)udp + sizeof(struct udphdr);
    if (nfs_payload >= data_end)
        return TC_ACT_OK;
    
    payload_len = data_end - nfs_payload;
    if (payload_len < sizeof(struct rpc_header))
        return TC_ACT_OK;
    
    /* Parse RPC header */
    if (parse_rpc_header(nfs_payload, data_end, payload_len, &rpc) < 0)
        return TC_ACT_OK;
    
    /* Validate this is an NFS call */
    if (rpc.msg_type != RPC_CALL || 
        rpc.rpc_version != 2 ||
        rpc.program != RPC_PROGRAM_NFS ||
        rpc.version != NFS_VERSION_3)
        return TC_ACT_OK;
    
    client_ip = ip->saddr;
    client_port = udp->source;
    
    /* Update client tracking */
    client_state = bpf_map_lookup_elem(&client_track, &client_ip);
    if (!client_state) {
        struct nfs_client_state new_state = {
            .client_addr = client_ip,
            .last_request_time = bpf_ktime_get_ns(),
            .request_count = 1,
            .kernel_processed = 0,
            .user_forwarded = 0
        };
        bpf_map_update_elem(&client_track, &client_ip, &new_state, BPF_ANY);
        client_state = &new_state;
    } else {
        client_state->last_request_time = bpf_ktime_get_ns();
        client_state->request_count++;
    }
    
    /* Create NFS request event */
    req_event = bpf_ringbuf_reserve(&nfs_events, sizeof(*req_event), 0);
    if (!req_event)
        return TC_ACT_OK;
    
    req_event->client_addr = client_ip;
    req_event->client_port = client_port;
    req_event->xid = rpc.xid;
    req_event->procedure = rpc.procedure;
    req_event->processed_in_kernel = 0;
    req_event->filename[0] = '\0';
    req_event->offset = 0;
    req_event->count = 0;
    __builtin_memset(&req_event->fh, 0, sizeof(req_event->fh));
    
    /* Create NFS operation event */
    nfs_event = bpf_ringbuf_reserve(&nfs_events, sizeof(*nfs_event), 0);
    if (!nfs_event) {
        bpf_ringbuf_discard(req_event, 0);
        return TC_ACT_OK;
    }
    
    nfs_event->client_addr = client_ip;
    nfs_event->client_port = client_port;
    nfs_event->xid = rpc.xid;
    nfs_event->procedure = rpc.procedure;
    nfs_event->result = NFS_OP_FORWARD_TO_USER;
    nfs_event->filename[0] = '\0';
    nfs_event->file_size = 0;
    nfs_event->timestamp = bpf_ktime_get_ns();
    nfs_event->forwarded_to_user = 1;
    nfs_event->from_cache = 0;
    
    /* Handle specific NFS procedures in kernel if enabled */
    if (enable_kernel_processing) {
        switch (rpc.procedure) {
            case NFSPROC3_NULL:
                /* NULL operation can be handled immediately */
                nfs_event->result = NFS_OP_SUCCESS;
                nfs_event->forwarded_to_user = 0;
                nfs_event->from_cache = 0;
                handled_in_kernel = 1;
                update_nfs_stats(1, 1); /* Kernel processed */
                break;
            case NFSPROC3_GETATTR:
                handled_in_kernel = handle_nfs_getattr(req_event, nfs_event);
                break;
            case NFSPROC3_READ:
                handled_in_kernel = handle_nfs_read(req_event, nfs_event);
                break;
            default:
                /* Forward complex operations to user space */
                nfs_event->result = NFS_OP_FORWARD_TO_USER;
                nfs_event->forwarded_to_user = 1;
                break;
        }
    }
    
    /* Update statistics */
    update_nfs_stats(0, 1); /* Total requests */
    if (handled_in_kernel) {
        req_event->processed_in_kernel = 1;
        client_state->kernel_processed++;
    } else {
        client_state->user_forwarded++;
        update_nfs_stats(2, 1); /* Forwarded to user space */
    }
    
    /* Submit events */
    bpf_ringbuf_submit(req_event, 0);
    bpf_ringbuf_submit(nfs_event, 0);
    
    return TC_ACT_OK;
}

/* Tracepoint for VFS operations to track file access */
SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    if (!enable_kernel_processing)
        return 0;
    
    /* This could be used to track file opens and pre-cache frequently accessed files */
    update_nfs_stats(3, 1); /* File system operations */
    return 0;
}

/* XDP program for early packet filtering */
SEC("xdp")
int nfs_server_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    
    /* Basic validation for NFS packets */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    
    /* Count NFS packets */
    if (udp->dest == bpf_htons(NFS_PORT)) {
        update_nfs_stats(4, 1); /* NFS packets received */
    }
    
    return XDP_PASS;
}
