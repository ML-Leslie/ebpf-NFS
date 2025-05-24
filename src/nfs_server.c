// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 NFS Server Kernel Processing */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <argp.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include "nfs_server.h"
#include "nfs_server.skel.h"

static struct env {
    bool verbose;
    const char *interface;
    const char *export_root;
    bool enable_kernel_cache;
    int nfs_port;
} env = {
    .verbose = false,
    .interface = "lo",
    .export_root = "./nfs_exports",
    .enable_kernel_cache = true,
    .nfs_port = NFS_PORT,
};

const char argp_program_doc[] =
    "NFS Server with Kernel-space Processing\n"
    "\n"
    "This program demonstrates an NFS server that processes simple requests\n"
    "in kernel space and forwards complex operations to user space.\n"
    "\n"
    "USAGE: ./nfs_server [-v] [-i interface] [-e export_root] [-p port]\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "interface", 'i', "INTERFACE", 0, "Network interface to attach" },
    { "export-root", 'e', "PATH", 0, "NFS export root directory" },
    { "port", 'p', "PORT", 0, "NFS server port (default: 2049)" },
    { "no-kernel-cache", 'n', NULL, 0, "Disable kernel-space caching" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'v':
        env.verbose = true;
        break;
    case 'i':
        env.interface = arg;
        break;
    case 'e':
        env.export_root = arg;
        break;
    case 'p':
        env.nfs_port = atoi(arg);
        break;
    case 'n':
        env.enable_kernel_cache = false;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

/* NFS server statistics */
struct nfs_server_stats {
    uint64_t total_requests;
    uint64_t kernel_processed;
    uint64_t user_processed;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t file_not_found;
    uint64_t access_denied;
    uint64_t errors;
} stats = {0};

/* Simple XDR encoding helpers */
static inline void xdr_encode_u32(char **p, uint32_t val)
{
    *((uint32_t *)*p) = htonl(val);
    *p += 4;
}

static inline void xdr_encode_u64(char **p, uint64_t val)
{
    *((uint32_t *)*p) = htonl((uint32_t)(val >> 32));
    *p += 4;
    *((uint32_t *)*p) = htonl((uint32_t)(val & 0xFFFFFFFF));
    *p += 4;
}

static inline uint32_t xdr_decode_u32(char **p)
{
    uint32_t val = ntohl(*((uint32_t *)*p));
    *p += 4;
    return val;
}

/* Generate NFS file handle from filename */
static void generate_nfs_file_handle(const char *filename, struct nfs_fh *fh)
{
    fh->len = 8;
    
    /* Simple hash-based file handle */
    uint32_t hash = 0;
    for (int i = 0; filename[i] && i < strlen(filename); i++) {
        hash = hash * 31 + filename[i];
    }
    
    *((uint32_t *)&fh->data[0]) = hash;
    *((uint32_t *)&fh->data[4]) = hash ^ 0xdeadbeef;
}

/* Cache file in kernel space */
static int cache_file_in_kernel(struct nfs_server_bpf *skel, const char *filename)
{
    char filepath[512];
    struct stat st;
    int fd;
    struct nfs_file_cache_entry cache_entry = {0};
    
    if (!env.enable_kernel_cache)
        return 0;
    
    snprintf(filepath, sizeof(filepath), "%s/%s", env.export_root, filename);
    
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode))
        return -1;
    
    /* Only cache small files in kernel */
    if (st.st_size > MAX_NFS_DATA_SIZE)
        return -1;
    
    fd = open(filepath, O_RDONLY);
    if (fd < 0)
        return -1;
    
    ssize_t bytes_read = read(fd, cache_entry.data, st.st_size);
    close(fd);
    
    if (bytes_read != st.st_size)
        return -1;
    
    /* Fill cache entry */
    strncpy(cache_entry.filename, filename, MAX_FILENAME_LEN - 1);
    generate_nfs_file_handle(filename, &cache_entry.fh);
    
    /* Fill file attributes */
    cache_entry.attr.type = S_ISDIR(st.st_mode) ? 2 : 1; /* 1=REG, 2=DIR */
    cache_entry.attr.mode = st.st_mode;
    cache_entry.attr.nlink = st.st_nlink;
    cache_entry.attr.uid = st.st_uid;
    cache_entry.attr.gid = st.st_gid;
    cache_entry.attr.size = st.st_size;
    cache_entry.attr.used = st.st_blocks * 512;
    cache_entry.attr.fsid = 1; /* Simple filesystem ID */
    cache_entry.attr.fileid = st.st_ino;
    cache_entry.attr.atime_sec = st.st_atime;
    cache_entry.attr.mtime_sec = st.st_mtime;
    cache_entry.attr.ctime_sec = st.st_ctime;
    
    cache_entry.data_size = st.st_size;
    cache_entry.cache_time = time(NULL) * 1000000000ULL; /* nanoseconds */
    cache_entry.valid = 1;
    cache_entry.data_valid = 1;
    cache_entry.cache_hits = 0;
    
    /* Update kernel cache map */
    int cache_map_fd = bpf_map__fd(skel->maps.nfs_file_cache);
    int fh_map_fd = bpf_map__fd(skel->maps.fh_to_name);
    
    if (bpf_map_update_elem(cache_map_fd, filename, &cache_entry, BPF_ANY) != 0)
        return -1;
    
    /* Update file handle to name mapping */
    if (bpf_map_update_elem(fh_map_fd, &cache_entry.fh, filename, BPF_ANY) != 0)
        return -1;
    
    return 0;
}

/* Handle NFS GETATTR request */
static void handle_nfs_getattr(int client_sock, struct sockaddr_in *client_addr,
                              char *request, int req_len, uint32_t xid)
{
    char response[1024];
    char *p = response;
    char filename[MAX_FILENAME_LEN];
    char filepath[512];
    struct stat st;
    
    /* For demonstration, extract filename from request - in real NFS this would be file handle */
    /* This is a simplified implementation */
    strcpy(filename, "test.txt"); /* Default file for demo */
    
    snprintf(filepath, sizeof(filepath), "%s/%s", env.export_root, filename);
    
    /* Encode RPC reply header */
    xdr_encode_u32(&p, xid);                    /* XID */
    xdr_encode_u32(&p, 1);                      /* REPLY */
    xdr_encode_u32(&p, 0);                      /* MSG_ACCEPTED */
    xdr_encode_u32(&p, 0);                      /* AUTH_NULL */
    xdr_encode_u32(&p, 0);                      /* Auth length */
    xdr_encode_u32(&p, 0);                      /* ACCEPT_STAT = SUCCESS */
    
    /* Check if file exists */
    if (stat(filepath, &st) != 0) {
        xdr_encode_u32(&p, 2);                  /* NFS3ERR_NOENT */
    } else {
        xdr_encode_u32(&p, 0);                  /* NFS3_OK */
        
        /* Encode file attributes */
        xdr_encode_u32(&p, S_ISDIR(st.st_mode) ? 2 : 1); /* file type */
        xdr_encode_u32(&p, st.st_mode);         /* mode */
        xdr_encode_u32(&p, st.st_nlink);        /* nlink */
        xdr_encode_u32(&p, st.st_uid);          /* uid */
        xdr_encode_u32(&p, st.st_gid);          /* gid */
        xdr_encode_u64(&p, st.st_size);         /* size */
        xdr_encode_u64(&p, st.st_blocks * 512); /* used */
        xdr_encode_u64(&p, 1);                  /* fsid */
        xdr_encode_u64(&p, st.st_ino);          /* fileid */
        xdr_encode_u64(&p, st.st_atime);        /* atime */
        xdr_encode_u32(&p, 0);                  /* atime nsec */
        xdr_encode_u64(&p, st.st_mtime);        /* mtime */
        xdr_encode_u32(&p, 0);                  /* mtime nsec */
        xdr_encode_u64(&p, st.st_ctime);        /* ctime */
        xdr_encode_u32(&p, 0);                  /* ctime nsec */
        
        stats.user_processed++;
    }
    
    /* Send response */
    sendto(client_sock, response, p - response, 0, 
           (struct sockaddr *)client_addr, sizeof(*client_addr));
}

/* Handle NFS READ request */
static void handle_nfs_read(int client_sock, struct sockaddr_in *client_addr,
                           char *request, int req_len, uint32_t xid)
{
    char response[4096];
    char *p = response;
    char filename[MAX_FILENAME_LEN];
    char filepath[512];
    int fd;
    ssize_t bytes_read;
    uint32_t offset = 0, count = 1024; /* Simplified - would parse from request */
    
    /* For demonstration */
    strcpy(filename, "test.txt");
    snprintf(filepath, sizeof(filepath), "%s/%s", env.export_root, filename);
    
    /* Encode RPC reply header */
    xdr_encode_u32(&p, xid);                    /* XID */
    xdr_encode_u32(&p, 1);                      /* REPLY */
    xdr_encode_u32(&p, 0);                      /* MSG_ACCEPTED */
    xdr_encode_u32(&p, 0);                      /* AUTH_NULL */
    xdr_encode_u32(&p, 0);                      /* Auth length */
    xdr_encode_u32(&p, 0);                      /* ACCEPT_STAT = SUCCESS */
    
    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        xdr_encode_u32(&p, 2);                  /* NFS3ERR_NOENT */
    } else {
        lseek(fd, offset, SEEK_SET);
        bytes_read = read(fd, p + 12, count);   /* Reserve space for NFS header */
        close(fd);
        
        if (bytes_read < 0) {
            xdr_encode_u32(&p, 5);              /* NFS3ERR_IO */
        } else {
            xdr_encode_u32(&p, 0);              /* NFS3_OK */
            xdr_encode_u32(&p, bytes_read);     /* count */
            xdr_encode_u32(&p, bytes_read < count ? 1 : 0); /* eof */
            xdr_encode_u32(&p, bytes_read);     /* data length */
            p += bytes_read;                    /* Skip over data */
            
            stats.user_processed++;
        }
    }
    
    /* Send response */
    sendto(client_sock, response, p - response, 0,
           (struct sockaddr *)client_addr, sizeof(*client_addr));
}

/* Process NFS request in user space */
static void process_nfs_request(int client_sock, struct sockaddr_in *client_addr,
                               char *buffer, int len)
{
    char *p = buffer;
    uint32_t xid, msg_type, rpc_vers, prog, vers, proc;
    
    if (len < 24) /* Minimum RPC header size */
        return;
    
    /* Decode RPC header */
    xid = xdr_decode_u32(&p);
    msg_type = xdr_decode_u32(&p);
    rpc_vers = xdr_decode_u32(&p);
    prog = xdr_decode_u32(&p);
    vers = xdr_decode_u32(&p);
    proc = xdr_decode_u32(&p);
    
    if (msg_type != 0 || rpc_vers != 2 || prog != RPC_PROGRAM_NFS || vers != NFS_VERSION_3)
        return;
    
    stats.total_requests++;
    
    switch (proc) {
        case NFSPROC3_GETATTR:
            handle_nfs_getattr(client_sock, client_addr, buffer, len, xid);
            break;
        case NFSPROC3_READ:
            handle_nfs_read(client_sock, client_addr, buffer, len, xid);
            break;
        default:
            if (env.verbose)
                printf("Unsupported NFS procedure: %u\n", proc);
            break;
    }
}

/* Event handler for eBPF events */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct nfs_request *req = data;
    const struct nfs_event *event = data;
    
    if (data_sz == sizeof(struct nfs_request)) {
        if (env.verbose) {
            printf("NFS Request: client=%s:%u xid=%u proc=%u kernel=%d file='%s'\n",
                   inet_ntoa((struct in_addr){req->client_addr}), 
                   ntohs(req->client_port), req->xid, req->procedure,
                   req->processed_in_kernel, req->filename);
        }
    } else if (data_sz == sizeof(struct nfs_event)) {
        if (env.verbose) {
            printf("NFS Event: client=%s:%u xid=%u proc=%u result=%u forward=%d cache=%d file='%s'\n",
                   inet_ntoa((struct in_addr){event->client_addr}),
                   ntohs(event->client_port), event->xid, event->procedure,
                   event->result, event->forwarded_to_user, event->from_cache, event->filename);
        }
        
        /* Update statistics based on event */
        if (event->from_cache) {
            stats.cache_hits++;
        } else if (event->forwarded_to_user) {
            stats.cache_misses++;
        }
        
        if (event->result == NFS_OP_SUCCESS && !event->forwarded_to_user) {
            stats.kernel_processed++;
        }
    }
    
    return 0;
}

/* Print statistics */
static void print_stats(void)
{
    printf("\n=== NFS Server Statistics ===\n");
    printf("Total requests:      %lu\n", stats.total_requests);
    printf("Kernel processed:    %lu\n", stats.kernel_processed);
    printf("User processed:      %lu\n", stats.user_processed);
    printf("Cache hits:          %lu\n", stats.cache_hits);
    printf("Cache misses:        %lu\n", stats.cache_misses);
    printf("File not found:      %lu\n", stats.file_not_found);
    printf("Access denied:       %lu\n", stats.access_denied);
    printf("Errors:              %lu\n", stats.errors);
    printf("==============================\n");
}

/* Main NFS server function */
int main(int argc, char **argv)
{
    struct nfs_server_bpf *skel;
    int err, server_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[4096];
    struct ring_buffer *rb;
    int ifindex;
    
    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;
    
    libbpf_set_print(libbpf_print_fn);
    
    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Create export directory if it doesn't exist */
    mkdir(env.export_root, 0755);
    
    /* Create a test file for demonstration */
    char test_file[512];
    snprintf(test_file, sizeof(test_file), "%s/test.txt", env.export_root);
    int fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, "Hello from NFS server!\n", 23);
        close(fd);
    }
    
    /* Open, load and verify BPF application */
    skel = nfs_server_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    /* Load & verify BPF programs */
    err = nfs_server_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }
    
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.nfs_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    /* Get interface index */
    ifindex = if_nametoindex(env.interface);
    if (!ifindex) {
        err = -errno;
        fprintf(stderr, "Failed to get interface index for %s: %s\n", 
                env.interface, strerror(-err));
        goto cleanup;
    }
    
    /* Attach TC program */
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1, .prog_fd = bpf_program__fd(skel->progs.nfs_server_tc));
    
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-err));
        goto cleanup;
    }
    
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC program: %s\n", strerror(-err));
        goto cleanup;
    }
    
    printf("Successfully started NFS server on %s:%d\n", env.interface, env.nfs_port);
    printf("Export root: %s\n", env.export_root);
    printf("Kernel processing: %s\n", env.enable_kernel_cache ? "enabled" : "disabled");
    
    /* Pre-cache some files */
    if (env.enable_kernel_cache) {
        cache_file_in_kernel(skel, "test.txt");
        printf("Pre-cached test.txt in kernel\n");
    }
    
    /* Create UDP socket for NFS */
    server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_sock < 0) {
        err = -errno;
        fprintf(stderr, "Failed to create socket: %s\n", strerror(-err));
        goto cleanup;
    }
    
    /* Bind to NFS port */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(env.nfs_port);
    
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        err = -errno;
        fprintf(stderr, "Failed to bind to port %d: %s\n", env.nfs_port, strerror(-err));
        goto cleanup;
    }
    
    printf("NFS server listening on UDP port %d\n", env.nfs_port);
    
    /* Main event loop */
    while (!exiting) {
        /* Poll eBPF events */
        err = ring_buffer__poll(rb, 100 /* timeout_ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
        
        /* Check for incoming NFS requests */
        fd_set readfds;
        struct timeval tv = {0, 100000}; /* 100ms timeout */
        
        FD_ZERO(&readfds);
        FD_SET(server_sock, &readfds);
        
        int activity = select(server_sock + 1, &readfds, NULL, NULL, &tv);
        if (activity > 0 && FD_ISSET(server_sock, &readfds)) {
            ssize_t len = recvfrom(server_sock, buffer, sizeof(buffer), 0,
                                  (struct sockaddr *)&client_addr, &client_len);
            if (len > 0) {
                process_nfs_request(server_sock, &client_addr, buffer, len);
            }
        }
    }
    
    print_stats();

cleanup:
    /* Cleanup */
    if (rb)
        ring_buffer__free(rb);
    if (server_sock >= 0)
        close(server_sock);
    nfs_server_bpf__destroy(skel);
    return -err;
}
