// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2023 File Server Kernel Processing */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include <argp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include "fileserver.h"
#include "fileserver.skel.h"

static struct env {
    bool verbose;
    const char *interface;
    const char *document_root;
    int server_port;
    bool enable_kernel_cache;
} env = {
    .verbose = false,
    .interface = "lo",
    .document_root = "./www",
    .server_port = 8080,
    .enable_kernel_cache = true,
};

const char argp_program_doc[] =
    "File Server with Kernel-space Processing\n"
    "\n"
    "This program demonstrates a file server that processes simple requests\n"
    "in kernel space and forwards complex operations to user space.\n"
    "\n"
    "USAGE: ./fileserver [-v] [-i interface] [-d document_root] [-p port]\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "interface", 'i', "INTERFACE", 0, "Network interface to attach" },
    { "document-root", 'd', "PATH", 0, "Document root directory" },
    { "port", 'p', "PORT", 0, "Server port (default: 8080)" },
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
    case 'd':
        env.document_root = arg;
        break;
    case 'p':
        env.server_port = atoi(arg);
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

/* Statistics tracking */
struct server_stats {
    uint64_t total_requests;
    uint64_t kernel_processed;
    uint64_t user_processed;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t file_not_found;
    uint64_t errors;
} stats = {0};

/* Simple HTTP response helper */
static void send_http_response(int client_sock, int status_code, const char *content_type, 
                              const char *body, size_t body_len)
{
    char header[512];
    const char *status_text;
    
    switch (status_code) {
        case 200: status_text = "OK"; break;
        case 404: status_text = "Not Found"; break;
        case 500: status_text = "Internal Server Error"; break;
        default: status_text = "Unknown"; break;
    }
    
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text, content_type, body_len);
    
    send(client_sock, header, header_len, 0);
    if (body && body_len > 0) {
        send(client_sock, body, body_len, 0);
    }
}

/* File serving function */
static int serve_file(int client_sock, const char *filename)
{
    char filepath[512];
    struct stat st;
    int fd;
    char *buffer;
    ssize_t bytes_read;
    
    /* Construct full file path */
    snprintf(filepath, sizeof(filepath), "%s/%s", env.document_root, filename);
    
    /* Security check - prevent directory traversal */
    if (strstr(filename, "..") || strstr(filename, "//")) {
        send_http_response(client_sock, 403, "text/plain", "Forbidden", 9);
        return -1;
    }
    
    /* Check if file exists and get size */
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode)) {
        const char *not_found = "<html><body><h1>404 Not Found</h1></body></html>";
        send_http_response(client_sock, 404, "text/html", not_found, strlen(not_found));
        stats.file_not_found++;
        return -1;
    }
    
    /* Open and read file */
    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        send_http_response(client_sock, 500, "text/plain", "Internal Server Error", 21);
        stats.errors++;
        return -1;
    }
    
    buffer = malloc(st.st_size + 1);
    if (!buffer) {
        close(fd);
        send_http_response(client_sock, 500, "text/plain", "Internal Server Error", 21);
        stats.errors++;
        return -1;
    }
    
    bytes_read = read(fd, buffer, st.st_size);
    close(fd);
    
    if (bytes_read != st.st_size) {
        free(buffer);
        send_http_response(client_sock, 500, "text/plain", "Internal Server Error", 21);
        stats.errors++;
        return -1;
    }
    
    /* Determine content type */
    const char *content_type = "text/plain";
    if (strstr(filename, ".html") || strstr(filename, ".htm"))
        content_type = "text/html";
    else if (strstr(filename, ".css"))
        content_type = "text/css";
    else if (strstr(filename, ".js"))
        content_type = "application/javascript";
    else if (strstr(filename, ".jpg") || strstr(filename, ".jpeg"))
        content_type = "image/jpeg";
    else if (strstr(filename, ".png"))
        content_type = "image/png";
    
    send_http_response(client_sock, 200, content_type, buffer, bytes_read);
    free(buffer);
    stats.user_processed++;
    
    return 0;
}

/* Cache file in kernel space */
static int cache_file_in_kernel(struct fileserver_bpf *skel, const char *filename)
{
    char filepath[512];
    struct stat st;
    int fd;
    struct file_cache_entry cache_entry = {0};
    
    if (!env.enable_kernel_cache)
        return 0;
    
    snprintf(filepath, sizeof(filepath), "%s/%s", env.document_root, filename);
    
    if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > MAX_PACKET_SIZE)
        return -1;
    
    fd = open(filepath, O_RDONLY);
    if (fd < 0)
        return -1;
    
    ssize_t bytes_read = read(fd, cache_entry.cached_data, st.st_size);
    close(fd);
    
    if (bytes_read != st.st_size)
        return -1;
    
    strncpy(cache_entry.filename, filename, MAX_FILENAME_LEN - 1);
    cache_entry.file_size = st.st_size;
    cache_entry.last_modified = st.st_mtime;
    cache_entry.valid = 1;
    cache_entry.cache_hits = 0;
    
    /* Update kernel cache map */
    int map_fd = bpf_map__fd(skel->maps.file_cache);
    return bpf_map_update_elem(map_fd, filename, &cache_entry, BPF_ANY);
}

/* Handle HTTP request */
static void handle_http_request(int client_sock, const char *request, struct fileserver_bpf *skel)
{
    char method[16], path[256], version[16];
    char filename[MAX_FILENAME_LEN] = {0};
    
    /* Parse request line */
    if (sscanf(request, "%15s %255s %15s", method, path, version) != 3) {
        send_http_response(client_sock, 400, "text/plain", "Bad Request", 11);
        return;
    }
    
    /* Extract filename from path */
    if (strcmp(path, "/") == 0) {
        strcpy(filename, "index.html");
    } else {
        strncpy(filename, path + 1, MAX_FILENAME_LEN - 1);
    }
    
    if (strcmp(method, "GET") == 0) {
        /* Try to cache file in kernel first */
        if (cache_file_in_kernel(skel, filename) == 0) {
            if (env.verbose)
                printf("Cached file '%s' in kernel\n", filename);
        }
        
        serve_file(client_sock, filename);
    } else {
        send_http_response(client_sock, 405, "text/plain", "Method Not Allowed", 18);
    }
    
    stats.total_requests++;
}

/* Forward declaration */
static int handle_event(void *ctx, void *data, size_t data_sz);

/* Simple HTTP server with BPF event integration */
static int run_http_server(struct fileserver_bpf *skel)
{
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[4096];
    struct ring_buffer *rb;
    
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return -1;
    }
    
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        ring_buffer__free(rb);
        return -1;
    }
    
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(env.server_port);
    
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        ring_buffer__free(rb);
        return -1;
    }
    
    if (listen(server_sock, 10) < 0) {
        perror("listen");
        close(server_sock);
        ring_buffer__free(rb);
        return -1;
    }
    
    printf("File server listening on port %d\n", env.server_port);
    printf("Document root: %s\n", env.document_root);
    
    while (!exiting) {
        fd_set read_fds;
        struct timeval timeout;
        
        FD_ZERO(&read_fds);
        FD_SET(server_sock, &read_fds);
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; /* 100ms */
        
        int activity = select(server_sock + 1, &read_fds, NULL, NULL, &timeout);
        if (activity < 0 && errno != EINTR) {
            perror("select");
            break;
        }
        
        /* Poll for BPF events */
        int poll_err = ring_buffer__poll(rb, 0 /* non-blocking */);
        if (poll_err < 0 && poll_err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", poll_err);
        }
        
        if (activity > 0 && FD_ISSET(server_sock, &read_fds)) {
            client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
            if (client_sock < 0) {
                if (errno != EINTR)
                    perror("accept");
                continue;
            }
            
            ssize_t bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                handle_http_request(client_sock, buffer, skel);
            }
            
            close(client_sock);
        }
    }
    
    close(server_sock);
    ring_buffer__free(rb);
    return 0;
}

/* Event handler for BPF ring buffer events */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz == sizeof(struct http_request)) {
        struct http_request *req = data;
        if (env.verbose) {
            printf("HTTP Request: %s %s from %s:%d - %s\n",
                   req->method == HTTP_GET ? "GET" : 
                   req->method == HTTP_POST ? "POST" : "OTHER",
                   req->filename,
                   inet_ntoa(*(struct in_addr*)&req->src_addr),
                   ntohs(req->src_port),
                   req->processed_in_kernel ? "processed in kernel" : "forwarded to user");
        }
        if (req->processed_in_kernel) {
            stats.kernel_processed++;
        }
    } else if (data_sz == sizeof(struct file_event)) {
        struct file_event *event = data;
        if (env.verbose) {
            printf("File Event: %s - %s (size: %u bytes)\n",
                   event->filename,
                   event->operation == FILE_OP_SUCCESS ? "success" :
                   event->operation == FILE_OP_NOT_FOUND ? "not found" :
                   event->operation == FILE_OP_FORWARD_TO_USER ? "forwarded" : "error",
                   event->file_size);
        }
    }
    
    return 0;
}

/* Attach TC program to network interface */
static int attach_tc_program(struct fileserver_bpf *skel, const char *ifname)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = if_nametoindex(ifname),
                        .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1,
                        .prog_fd = bpf_program__fd(skel->progs.fileserver_ingress));
    int err;

    if (!hook.ifindex) {
        fprintf(stderr, "Interface %s not found\n", ifname);
        return -ENOENT;
    }

    if (env.verbose) {
        printf("Attaching TC program to interface %s (ifindex: %d)\n", ifname, hook.ifindex);
    }

    /* Try to clean up any existing filters first */
    bpf_tc_detach(&hook, &opts);
    
    /* Create TC qdisc */
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %d\n", err);
        return err;
    }

    /* Attach TC program */
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Failed to attach TC program: %d\n", err);
        return err;
    }

    if (env.verbose) {
        printf("Successfully attached TC program to %s\n", ifname);
    }

    return 0;
}

/* Print statistics */
static void print_stats(struct fileserver_bpf *skel)
{
    printf("\n=== Server Statistics ===\n");
    printf("Total Requests: %lu\n", stats.total_requests);
    printf("Kernel Processed: %lu\n", stats.kernel_processed);
    printf("User Processed: %lu\n", stats.user_processed);
    printf("File Not Found: %lu\n", stats.file_not_found);
    printf("Errors: %lu\n", stats.errors);
    
    /* Read BPF statistics */
    int stats_fd = bpf_map__fd(skel->maps.stats);
    if (stats_fd >= 0) {
        uint64_t value;
        uint32_t key;
        
        key = 0; /* Total requests in BPF */
        if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0)
            printf("BPF Total Requests: %lu\n", value);
        
        key = 1; /* Kernel processed in BPF */
        if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0)
            printf("BPF Kernel Processed: %lu\n", value);
        
        key = 2; /* Forwarded to user space */
        if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0)
            printf("BPF Forwarded to User: %lu\n", value);
        
        key = 4; /* Total packets processed */
        if (bpf_map_lookup_elem(stats_fd, &key, &value) == 0)
            printf("BPF Total Packets: %lu\n", value);
    }
    printf("========================\n");
}

int main(int argc, char **argv)
{
    struct fileserver_bpf *skel;
    int err;
    
    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;
    
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);
    
    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Create document root directory if it doesn't exist */
    mkdir(env.document_root, 0755);
    
    /* Create a simple index.html for testing */
    char index_path[512];
    snprintf(index_path, sizeof(index_path), "%s/index.html", env.document_root);
    FILE *f = fopen(index_path, "w");
    if (f) {
        fprintf(f, "<html><body><h1>File Server with Kernel Processing</h1>");
        fprintf(f, "<p>This is a demonstration of eBPF-based file server.</p>");
        fprintf(f, "<p>Server time: %s</p>", ctime(&(time_t){time(NULL)}));
        fprintf(f, "</body></html>");
        fclose(f);
    }
    
    /* Load and verify BPF application */
    skel = fileserver_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Attach TC program to interface */
    err = attach_tc_program(skel, env.interface);
    if (err) {
        fprintf(stderr, "Failed to attach TC program to interface %s: %d\n", env.interface, err);
        goto cleanup;
    }
    
    printf("File Server with Kernel Processing started\n");
    printf("Interface: %s\n", env.interface);
    printf("Document root: %s\n", env.document_root);
    printf("Kernel caching: %s\n", env.enable_kernel_cache ? "enabled" : "disabled");
    printf("Use Ctrl-C to stop\n");
    
    /* Start the HTTP server */
    err = run_http_server(skel);
    if (err) {
        fprintf(stderr, "Failed to start HTTP server\n");
        goto cleanup;
    }
    
    print_stats(skel);

cleanup:
    fileserver_bpf__destroy(skel);
    return -err;
}
