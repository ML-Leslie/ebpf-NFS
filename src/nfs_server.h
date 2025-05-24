// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2024 NFS Server Kernel Processing */
#ifndef __NFS_SERVER_H
#define __NFS_SERVER_H

#ifdef __KERNEL__
/* For eBPF programs - use basic types */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;
#else
/* For user space programs */
#include <linux/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#endif

#define MAX_FILENAME_LEN 256
#define MAX_PACKET_SIZE 1500
#define MAX_NFS_DATA_SIZE 8192
#define NFS_PORT 2049
#define RPC_PROGRAM_NFS 100003
#define NFS_VERSION_3 3

/* NFS v3 procedure numbers */
enum nfs_proc {
    NFSPROC3_NULL = 0,
    NFSPROC3_GETATTR = 1,
    NFSPROC3_SETATTR = 2,
    NFSPROC3_LOOKUP = 3,
    NFSPROC3_ACCESS = 4,
    NFSPROC3_READLINK = 5,
    NFSPROC3_READ = 6,
    NFSPROC3_WRITE = 7,
    NFSPROC3_CREATE = 8,
    NFSPROC3_MKDIR = 9,
    NFSPROC3_SYMLINK = 10,
    NFSPROC3_MKNOD = 11,
    NFSPROC3_REMOVE = 12,
    NFSPROC3_RMDIR = 13,
    NFSPROC3_RENAME = 14,
    NFSPROC3_LINK = 15,
    NFSPROC3_READDIR = 16,
    NFSPROC3_READDIRPLUS = 17,
    NFSPROC3_FSSTAT = 18,
    NFSPROC3_FSINFO = 19,
    NFSPROC3_PATHCONF = 20,
    NFSPROC3_COMMIT = 21
};

/* NFS operation result codes */
enum nfs_op_result {
    NFS_OP_SUCCESS = 0,
    NFS_OP_NOT_FOUND = 2,        /* ENOENT */
    NFS_OP_ACCESS_DENIED = 13,   /* EACCES */
    NFS_OP_INVALID_HANDLE = 10001,
    NFS_OP_FORWARD_TO_USER = 10002,
    NFS_OP_CACHE_HIT = 10003,
    NFS_OP_ERROR = 10004
};

/* RPC message types */
enum rpc_msg_type {
    RPC_CALL = 0,
    RPC_REPLY = 1
};

/* RPC auth flavors */
enum rpc_auth_flavor {
    RPC_AUTH_NULL = 0,
    RPC_AUTH_UNIX = 1,
    RPC_AUTH_SHORT = 2,
    RPC_AUTH_DES = 3
};

/* Simple RPC header structure */
struct rpc_header {
    __u32 xid;           /* Transaction ID */
    __u32 msg_type;      /* CALL or REPLY */
    __u32 rpc_version;   /* RPC version (must be 2) */
    __u32 program;       /* Program number */
    __u32 version;       /* Program version */
    __u32 procedure;     /* Procedure number */
    __u32 auth_flavor;   /* Authentication flavor */
    __u32 auth_len;      /* Authentication data length */
};

/* NFS file handle structure (simplified) */
struct nfs_fh {
    __u32 len;
    __u8 data[64];  /* NFS file handle data */
};

/* NFS file attributes (simplified) */
struct nfs_fattr {
    __u32 type;         /* File type */
    __u32 mode;         /* File mode */
    __u32 nlink;        /* Number of links */
    __u32 uid;          /* User ID */
    __u32 gid;          /* Group ID */
    __u64 size;         /* File size */
    __u64 used;         /* Bytes used */
    __u64 fsid;         /* File system ID */
    __u64 fileid;       /* File ID */
    __u64 atime_sec;    /* Access time */
    __u32 atime_nsec;
    __u64 mtime_sec;    /* Modification time */
    __u32 mtime_nsec;
    __u64 ctime_sec;    /* Change time */
    __u32 ctime_nsec;
};

/* NFS request event for userspace */
struct nfs_request {
    __u32 client_addr;
    __u16 client_port;
    __u32 xid;           /* RPC transaction ID */
    __u32 procedure;     /* NFS procedure number */
    __u8 processed_in_kernel;  /* 1 if handled in kernel, 0 if forwarded */
    char filename[MAX_FILENAME_LEN];
    __u32 offset;        /* For READ/WRITE operations */
    __u32 count;         /* For READ/WRITE operations */
    struct nfs_fh fh;    /* File handle */
};

/* NFS operation event */
struct nfs_event {
    __u32 client_addr;
    __u16 client_port;
    __u32 xid;
    __u32 procedure;
    __u32 result;        /* nfs_op_result enum */
    char filename[MAX_FILENAME_LEN];
    __u32 file_size;
    __u64 timestamp;
    __u8 forwarded_to_user;
    __u8 from_cache;
};

/* File cache entry for NFS */
struct nfs_file_cache_entry {
    char filename[MAX_FILENAME_LEN];
    struct nfs_fh fh;           /* File handle */
    struct nfs_fattr attr;      /* File attributes */
    __u32 data_size;            /* Size of cached data */
    __u8 data[MAX_NFS_DATA_SIZE]; /* Cached file data (for small files) */
    __u64 cache_time;           /* When this was cached */
    __u32 cache_hits;
    __u8 valid;
    __u8 data_valid;            /* Whether data is cached */
};

/* Directory entry cache */
struct nfs_dir_entry {
    char name[MAX_FILENAME_LEN];
    struct nfs_fh fh;
    __u64 fileid;
    __u8 valid;
};

/* Connection state tracking */
struct nfs_client_state {
    __u32 client_addr;
    __u64 last_request_time;
    __u32 request_count;
    __u32 kernel_processed;
    __u32 user_forwarded;
};

#endif /* __NFS_SERVER_H */