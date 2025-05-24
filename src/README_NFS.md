# eBPF 增强的 NFS 服务器

本项目实现了一个基于 eBPF 技术的高性能 NFS（网络文件系统）服务器，能够在内核空间直接处理简单的 NFS 请求，显著提升服务性能。

## 项目概述

该项目利用 eBPF (Extended Berkeley Packet Filter) 在内核空间拦截和处理 NFS 请求。对于简单的文件操作（如 GETATTR、READ 小文件），服务器能够完全绕过用户空间处理，直接在内核中完成响应，从而大幅降低延迟并提高吞吐量。

### 🚀 核心特性

- **内核空间处理**: 简单 NFS 请求在内核空间直接处理，避免用户态切换开销
- **智能路由**: 简单请求走内核，复杂请求自动降级到用户空间
- **高性能缓存**: 文件属性和小文件内容自动缓存到内核内存中
- **NFS v3 支持**: 兼容标准 NFS v3 协议
- **安全性增强**: 利用 eBPF 的安全特性进行访问控制
- **实时监控**: 丰富的性能指标和实时统计
- **零拷贝优化**: 最小化数据在内核和用户空间之间的拷贝

### 📊 性能优势

- ⚡ **延迟降低**: 消除内核-用户空间上下文切换开销
- 🚀 **吞吐量提升**: 内核直接处理简单请求
- 💾 **内存效率**: 跨进程共享的内核缓存
- 📈 **CPU 使用率降低**: 减少文件系统操作的处理开销
- 🔧 **并发处理能力**: 支持更多并发 NFS 客户端

## 架构设计

### 系统架构图

```
NFS 请求 → TC Ingress (eBPF) → 解析 RPC → 检查内核缓存
     ↓                                          ↓
缓存命中 ← 直接响应 ← 内核空间处理          缓存未命中
     ↓                                          ↓
  响应客户端                               转发到用户空间
                                                 ↓
                                          文件系统读取 → 更新缓存
                                                 ↓
                                              响应客户端
```

### 详细组件说明

1. **eBPF TC 程序 (nfs_server.bpf.c)**
   - 拦截 UDP 2049 端口的 NFS 数据包
   - 解析 RPC 协议头
   - 处理简单的 NFS 操作（GETATTR、READ）
   - 管理内核缓存

2. **用户空间 NFS 服务器 (nfs_server.c)**
   - 处理复杂的 NFS 操作
   - 管理文件系统访问
   - 维护缓存一致性
   - 提供监控和统计

3. **内核缓存系统**
   - 文件属性缓存（元数据）
   - 小文件内容缓存
   - 文件句柄到文件名映射
   - 客户端连接状态跟踪

## 支持的 NFS 操作

### 内核空间处理的操作：
- **GETATTR**: 获取文件属性（如果已缓存）
- **READ**: 读取小文件内容（如果已缓存）

### 用户空间处理的操作：
- **WRITE**: 写入文件
- **CREATE**: 创建文件/目录
- **REMOVE**: 删除文件/目录
- **LOOKUP**: 文件名查找
- **READDIR**: 目录列表
- **SETATTR**: 设置文件属性
- **其他复杂操作**

## 编译和运行

### 前提条件

```bash
# Ubuntu/Debian
sudo apt-get install -y build-essential clang llvm libelf-dev libssl-dev pkg-config

# CentOS/RHEL
sudo yum install -y gcc clang llvm elfutils-libelf-devel openssl-devel pkgconfig
```

### 编译

```bash
cd src
make nfs_server
```

### 运行

```bash
# 以 root 权限运行（eBPF 需要）
sudo ./nfs_server -v -i ens33 -e ./nfs_exports -p 2049

# 参数说明：
# -v: 详细输出
# -i: 网络接口
# -e: NFS 导出目录
# -p: NFS 端口（默认 2049）
# -n: 禁用内核缓存
```
### 停止
```bash
# 停止 NFS 服务器
sudo pkill -f nfs_server

# 清理TC
sudo tc filter del dev lo ingress
sudo tc filter del dev ens33 ingress
```
### 测试

```bash
# 运行测试脚本
sudo ./test_nfs_server.sh

# 或者单独构建
./test_nfs_server.sh build

# 启动服务器
./test_nfs_server.sh start
```

## 配置选项

### 内核配置参数

- `enable_kernel_processing`: 启用内核处理（默认启用）
- `max_cached_file_size`: 最大缓存文件大小（默认 4KB）
- `cache_ttl_seconds`: 缓存生存时间（默认 300 秒）

### 运行时配置

```bash
# 查看 eBPF 程序状态
sudo bpftool prog list | grep nfs

# 查看映射内容
sudo bpftool map list | grep nfs

# 查看统计信息
sudo bpftool map dump name nfs_stats
```

## 监控和调试

### 性能指标

服务器提供以下统计信息：
- 总请求数
- 内核处理的请求数
- 用户空间处理的请求数
- 缓存命中率
- 缓存未命中数
- 错误数量

### 调试信息

使用 `-v` 参数启用详细日志：
```bash
sudo ./nfs_server -v -i lo -e ./nfs_exports
```

### 使用 bpftrace 进行高级调试

```bash
# 跟踪 NFS 请求
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("File opened: %s\n", str(args->filename)); }'

# 监控网络流量
sudo bpftrace -e 'kprobe:udp_rcv { printf("UDP packet received\n"); }'
```

## 安全性

### eBPF 安全特性

- **内存安全**: eBPF 程序经过验证器检查，确保内存访问安全
- **权限控制**: 需要 CAP_BPF 或 root 权限加载程序
- **边界检查**: 自动进行数组和指针边界检查

### NFS 安全建议

- 使用防火墙限制访问端口 2049
- 配置适当的文件系统权限
- 考虑使用 NFSv4 和 Kerberos 认证（未来版本）
- 定期更新 eBPF 程序和内核

## 故障排除

### 常见问题

1. **eBPF 程序加载失败**
   ```bash
   # 检查内核版本（需要 >= 4.15）
   uname -r
   
   # 检查 eBPF 支持
   sudo bpftool feature
   ```

2. **权限不足**
   ```bash
   # 确保以 root 权限运行
   sudo ./nfs_server
   ```

3. **网络接口不存在**
   ```bash
   # 检查可用接口
   ip link show
   ```

4. **端口被占用**
   ```bash
   # 检查端口使用情况
   sudo netstat -ulpn | grep 2049
   
   # 或使用其他端口
   sudo ./nfs_server -p 2050
   ```

### 日志分析

检查系统日志：
```bash
# 查看内核日志
sudo dmesg | grep -i bpf

# 查看系统日志
sudo journalctl -f | grep nfs
```

## 性能优化

### 调优建议

1. **增加缓存大小**：修改映射大小以缓存更多文件
2. **调整 TTL**：根据文件更新频率调整缓存生存时间
3. **网络优化**：使用高速网络接口
4. **CPU 亲和性**：绑定进程到特定 CPU 核心

### 基准测试

使用标准 NFS 基准测试工具：
```bash
# 安装 nfs-utils
sudo apt-get install nfs-utils

# 挂载 NFS
sudo mount -t nfs 127.0.0.1:/path/to/export /mnt/nfs

# 运行性能测试
dd if=/dev/zero of=/mnt/nfs/testfile bs=1M count=100
```

## 扩展开发

### 添加新的 NFS 操作

1. 在 `nfs_server.h` 中定义新的过程常量
2. 在 `nfs_server.bpf.c` 中添加处理函数
3. 在 `nfs_server.c` 中实现用户空间逻辑
4. 更新统计信息和监控

### 示例：添加 LOOKUP 操作

```c
// 在 nfs_server.bpf.c 中
static inline int handle_nfs_lookup(struct nfs_request *req, 
                                   struct nfs_event *event)
{
    // 实现查找逻辑
    return 0;
}
```

## 贡献

欢迎贡献代码和报告问题！请遵循以下步骤：

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 创建 Pull Request

## 许可证

本项目采用双重许可：
- GPL-2.0（对于内核 eBPF 代码）
- LGPL-2.1 或 BSD-2-Clause（对于用户空间代码）

## 相关资源

- [eBPF 官方文档](https://ebpf.io/)
- [NFS RFC 1813](https://tools.ietf.org/html/rfc1813)
- [Linux TC 子系统](https://man7.org/linux/man-pages/man8/tc.8.html)
- [libbpf 文档](https://github.com/libbpf/libbpf)
