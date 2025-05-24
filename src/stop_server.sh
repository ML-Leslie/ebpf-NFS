#!/bin/bash

# eBPF File Server Stop Script
# 用于停止eBPF文件服务器和清理相关资源

echo "正在停止eBPF文件服务器..."

# 停止fileserver进程
echo "1. 停止fileserver进程..."
sudo pkill -f fileserver 2>/dev/null || true

# 停止监控脚本
echo "2. 停止监控脚本..."
sudo pkill -f "python3 fileserver_stats.py" 2>/dev/null || true
pkill -f "python3 fileserver_stats.py" 2>/dev/null || true

# 清理TC过滤器
echo "3. 清理TC过滤器..."
sudo tc qdisc del dev lo clsact 2>/dev/null || true
sudo tc qdisc del dev eth0 clsact 2>/dev/null || true

# 等待进程完全终止
sleep 2

# 检查是否还有残留进程
remaining=$(ps aux | grep -v grep | grep fileserver | wc -l)
if [ $remaining -gt 0 ]; then
    echo "警告: 仍有fileserver进程在运行"
    ps aux | grep -v grep | grep fileserver
    echo "尝试强制终止..."
    sudo pkill -9 -f fileserver 2>/dev/null || true
else
    echo "✓ 所有fileserver进程已停止"
fi

# 验证端口释放
if ss -tlnp | grep -q ":8080\|:8081"; then
    echo "警告: 端口仍被占用"
    ss -tlnp | grep ":8080\|:8081"
else
    echo "✓ 端口已释放"
fi

echo "eBPF文件服务器停止完成！"
