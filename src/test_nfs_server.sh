#!/bin/bash

# NFS Server Test Script
# This script demonstrates the eBPF-enhanced NFS server functionality

set -e

# Configuration
NFS_SERVER="./nfs_server"
EXPORT_DIR="./nfs_exports"
TEST_FILE="test.txt"
INTERFACE="lo"
NFS_PORT=2049

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root for eBPF programs to work properly"
   exit 1
fi

# Create export directory and test files
setup_test_environment() {
    log_info "Setting up test environment..."
    
    mkdir -p "$EXPORT_DIR"
    
    # Create test files
    echo "Hello from eBPF-enhanced NFS server!" > "$EXPORT_DIR/$TEST_FILE"
    echo "This file is cached in kernel space for fast access." >> "$EXPORT_DIR/$TEST_FILE"
    
    # Create a larger test file
    dd if=/dev/zero of="$EXPORT_DIR/large_file.bin" bs=1024 count=10 2>/dev/null
    
    # Create a directory
    mkdir -p "$EXPORT_DIR/testdir"
    echo "File in subdirectory" > "$EXPORT_DIR/testdir/subfile.txt"
    
    log_success "Test environment created in $EXPORT_DIR"
}

# Build the NFS server
build_nfs_server() {
    log_info "Building NFS server..."
    
    if ! make nfs_server; then
        log_error "Failed to build NFS server"
        exit 1
    fi
    
    if [[ ! -f "$NFS_SERVER" ]]; then
        log_error "NFS server binary not found: $NFS_SERVER"
        exit 1
    fi
    
    log_success "NFS server built successfully"
}

# Start NFS server in background
start_nfs_server() {
    log_info "Starting NFS server on interface $INTERFACE, port $NFS_PORT..."
    
    # Kill any existing instance
    pkill -f nfs_server || true
    sleep 1
    
    # Start server in background
    "$NFS_SERVER" -v -i "$INTERFACE" -e "$EXPORT_DIR" -p "$NFS_PORT" &
    NFS_PID=$!
    
    # Wait a moment for server to start
    sleep 2
    
    # Check if server is running
    if ! kill -0 $NFS_PID 2>/dev/null; then
        log_error "Failed to start NFS server"
        exit 1
    fi
    
    log_success "NFS server started with PID $NFS_PID"
}

# Stop NFS server
stop_nfs_server() {
    log_info "Stopping NFS server..."
    
    if [[ -n "$NFS_PID" ]] && kill -0 $NFS_PID 2>/dev/null; then
        kill $NFS_PID
        wait $NFS_PID 2>/dev/null || true
    fi
    
    # Clean up any remaining processes
    pkill -f nfs_server || true
    
    log_success "NFS server stopped"
}

# Test NFS functionality using simple UDP packets
test_nfs_functionality() {
    log_info "Testing NFS functionality..."
    
    # Create a simple NFS GETATTR request packet
    # This is a simplified test - real NFS clients would send proper RPC packets
    
    python3 << 'EOF'
import socket
import struct
import time

def send_nfs_getattr():
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # Simple RPC header for NFS GETATTR (procedure 1)
        xid = 0x12345678
        msg_type = 0  # CALL
        rpc_version = 2
        program = 100003  # NFS
        version = 3  # NFSv3
        procedure = 1  # GETATTR
        auth_flavor = 0  # AUTH_NULL
        auth_len = 0
        
        # Pack RPC header (big-endian)
        packet = struct.pack('!IIIIIIII', 
                           xid, msg_type, rpc_version, program, 
                           version, procedure, auth_flavor, auth_len)
        
        # Send to NFS server
        server_addr = ('127.0.0.1', 2049)
        sock.sendto(packet, server_addr)
        
        print(f"Sent NFS GETATTR request to {server_addr}")
        
        # Try to receive response (with timeout)
        sock.settimeout(5.0)
        try:
            response, addr = sock.recvfrom(1024)
            print(f"Received response from {addr}: {len(response)} bytes")
            return True
        except socket.timeout:
            print("No response received (timeout)")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        sock.close()

def send_nfs_read():
    # Similar test for READ operation
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        xid = 0x12345679
        msg_type = 0  # CALL
        rpc_version = 2
        program = 100003  # NFS
        version = 3  # NFSv3
        procedure = 6  # READ
        auth_flavor = 0
        auth_len = 0
        
        packet = struct.pack('!IIIIIIII', 
                           xid, msg_type, rpc_version, program, 
                           version, procedure, auth_flavor, auth_len)
        
        server_addr = ('127.0.0.1', 2049)
        sock.sendto(packet, server_addr)
        
        print(f"Sent NFS READ request to {server_addr}")
        
        sock.settimeout(5.0)
        try:
            response, addr = sock.recvfrom(1024)
            print(f"Received response from {addr}: {len(response)} bytes")
            return True
        except socket.timeout:
            print("No response received (timeout)")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        sock.close()

# Run tests
print("=== NFS Server Test ===")
success = True

print("\n1. Testing GETATTR operation:")
if send_nfs_getattr():
    print("✓ GETATTR test passed")
else:
    print("✗ GETATTR test failed")
    success = False

time.sleep(1)

print("\n2. Testing READ operation:")
if send_nfs_read():
    print("✓ READ test passed")
else:
    print("✗ READ test failed")
    success = False

print(f"\n=== Test Summary ===")
if success:
    print("✓ All tests passed")
else:
    print("✗ Some tests failed")

EOF

    log_success "NFS functionality test completed"
}

# Monitor eBPF statistics
show_statistics() {
    log_info "Showing eBPF maps statistics..."
    
    # Use bpftool to show map contents if available
    if command -v bpftool &> /dev/null; then
        echo "=== eBPF Maps ==="
        bpftool map list | grep -E "(nfs_|file_|client_|stats)" || true
        echo
    fi
    
    log_info "Statistics can be observed in the server output"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    stop_nfs_server
    
    # Remove test files if requested
    if [[ "$1" == "clean" ]]; then
        rm -rf "$EXPORT_DIR"
        log_success "Test environment cleaned up"
    fi
}

# Main execution
main() {
    log_info "Starting eBPF NFS Server Test"
    echo "=================================="
    
    trap 'cleanup' EXIT
    
    setup_test_environment
    build_nfs_server
    start_nfs_server
    
    log_info "Waiting for server to initialize..."
    sleep 3
    
    test_nfs_functionality
    show_statistics
    
    log_info "Press Ctrl+C to stop the server and exit"
    
    # Keep running and show periodic stats
    while true; do
        sleep 10
        log_info "Server running... (Ctrl+C to stop)"
    done
}

# Handle command line arguments
case "${1:-}" in
    "clean")
        cleanup clean
        ;;
    "build")
        build_nfs_server
        ;;
    "start")
        setup_test_environment
        build_nfs_server
        start_nfs_server
        log_info "Server started. Run 'pkill -f nfs_server' to stop."
        ;;
    *)
        main
        ;;
esac
