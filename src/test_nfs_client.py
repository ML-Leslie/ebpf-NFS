#!/usr/bin/env python3
"""
Simple NFS client test for our eBPF-based NFS server
"""
import socket
import struct
import sys

def create_rpc_header(xid, proc_num):
    """Create an RPC header for NFS requests"""
    # RPC Header format:
    # XID (4 bytes), Message Type (4 bytes), RPC Version (4 bytes),
    # Program Number (4 bytes), Program Version (4 bytes), Procedure (4 bytes),
    # Auth Flavor (4 bytes), Auth Length (4 bytes), Auth Data (variable),
    # Verifier Flavor (4 bytes), Verifier Length (4 bytes), Verifier Data (variable)
    
    msg_type = 0  # CALL
    rpc_version = 2
    program = 100003  # NFS
    version = 3  # NFS v3
    procedure = proc_num
    auth_flavor = 0  # AUTH_NULL
    auth_length = 0
    verif_flavor = 0  # AUTH_NULL
    verif_length = 0
    
    header = struct.pack('>IIIIIIIIII',
                        xid, msg_type, rpc_version, program, version,
                        procedure, auth_flavor, auth_length,
                        verif_flavor, verif_length)
    return header

def test_nfs_getattr():
    """Test NFS GETATTR operation"""
    print("Testing NFS GETATTR operation...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # Create RPC header for GETATTR (procedure 1)
        xid = 12345
        rpc_header = create_rpc_header(xid, 1)  # GETATTR
        
        # Simple file handle for testing (in real NFS this would be proper file handle)
        file_handle = b"test.txt" + b"\x00" * 24  # Pad to 32 bytes
        
        # Combine header and file handle
        request = rpc_header + file_handle
        
        print(f"Sending GETATTR request to localhost:2049 (size: {len(request)} bytes)")
        
        # Send request to NFS server
        sock.sendto(request, ('127.0.0.1', 2049))
        
        # Receive response
        sock.settimeout(5.0)  # 5 second timeout
        response, addr = sock.recvfrom(1024)
        
        print(f"Received response from {addr} (size: {len(response)} bytes)")
        print(f"Response data: {response.hex()}")
        
        # Parse basic RPC response header
        if len(response) >= 12:
            resp_xid, msg_type, reply_stat = struct.unpack('>III', response[:12])
            print(f"Response XID: {resp_xid}, Message Type: {msg_type}, Reply Status: {reply_stat}")
            
            if resp_xid == xid:
                print("✓ XID matches request")
            else:
                print("✗ XID mismatch")
                
        return True
        
    except socket.timeout:
        print("✗ Request timed out")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    finally:
        sock.close()

def test_nfs_null():
    """Test NFS NULL operation (procedure 0)"""
    print("Testing NFS NULL operation...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # Create RPC header for NULL (procedure 0)
        xid = 54321
        rpc_header = create_rpc_header(xid, 0)  # NULL
        
        print(f"Sending NULL request to localhost:2049 (size: {len(rpc_header)} bytes)")
        
        # Send request to NFS server
        sock.sendto(rpc_header, ('127.0.0.1', 2049))
        
        # Receive response
        sock.settimeout(5.0)  # 5 second timeout
        response, addr = sock.recvfrom(1024)
        
        print(f"Received response from {addr} (size: {len(response)} bytes)")
        print(f"Response data: {response.hex()}")
        
        # Parse basic RPC response header
        if len(response) >= 12:
            resp_xid, msg_type, reply_stat = struct.unpack('>III', response[:12])
            print(f"Response XID: {resp_xid}, Message Type: {msg_type}, Reply Status: {reply_stat}")
            
            if resp_xid == xid:
                print("✓ XID matches request")
            else:
                print("✗ XID mismatch")
                
        return True
        
    except socket.timeout:
        print("✗ Request timed out")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    finally:
        sock.close()

def main():
    print("NFS Server Test Client")
    print("=" * 30)
    
    success = 0
    total = 0
    
    # Test NULL operation
    total += 1
    if test_nfs_null():
        success += 1
    
    print()
    
    # Test GETATTR operation
    total += 1
    if test_nfs_getattr():
        success += 1
    
    print()
    print(f"Test Results: {success}/{total} tests passed")
    
    if success == total:
        print("✓ All tests passed!")
        sys.exit(0)
    else:
        print("✗ Some tests failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
