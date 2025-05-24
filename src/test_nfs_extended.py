#!/usr/bin/env python3
"""
Extended NFS Server Test Client
Tests NULL, GETATTR, and READ operations
"""

import socket
import struct
import time

class NFSClient:
    def __init__(self, host='localhost', port=2049):
        self.host = host
        self.port = port
        
    def create_rpc_header(self, xid, program=100003, version=3, procedure=0):
        """Create RPC call header"""
        # RPC Header: XID, Message Type (0=call), RPC Version (2), Program, Version, Procedure
        return struct.pack('!6I', xid, 0, 2, program, version, procedure)
    
    def create_auth_none(self):
        """Create AUTH_NONE authentication"""
        # AUTH_NONE: flavor=0, length=0
        return struct.pack('!2I', 0, 0)
    
    def send_nfs_request(self, request_data, operation_name, expected_xid):
        """Send NFS request and receive response"""
        try:
            print(f"\nTesting NFS {operation_name} operation...")
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)  # 5 second timeout
            
            print(f"Sending {operation_name} request to {self.host}:{self.port} (size: {len(request_data)} bytes)")
            sock.sendto(request_data, (self.host, self.port))
            
            # Receive response
            response, addr = sock.recvfrom(4096)
            print(f"Received response from {addr} (size: {len(response)} bytes)")
            print(f"Response data: {response.hex()}")
            
            # Parse response header
            if len(response) >= 12:
                xid, msg_type, reply_state = struct.unpack('!3I', response[:12])
                print(f"Response XID: {xid}, Message Type: {msg_type}, Reply Status: {reply_state}")
                
                if xid == expected_xid:
                    print("✓ XID matches request")
                    return True, response
                else:
                    print(f"✗ XID mismatch: expected {expected_xid}, got {xid}")
                    return False, response
            else:
                print("✗ Response too short")
                return False, response
                
        except socket.timeout:
            print(f"✗ Timeout waiting for {operation_name} response")
            return False, None
        except Exception as e:
            print(f"✗ Error during {operation_name} test: {e}")
            return False, None
        finally:
            sock.close()
    
    def test_null(self):
        """Test NFS NULL operation (procedure 0)"""
        xid = 54321
        
        # Build NULL request
        rpc_header = self.create_rpc_header(xid, procedure=0)
        auth_cred = self.create_auth_none()  # credential
        auth_verf = self.create_auth_none()  # verifier
        
        request = rpc_header + auth_cred + auth_verf
        return self.send_nfs_request(request, "NULL", xid)
    
    def test_getattr(self):
        """Test NFS GETATTR operation (procedure 1)"""
        xid = 12345
        
        # Build GETATTR request
        rpc_header = self.create_rpc_header(xid, procedure=1)
        auth_cred = self.create_auth_none()
        auth_verf = self.create_auth_none()
        
        # File handle (32 bytes, all zeros for simplicity)
        file_handle = b'\x00' * 32
        
        request = rpc_header + auth_cred + auth_verf + file_handle
        return self.send_nfs_request(request, "GETATTR", xid)
    
    def test_read(self):
        """Test NFS READ operation (procedure 6)"""
        xid = 67890
        
        # Build READ request
        rpc_header = self.create_rpc_header(xid, procedure=6)
        auth_cred = self.create_auth_none()
        auth_verf = self.create_auth_none()
        
        # File handle (32 bytes, all zeros)
        file_handle = b'\x00' * 32
        
        # READ parameters: offset=0, count=1024
        offset = struct.pack('!Q', 0)      # 64-bit offset
        count = struct.pack('!I', 1024)    # 32-bit count
        
        request = rpc_header + auth_cred + auth_verf + file_handle + offset + count
        return self.send_nfs_request(request, "READ", xid)

def main():
    print("Extended NFS Server Test Client")
    print("=" * 40)
    
    client = NFSClient()
    tests_passed = 0
    total_tests = 3
    
    # Test NULL operation
    success, response = client.test_null()
    if success:
        tests_passed += 1
    
    # Test GETATTR operation  
    success, response = client.test_getattr()
    if success:
        tests_passed += 1
    
    # Test READ operation
    success, response = client.test_read()
    if success:
        tests_passed += 1
    
    print(f"\nTest Results: {tests_passed}/{total_tests} tests passed")
    if tests_passed == total_tests:
        print("✓ All tests passed!")
    else:
        print(f"✗ {total_tests - tests_passed} test(s) failed")
    
    return tests_passed == total_tests

if __name__ == "__main__":
    main()
