#!/usr/bin/env python3
"""
Real-time statistics viewer for eBPF file server
Shows kernel vs user-space processing statistics
"""

import time
import subprocess
import json
import os

def clear_screen():
    os.system('clear')

def get_bpf_map_stats():
    """Get statistics from BPF maps using bpftool"""
    try:
        # Get stats map dump
        result = subprocess.run(['sudo', 'bpftool', 'map', 'dump', 'name', 'stats'], 
                               capture_output=True, text=True)
        if result.returncode != 0:
            return None
        
        stats = {}
        lines = result.stdout.strip().split('\n')
        for line in lines:
            if 'key:' in line and 'value:' in line:
                # Parse key and value from bpftool output
                parts = line.split()
                key_idx = parts.index('key:') + 1
                value_idx = parts.index('value:') + 1
                
                if key_idx < len(parts) and value_idx < len(parts):
                    key = int(parts[key_idx], 16)
                    # Find the actual numeric value (may be after hex prefix)
                    value_str = parts[value_idx]
                    try:
                        if value_str.startswith('0x'):
                            value = int(value_str, 16)
                        else:
                            value = int(value_str)
                    except:
                        # Try next elements for the actual value
                        for i in range(value_idx + 1, len(parts)):
                            try:
                                value = int(parts[i])
                                break
                            except:
                                continue
                        else:
                            value = 0
                    
                    stats[key] = value
        
        return stats
    except Exception as e:
        return None

def format_stats(stats):
    """Format statistics for display"""
    if not stats:
        return "No statistics available (is the server running?)"
    
    stat_names = {
        0: "Total Requests",
        1: "Kernel Processed", 
        2: "Forwarded to User",
        3: "File Not Found",
        4: "Total Packets"
    }
    
    output = []
    output.append("📊 eBPF File Server Statistics")
    output.append("=" * 40)
    
    total_requests = stats.get(0, 0)
    kernel_processed = stats.get(1, 0)
    user_processed = stats.get(2, 0)
    not_found = stats.get(3, 0)
    total_packets = stats.get(4, 0)
    
    output.append(f"🌐 Total HTTP Requests: {total_requests}")
    output.append(f"⚡ Kernel Processed:    {kernel_processed}")
    output.append(f"👤 User Space:          {user_processed}")
    output.append(f"❌ Not Found:           {not_found}")
    output.append(f"📦 Total Packets:       {total_packets}")
    output.append("")
    
    if total_requests > 0:
        kernel_ratio = (kernel_processed / total_requests) * 100
        user_ratio = (user_processed / total_requests) * 100
        output.append("📈 Performance Breakdown:")
        output.append(f"   Kernel Space: {kernel_ratio:.1f}%")
        output.append(f"   User Space:   {user_ratio:.1f}%")
        output.append("")
        
        # Performance indicator
        if kernel_ratio > 50:
            output.append("🚀 Excellent: High kernel-space processing!")
        elif kernel_ratio > 25:
            output.append("✅ Good: Balanced processing")
        else:
            output.append("💡 Tip: More caching could improve performance")
    
    return "\n".join(output)

def main():
    print("🔄 Starting eBPF File Server Statistics Monitor...")
    print("Press Ctrl+C to exit")
    time.sleep(2)
    
    try:
        while True:
            clear_screen()
            stats = get_bpf_map_stats()
            print(format_stats(stats))
            print("\n⏱️  Updated:", time.strftime("%H:%M:%S"))
            print("🔄 Refreshing every 2 seconds...")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n👋 Statistics monitor stopped.")

if __name__ == "__main__":
    main()
