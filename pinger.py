#!/usr/bin/env python3
"""
IP Connectivity Tester - Test connectivity to single IPs or IP ranges with multi-threading support
Uses TCP connection attempts on common ports (80, 443, 53) instead of ICMP ping
Usage: python pinger.py <IP1> [IP2 | IP1-IP2]
Examples:
  python pinger.py 8.8.8.8
  python pinger.py 192.168.1.1-192.168.1.10
  python pinger.py 8.8.8.8 8.8.4.4
"""

import sys
import socket
import threading
import time
import ipaddress
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


class IPPinger:
    def __init__(self, timeout=3, max_workers=50):
        """
        Initialize the IP Pinger
        
        Args:
            timeout: Ping timeout in seconds
            max_workers: Maximum number of concurrent ping threads
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = {}
        self.lock = threading.Lock()
    
    def ping_ip(self, ip):
        """
        Test connectivity to a single IP address using TCP connection
        
        Args:
            ip: IP address to test (string)
            
        Returns:
            dict: Result containing IP, status, and response time
        """
        # Common ports to test connectivity (HTTP, HTTPS, DNS)
        test_ports = [80, 443, 53]
        connection_refused_count = 0
        
        for port in test_ports:
            try:
                start_time = time.time()
                
                # Create socket and attempt connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                result = sock.connect_ex((ip, port))
                sock.close()
                
                end_time = time.time()
                response_time = round((end_time - start_time) * 1000, 2)
                
                if result == 0:
                    # Connection successful
                    return {
                        'ip': ip,
                        'status': 'SUCCESS',
                        'response_time': response_time,
                        'message': f'Connection to {ip}:{port} successful: time={response_time}ms'
                    }
                elif result in [111, 61]:  # ECONNREFUSED - host reachable but port closed
                    connection_refused_count += 1
                    continue
                else:
                    # Other errors (timeout, no route, etc.) - host likely unreachable
                    continue
                    
            except socket.timeout:
                continue  # Try next port
            except Exception:
                continue  # Try next port
        
        # Determine final status based on results
        if connection_refused_count > 0:
            # Host is reachable but tested ports are closed
            return {
                'ip': ip,
                'status': 'PARTIAL',
                'response_time': None,
                'message': f'Host {ip} reachable but no tested ports (80,443,53) are open'
            }
        else:
            # No successful connections and no refused connections - host unreachable
            return {
                'ip': ip,
                'status': 'FAILED',
                'response_time': None,
                'message': f'Host {ip} unreachable or connection timeout'
            }
    
    def parse_ip_range(self, ip_range):
        """
        Parse IP range string and return list of IP addresses
        
        Args:
            ip_range: String in format "IP1-IP2" or single IP
            
        Returns:
            list: List of IP address strings
        """
        if '-' in ip_range:
            try:
                start_ip, end_ip = ip_range.split('-', 1)
                start_ip = start_ip.strip()
                end_ip = end_ip.strip()
                
                # Convert to IP objects for validation and range generation
                start = ipaddress.IPv4Address(start_ip)
                end = ipaddress.IPv4Address(end_ip)
                
                if start > end:
                    raise ValueError(f"Start IP {start_ip} is greater than end IP {end_ip}")
                
                # Generate IP range
                ip_list = []
                current = start
                while current <= end:
                    ip_list.append(str(current))
                    current += 1
                
                return ip_list
                
            except ValueError as e:
                print(f"Error parsing IP range '{ip_range}': {e}")
                return []
        else:
            # Single IP
            try:
                # Validate IP
                ipaddress.IPv4Address(ip_range.strip())
                return [ip_range.strip()]
            except ValueError as e:
                print(f"Invalid IP address '{ip_range}': {e}")
                return []
    
    def print_result(self, result):
        """Print connectivity test result with thread-safe output"""
        with self.lock:
            if result['status'] == 'SUCCESS':
                print(f"✓ {result['message']}")
            elif result['status'] == 'PARTIAL':
                print(f"~ {result['message']}")
            else:
                print(f"✗ {result['message']}")
    
    def ping_ips(self, ip_list):
        """
        Ping multiple IPs concurrently
        
        Args:
            ip_list: List of IP addresses to ping
            
        Returns:
            dict: Summary of ping results
        """
        if not ip_list:
            return {'total': 0, 'success': 0, 'failed': 0}
        
        print(f"\nPinging {len(ip_list)} IP address(es)...\n")
        
        successful = 0
        failed = 0
        
        # Use ThreadPoolExecutor for concurrent pinging
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(ip_list))) as executor:
            # Submit all ping tasks
            future_to_ip = {executor.submit(self.ping_ip, ip): ip for ip in ip_list}
            
            # Process results as they complete
            for future in as_completed(future_to_ip):
                result = future.result()
                self.print_result(result)
                
                if result['status'] == 'SUCCESS':
                    successful += 1
                else:
                    failed += 1
                
                self.results[result['ip']] = result
        
        return {
            'total': len(ip_list),
            'success': successful,
            'failed': failed
        }


def main():
    """Main function to handle command line arguments and execute pinging"""
    
    if len(sys.argv) < 2:
        print("Usage: python pinger.py <IP1> [IP2 | IP1-IP2]")
        print("\nExamples:")
        print("  python pinger.py 8.8.8.8")
        print("  python pinger.py 192.168.1.1-192.168.1.10")
        print("  python pinger.py 8.8.8.8 8.8.4.4")
        sys.exit(1)
    
    # Create pinger instance
    pinger = IPPinger()
    
    # Parse all command line arguments as IPs or IP ranges
    all_ips = []
    
    for arg in sys.argv[1:]:
        ips = pinger.parse_ip_range(arg)
        if ips:
            all_ips.extend(ips)
        else:
            print(f"Skipping invalid IP/range: {arg}")
    
    if not all_ips:
        print("No valid IP addresses to ping.")
        sys.exit(1)
    
    # Remove duplicates while preserving order
    unique_ips = []
    seen = set()
    for ip in all_ips:
        if ip not in seen:
            unique_ips.append(ip)
            seen.add(ip)
    
    # Ping all IPs
    start_time = time.time()
    summary = pinger.ping_ips(unique_ips)
    end_time = time.time()
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"PING SUMMARY")
    print(f"{'='*50}")
    print(f"Total IPs: {summary['total']}")
    print(f"Successful: {summary['success']}")
    print(f"Failed: {summary['failed']}")
    print(f"Success Rate: {(summary['success']/summary['total']*100):.1f}%")
    print(f"Total Time: {(end_time - start_time):.2f} seconds")
    
    # Exit with appropriate code - success only if no failures
    sys.exit(0 if summary['failed'] == 0 else 1)


if __name__ == "__main__":
    main()