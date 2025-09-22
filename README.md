# IP Connectivity Tester

A Python-based IP connectivity testing tool that provides an alternative to traditional ICMP ping. This application tests network connectivity by attempting TCP connections on common ports (80, 443, 53) instead of using ICMP packets, making it useful in environments where ICMP is blocked or filtered.

## Features

- ✅ **Single IP testing**: Test connectivity to individual IP addresses
- ✅ **IP range support**: Test ranges like `192.168.1.1-192.168.1.10`
- ✅ **Multiple IPs**: Test multiple discrete IP addresses in one command
- ✅ **Multi-threaded**: Concurrent testing for faster results (up to 50 parallel connections)
- ✅ **Real-time feedback**: Shows results as they complete
- ✅ **Comprehensive reporting**: Success rate, response times, and summary statistics
- ✅ **No special permissions**: Works without root/admin privileges (unlike ICMP ping)

## How It Works

The tool replaces traditional ICMP ping with TCP connection attempts on common service ports:
- **Port 80** (HTTP)
- **Port 443** (HTTPS) 
- **Port 53** (DNS)

A host is considered reachable if any of these ports accepts connections. This approach works in environments where ICMP is filtered or blocked.

## Setup Guide

### Prerequisites

- Python 3.7 or higher
- Internet connection for testing external IPs

### Installation

1. **Clone or download this repository**:
   ```bash
   git clone https://github.com/hiveryparkk/ip-connectivity-tester
   cd ip-connectivity-tester
   ```

2. **No additional dependencies required** - uses Python standard library only

### Usage

#### Basic Usage

```bash
# Test a single IP
python pinger.py 8.8.8.8

# Test multiple IPs
python pinger.py 8.8.8.8 8.8.4.4 1.1.1.1

# Test an IP range
python pinger.py 192.168.1.1-192.168.1.10

# Test mixed IPs and ranges
python pinger.py 8.8.8.8 192.168.1.1-192.168.1.5 1.1.1.1
```

#### Example Output

```
$ python pinger.py 8.8.8.8 8.8.4.4

Pinging 2 IP address(es)...

✓ Connection to 8.8.8.8:443 successful: time=1.17ms
✓ Connection to 8.8.4.4:443 successful: time=0.98ms

==================================================
PING SUMMARY
==================================================
Total IPs: 2
Successful: 2
Failed: 0
Success Rate: 100.0%
Total Time: 3.01 seconds
```

### Status Indicators

- ✅ **✓ SUCCESS**: Host is reachable and at least one tested port is open
- ⚠️ **PARTIAL**: Host is reachable but tested ports are closed/filtered
- ❌ **✗ FAILED**: Host is unreachable or connection timeout

### Exit Codes

- **0**: All tested IPs were successful
- **1**: One or more IPs failed or had connectivity issues

## Advanced Configuration

The script uses sensible defaults but can be customized by modifying the `IPPinger` class:

- **Timeout**: Default 3 seconds per connection attempt
- **Max Workers**: Default 50 concurrent threads
- **Test Ports**: Default [80, 443, 53]

## Use Cases

### Network Troubleshooting
```bash
# Test if your default gateway is reachable
python pinger.py 192.168.1.1

# Test connectivity to DNS servers
python pinger.py 8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1
```

### Infrastructure Monitoring
```bash
# Test a range of servers
python pinger.py 10.0.1.1-10.0.1.20

# Check if web services are running
python pinger.py web1.example.com web2.example.com
```

### Security Scanning
```bash
# Quick port scan on common services
python pinger.py 192.168.1.100-192.168.1.200
```

## Technical Details

### Architecture
- **Single-responsibility design**: Main `IPPinger` class handles all connectivity testing
- **Thread-safe operations**: Uses `threading.Lock` for coordinated result reporting
- **Concurrent execution**: `ThreadPoolExecutor` manages worker threads efficiently
- **IP validation**: Leverages Python's `ipaddress` module for robust IP handling

### Why TCP Instead of ICMP?
1. **No special privileges required**: TCP connections don't need root/admin access
2. **Firewall compatibility**: Many networks block ICMP but allow TCP
3. **Service verification**: Actually tests if services are running, not just if host responds
4. **Universal compatibility**: Works in containerized and restricted environments

## Troubleshooting

### Common Issues

**"Connection timeout" errors**:
- Network may be slow or unreachable
- Firewall blocking connections
- IP address doesn't exist

**"No tested ports are open"**:
- Host is reachable but running different services
- Ports 80, 443, 53 may be filtered
- Host may be running but not providing web/DNS services

### Performance Tips

- For large IP ranges, the tool automatically limits concurrent connections
- Response times include network latency and connection setup time
- Use smaller ranges for more detailed analysis

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is open source and available under the MIT License.