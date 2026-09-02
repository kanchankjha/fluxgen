# fluxgen

**fluxgen** is a powerful multi-client traffic generator inspired by hping3. It simulates many clients on a single Linux host, sending customizable network traffic with spoofed IP/MAC addresses from the same subnet. Perfect for network testing, load testing, and security research.

> **Companion Tool:** Check out [FluxProbe](https://github.com/kanchankjha/fluxprobe) - a schema-driven protocol fuzzer for security testing and vulnerability discovery.

## Features

- **Multi-client simulation** - Simulate hundreds of clients from a single host
- **Independent responder** - Run a dual-stack responder on a separate destination host
- **Protocol support** - TCP, UDP, ICMP, IGMP, GRE, ESP, AH, SCTP, ARP, VRRP, OSPF
- **Header fuzzing** - Emit each normal packet together with a structure-aware fuzzed copy
- **Spoofed identities** - Unique IP/MAC addresses per simulated client
- **Flexible traffic patterns** - Randomize sources, destinations, ports
- **Custom payloads** - Send text or hex-encoded data
- **Traffic capture** - Export sent traffic to PCAP files
- **Load testing** - Flood mode for maximum throughput
- **Beast mode** - Continuously rotate protocols, ports, flags, and MTU-sized traffic profiles
- **Configuration files** - YAML/JSON configuration support
- **Bidirectional transactions** - Complete synthetic TCP/UDP/ICMP exchanges over the wire

## Installation

### Prerequisites

- **Python 3.8+** (tested with Python 3.12)
- **Linux** operating system (required for raw socket support)
- **Root privileges** or CAP_NET_RAW capability
- **Git** for cloning the repository
- **pip** for universal fallback installation

### Quick Install (Recommended)

Works on all Linux flavors listed below and avoids distro package conflicts:

```bash
python3 -m venv ~/.venvs/fluxgen
~/.venvs/fluxgen/bin/pip install --upgrade pip
~/.venvs/fluxgen/bin/pip install git+https://github.com/kanchankjha/fluxgen.git
~/.venvs/fluxgen/bin/fluxgen --help
```

Run traffic commands with root/capabilities:

```bash
sudo ~/.venvs/fluxgen/bin/fluxgen --help
```

### Distro Package Install (Optional)

Current packaging and CI target:
- **Debian family:** Debian, Ubuntu, Kali, Parrot (APT)
- **RHEL family:** CentOS Stream / compatible (RPM)

Use distro packages if you prefer system-managed installs.

### Debian/Ubuntu/Kali/Parrot (APT)

```bash
curl -fL https://raw.githubusercontent.com/kanchankjha/fluxgen/apt-repo/fluxgen.gpg.key -o /tmp/fluxgen.gpg.key
sudo gpg --dearmor --yes -o /usr/share/keyrings/fluxgen-archive-keyring.gpg /tmp/fluxgen.gpg.key
echo "deb [arch=all signed-by=/usr/share/keyrings/fluxgen-archive-keyring.gpg] https://raw.githubusercontent.com/kanchankjha/fluxgen/apt-repo stable main" | sudo tee /etc/apt/sources.list.d/fluxgen.list
sudo apt-get update
sudo apt-get install -y fluxgen
```

### CentOS Stream / RHEL-like (RPM)

```bash
# 1) Add repository
sudo tee /etc/yum.repos.d/fluxgen.repo >/dev/null <<'EOF'
[fluxgen]
name=Fluxgen RPM Repository
baseurl=https://raw.githubusercontent.com/kanchankjha/fluxgen/yum-repo/
enabled=1
gpgcheck=0
repo_gpgcheck=0
EOF

# 2) Install package
sudo dnf makecache
sudo dnf install -y fluxgen
```

### Universal Linux Fallback (pip)
This is the same as the Quick Install above.

If/when published to PyPI, you can use:

```bash
~/.venvs/fluxgen/bin/pip install meraki-fluxgen
```

`fluxgen` on PyPI is already used by another project, so this project publishes
the Python package under `meraki-fluxgen` while keeping the CLI command name
as `fluxgen`.

### Source Install (Development)

```bash
git clone https://github.com/kanchankjha/fluxgen.git
cd fluxgen
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
fluxgen --help
```

**Note:** fluxgen requires Linux for raw socket support. macOS and Windows are not supported for packet sending.

### Grant Network Capabilities

fluxgen needs raw socket access to craft and send custom packets. You have two options:

#### Option A: Run with sudo (Simple but less secure)

```bash
sudo fluxgen --interface eth0 --clients 5 --dst 10.0.0.5 --dport 80
```

#### Option B: Grant Capabilities (Recommended)

```bash
# Grant capabilities to Python interpreter
sudo setcap cap_net_raw,cap_net_admin+ep .venv/bin/python3

# Or if installed system-wide
sudo setcap cap_net_raw,cap_net_admin+ep $(which python3)

# Now you can run without sudo
fluxgen --interface eth0 --clients 5 --dst 10.0.0.5 --dport 80
```

**Verify capabilities:**
```bash
getcap .venv/bin/python3
# Should show: cap_net_admin,cap_net_raw=ep
```

### Verify Installation

```bash
# Check version and help
fluxgen --help

# Test with dry-run (no packets sent)
fluxgen --interface eth0 --clients 2 --dst 192.168.1.1 --dport 80 --count 5 --dry-run

# Send a few test packets (requires root/capabilities)
fluxgen --interface eth0 --clients 2 --dst 192.168.1.1 --dport 80 --count 5
```

### For Developers

If you plan to modify or contribute to fluxgen:

```bash
# Clone the repository
git clone https://github.com/kanchankjha/fluxgen.git
cd fluxgen

# Install with development dependencies
pip install -e ".[dev]"

# This installs:
# - pytest>=7.0 - Testing framework
# - pytest-cov>=4.0 - Coverage reporting
# - pytest-mock>=3.10 - Mocking support

# Run tests to verify setup
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=fluxgen --cov-report=html
open htmlcov/index.html
```

## Quick Start Guide


### 1. Basic TCP SYN Flood

Simulate 10 clients sending TCP SYN packets:

```bash
fluxgen --interface eth0 --clients 10 --dst 10.0.0.5 --dport 80 --proto tcp --flags S --count 100 --interval 0.01
```

### 2. UDP Traffic Generation

Send UDP packets from multiple sources:

```bash
fluxgen --interface eth0 --clients 20 --dst 192.168.1.100 --dport 53 --proto udp --count 500 --interval 0.005
```

### 3. ICMP Ping Flood

Simulate multiple clients pinging a target:

```bash
fluxgen --interface eth0 --clients 50 --dst 8.8.8.8 --proto icmp --icmp-type 8 --icmp-code 0 --count 1000 --flood
```

### 4. Random Source and Destination

Test with randomized traffic patterns:

```bash
fluxgen --interface eth0 --clients 15 --dest-subnet 10.0.0.0/24 --rand-dest --rand-source --proto tcp --dport 80 --count 200
```

### 5. Custom Payload

Send packets with custom data:

```bash
# Text payload
fluxgen --interface eth0 --clients 5 --dst 10.0.0.5 --dport 8080 --proto tcp --payload "Hello Server" --count 10

# Hex payload
fluxgen --interface eth0 --clients 5 --dst 10.0.0.5 --dport 8080 --proto udp --payload "deadbeef" --payload-hex --count 10

# Auto-generated payload of specific size
fluxgen --interface eth0 --clients 2 --dst 10.0.0.5 --dport 53 --proto udp --data-size 512 --count 5

# IPv6 example (auto-detects family)
fluxgen --interface eth0 --clients 3 --dst 2001:db8::50 --dport 443 --proto tcp --ip-version auto --count 20
```

### 6. PCAP Capture

Export sent traffic for analysis:

```bash
fluxgen --interface eth0 --clients 10 --dst 10.0.0.5 --dport 443 --proto tcp --flags S --count 100 --pcap-out traffic.pcap
```

### 7. Configuration File

Use YAML configuration for complex scenarios:

```yaml
# config.yaml
interface: eth0
clients: 100
application: webex,outlook,iot
dst: 192.168.1.50
count: 1000
interval: 0.001
rand_source: true
pcap_out: load_test.pcap
```

```bash
fluxgen --config config.yaml
```

An independent responder configuration does not need a destination or client
pool. The interface supplies its IPv4 and IPv6 response addresses:

```yaml
interface: eth1
mode: server
application: all
ip_version: auto
duration: 300
pcap_out: responder.pcap
```

### 8. Beast Mode

Generate a continuous mix of all supported protocols (excluding IPv4-only ARP
and IGMP on IPv6). Packet sizes sweep from the valid minimum Ethernet frame
size through the selected interface's MTU and then repeat. Each simulated
client starts at a different point in the sequence.

```bash
# Run until Ctrl-C, sending without an interval
fluxgen --interface eth0 --client 100 --dst 192.168.1.1 --beast --faster

# Stop all clients after 60 seconds
fluxgen --interface eth0 --client 100 --dst 192.168.1.1 --beast --faster --time 60
```

`--client` is an alias for `--clients`, and `--faster` is an alias for
`--flood`. A missing `--time` or a value of `0` runs until interrupted. Beast
mode controls the protocol and payload profile, so it cannot be combined with
`--proto`, `--payload`, `--data-size`, or `--frag`. Explicit source and
destination ports remain supported as overrides.

### 9. Normal Traffic with Fuzzed Header Copies

`--fuzz` emits the normal packet first and then a same-size copy with mutations
on every applicable IP and protocol-header layer. Destination MAC/IP fields and
destination ports are preserved so both variants reach the same DUT. Boundary
values and explicitly malformed lengths/checksums are used where supported.

```bash
# Each logical send produces one normal TCP frame and one fuzzed copy
fluxgen --interface eth0 --dst 10.0.0.5 --proto tcp --dport 443 \
    --count 100 --fuzz --fuzz-seed 42

# Apply three mutations to every applicable header layer
fluxgen --interface eth0 --dst 10.0.0.5 --beast --fuzz \
    --fuzz-mutations 3 --time 30 --faster --pcap-out fuzz.pcap
```

`--count` counts logical sends, so fuzz mode normally emits twice that number
of frames. Fragmented traffic emits a normal/fuzzed pair for each fragment.
`--fuzz-seed` makes each client's mutation sequence reproducible.

## Usage

```bash
fluxgen --interface eth0 --clients 10 --dst 10.0.0.5 --dport 80 --proto tcp --flags S --count 100 --interval 0.01
```

Key flags:
- `--subnet-pool` CIDR to allocate client IPs (defaults to interface subnet)
- `--rand-source` randomize client identity per packet
- `--rand-dest --dest-subnet 10.0.0.0/24` randomize destination IPs
- `--payload "deadbeef" --payload-hex` send custom payload, or `--data-size 1024` to auto-fill a payload
- `--frag --frag-size 500 --frag-mode random` enable fragmentation with fixed or randomized fragment sizes
- `--ip-version 4|6|auto` force IPv4/IPv6 or let fluxgen infer from destinations
- `--flood` remove delay, `--dry-run` craft packets only, `--pcap-out out.pcap` write sent frames
- `--beast` continuously vary supported protocols and packet sizes; add `--time SECONDS` for a bounded run
- `--fuzz [--fuzz-seed N] [--fuzz-mutations N]` emit normal packets plus fuzzed header copies

### Common Use Cases

#### Load Testing a Web Server

```bash
# Simulate 100 concurrent clients
fluxgen --interface eth0 --clients 100 --dst webserver.local --dport 80 \
    --proto tcp --flags S --count 10000 --interval 0.001 \
    --pcap-out webserver_load.pcap
```

#### DDoS Simulation (Controlled Environment)

```bash
# High-rate flood from many sources
fluxgen --interface eth0 --clients 500 --dest-subnet 10.0.0.0/24 \
    --rand-dest --rand-source --proto tcp --dport 80 --flags S \
    --flood --count 50000
```

#### Network Device Stress Testing

```bash
# Test router/firewall with diverse traffic
fluxgen --interface eth0 --clients 50 --dst 192.168.1.1 \
    --proto tcp --dport 443 --flags SA --ttl 32 \
    --count 5000 --interval 0.002 --verbose
```

#### Protocol Testing

```bash
# Test ICMP handling
fluxgen --interface eth0 --clients 20 --dst target.local \
    --proto icmp --icmp-type 8 --icmp-code 0 \
    --count 1000 --interval 0.01

# Test UDP services
fluxgen --interface eth0 --clients 30 --dst dns-server.local \
    --proto udp --dport 53 --sport 50000 \
    --payload "test" --count 500
```

#### Multicast Testing (IGMP)

```bash
# Send IGMP membership reports
fluxgen --interface eth0 --clients 10 --dst 224.0.0.1 \
    --proto igmp --count 100 --interval 0.1
```

#### VPN/Tunnel Testing (GRE, ESP)

```bash
# Test GRE tunneling
fluxgen --interface eth0 --clients 5 --dst tunnel-endpoint.local \
    --proto gre --payload "encapsulated" --count 200

# Test IPsec ESP
fluxgen --interface eth0 --clients 5 --dst vpn-gateway.local \
    --proto esp --count 100
```

### Advanced Examples

#### Fragmented Traffic

```bash
# Send fragmented IP packets
fluxgen --interface eth0 --clients 10 --dst 10.0.0.5 --dport 80 \
    --proto tcp --frag --frag-size 512 --count 100
```

#### Custom IP Options

```bash
# Set custom TTL, TOS, and IP ID
fluxgen --interface eth0 --clients 5 --dst 10.0.0.5 --dport 22 \
    --proto tcp --ttl 16 --tos 0x10 --ip-id 12345 --count 50
```

#### Dry Run for Testing

```bash
# Build packets without sending (test configuration)
fluxgen --interface eth0 --clients 100 --dst 10.0.0.5 --dport 80 \
    --proto tcp --flags S --count 10 --dry-run --verbose
```

## CLI Reference

### Complete Parameter Reference

#### Configuration
- `--config PATH` - Load settings from YAML/JSON configuration file

#### Required Parameters
- `--interface IFACE` - Network interface to send packets on (e.g., eth0, wlan0)
- `--dst IP` - Destination IP address (required unless using `--dest-subnet`)

#### Operating Modes
- `--mode {client,server}` - Run the normal sender or an independent responder (default: `client`)
- `--bidirectional` - In client mode, track responder packets and complete synthetic transactions
- `--response-timeout SECONDS` - Reply wait time for bidirectional client transactions (default: `1.0`)
- `--session-timeout SECONDS` - Expire inactive responder TCP sessions (default: `300`)
- `--max-sessions N` - Bound responder TCP session memory (default: `10000`)

Server mode requires only `--interface`; it does not use `--dst`, `--clients`,
or client identity allocation. It discovers both IPv4 and non-link-local IPv6
addresses from that interface unless `--ip-version` selects one family.

#### Client Simulation
- `--clients N` - Number of simulated clients with unique IPs/MACs (default: 1)
- `--client-start-index N` - Start client IP allocation at host index `N` within the client subnet (for example, `21` gives `192.168.1.21` in `192.168.1.0/24`)
- `--application NAME[,NAME...]` - Generate application-shaped traffic using one or more built-in profiles, or use `all` to cycle through the full catalog
- `--subnet-pool CIDR` - IP range for client addresses (default: interface subnet)
- `--rand-source` - Randomize source identity for each packet

Application profiles control the default transport, destination ports, payload
sizes, and traffic shape. They generate synthetic L7-shaped frames rather than
real authenticated application sessions. Application profiles cannot be
combined with `--proto`, `--flags`, `--payload`, `--data-size`, or `--beast`; explicit
`--dport` and `--sport` overrides remain supported.

The built-in catalog contains 100 profiles:

| Category | Profiles |
| --- | --- |
| Collaboration | `webex`, `zoom`, `microsoft-teams`, `google-meet`, `slack`, `discord`, `mattermost`, `rocket-chat`, `zulip`, `jabber` |
| Productivity | `outlook`, `gmail`, `exchange-online`, `sharepoint`, `onedrive`, `google-drive`, `dropbox`, `box`, `confluence`, `notion` |
| Web/business | `web-browsing`, `https-saas`, `rest-api`, `graphql-api`, `webhooks`, `e-commerce`, `salesforce`, `servicenow`, `jira`, `sap` |
| Voice/media | `voice`, `video`, `live-video`, `video-on-demand`, `music-streaming`, `podcast`, `webinar`, `screen-sharing`, `telemedicine`, `online-classroom` |
| Network services | `dns`, `dns-over-https`, `dns-over-tls`, `ntp`, `dhcp`, `ldap`, `kerberos`, `radius`, `tacacs-plus`, `snmp` |
| IoT/OT | `iot`, `mqtt`, `mqtt-tls`, `coap`, `lwm2m`, `modbus-tcp`, `opc-ua`, `bacnet-ip`, `smart-meter`, `sensor-telemetry` |
| Development/cloud | `git-https`, `git-ssh`, `container-registry`, `kubernetes-api`, `cloud-object-storage`, `ci-cd`, `artifact-repository`, `package-manager`, `terraform-api`, `serverless-invocation` |
| Data/database | `data`, `postgresql`, `mysql`, `mssql`, `oracle-db`, `redis`, `mongodb`, `elasticsearch`, `kafka`, `amqp` |
| Security/remote | `ipsec-vpn`, `ssl-vpn`, `ssh`, `rdp`, `vnc`, `winrm`, `syslog`, `siem-ingestion`, `edr-telemetry`, `vulnerability-scanner` |
| Consumer/edge | `online-gaming`, `game-voice-chat`, `p2p-file-sharing`, `software-update`, `backup-sync`, `smart-tv`, `social-media`, `ads-analytics`, `video-surveillance`, `digital-signage` |

Examples:

```bash
# One application profile
fluxgen --interface eth0 --clients 100 --application webex --dst 10.0.0.5 --count 1000

# Rotate through a selected mix
fluxgen --interface eth0 --clients 100 --application webex,outlook,iot --dst 10.0.0.5 --count 1000

# Cycle through all 100 profiles
fluxgen --interface eth0 --clients 100 --application all --dst 10.0.0.5 --count 1000
```

### Independent responder mode

Fluxgen can run as an independent responder on a separate machine from the
sender. In server mode, `--interface` is the address-selection input:
Fluxgen discovers the interface's eligible IPv4 and non-link-local IPv6
addresses and responds to traffic addressed to those addresses. With
`--ip-version auto` (the default for server mode), both families are enabled;
use `--ip-version 4` or `--ip-version 6` to restrict the responder to one
family.

Start the responder on the destination machine:

```bash
fluxgen --mode server --interface eth1 --application all --time 300
```

Start stateless application traffic on the sender machine as before:

```bash
fluxgen --interface eth0 --clients 100 --dst 192.0.2.10 \
    --application all --count 1000
```

Use `--bidirectional` on the sender when the client should track replies and
complete synthetic transactions:

```bash
fluxgen --interface eth0 --clients 100 --dst 192.0.2.10 \
    --application all --bidirectional --count 1000
```

The responder and sender coordinate only through packets; they do not share a
process or control connection. The responder supports synthetic TCP
SYN/SYN-ACK and payload exchanges, UDP request/response traffic,
ICMP/ICMPv6 echo replies, ARP replies, and basic SCTP responses. All 100
application profiles are supported as synthetic TCP/UDP request/response
shapes. These profiles are designed for DUT flow and traffic classification;
they do not authenticate to or reproduce proprietary, encrypted applications
such as Webex, Outlook, VPNs, or database products.

Server mode is scoped to packets addressed to the selected interface. It does
not act as an open response reflector. For routed testbeds, ensure the
responder host has a return route to the simulated client subnet; for a
directly connected DUT, the responder uses the incoming Ethernet peer for the
reverse frame.

#### Destination Options
- `--dest-subnet CIDR` - IP range for random destination addresses
- `--rand-dest` - Randomize destination IP per packet (uses `--dest-subnet` if provided)

#### Protocol Settings
- `--proto {tcp,udp,icmp,igmp,gre,esp,ah,sctp,arp,vrrp,ospf}` - Protocol (default: tcp)

#### TCP/UDP/SCTP Options
- `--dport N` - Destination port (1-65535)
- `--sport N` - Source port (1-65535, default: random)
- `--flags STRING` - TCP flags: S (SYN), A (ACK), F (FIN), R (RST), P (PSH), U (URG) (default: S)

#### ICMP Options
- `--icmp-type N` - ICMP type (default: 8 for echo request)
- `--icmp-code N` - ICMP code (default: 0)

#### IP Layer Options
- `--ttl N` - IP Time-To-Live (default: 64)
- `--tos N` - IP Type of Service / DSCP value (default: 0)
- `--ip-id N` - IP identification field (default: random)
- `--frag` - Enable IP fragmentation
- `--frag-size N` - Fragment size in bytes (requires `--frag`)

#### Payload Options
- `--payload STRING` - Packet payload as text
- `--payload-hex` - Interpret payload as hexadecimal string (e.g., "deadbeef")

#### Traffic Control
- `--count N` - Packets to send per client (0 = infinite, default: 0)
- `--interval SECONDS` - Delay between packets (default: 0.1 seconds)
- `--flood`, `--faster` - Remove delay between packets (maximum speed)
- `--beast` - Rotate supported protocols, ports, flags, TTL/TOS, and packet sizes
- `--fuzz` - Emit every normal frame followed by a fuzzed header copy
- `--fuzz-seed N` - Seed the per-client header mutation sequence
- `--fuzz-mutations N` - Mutations per applicable header layer (default: 1)
- `--time SECONDS` - Global runtime; missing or 0 means run until interrupted

#### Output and Debugging
- `--pcap-out PATH` - Write sent packets to PCAP file
- `--dry-run` - Build packets without sending (test configuration)
- `--verbose` - Print detailed error messages for send/craft failures
- `--quiet` - Suppress periodic statistics output

### Examples by Scenario

#### Web Server Load Testing
```bash
# Simulate 200 users making HTTP requests
fluxgen --interface eth0 --clients 200 --dst web.example.com --dport 80 \
    --proto tcp --flags S --count 5000 --interval 0.002
```

#### DNS Server Testing
```bash
# Simulate 50 clients making DNS queries
fluxgen --interface eth0 --clients 50 --dst 8.8.8.8 --dport 53 \
    --proto udp --payload "example.com" --count 1000 --interval 0.01
```

#### Firewall Rule Testing
```bash
# Test firewall with various ports and protocols
fluxgen --interface eth0 --clients 10 --dst firewall.local \
    --proto tcp --dport 443 --flags S --ttl 64 --count 500 \
    --pcap-out firewall_test.pcap
```

#### Network Monitoring Tool Testing
```bash
# Generate diverse traffic patterns for IDS/IPS testing
fluxgen --interface eth0 --clients 100 --dest-subnet 192.168.1.0/24 \
    --rand-dest --rand-source --proto tcp --dport 80 --flags S \
    --count 10000 --interval 0.001 --verbose
```

## Supported Protocols

fluxgen supports a wide range of network protocols for comprehensive testing:

### Layer 4 Protocols

#### TCP (Transmission Control Protocol)
- Full control over TCP flags (SYN, ACK, FIN, RST, PSH, URG)
- Custom source and destination ports
- Ideal for connection-oriented testing
```bash
fluxgen --interface eth0 --dst target --dport 80 --proto tcp --flags S
```

#### UDP (User Datagram Protocol)
- Connectionless packet delivery
- Custom payloads and ports
- Perfect for DNS, DHCP, streaming protocols
```bash
fluxgen --interface eth0 --dst target --dport 53 --proto udp
```

#### SCTP (Stream Control Transmission Protocol)
- Multi-homing support
- Message-oriented reliability
- Used in telecom and signaling
```bash
fluxgen --interface eth0 --dst target --dport 5060 --proto sctp
```

### Layer 3 Protocols

#### ARP (Address Resolution Protocol, IPv4 only)
- Broadcast ARP requests using each simulated client's IP/MAC identity
- Fuzz ARP operation and target-hardware fields while preserving the target IP
```bash
fluxgen --interface eth0 --dst 192.168.1.1 --proto arp --fuzz
```

#### VRRP (Virtual Router Redundancy Protocol)
- VRRPv2 over IPv4 and VRRPv3 over IPv6
```bash
fluxgen --interface eth0 --dst 224.0.0.18 --proto vrrp
```

#### OSPF (Open Shortest Path First)
- OSPFv2 Hello packets over IPv4 and OSPFv3 Hello packets over IPv6
```bash
fluxgen --interface eth0 --dst 224.0.0.5 --proto ospf
```

#### ICMP (Internet Control Message Protocol)
- Echo requests (ping)
- Customizable type and code
- Network diagnostics and reachability testing
```bash
fluxgen --interface eth0 --dst target --proto icmp --icmp-type 8 --icmp-code 0
```

#### IGMP (Internet Group Management Protocol)
- Multicast group management
- Test multicast routing and switches
- Membership reports and queries
```bash
fluxgen --interface eth0 --dst 224.0.0.1 --proto igmp
```

#### GRE (Generic Routing Encapsulation)
- IP tunneling protocol
- Test VPN and tunnel endpoints
- Encapsulation of various protocols
```bash
fluxgen --interface eth0 --dst tunnel-endpoint --proto gre
```

### IPsec Protocols

#### ESP (Encapsulating Security Payload)
- IPsec encryption protocol
- Test VPN gateways
- Encrypted packet delivery
```bash
fluxgen --interface eth0 --dst vpn-gateway --proto esp
```

#### AH (Authentication Header)
- IPsec authentication protocol
- Integrity verification
- Test IPsec implementations
```bash
fluxgen --interface eth0 --dst vpn-gateway --proto ah
```

## Troubleshooting

### Common Issues and Solutions

#### 1. "Permission denied" or "Operation not permitted"

**Problem:** fluxgen requires raw socket access to craft custom packets.

**Solutions:**
```bash
# Solution A: Run with sudo
sudo fluxgen --interface eth0 --dst 10.0.0.5 --dport 80

# Solution B: Grant capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin+ep $(which python3)
# Or for venv:
sudo setcap cap_net_raw,cap_net_admin+ep .venv/bin/python3

# Verify capabilities
getcap $(which python3)
```

#### 2. "No such device" or interface not found

**Problem:** Invalid or non-existent network interface.

**Solutions:**
```bash
# List available interfaces
ip link show
# Or
ifconfig -a

# Use correct interface name
fluxgen --interface enp0s3 --dst 10.0.0.5 --dport 80
```

#### 3. "ModuleNotFoundError: No module named 'scapy'"

**Problem:** Dependencies not installed.

**Solution:**
```bash
# Install all dependencies
pip install -r requirements.txt

# Or install individually
pip install scapy psutil pyyaml netifaces
```

#### 4. No packets being sent (dry-run mode)

**Problem:** Accidentally running in dry-run mode.

**Solution:**
```bash
# Remove --dry-run flag
fluxgen --interface eth0 --dst 10.0.0.5 --dport 80 --count 10
# Not: ... --dry-run
```

#### 5. "Cannot allocate memory" or system slowdown

**Problem:** Too many clients or flood mode overwhelming system.

**Solutions:**
```bash
# Reduce number of clients
fluxgen --interface eth0 --clients 50 --dst target --dport 80
# Instead of: --clients 10000

# Add interval (remove --flood)
fluxgen --interface eth0 --clients 100 --dst target --dport 80 --interval 0.001

# Monitor system resources
htop  # or top
```

#### 6. Packets not reaching destination

**Problem:** Firewall, routing, or network configuration issues.

**Troubleshooting:**
```bash
# Check if target is reachable
ping target-ip

# Verify routing
ip route show
traceroute target-ip

# Check firewall rules
sudo iptables -L -n -v

# Test with PCAP capture
fluxgen --interface eth0 --dst target --dport 80 --count 10 --pcap-out test.pcap
# Verify with Wireshark: wireshark test.pcap

# Enable verbose mode
fluxgen --interface eth0 --dst target --dport 80 --count 10 --verbose
```

#### 7. Python version incompatibility

**Problem:** fluxgen requires Python 3.8+.

**Solution:**
```bash
# Check Python version
python3 --version

# Upgrade if needed (Ubuntu/Debian)
sudo apt update
sudo apt install python3.11

# Or use pyenv for version management
pyenv install 3.11.0
pyenv local 3.11.0
```

### Getting Help

```bash
# Display all available options
fluxgen --help

# Test with minimal configuration
fluxgen --interface eth0 --dst 127.0.0.1 --dport 8080 --count 5 --dry-run

# Run with verbose output for debugging
fluxgen --interface eth0 --dst target --dport 80 --count 10 --verbose

# Check packet crafting without sending
fluxgen --interface eth0 --clients 5 --dst target --dport 80 --count 2 --dry-run --verbose
```

### Debug Workflow

```bash
# Step 1: Verify installation
fluxgen --help

# Step 2: Test packet building (no sending)
fluxgen --interface eth0 --dst 192.168.1.1 --dport 80 --count 1 --dry-run --verbose

# Step 3: Send to localhost first
fluxgen --interface lo --dst 127.0.0.1 --dport 8080 --count 5

# Step 4: Capture and inspect packets
fluxgen --interface eth0 --dst target --dport 80 --count 10 --pcap-out debug.pcap
wireshark debug.pcap

# Step 5: Gradually increase complexity
fluxgen --interface eth0 --clients 2 --dst target --dport 80 --count 10
fluxgen --interface eth0 --clients 10 --dst target --dport 80 --count 100
```


## Project Structure


```
fluxgen/
├── fluxgen/               # Main package directory
│   ├── __init__.py      # Package initialization
│   ├── __main__.py      # Entry point for `python -m fluxgen`
│   ├── applications.py  # Declarative application traffic profiles
│   ├── cli.py           # Command-line interface and argument parsing
│   ├── config.py        # Configuration file loading (YAML/JSON)
│   ├── identity.py      # Client identity generation (IP/MAC)
│   ├── netinfo.py       # Network interface introspection
│   ├── packet_builder.py # Packet crafting with Scapy
│   ├── responder.py     # Independent dual-stack packet responder
│   └── sender.py        # Multi-client orchestration and sending
├── tests/               # Unit tests
│   ├── test_applications.py # Application profile tests
│   ├── test_cli.py      # CLI argument parsing tests
│   ├── test_config.py   # Configuration file tests
│   ├── test_identity.py # Client identity tests
│   ├── test_netinfo.py  # Network interface tests
│   ├── test_packet_builder.py # Packet building tests
│   ├── test_responder.py # Independent responder tests
│   └── test_sender.py   # Sender orchestration tests
├── pyproject.toml       # Project metadata and dependencies
├── requirements.txt     # Runtime dependencies
└── README.md           # This file
```

### Key Modules

- **applications.py**: Defines the 100 built-in application-shaped traffic profiles
- **cli.py**: Parses command-line arguments, validates inputs, and orchestrates execution
- **identity.py**: Generates unique client identities (source IPs, MACs) within subnet constraints
- **netinfo.py**: Queries system network interfaces using `psutil` and `netifaces`
- **packet_builder.py**: Constructs protocol packets using Scapy with custom fields
- **responder.py**: Captures traffic addressed to interface IPv4/IPv6 addresses and emits synthetic protocol/application responses
- **sender.py**: Manages multiple client threads/processes, sends packets, optionally tracks responses, and collects statistics
- **config.py**: Loads configuration from YAML/JSON files for reproducible testing scenarios

## Testing

fluxgen includes comprehensive unit tests for all modules.

### Running Tests

```bash
# Install development dependencies
pip install pytest pytest-cov pytest-mock

# Run all tests
pytest

# Run with coverage report
pytest --cov=fluxgen --cov-report=html

# Run specific test file
pytest tests/test_packet_builder.py

# Run tests with verbose output
pytest -v

# Run tests matching a pattern
pytest -k "test_tcp"
```

### Test Coverage

The test suite covers:
- ✅ CLI argument parsing and validation
- ✅ Configuration file loading (YAML/JSON)
- ✅ Client identity generation with subnet constraints
- ✅ Network interface introspection
- ✅ Packet building for all supported protocols
- ✅ Multi-client sender orchestration
- ✅ Independent dual-stack responder and synthetic protocol responses
- ✅ Bidirectional client transaction framing and response correlation
- ✅ Error handling and edge cases
- ✅ Dry-run mode and PCAP output

```bash
# View coverage report
pytest --cov=fluxgen --cov-report=term-missing

# Generate HTML coverage report
pytest --cov=fluxgen --cov-report=html
open htmlcov/index.html  # macOS
# Or: firefox htmlcov/index.html  # Linux
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Write tests** for new functionality
3. **Ensure all tests pass**: `pytest`
4. **Follow PEP 8** coding style
5. **Submit a pull request** with clear description

### Development Setup

```bash
# Clone and setup development environment
git clone <repository-url>
cd fluxgen
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-cov pytest-mock

# Run tests before committing
pytest --cov=fluxgen

# Install in editable mode for development
pip install -e .
```

## License

This project is provided as-is for educational and testing purposes. Ensure you have proper authorization before using fluxgen on any network.
