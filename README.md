# Outfazed
Outfaze is a Red Team tool designed to assess outbound egress paths and simulate controlled data exfiltration. It includes a .NET-based client probe and a Go-based server collector.

## Components
### 1. egress-n-exfil (C#/.NET)
A console tool for probing outbound egress vectors and testing data transfer to a specified target.

#### Features
- **TCP Egress Testing** (Ports 1–65535)
- **UDP Packet Send Test** (optional)
- **ICMP Ping**
- **HTTP/HTTPS POST Payload**
- **DNS-Based Covert Exfiltration** (via Base32 subdomain chunks)

#### Usage
```Outfaze.Client.exe <target_host_or_ip> <dns_exfil_domain> [payload_file]```

### 2. serve-n-collect (Golang)
A flexible multi-protocol server that listens for incoming exfiltration payloads, logs data by channel, and supports:

#### Features
- **All TCP ports (1–65535)**: Binds and logs connections on all ports
- **HTTP(S) POST**: Logs /collect payloads
- **UDP Receiver**: Logs packet source/length
- **DNS Server (UDP/TCP)**: Responds with configurable A-record and logs queries

#### Deployment
- Build the Binary
```GOOS=linux GOARCH=amd64 go build -o serve-n-collect main.go```
- Run the install script
```sudo bash setup_server.sh```
- This will:
  - Install prerequisites
  - Create service user
  - Deploy binary to /opt/outfaze
  - Set capabilities for low-port binding
  - Install and enable systemd service
  - Open required firewall ports via UFW
  
 ### 3.Use Cases
- Red Team post-exploitation testing
- Firewall/egress audit validation
- Data exfiltration simulation
- Blue Team detection effectiveness testing
- Network segmentation control validation

