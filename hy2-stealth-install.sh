#!/bin/bash

# Enhanced Hysteria 2 Installation Script with Security & Stealth Features
# Version: 2.0 Enhanced

export LANG=en_US.UTF-8
export PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"

# Colors
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PURPLE="\033[35m"
CYAN="\033[36m"
PLAIN="\033[0m"

# Enhanced color functions
red() { echo -e "\033[31m\033[01m$1\033[0m"; }
green() { echo -e "\033[32m\033[01m$1\033[0m"; }
yellow() { echo -e "\033[33m\033[01m$1\033[0m"; }
blue() { echo -e "\033[34m\033[01m$1\033[0m"; }
purple() { echo -e "\033[35m\033[01m$1\033[0m"; }
cyan() { echo -e "\033[36m\033[01m$1\033[0m"; }

# System detection arrays
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora" "arch")
RELEASE=("Debian" "Ubuntu" "CentOS" "Amazon" "Fedora" "Arch")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update" "pacman -Sy")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install" "pacman -S --noconfirm")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove" "pacman -R --noconfirm")

# Security check - must run as root
[[ $EUID -ne 0 ]] && red "Error: Please run this script as root user" && exit 1

# Enhanced system detection
detect_system() {
    CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" 
         "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" 
         "$(lsb_release -sd 2>/dev/null)" 
         "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" 
         "$(grep . /etc/redhat-release 2>/dev/null)" 
         "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

    for i in "${CMD[@]}"; do
        SYS="$i" && [[ -n $SYS ]] && break
    done

    for ((int = 0; int < ${#REGEX[@]}; int++)); do
        [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
    done

    [[ -z $SYSTEM ]] && red "Unsupported operating system!" && exit 1
    green "Detected system: $SYSTEM"
}

# Enhanced dependency installation
install_dependencies() {
    yellow "Installing necessary dependencies..."
    
    if [[ ! $SYSTEM == "CentOS" && ! $SYSTEM == "Amazon" ]]; then
        ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
    fi
    
    # Install basic tools
    ${PACKAGE_INSTALL[int]} curl wget sudo qrencode procps >/dev/null 2>&1
    
    # Install firewall tools based on system
    if [[ $SYSTEM == "Debian" || $SYSTEM == "Ubuntu" ]]; then
        ${PACKAGE_INSTALL[int]} iptables-persistent netfilter-persistent ufw >/dev/null 2>&1
    elif [[ $SYSTEM == "CentOS" || $SYSTEM == "Amazon" || $SYSTEM == "Fedora" ]]; then
        ${PACKAGE_INSTALL[int]} iptables-services firewalld >/dev/null 2>&1
    fi
    
    green "Dependencies installed successfully"
}

# Get real IP with enhanced detection
get_real_ip() {
    # Try multiple IP detection services
    local ip_services=("ip.sb" "ipinfo.io/ip" "icanhazip.com" "ident.me" "whatismyipaddress.com/api/ip.php")
    
    for service in "${ip_services[@]}"; do
        ip=$(curl -s4m8 "$service" -k 2>/dev/null | grep -oE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
        [[ -n $ip ]] && break
        
        # Try IPv6 if IPv4 fails
        ip=$(curl -s6m8 "$service" -k 2>/dev/null)
        [[ -n $ip ]] && break
    done
    
    [[ -z $ip ]] && red "Failed to get server IP" && exit 1
    green "Server IP: $ip"
}

# Enhanced certificate management
setup_certificate() {
    green "Certificate configuration options:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Self-signed certificate ${YELLOW}(Default, Most Secure)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} ACME automatic certificate"
    echo -e " ${GREEN}3.${PLAIN} Custom certificate path"
    echo -e " ${GREEN}4.${PLAIN} Generate custom domain certificate"
    echo ""
    read -rp "Select option [1-4]: " cert_choice
    
    case $cert_choice in
        2) setup_acme_cert ;;
        3) setup_custom_cert ;;
        4) setup_custom_domain_cert ;;
        *) setup_self_signed_cert ;;
    esac
}

setup_self_signed_cert() {
    green "Generating enhanced self-signed certificate..."
    
    # Create secure directory
    mkdir -p /etc/hysteria/certs
    chmod 700 /etc/hysteria/certs
    
    # Generate random domain name for stealth
    local domains=("www.google.com" "www.microsoft.com" "www.apple.com" "www.amazon.com" "www.cloudflare.com")
    hy_domain=${domains[$RANDOM % ${#domains[@]}]}
    
    cert_path="/etc/hysteria/certs/server.crt"
    key_path="/etc/hysteria/certs/server.key"
    
    # Generate certificate with enhanced security
    openssl ecparam -genkey -name prime256v1 -out "$key_path"
    openssl req -new -x509 -days 36500 -key "$key_path" -out "$cert_path" \
        -subj "/C=US/ST=CA/L=Los Angeles/O=Technology Inc/CN=$hy_domain" >/dev/null 2>&1
    
    # Set secure permissions
    chmod 600 "$cert_path" "$key_path"
    chown root:root "$cert_path" "$key_path"
    
    green "Self-signed certificate generated with domain: $hy_domain"
}

setup_acme_cert() {
    yellow "Setting up ACME certificate..."
    
    # Check WARP status
    local warp_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ $warp_status =~ on|plus ]]; then
        yellow "WARP detected, temporarily disabling..."
        wg-quick down wgcf >/dev/null 2>&1
        systemctl stop warp-go >/dev/null 2>&1
    fi
    
    get_real_ip
    
    read -p "Enter domain name for certificate: " domain
    [[ -z $domain ]] && red "Domain name required!" && exit 1
    
    # Verify domain points to server
    local domain_ip=$(curl -sm8 "ipget.net/?ip=${domain}" 2>/dev/null)
    if [[ $domain_ip != $ip ]]; then
        red "Domain IP ($domain_ip) doesn't match server IP ($ip)"
        exit 1
    fi
    
    # Install acme.sh
    curl -s https://get.acme.sh | sh -s email=admin@$(date +%s%N | md5sum | cut -c 1-8).com >/dev/null 2>&1
    source ~/.bashrc
    
    cert_path="/etc/hysteria/certs/${domain}.crt"
    key_path="/etc/hysteria/certs/${domain}.key"
    
    mkdir -p /etc/hysteria/certs
    chmod 700 /etc/hysteria/certs
    
    # Issue certificate
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --insecure >/dev/null 2>&1
    ~/.acme.sh/acme.sh --install-cert -d "$domain" --key-file "$key_path" --fullchain-file "$cert_path" --ecc >/dev/null 2>&1
    
    if [[ -f $cert_path && -f $key_path ]]; then
        chmod 600 "$cert_path" "$key_path"
        chown root:root "$cert_path" "$key_path"
        echo "$domain" > /etc/hysteria/domain.conf
        hy_domain=$domain
        green "ACME certificate installed successfully"
    else
        red "Certificate installation failed"
        exit 1
    fi
    
    # Re-enable WARP if it was running
    [[ $warp_status =~ on|plus ]] && systemctl start warp-go >/dev/null 2>&1
}

setup_custom_cert() {
    read -p "Enter certificate file path: " cert_path
    read -p "Enter private key file path: " key_path
    read -p "Enter domain name: " hy_domain
    
    if [[ ! -f $cert_path || ! -f $key_path ]]; then
        red "Certificate or key file not found!"
        exit 1
    fi
    
    # Set secure permissions
    chmod 600 "$cert_path" "$key_path"
    chown root:root "$cert_path" "$key_path"
    
    green "Custom certificate configured"
}

setup_custom_domain_cert() {
    read -p "Enter custom domain name: " custom_domain
    [[ -z $custom_domain ]] && custom_domain="cdn.$(date +%s%N | md5sum | cut -c 1-6).net"
    
    cert_path="/etc/hysteria/certs/custom.crt"
    key_path="/etc/hysteria/certs/custom.key"
    
    mkdir -p /etc/hysteria/certs
    chmod 700 /etc/hysteria/certs
    
    openssl ecparam -genkey -name prime256v1 -out "$key_path"
    openssl req -new -x509 -days 36500 -key "$key_path" -out "$cert_path" \
        -subj "/C=US/ST=NY/L=New York/O=CDN Services/CN=$custom_domain" >/dev/null 2>&1
    
    chmod 600 "$cert_path" "$key_path"
    chown root:root "$cert_path" "$key_path"
    
    hy_domain=$custom_domain
    green "Custom domain certificate generated: $custom_domain"
}

# Enhanced port configuration with stealth features
setup_port() {
    # Clear any existing NAT rules safely
    iptables -t nat -F HYSTERIA_PREROUTING >/dev/null 2>&1
    iptables -t nat -X HYSTERIA_PREROUTING >/dev/null 2>&1
    
    echo ""
    green "Port configuration options:"
    echo -e " ${GREEN}1.${PLAIN} Random high port ${YELLOW}(Recommended)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Custom single port"
    echo -e " ${GREEN}3.${PLAIN} Port hopping range"
    echo -e " ${GREEN}4.${PLAIN} Disguised common port"
    echo ""
    read -rp "Select option [1-4]: " port_choice
    
    case $port_choice in
        2) setup_custom_port ;;
        3) setup_port_hopping ;;
        4) setup_disguised_port ;;
        *) setup_random_port ;;
    esac
}

setup_random_port() {
    # Use high random port for better stealth
    port=$(shuf -i 10000-65535 -n 1)
    while [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        port=$(shuf -i 10000-65535 -n 1)
    done
    green "Using random port: $port"
}

setup_custom_port() {
    read -p "Enter custom port [1-65535]: " port
    [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1)
    
    while [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        red "Port $port is already in use!"
        read -p "Enter another port: " port
        [[ -z $port ]] && port=$(shuf -i 10000-65535 -n 1)
    done
    green "Using custom port: $port"
}

setup_port_hopping() {
    read -p "Enter start port [10000-65000]: " start_port
    read -p "Enter end port [10001-65535]: " end_port
    
    [[ -z $start_port ]] && start_port=10000
    [[ -z $end_port ]] && end_port=20000
    
    if [[ $start_port -ge $end_port ]]; then
        red "Start port must be less than end port!"
        return
    fi
    
    port=$(shuf -i $start_port-$end_port -n 1)
    
    # Create NAT rules for port hopping
    iptables -t nat -N HYSTERIA_PREROUTING >/dev/null 2>&1
    iptables -t nat -A HYSTERIA_PREROUTING -p udp --dport $start_port:$end_port -j DNAT --to-destination :$port
    iptables -t nat -I PREROUTING -j HYSTERIA_PREROUTING
    
    # IPv6 support
    ip6tables -t nat -N HYSTERIA_PREROUTING >/dev/null 2>&1
    ip6tables -t nat -A HYSTERIA_PREROUTING -p udp --dport $start_port:$end_port -j DNAT --to-destination :$port
    ip6tables -t nat -I PREROUTING -j HYSTERIA_PREROUTING >/dev/null 2>&1
    
    # Save rules
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1
    fi
    
    port_range="$start_port-$end_port"
    green "Port hopping configured: $start_port-$end_port -> $port"
}

setup_disguised_port() {
    local common_ports=(80 443 8080 8443 3306 5432 6379 11211)
    echo "Common service ports for disguise:"
    for i in "${!common_ports[@]}"; do
        echo -e " $((i+1)). ${common_ports[i]}"
    done
    
    read -p "Select disguised port [1-8] or enter custom: " disguise_choice
    
    if [[ $disguise_choice =~ ^[1-8]$ ]]; then
        disguise_port=${common_ports[$((disguise_choice-1))]}
    else
        disguise_port=$disguise_choice
    fi
    
    port=$(shuf -i 10000-65535 -n 1)
    
    # Set up port forwarding
    iptables -t nat -N HYSTERIA_PREROUTING >/dev/null 2>&1
    iptables -t nat -A HYSTERIA_PREROUTING -p udp --dport $disguise_port -j DNAT --to-destination :$port
    iptables -t nat -I PREROUTING -j HYSTERIA_PREROUTING
    
    green "Port disguised: $disguise_port -> $port"
    display_port=$disguise_port
}

# Enhanced password generation
setup_password() {
    echo ""
    green "Password configuration:"
    echo -e " ${GREEN}1.${PLAIN} Strong random password ${YELLOW}(Recommended)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Custom password"
    echo -e " ${GREEN}3.${PLAIN} UUID-based password"
    echo ""
    read -rp "Select option [1-3]: " pwd_choice
    
    case $pwd_choice in
        2)
            read -p "Enter custom password: " auth_pwd
            [[ -z $auth_pwd ]] && auth_pwd=$(generate_strong_password)
            ;;
        3)
            auth_pwd=$(uuidgen | tr -d '-' | tr '[:upper:]' '[:lower:]')
            ;;
        *)
            auth_pwd=$(generate_strong_password)
            ;;
    esac
    
    green "Password configured: $auth_pwd"
}

generate_strong_password() {
    # Generate a 16-character strong password
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-16
}

# Enhanced masquerade setup
setup_masquerade() {
    echo ""
    green "Masquerade website options:"
    echo -e " ${GREEN}1.${PLAIN} Popular tech sites ${YELLOW}(Recommended)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Educational institutions"
    echo -e " ${GREEN}3.${PLAIN} Cloud services"
    echo -e " ${GREEN}4.${PLAIN} Custom website"
    echo ""
    read -rp "Select option [1-4]: " masq_choice
    
    case $masq_choice in
        2)
            local edu_sites=("www.mit.edu" "www.stanford.edu" "www.harvard.edu" "www.berkeley.edu")
            masquerade_site=${edu_sites[$RANDOM % ${#edu_sites[@]}]}
            ;;
        3)
            local cloud_sites=("aws.amazon.com" "cloud.google.com" "azure.microsoft.com" "www.digitalocean.com")
            masquerade_site=${cloud_sites[$RANDOM % ${#cloud_sites[@]}]}
            ;;
        4)
            read -p "Enter custom website (without https://): " masquerade_site
            [[ -z $masquerade_site ]] && masquerade_site="www.google.com"
            ;;
        *)
            local tech_sites=("www.google.com" "www.microsoft.com" "www.apple.com" "www.github.com" "www.stackoverflow.com")
            masquerade_site=${tech_sites[$RANDOM % ${#tech_sites[@]}]}
            ;;
    esac
    
    green "Masquerade site: $masquerade_site"
}

# Download and install Hysteria 2
install_hysteria() {
    yellow "Downloading Hysteria 2..."
    
    # Get latest version
    local latest_version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" | grep -Po '"tag_name": "\K.*?(?=")')
    [[ -z $latest_version ]] && latest_version="v2.2.0"
    
    # Detect architecture
    local arch=$(uname -m)
    case $arch in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l) arch="armv7" ;;
        *) red "Unsupported architecture: $arch" && exit 1 ;;
    esac
    
    # Download Hysteria 2
    local download_url="https://github.com/apernet/hysteria/releases/download/${latest_version}/hysteria-linux-${arch}"
    
    if curl -L -o /usr/local/bin/hysteria "$download_url" >/dev/null 2>&1; then
        chmod +x /usr/local/bin/hysteria
        green "Hysteria 2 downloaded successfully"
    else
        red "Failed to download Hysteria 2"
        exit 1
    fi
}

# Create enhanced configuration
create_config() {
    mkdir -p /etc/hysteria
    chmod 700 /etc/hysteria
    
    # Determine final port configuration
    if [[ -n $port_range ]]; then
        final_port="${display_port:-$port},$port_range"
    else
        final_port="${display_port:-$port}"
    fi
    
    # Format IP address
    if [[ -n $(echo $ip | grep ":") ]]; then
        formatted_ip="[$ip]"
    else
        formatted_ip=$ip
    fi
    
    # Create server configuration
    cat > /etc/hysteria/config.yaml << EOF
# Hysteria 2 Server Configuration
listen: :$port

tls:
  cert: $cert_path
  key: $key_path

quic:
  initStreamReceiveWindow: 26214400
  maxStreamReceiveWindow: 26214400
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

bandwidth:
  up: 1 gbps
  down: 1 gbps

ignoreClientBandwidth: false

auth:
  type: password
  password: $auth_pwd

masquerade:
  type: proxy
  proxy:
    url: https://$masquerade_site
    rewriteHost: true

resolver:
  type: udp
  tcp:
    addr: 8.8.8.8:53
    timeout: 4s
  udp:
    addr: 8.8.8.8:53
    timeout: 4s
  tls:
    addr: 8.8.8.8:853
    timeout: 10s
    sni: dns.google
    insecure: false
  https:
    addr: https://1.1.1.1/dns-query
    timeout: 10s

acl:
  inline:
    - reject(geoip:private)

outbounds:
  - name: default
    type: direct
EOF

    # Create client configurations directory
    mkdir -p /etc/hysteria/clients
    chmod 700 /etc/hysteria/clients
    
    # Create YAML client config
    cat > /etc/hysteria/clients/config.yaml << EOF
server: $formatted_ip:$final_port

auth: $auth_pwd

tls:
  sni: $hy_domain
  insecure: true

quic:
  initStreamReceiveWindow: 26214400
  maxStreamReceiveWindow: 26214400
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864

fastOpen: true

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080

transport:
  udp:
    hopInterval: 30s
EOF

    # Create JSON client config
    cat > /etc/hysteria/clients/config.json << EOF
{
  "server": "$formatted_ip:$final_port",
  "auth": "$auth_pwd",
  "tls": {
    "sni": "$hy_domain",
    "insecure": true
  },
  "quic": {
    "initStreamReceiveWindow": 26214400,
    "maxStreamReceiveWindow": 26214400,
    "initConnReceiveWindow": 67108864,
    "maxConnReceiveWindow": 67108864
  },
  "fastOpen": true,
  "socks5": {
    "listen": "127.0.0.1:1080"
  },
  "http": {
    "listen": "127.0.0.1:8080"
  },
  "transport": {
    "udp": {
      "hopInterval": "30s"
    }
  }
}
EOF

    # Create connection URL
    local connection_url="hysteria2://$auth_pwd@$formatted_ip:$final_port/?insecure=1&sni=$hy_domain#Hysteria2-Enhanced"
    echo "$connection_url" > /etc/hysteria/clients/connection.txt
    
    # Set secure permissions
    chmod 600 /etc/hysteria/config.yaml
    chmod 600 /etc/hysteria/clients/*
    
    green "Configuration files created successfully"
}

# Create systemd service with enhanced security
create_service() {
    cat > /etc/systemd/system/hysteria-server.service << EOF
[Unit]
Description=Hysteria 2 Server
Documentation=https://hysteria.network
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=exec
User=hysteria
Group=hysteria
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
RestartPreventExitStatus=23

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/hysteria
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictNamespaces=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

    # Create dedicated user for Hysteria
    if ! id hysteria >/dev/null 2>&1; then
        useradd -r -d /etc/hysteria -s /sbin/nologin hysteria
    fi
    
    # Set ownership
    chown -R hysteria:hysteria /etc/hysteria
    
    systemctl daemon-reload
    systemctl enable hysteria-server
    
    green "Systemd service created with enhanced security"
}

# Configure firewall with stealth rules
setup_firewall() {
    yellow "Configuring firewall..."
    
    # Configure UFW if available
    if command -v ufw >/dev/null 2>&1; then
        ufw --force enable >/dev/null 2>&1
        ufw allow ${display_port:-$port}/udp >/dev/null 2>&1
        [[ -n $port_range ]] && ufw allow $port_range/udp >/dev/null 2>&1
    fi
    
    # Configure firewalld if available
    if command -v firewall-cmd >/dev/null 2>&1; then
        systemctl start firewalld >/dev/null 2>&1
        systemctl enable firewalld >/dev/null 2>&1
        firewall-cmd --permanent --add-port=${display_port:-$port}/udp >/dev/null 2>&1
        [[ -n $port_range ]] && firewall-cmd --permanent --add-port=$port_range/udp >/dev/null 2>&1
        firewall-cmd
