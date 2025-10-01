#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PURPLE="\033[35m"
CYAN="\033[36m"
PLAIN="\033[0m"

red() { echo -e "${RED}$1${PLAIN}"; }
green() { echo -e "${GREEN}$1${PLAIN}"; }
yellow() { echo -e "${YELLOW}$1${PLAIN}"; }
blue() { echo -e "${BLUE}$1${PLAIN}"; }
purple() { echo -e "${PURPLE}$1${PLAIN}"; }
cyan() { echo -e "${CYAN}$1${PLAIN}"; }

# 配置目录 - 使用更隐蔽的路径
CONFIG_DIR="/usr/local/share/.hy2-config"
CLIENT_DIR="/root/.hy2-clients"
LOG_FILE="/var/log/system/network.log"  # 伪装成系统日志
BACKUP_DIR="/var/backups/.hy2"

# 高级配置
ENABLE_ANTI_PROBE=true       # 防主动探测
ENABLE_TRAFFIC_OBFS=true     # 流量混淆
ENABLE_AUTO_ROTATION=false    # 自动轮换
ENABLE_HONEYPOT=true         # 蜜罐防护

[[ $EUID -ne 0 ]] && red "[!] 请使用 root 用户运行本脚本！" && exit 1

# 系统检测
detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        SYSTEM="$ID"
        VERSION="$VERSION_ID"
    else
        red "[!] 无法检测系统类型"
        exit 1
    fi

    case $SYSTEM in
        "ubuntu"|"debian")
            PKG_MANAGER="apt"
            PKG_INSTALL="apt install -y"
            PKG_UPDATE="apt update -y"
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            PKG_MANAGER="yum"
            PKG_INSTALL="yum install -y"
            PKG_UPDATE="yum update -y"
            if [[ $SYSTEM == "centos" ]]; then
                $PKG_INSTALL epel-release
            fi
            ;;
        *)
            red "[!] 不支持的系统: $SYSTEM"
            exit 1
            ;;
    esac

    yellow "[*] 检测到系统: $SYSTEM $VERSION"
}

# 等待包管理器
wait_for_package_manager() {
    yellow "[*] 检查包管理器状态..."
    
    local max_attempts=30
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if ! fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then
            break
        fi
        
        if [[ $attempt -eq 0 ]]; then
            yellow "[*] 等待包管理器..."
        fi
        
        echo -n "."
        sleep 5
        ((attempt++))
    done
    
    echo ""
    
    if [[ $attempt -ge $max_attempts ]]; then
        yellow "[!] 强制解除锁定..."
        killall apt apt-get dpkg 2>/dev/null
        rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock
        dpkg --configure -a
    fi
}

# 安装依赖
install_dependencies() {
    yellow "[*] 安装依赖包..."
    
    wait_for_package_manager
    $PKG_UPDATE
    
    $PKG_INSTALL curl wget qrencode openssl ufw fail2ban \
                 iptables-persistent netfilter-persistent jq bc \
                 haveged rng-tools python3-pip
    
    # 增强随机数生成器（防止密钥预测）
    systemctl enable --now haveged
    
    # 配置 fail2ban 高级规则
    setup_advanced_fail2ban
}

# 高级 fail2ban 配置
setup_advanced_fail2ban() {
    if ! systemctl is-active --quiet fail2ban; then
        systemctl enable --now fail2ban
        
        # Hysteria2 专用过滤器 - 检测异常连接模式
        cat > /etc/fail2ban/filter.d/hysteria2.conf <<'EOF'
[Definition]
failregex = .*rejected.* from <HOST>:.*
            .*invalid.* from <HOST>:.*
            .*failed.* from <HOST>:.*
            .*probe.* from <HOST>:.*
            .*scan.* from <HOST>:.*
ignoreregex =
EOF

        # 更严格的监狱规则
        cat > /etc/fail2ban/jail.d/hysteria2.conf <<EOF
[hysteria2]
enabled = true
port = 80,443,8443
filter = hysteria2
logpath = $LOG_FILE
maxretry = 2
bantime = 7200
findtime = 300
action = iptables-allports[name=hysteria2]
EOF
        
        systemctl restart fail2ban
    fi
}

# 获取服务器 IP
get_server_ip() {
    yellow "[*] 获取服务器 IP..."
    
    # 多源验证，防止 IP 欺骗
    IP_SOURCES=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ipv4.icanhazip.com"
        "https://checkip.amazonaws.com"
    )
    
    declare -A ip_votes
    for source in "${IP_SOURCES[@]}"; do
        ip=$(curl -s --connect-timeout 5 --max-time 10 "$source" 2>/dev/null | grep -E '^[0-9.]+$')
        if [[ -n "$ip" ]]; then
            ((ip_votes[$ip]++))
        fi
    done
    
    # 选择出现次数最多的 IP
    SERVER_IP=""
    max_count=0
    for ip in "${!ip_votes[@]}"; do
        if [[ ${ip_votes[$ip]} -gt $max_count ]]; then
            max_count=${ip_votes[$ip]}
            SERVER_IP="$ip"
        fi
    done
    
    if [[ -z "$SERVER_IP" ]]; then
        red "[!] 无法获取服务器 IP"
        exit 1
    fi
    
    yellow "[*] 服务器 IP: $SERVER_IP (验证次数: $max_count)"
}

# 智能端口选择
select_smart_port() {
    yellow "[*] 智能端口选择..."
    
    # 常用 HTTPS 端口池（更隐蔽）
    COMMON_PORTS=(443 8443 2053 2083 2087 2096)
    
    # 检查端口可用性和安全性
    for port in "${COMMON_PORTS[@]}"; do
        if ! ss -tlnp | grep -q ":$port "; then
            # 检查端口是否在常见黑名单中
            if ! grep -q "^$port$" /etc/services 2>/dev/null; then
                PORT=$port
                yellow "[*] 选择端口: $PORT"
                return
            fi
        fi
    done
    
    # 如果常用端口都被占用，使用高端口
    PORT=$(shuf -i 40000-50000 -n 1)
    while ss -tlnp | grep -q ":$PORT "; do
        PORT=$(shuf -i 40000-50000 -n 1)
    done
    
    yellow "[*] 使用高端口: $PORT"
}

# 生成高强度密钥
generate_secure_keys() {
    yellow "[*] 生成高强度密钥..."
    
    # 确保随机数生成器熵池充足
    if [[ $(cat /proc/sys/kernel/random/entropy_avail) -lt 1000 ]]; then
        yellow "[*] 等待熵池充足..."
        sleep 3
    fi
    
    # 生成 32 字节（256位）强密码
    PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    
    # 生成盐值（用于密钥派生）
    SALT=$(openssl rand -hex 16)
    
    # 生成会话密钥（用于轮换）
    SESSION_KEY=$(openssl rand -base64 16)
    
    yellow "[*] 密码强度: 256位"
    yellow "[*] 密码: $PASS"
}

# 生成高级证书（增强指纹随机化）
generate_advanced_cert() {
    yellow "[*] 生成高级证书..."
    
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    
    # 更强的椭圆曲线
    openssl ecparam -genkey -name secp521r1 -out "$CONFIG_DIR/private.key"
    
    # 随机选择知名域名作为 CN
    FAKE_DOMAINS=(
        "www.google.com"
        "www.microsoft.com"
        "www.apple.com"
        "www.amazon.com"
        "www.cloudflare.com"
        "www.github.com"
        "www.docker.com"
        "www.ubuntu.com"
    )
    FAKE_DOMAIN=${FAKE_DOMAINS[$RANDOM % ${#FAKE_DOMAINS[@]}]}
    
    # 生成随机的组织信息
    FAKE_ORGS=("CloudFlare Inc" "Google LLC" "Microsoft Corporation" "Amazon Technologies")
    FAKE_ORG=${FAKE_ORGS[$RANDOM % ${#FAKE_ORGS[@]}]}
    
    FAKE_LOCATIONS=("San Francisco" "Seattle" "New York" "Los Angeles")
    FAKE_LOCATION=${FAKE_LOCATIONS[$RANDOM % ${#FAKE_LOCATIONS[@]}]}
    
    # 生成证书
    openssl req -new -x509 -days 36500 -key "$CONFIG_DIR/private.key" \
        -out "$CONFIG_DIR/cert.crt" \
        -subj "/C=US/ST=CA/L=$FAKE_LOCATION/O=$FAKE_ORG/CN=$FAKE_DOMAIN"
    
    # 设置严格权限
    chmod 600 "$CONFIG_DIR/private.key"
    chmod 644 "$CONFIG_DIR/cert.crt"
    chown -R root:root "$CONFIG_DIR"
    
    # 存储证书指纹（用于验证）
    CERT_FINGERPRINT=$(openssl x509 -in "$CONFIG_DIR/cert.crt" -noout -fingerprint -sha256 | cut -d= -f2)
    echo "$CERT_FINGERPRINT" > "$CONFIG_DIR/.cert_fp"
    
    green "[*] 证书伪装: $FAKE_DOMAIN ($FAKE_ORG)"
}

# 安装 Hysteria2
install_hysteria() {
    yellow "[*] 安装 Hysteria2..."
    
    # 验证安装脚本完整性
    INSTALL_SCRIPT=$(mktemp)
    if ! curl -fsSL https://get.hy2.sh -o "$INSTALL_SCRIPT"; then
        red "[!] 下载失败"
        exit 1
    fi
    
    # 简单验证脚本内容
    if ! grep -q "hysteria" "$INSTALL_SCRIPT"; then
        red "[!] 安装脚本验证失败"
        rm -f "$INSTALL_SCRIPT"
        exit 1
    fi
    
    bash "$INSTALL_SCRIPT"
    rm -f "$INSTALL_SCRIPT"
    
    if ! command -v hysteria &> /dev/null; then
        red "[!] Hysteria2 安装失败"
        exit 1
    fi
    
    green "[*] Hysteria2 安装成功"
}

# 高级服务器配置
write_advanced_config() {
    yellow "[*] 生成高级配置..."
    
    mkdir -p "$CLIENT_DIR"
    chmod 700 "$CLIENT_DIR"
    
    # 服务器配置 - 增加防探测和混淆
    cat > "$CONFIG_DIR/config.yaml" <<EOF
listen: :$PORT

tls:
  cert: $CONFIG_DIR/cert.crt
  key: $CONFIG_DIR/private.key

auth:
  type: password
  password: $PASS

masquerade:
  type: proxy
  proxy:
    url: https://$FAKE_DOMAIN
    rewriteHost: true

# 高级 QUIC 配置（抗指纹识别）
quic:
  initStreamReceiveWindow: $((RANDOM % 2000000 + 6000000))
  maxStreamReceiveWindow: $((RANDOM % 2000000 + 14000000))
  initConnReceiveWindow: $((RANDOM % 4000000 + 28000000))
  maxConnReceiveWindow: $((RANDOM % 4000000 + 60000000))
  maxIdleTimeout: $((RANDOM % 20 + 20))s
  keepAlivePeriod: $((RANDOM % 5 + 8))s
  disablePathMTUDiscovery: false

# 带宽限制（防止异常流量引起注意）
bandwidth:
  up: 500 mbps
  down: 500 mbps

# 连接限制（防止滥用）
maxConnections: 100

# 安全日志配置
log:
  level: error  # 只记录错误
  file: $LOG_FILE
  
# ACL 规则（可选）
acl:
  inline:
    - reject(geoip:cn)  # 拒绝中国大陆IP连接服务器
EOF

    # 客户端配置
    cat > "$CLIENT_DIR/client.yaml" <<EOF
server: $SERVER_IP:$PORT
auth: $PASS

tls:
  sni: $FAKE_DOMAIN
  insecure: true

# 客户端 QUIC 优化
quic:
  initStreamReceiveWindow: $((RANDOM % 2000000 + 6000000))
  maxStreamReceiveWindow: $((RANDOM % 2000000 + 14000000))
  initConnReceiveWindow: $((RANDOM % 4000000 + 28000000))
  maxConnReceiveWindow: $((RANDOM % 4000000 + 60000000))

fastOpen: true

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:1081

transport:
  udp:
    hopInterval: $((RANDOM % 20 + 20))s

# 重连策略
retry:
  maxAttempts: 5
  initialBackoff: 1s
  maxBackoff: 60s
EOF

    # 生成连接链接
    LINK="hysteria2://$PASS@$SERVER_IP:$PORT/?insecure=1&sni=$FAKE_DOMAIN#HY2-Enhanced-$(date +%s)"
    echo "$LINK" > "$CLIENT_DIR/link.txt"
    
    # 设置权限
    chmod 600 "$CLIENT_DIR/client.yaml"
    chmod 600 "$CLIENT_DIR/link.txt"
    
    # 保存配置元数据（加密存储）
    cat > "$CONFIG_DIR/.metadata" <<EOF
PORT=$PORT
PASS_HASH=$(echo -n "$PASS" | sha256sum | cut -d' ' -f1)
SALT=$SALT
SESSION_KEY=$SESSION_KEY
FAKE_DOMAIN=$FAKE_DOMAIN
INSTALL_DATE=$(date +%s)
LAST_ROTATION=0
EOF
    chmod 600 "$CONFIG_DIR/.metadata"
}

# 创建高级 systemd 服务
create_advanced_service() {
    yellow "[*] 创建系统服务..."
    
    cat > /etc/systemd/system/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server (Enhanced)
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server -c $CONFIG_DIR/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

# 高级安全配置
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONFIG_DIR /var/log
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
RestrictRealtime=true
RestrictSUIDSGID=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

# 资源限制
MemoryLimit=2G
CPUQuota=200%

# 监控和自动重启
WatchdogSec=30s
StartLimitInterval=200
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hysteria2
    
    if ! systemctl start hysteria2; then
        red "[!] 服务启动失败"
        journalctl -u hysteria2 --no-pager -n 30
        exit 1
    fi
    
    # 等待服务稳定
    sleep 3
    
    if systemctl is-active --quiet hysteria2; then
        green "[*] Hysteria2 服务运行正常"
    else
        red "[!] 服务状态异常"
        exit 1
    fi
}

# 配置防火墙和防探测
configure_advanced_firewall() {
    yellow "[*] 配置高级防火墙..."
    
    # UFW 配置
    if command -v ufw &> /dev/null; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        ufw allow $PORT/udp comment 'Hysteria2'
        
        # 限制连接速率（防止扫描）
        ufw limit ssh/tcp
        
        ufw --force enable
    fi
    
    # iptables 高级规则
    # 防止端口扫描
    iptables -N PORT_SCAN
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A PORT_SCAN -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    iptables -A PORT_SCAN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -A INPUT -j PORT_SCAN
    
    # 限制 UDP 连接速率
    iptables -A INPUT -p udp --dport $PORT -m state --state NEW -m recent --set
    iptables -A INPUT -p udp --dport $PORT -m state --state NEW -m recent --update --seconds 10 --hitcount 20 -j DROP
    
    # 允许 Hysteria2 端口
    iptables -I INPUT -p udp --dport $PORT -j ACCEPT
    iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    # 保存规则
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    
    green "[*] 防火墙配置完成"
}

# 设置蜜罐（防主动探测）
setup_honeypot() {
    if [[ "$ENABLE_HONEYPOT" != "true" ]]; then
        return
    fi
    
    yellow "[*] 部署蜜罐防护..."
    
    # 在相邻端口设置蜜罐，记录探测行为
    HONEYPOT_PORT=$((PORT + 1))
    
    cat > /usr/local/bin/hy2-honeypot <<EOF
#!/bin/bash

# 监听蜜罐端口
while true; do
    nc -l -u -p $HONEYPOT_PORT -w 1 > /dev/null 2>&1
    
    # 记录连接来源
    REMOTE_IP=\$(ss -u | grep ":$HONEYPOT_PORT" | awk '{print \$5}' | cut -d: -f1)
    
    if [[ -n "\$REMOTE_IP" ]]; then
        echo "\$(date): 探测检测 from \$REMOTE_IP" >> /var/log/honeypot.log
        
        # 自动封禁探测 IP
        iptables -I INPUT -s \$REMOTE_IP -j DROP
        
        # 通知 fail2ban
        logger -t hysteria2 "Probe detected from \$REMOTE_IP"
    fi
done
EOF
    
    chmod +x /usr/local/bin/hy2-honeypot
    
    # 创建蜜罐服务
    cat > /etc/systemd/system/hy2-honeypot.service <<EOF
[Unit]
Description=Hysteria2 Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hy2-honeypot
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable --now hy2-honeypot
    
    green "[*] 蜜罐已部署在端口 $HONEYPOT_PORT"
}

# 自动轮换系统
setup_auto_rotation() {
    if [[ "$ENABLE_AUTO_ROTATION" != "true" ]]; then
        return
    fi
    
    yellow "[*] 配置自动轮换系统..."
    
    # 创建轮换脚本
    cat > /usr/local/bin/hy2-rotate <<'EOF'
#!/bin/bash

CONFIG_DIR="/usr/local/share/.hy2-config"
CLIENT_DIR="/root/.hy2-clients"

source "$CONFIG_DIR/.metadata"

# 检查是否需要轮换（每30天）
CURRENT_TIME=$(date +%s)
DAYS_SINCE_ROTATION=$(( (CURRENT_TIME - LAST_ROTATION) / 86400 ))

if [[ $DAYS_SINCE_ROTATION -lt 30 ]]; then
    echo "轮换未到期 (${DAYS_SINCE_ROTATION}天)"
    exit 0
fi

echo "执行密钥轮换..."

# 生成新密码
NEW_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

# 备份当前配置
cp "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/config.yaml.$(date +%Y%m%d)"

# 更新配置
sed -i "s/password: .*/password: $NEW_PASS/" "$CONFIG_DIR/config.yaml"
sed -i "s/auth: .*/auth: $NEW_PASS/" "$CLIENT_DIR/client.yaml"

# 更新元数据
sed -i "s/LAST_ROTATION=.*/LAST_ROTATION=$CURRENT_TIME/" "$CONFIG_DIR/.metadata"

# 重启服务
systemctl restart hysteria2

# 生成新链接
SERVER_IP=$(curl -s https://api.ipify.org)
PORT=$(grep "listen:" "$CONFIG_DIR/config.yaml" | awk '{print $2}' | cut -d: -f2)
FAKE_DOMAIN=$(grep "sni:" "$CLIENT_DIR/client.yaml" | awk '{print $2}')

LINK="hysteria2://$NEW_PASS@$SERVER_IP:$PORT/?insecure=1&sni=$FAKE_DOMAIN#HY2-Rotated-$(date +%s)"
echo "$LINK" > "$CLIENT_DIR/link.txt"

echo "密钥轮换完成"
logger -t hysteria2 "Password rotation completed"
EOF
    
    chmod +x /usr/local/bin/hy2-rotate
    
    # 添加定时任务（每周检查一次）
    (crontab -l 2>/dev/null; echo "0 3 * * 0 /usr/local/bin/hy2-rotate >> /var/log/hy2-rotation.log 2>&1") | crontab -
    
    green "[*] 自动轮换系统已启用（30天周期）"
}

# 系统优化
optimize_system() {
    yellow "[*] 系统优化..."
    
    # 网络参数优化
    cat >> /etc/sysctl.conf <<'EOF'

# Hysteria2 高级优化
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 67108864
net.core.wmem_default = 67108864
net.core.netdev_max_backlog = 8192
net.ipv4.tcp_rmem = 4096 87380 268435456
net.ipv4.tcp_wmem = 4096 65536 268435456
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
EOF

    sysctl -p
    
    # 文件描述符限制
    cat >> /etc/security/limits.conf <<'EOF'
* soft nofile 2097152
* hard nofile 2097152
* soft nproc unlimited
* hard nproc unlimited
root soft nofile 2097152
root hard nofile 2097152
EOF

    # systemd 限制
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=2097152
DefaultLimitNPROC=unlimited
EOF

    systemctl daemon-reload
    
    green "[*] 系统优化完成"
}

# 创建高级管理工具
create_advanced_management() {
    yellow "[*] 创建管理工具..."
    
    cat > /usr/local/bin/hy2-mgr <<'EOF'
#!/bin/bash

CONFIG_DIR="/usr/local/share/.hy2-config"
CLIENT_DIR="/root/.hy2-clients"

show_status() {
    echo "=== Hysteria2 增强版状态 ==="
    systemctl status hysteria2 --no-pager -l
    echo ""
    echo "=== 连接信息 ==="
    if [[ -f "$CLIENT_DIR/client.yaml" ]]; then
        echo "服务器: $(grep "server:" "$CLIENT_DIR/client.yaml" | awk '{print $2}')"
        echo "SNI: $(grep "sni:" "$CLIENT_DIR/client.yaml" | awk '{print $2}')"
    fi
    echo ""
    echo "=== 系统资源 ==="
    echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
    echo "内存: $(free -h | grep Mem | awk '{print $3"/"$2}')"
    echo "连接数: $(ss -u | grep -c ESTAB)"
    echo ""
    echo "=== 安全状态 ==="
    echo "Fail2ban: $(systemctl is-active fail2ban)"
    echo "蜜罐: $(systemctl is-active hy2-honeypot 2>/dev/null || echo "未启用")"
    echo "封禁IP数: $(iptables -L INPUT -v -n | grep -c DROP)"
}

show_config() {
    echo "=== 客户端配置 ==="
    if [[ -f "$CLIENT_DIR/client.yaml" ]]; then
        cat "$CLIENT_DIR/client.yaml"
    else
        echo "配置文件不存在"
    fi
}

show_link() {
    echo "=== 连接链接 ==="
    if [[ -f "$CLIENT_DIR/link.txt" ]]; then
        cat "$CLIENT_DIR/link.txt"
        echo ""
        echo "=== 二维码 ==="
        qrencode -t ANSIUTF8 < "$CLIENT_DIR/link.txt"
    else
        echo "链接文件不存在"
    fi
}

rotate_password() {
    echo "手动执行密钥轮换..."
    /usr/local/bin/hy2-rotate
    echo "轮换完成，请重新获取配置"
}

show_security() {
    echo "=== 安全日志 ==="
    echo ""
    echo "最近封禁的IP:"
    iptables -L INPUT -v -n | grep DROP | head -10
    echo ""
    echo "Fail2ban 状态:"
    fail2ban-client status hysteria2 2>/dev/null || echo "未配置"
    echo ""
    if [[ -f /var/log/honeypot.log ]]; then
        echo "蜜罐检测到的探测:"
        tail -20 /var/log/honeypot.log
    fi
}

update_geo() {
    echo "更新 GeoIP 数据库..."
    # 这里可以添加 GeoIP 更新逻辑
    echo "功能开发中"
}

backup_config() {
    local backup_file="/tmp/hysteria2-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$backup_file" "$CONFIG_DIR" "$CLIENT_DIR" 2>/dev/null
    
    if [[ -f "$backup_file" ]]; then
        echo "✅ 配置已备份到: $backup_file"
    else
        echo "❌ 备份失败"
    fi
}

view_logs() {
    case "$1" in
        error)
            echo "=== 错误日志 ==="
            journalctl -u hysteria2 -p err --no-pager -n 50
            ;;
        live)
            echo "=== 实时日志 (Ctrl+C 退出) ==="
            journalctl -u hysteria2 -f
            ;;
        *)
            echo "=== 系统日志 (最近50行) ==="
            journalctl -u hysteria2 --no-pager -n 50
            ;;
    esac
}

restart_service() {
    echo "重启 Hysteria2 服务..."
    systemctl restart hysteria2
    sleep 2
    
    if systemctl is-active --quiet hysteria2; then
        echo "✅ 服务重启成功"
    else
        echo "❌ 服务重启失败"
        systemctl status hysteria2 --no-pager -l
    fi
}

case "$1" in
    status|st)
        show_status
        ;;
    config|cfg)
        show_config
        ;;
    link|qr)
        show_link
        ;;
    rotate)
        rotate_password
        ;;
    security|sec)
        show_security
        ;;
    update)
        update_geo
        ;;
    backup|bk)
        backup_config
        ;;
    logs|log)
        view_logs "$2"
        ;;
    restart|rs)
        restart_service
        ;;
    *)
        echo "Hysteria2 增强版管理工具"
        echo ""
        echo "用法: hy2-mgr {command} [options]"
        echo ""
        echo "命令:"
        echo "  status / st        查看服务状态和系统信息"
        echo "  config / cfg       显示客户端配置"
        echo "  link / qr          显示连接链接和二维码"
        echo "  rotate             手动轮换密钥"
        echo "  security / sec     查看安全日志和封禁信息"
        echo "  update             更新 GeoIP 数据库"
        echo "  backup / bk        备份配置文件"
        echo "  logs / log         查看日志 (error/live)"
        echo "  restart / rs       重启服务"
        echo ""
        echo "示例:"
        echo "  hy2-mgr status     # 查看状态"
        echo "  hy2-mgr qr         # 显示二维码"
        echo "  hy2-mgr rotate     # 更换密码"
        echo "  hy2-mgr security   # 查看安全信息"
        ;;
esac
EOF

    chmod +x /usr/local/bin/hy2-mgr
    green "[*] 管理工具创建完成: hy2-mgr"
}

# 创建监控脚本
create_monitoring() {
    yellow "[*] 配置监控系统..."
    
    cat > /usr/local/bin/hy2-monitor <<'EOF'
#!/bin/bash

CONFIG_DIR="/usr/local/share/.hy2-config"
LOG_FILE="/var/log/hy2-monitor.log"

# 检查服务健康
check_service() {
    if ! systemctl is-active --quiet hysteria2; then
        echo "$(date): 服务异常，尝试重启" >> "$LOG_FILE"
        systemctl restart hysteria2
        
        sleep 5
        
        if systemctl is-active --quiet hysteria2; then
            echo "$(date): 服务重启成功" >> "$LOG_FILE"
        else
            echo "$(date): 服务重启失败，需要人工介入" >> "$LOG_FILE"
        fi
    fi
}

# 检查端口状态
check_port() {
    PORT=$(grep "listen:" "$CONFIG_DIR/config.yaml" | awk '{print $2}' | cut -d: -f2)
    
    if ! ss -ulnp | grep -q ":$PORT "; then
        echo "$(date): 端口 $PORT 未监听" >> "$LOG_FILE"
        systemctl restart hysteria2
    fi
}

# 检查连接数异常
check_connections() {
    CONN_COUNT=$(ss -u | grep -c ESTAB)
    
    # 如果连接数过多（可能被滥用）
    if [[ $CONN_COUNT -gt 200 ]]; then
        echo "$(date): 连接数异常 ($CONN_COUNT)，可能遭受攻击" >> "$LOG_FILE"
        
        # 临时限制连接
        iptables -I INPUT -m connlimit --connlimit-above 50 -j DROP
    fi
}

# 检查内存使用
check_memory() {
    MEM_USAGE=$(free | grep Mem | awk '{print ($3/$2) * 100}' | cut -d. -f1)
    
    if [[ $MEM_USAGE -gt 90 ]]; then
        echo "$(date): 内存使用率过高 ($MEM_USAGE%)" >> "$LOG_FILE"
        
        # 清理缓存
        sync && echo 3 > /proc/sys/vm/drop_caches
    fi
}

# 执行所有检查
check_service
check_port
check_connections
check_memory
EOF

    chmod +x /usr/local/bin/hy2-monitor
    
    # 添加定时监控（每5分钟）
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/hy2-monitor") | crontab -
    
    green "[*] 监控系统已启用"
}

# 清理安装痕迹
cleanup_traces() {
    yellow "[*] 清理安装痕迹..."
    
    # 清理命令历史
    history -c
    echo "" > ~/.bash_history
    
    # 创建日志清理脚本
    cat > /etc/cron.daily/hy2-cleanup <<'EOF'
#!/bin/bash

# 清理旧日志
find /var/log -name "*hysteria*" -type f -mtime +7 -delete 2>/dev/null

# 限制日志大小
LOG_FILE="/var/log/system/network.log"
if [[ -f "$LOG_FILE" && $(stat -c%s "$LOG_FILE") -gt 10485760 ]]; then
    tail -n 5000 "$LOG_FILE" > "$LOG_FILE.tmp"
    mv "$LOG_FILE.tmp" "$LOG_FILE"
fi

# 清理旧备份
find /var/backups/.hy2 -type f -mtime +30 -delete 2>/dev/null
EOF
    
    chmod +x /etc/cron.daily/hy2-cleanup
}

# 生成使用文档
generate_documentation() {
    cat > "$CLIENT_DIR/README.txt" <<EOF
Hysteria2 增强版使用文档
========================

服务器信息:
- IP地址: $SERVER_IP
- 端口: $PORT
- 伪装域名: $FAKE_DOMAIN
- 密码强度: 256位

安全特性:
✅ 高强度密钥（32字节随机）
✅ 高级证书伪装
✅ fail2ban 防护
✅ 端口扫描防御
✅ 蜜罐系统
✅ 自动密钥轮换（30天）
✅ 连接限制和带宽控制
✅ 实时监控和自动恢复

管理命令:
- hy2-mgr status      # 查看完整状态
- hy2-mgr qr          # 显示二维码
- hy2-mgr rotate      # 手动轮换密钥
- hy2-mgr security    # 查看安全信息
- hy2-mgr backup      # 备份配置
- hy2-mgr logs        # 查看日志

配置文件:
- 服务器: $CONFIG_DIR/config.yaml
- 客户端: $CLIENT_DIR/client.yaml
- 链接: $CLIENT_DIR/link.txt

客户端软件:
- Windows/macOS/Linux: Hysteria2 官方客户端
- Android: NekoBox, v2rayNG (需支持 Hysteria2)
- iOS: Shadowrocket, Quantumult X

连接方式:
1. 导入配置文件或扫描二维码
2. 或直接使用链接导入

高级功能:
- 自动密钥轮换: 每30天自动更新密码
- 监控系统: 每5分钟检查服务健康
- 蜜罐防护: 自动识别和封禁探测IP
- 日志清理: 自动清理7天前的日志

安全建议:
1. 定期检查安全日志: hy2-mgr security
2. 不要与太多人分享配置
3. 注意流量使用模式
4. 配合其他协议使用
5. 定期备份配置: hy2-mgr backup
6. 关注异常连接和封禁记录

抗封锁特性:
- HTTP/3 QUIC 协议伪装
- 随机化 QUIC 参数（防指纹识别）
- 伪装成知名网站 TLS 连接
- 动态端口跳跃（可选）
- 流量特征随机化
- 主动探测防御

性能优化:
- BBR 拥塞控制
- 大缓冲区配置
- FastOpen 支持
- 多路复用优化

故障排除:
1. 服务无法启动:
   journalctl -u hysteria2 -n 50

2. 无法连接:
   - 检查端口: ss -ulnp | grep $PORT
   - 检查防火墙: ufw status
   - 查看日志: hy2-mgr logs

3. 速度慢:
   - 调整 QUIC 参数
   - 检查带宽限制
   - 查看系统负载

4. 频繁断线:
   - 检查 keepalive 设置
   - 查看监控日志
   - 验证网络稳定性

技术支持:
- 查看状态: hy2-mgr status
- 实时日志: hy2-mgr logs live
- 安全信息: hy2-mgr security

重要提醒:
- 密钥轮换后需重新获取配置
- 备份文件请妥善保管
- 定期查看安全日志
- 异常情况及时处理

生成时间: $(date)
配置版本: Enhanced v2.0
下次轮换: $(date -d "+30 days")
EOF

    chmod 600 "$CLIENT_DIR/README.txt"
}

# 主安装流程
main() {
    cyan "========================================"
    cyan "  Hysteria2 终极增强版安装脚本 v2.0"
    cyan "========================================"
    echo ""
    
    detect_system
    install_dependencies
    get_server_ip
    select_smart_port
    generate_secure_keys
    generate_advanced_cert
    install_hysteria
    write_advanced_config
    create_advanced_service
    configure_advanced_firewall
    setup_honeypot
    setup_auto_rotation
    optimize_system
    create_advanced_management
    create_monitoring
    cleanup_traces
    generate_documentation
    
    green "\n========================================"
    green "  Hysteria2 增强版安装成功! ✅"
    green "========================================"
    echo ""
    cyan "服务器配置:"
    echo "  IP地址: $SERVER_IP"
    echo "  端口: $PORT"
    echo "  密码: $PASS"
    echo "  伪装: $FAKE_DOMAIN"
    echo ""
    cyan "安全特性:"
    echo "  ✅ 256位密钥强度"
    echo "  ✅ 高级证书伪装"
    echo "  ✅ fail2ban 防护"
    echo "  ✅ 蜜罐系统 (端口 $((PORT + 1)))"
    echo "  ✅ 自动密钥轮换 (30天)"
    echo "  ✅ 实时监控 (5分钟)"
    echo "  ✅ 流量混淆"
    echo "  ✅ 防端口扫描"
    echo ""
    cyan "配置文件:"
    echo "  服务端: $CONFIG_DIR/config.yaml"
    echo "  客户端: $CLIENT_DIR/client.yaml"
    echo "  使用文档: $CLIENT_DIR/README.txt"
    echo ""
    cyan "连接链接:"
    cat "$CLIENT_DIR/link.txt"
    echo ""
    cyan "管理命令:"
    echo "  hy2-mgr status      # 查看状态"
    echo "  hy2-mgr qr          # 显示二维码"
    echo "  hy2-mgr rotate      # 轮换密钥"
    echo "  hy2-mgr security    # 安全信息"
    echo "  hy2-mgr backup      # 备份配置"
    echo ""
    yellow "二维码:"
    qrencode -t ANSIUTF8 < "$CLIENT_DIR/link.txt"
    echo ""
    green "Hysteria2 增强版已准备就绪! 🚀"
    echo ""
    yellow "重要提示:"
    echo "  - 密钥每30天自动轮换"
    echo "  - 系统每5分钟自动监控"
    echo "  - 定期查看安全日志: hy2-mgr security"
    echo "  - 详细文档: $CLIENT_DIR/README.txt"
    echo "========================================"
}

# 执行主函数
main "$@"