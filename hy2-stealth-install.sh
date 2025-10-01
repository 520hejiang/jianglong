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
LOG_FILE="/var/log/system/network.log"
BACKUP_DIR="/var/backups/.hy2"

# 高级配置 - 关闭自动轮换
ENABLE_ANTI_PROBE=true       # 防主动探测
ENABLE_TRAFFIC_OBFS=true     # 流量混淆
ENABLE_AUTO_ROTATION=false   # 关闭自动轮换（根据用户要求）
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
    
    local max_attempts=60
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if ! fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock >/dev/null 2>&1; then
            break
        fi
        
        if [[ $attempt -eq 0 ]]; then
            yellow "[*] 等待其他包管理器进程完成..."
        fi
        
        echo -n "."
        sleep 5
        ((attempt++))
    done
    
    echo ""
    
    if [[ $attempt -ge $max_attempts ]]; then
        yellow "[!] 等待超时，尝试解除锁定..."
        
        # 终止相关进程
        killall apt apt-get dpkg 2>/dev/null
        sleep 2
        
        # 清理锁定文件
        rm -f /var/lib/dpkg/lock-frontend
        rm -f /var/lib/dpkg/lock
        rm -f /var/cache/apt/archives/lock
        
        # 修复 dpkg
        dpkg --configure -a
        
        sleep 2
    fi
    
    green "[*] 包管理器已就绪"
}

# 修复的依赖安装
install_dependencies() {
    yellow "[*] 安装依赖包..."
    
    wait_for_package_manager
    
    # 更新包列表
    $PKG_UPDATE || {
        red "[!] 更新失败，重试..."
        sleep 3
        $PKG_UPDATE
    }
    
    case $SYSTEM in
        "ubuntu"|"debian")
            # 分步安装，避免冲突
            yellow "[*] 安装基础工具..."
            $PKG_INSTALL curl wget qrencode openssl jq bc
            
            yellow "[*] 安装防火墙工具..."
            # 检查是否已安装 iptables-persistent
            if dpkg -l | grep -q iptables-persistent; then
                yellow "[*] iptables-persistent 已安装"
            else
                # 预配置避免交互
                echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
                echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
                $PKG_INSTALL iptables iptables-persistent
            fi
            
            $PKG_INSTALL ufw
            
            yellow "[*] 安装安全工具..."
            $PKG_INSTALL fail2ban || {
                yellow "[!] fail2ban 安装失败，跳过"
            }
            
            yellow "[*] 安装随机数生成器..."
            # haveged 在某些系统可能不可用
            $PKG_INSTALL haveged rng-tools || {
                yellow "[!] haveged 安装失败，使用系统默认随机数生成器"
            }
            ;;
            
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            # RHEL 系列
            if [[ $SYSTEM == "centos" ]]; then
                $PKG_INSTALL epel-release
            fi
            
            $PKG_INSTALL curl wget qrencode openssl jq bc \
                         iptables-services firewalld fail2ban \
                         rng-tools
            ;;
    esac
    
    # 启用随机数生成器（如果安装成功）
    if systemctl list-unit-files | grep -q haveged; then
        systemctl enable --now haveged 2>/dev/null
    fi
    
    if systemctl list-unit-files | grep -q rngd; then
        systemctl enable --now rngd 2>/dev/null
    fi
    
    # 配置 fail2ban（如果安装成功）
    if command -v fail2ban-client &> /dev/null; then
        setup_fail2ban
    else
        yellow "[!] fail2ban 未安装，跳过配置"
    fi
    
    green "[*] 依赖安装完成"
}

# fail2ban 配置
setup_fail2ban() {
    yellow "[*] 配置 fail2ban..."
    
    if ! systemctl is-active --quiet fail2ban; then
        systemctl enable --now fail2ban 2>/dev/null || {
            yellow "[!] fail2ban 启动失败"
            return
        }
    fi
    
    # 创建过滤器
    mkdir -p /etc/fail2ban/filter.d
    cat > /etc/fail2ban/filter.d/hysteria2.conf <<'EOF'
[Definition]
failregex = .*rejected.* from <HOST>:.*
            .*invalid.* from <HOST>:.*
            .*failed.* from <HOST>:.*
ignoreregex =
EOF

    # 创建监狱配置
    mkdir -p /etc/fail2ban/jail.d
    cat > /etc/fail2ban/jail.d/hysteria2.conf <<EOF
[hysteria2]
enabled = true
port = 80,443,8443
filter = hysteria2
logpath = $LOG_FILE
maxretry = 3
bantime = 3600
findtime = 600
EOF
    
    systemctl restart fail2ban 2>/dev/null
    green "[*] fail2ban 配置完成"
}

# 获取服务器 IP
get_server_ip() {
    yellow "[*] 获取服务器 IP..."
    
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
    
    yellow "[*] 服务器 IP: $SERVER_IP (验证: $max_count 次)"
}

# 智能端口选择
select_smart_port() {
    yellow "[*] 选择端口..."
    
    COMMON_PORTS=(443 8443 2053 2083 2087 2096)
    
    for port in "${COMMON_PORTS[@]}"; do
        if ! ss -tlnp | grep -q ":$port " && ! ss -ulnp | grep -q ":$port "; then
            PORT=$port
            yellow "[*] 选择端口: $PORT"
            return
        fi
    done
    
    PORT=$(shuf -i 40000-50000 -n 1)
    while ss -ulnp | grep -q ":$PORT "; do
        PORT=$(shuf -i 40000-50000 -n 1)
    done
    
    yellow "[*] 使用高端口: $PORT"
}

# 生成高强度密钥
generate_secure_keys() {
    yellow "[*] 生成高强度密钥..."
    
    # 等待熵池
    if [[ -f /proc/sys/kernel/random/entropy_avail ]]; then
        ENTROPY=$(cat /proc/sys/kernel/random/entropy_avail)
        if [[ $ENTROPY -lt 1000 ]]; then
            yellow "[*] 等待随机数生成器..."
            sleep 2
        fi
    fi
    
    # 生成 256位强密码
    PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    
    yellow "[*] 密码长度: ${#PASS} 字符"
}

# 生成高级证书
generate_advanced_cert() {
    yellow "[*] 生成证书..."
    
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    
    # 使用强椭圆曲线
    openssl ecparam -genkey -name secp521r1 -out "$CONFIG_DIR/private.key" 2>/dev/null || \
    openssl ecparam -genkey -name secp384r1 -out "$CONFIG_DIR/private.key"
    
    # 随机选择伪装域名
    FAKE_DOMAINS=(
        "www.google.com"
        "www.microsoft.com"
        "www.apple.com"
        "www.cloudflare.com"
        "www.github.com"
    )
    FAKE_DOMAIN=${FAKE_DOMAINS[$RANDOM % ${#FAKE_DOMAINS[@]}]}
    
    FAKE_ORGS=("Google LLC" "Microsoft Corporation" "Apple Inc" "CloudFlare Inc")
    FAKE_ORG=${FAKE_ORGS[$RANDOM % ${#FAKE_ORGS[@]}]}
    
    # 生成证书
    openssl req -new -x509 -days 36500 -key "$CONFIG_DIR/private.key" \
        -out "$CONFIG_DIR/cert.crt" \
        -subj "/C=US/ST=CA/L=San Francisco/O=$FAKE_ORG/CN=$FAKE_DOMAIN"
    
    chmod 600 "$CONFIG_DIR/private.key"
    chmod 644 "$CONFIG_DIR/cert.crt"
    
    green "[*] 证书伪装: $FAKE_DOMAIN"
}

# 安装 Hysteria2
install_hysteria() {
    yellow "[*] 安装 Hysteria2..."
    
    INSTALL_SCRIPT=$(mktemp)
    if ! curl -fsSL https://get.hy2.sh -o "$INSTALL_SCRIPT"; then
        red "[!] 下载失败"
        exit 1
    fi
    
    if ! grep -q "hysteria" "$INSTALL_SCRIPT"; then
        red "[!] 脚本验证失败"
        rm -f "$INSTALL_SCRIPT"
        exit 1
    fi
    
    bash "$INSTALL_SCRIPT"
    rm -f "$INSTALL_SCRIPT"
    
    if ! command -v hysteria &> /dev/null; then
        red "[!] 安装失败"
        exit 1
    fi
    
    green "[*] Hysteria2 安装成功"
}

# 生成配置
write_config() {
    yellow "[*] 生成配置..."
    
    mkdir -p "$CLIENT_DIR"
    mkdir -p "$(dirname "$LOG_FILE")"
    chmod 700 "$CLIENT_DIR"
    
    # 服务器配置
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

quic:
  initStreamReceiveWindow: $((RANDOM % 2000000 + 6000000))
  maxStreamReceiveWindow: $((RANDOM % 2000000 + 14000000))
  initConnReceiveWindow: $((RANDOM % 4000000 + 28000000))
  maxConnReceiveWindow: $((RANDOM % 4000000 + 60000000))
  maxIdleTimeout: $((RANDOM % 20 + 20))s
  keepAlivePeriod: $((RANDOM % 5 + 8))s

bandwidth:
  up: 1000 mbps
  down: 1000 mbps

log:
  level: warn
  file: $LOG_FILE
EOF

    # 客户端配置
    cat > "$CLIENT_DIR/client.yaml" <<EOF
server: $SERVER_IP:$PORT
auth: $PASS

tls:
  sni: $FAKE_DOMAIN
  insecure: true

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
EOF

    # 生成连接链接
    LINK="hysteria2://$PASS@$SERVER_IP:$PORT/?insecure=1&sni=$FAKE_DOMAIN#HY2-Enhanced-$(date +%s)"
    echo "$LINK" > "$CLIENT_DIR/link.txt"
    
    chmod 600 "$CLIENT_DIR/client.yaml"
    chmod 600 "$CLIENT_DIR/link.txt"
    
    green "[*] 配置生成完成"
}

# 创建 systemd 服务
create_service() {
    yellow "[*] 创建系统服务..."
    
    cat > /etc/systemd/system/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server Enhanced
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server -c $CONFIG_DIR/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONFIG_DIR $(dirname "$LOG_FILE")
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hysteria2
    
    if ! systemctl start hysteria2; then
        red "[!] 服务启动失败"
        journalctl -u hysteria2 --no-pager -n 20
        exit 1
    fi
    
    sleep 2
    
    if systemctl is-active --quiet hysteria2; then
        green "[*] 服务运行正常"
    else
        red "[!] 服务状态异常"
        exit 1
    fi
}

# 配置防火墙
configure_firewall() {
    yellow "[*] 配置防火墙..."
    
    # UFW
    if command -v ufw &> /dev/null; then
        ufw --force reset >/dev/null 2>&1
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        ufw allow $PORT/udp comment 'Hysteria2'
        ufw --force enable
    fi
    
    # iptables 基础规则
    iptables -I INPUT -p udp --dport $PORT -j ACCEPT 2>/dev/null
    iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    
    # 防端口扫描
    iptables -N PORT_SCAN 2>/dev/null
    iptables -F PORT_SCAN 2>/dev/null
    iptables -A PORT_SCAN -p tcp --tcp-flags ALL NONE -j DROP 2>/dev/null
    iptables -A PORT_SCAN -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP 2>/dev/null
    
    # 保存规则
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save 2>/dev/null
    elif command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
    fi
    
    green "[*] 防火墙配置完成"
}

# 设置蜜罐
setup_honeypot() {
    if [[ "$ENABLE_HONEYPOT" != "true" ]]; then
        return
    fi
    
    yellow "[*] 配置蜜罐..."
    
    HONEYPOT_PORT=$((PORT + 1))
    
    cat > /usr/local/bin/hy2-honeypot <<EOF
#!/bin/bash

while true; do
    timeout 5 nc -l -u -p $HONEYPOT_PORT >/dev/null 2>&1
    
    REMOTE_IP=\$(ss -u 2>/dev/null | grep ":$HONEYPOT_PORT" | awk '{print \$5}' | cut -d: -f1 | head -1)
    
    if [[ -n "\$REMOTE_IP" && "\$REMOTE_IP" != "127.0.0.1" ]]; then
        echo "\$(date): 探测检测 from \$REMOTE_IP" >> /var/log/honeypot.log
        iptables -I INPUT -s \$REMOTE_IP -j DROP 2>/dev/null
    fi
    
    sleep 1
done
EOF
    
    chmod +x /usr/local/bin/hy2-honeypot
    
    cat > /etc/systemd/system/hy2-honeypot.service <<EOF
[Unit]
Description=Hysteria2 Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hy2-honeypot
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable --now hy2-honeypot 2>/dev/null
    
    green "[*] 蜜罐已部署"
}

# 系统优化
optimize_system() {
    yellow "[*] 系统优化..."
    
    cat >> /etc/sysctl.conf <<'EOF'

# Hysteria2 优化
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.netdev_max_backlog = 8192
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
fs.file-max = 2097152
EOF

    sysctl -p >/dev/null 2>&1
    
    cat >> /etc/security/limits.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
EOF

    green "[*] 系统优化完成"
}

# 创建管理工具
create_management() {
    yellow "[*] 创建管理工具..."
    
    cat > /usr/local/bin/hy2-mgr <<'EOF'
#!/bin/bash

CONFIG_DIR="/usr/local/share/.hy2-config"
CLIENT_DIR="/root/.hy2-clients"

show_status() {
    echo "=== Hysteria2 增强版状态 ==="
    systemctl status hysteria2 --no-pager -l
    echo ""
    echo "=== 系统资源 ==="
    echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')%"
    echo "内存: $(free -h | grep Mem | awk '{print $3"/"$2}')"
}

show_config() {
    echo "=== 客户端配置 ==="
    [[ -f "$CLIENT_DIR/client.yaml" ]] && cat "$CLIENT_DIR/client.yaml" || echo "配置不存在"
}

show_link() {
    echo "=== 连接链接 ==="
    if [[ -f "$CLIENT_DIR/link.txt" ]]; then
        cat "$CLIENT_DIR/link.txt"
        echo ""
        echo "=== 二维码 ==="
        qrencode -t ANSIUTF8 < "$CLIENT_DIR/link.txt"
    else
        echo "链接不存在"
    fi
}

show_security() {
    echo "=== 安全状态 ==="
    echo "Hysteria2: $(systemctl is-active hysteria2)"
    echo "蜜罐: $(systemctl is-active hy2-honeypot 2>/dev/null || echo '未启用')"
    echo "Fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo '未安装')"
    echo ""
    echo "=== 最近封禁的IP ==="
    iptables -L INPUT -v -n 2>/dev/null | grep DROP | head -5 || echo "无"
}

view_logs() {
    case "$1" in
        live)
            journalctl -u hysteria2 -f
            ;;
        *)
            journalctl -u hysteria2 --no-pager -n 50
            ;;
    esac
}

restart_service() {
    echo "重启服务..."
    systemctl restart hysteria2
    sleep 2
    systemctl is-active --quiet hysteria2 && echo "✅ 重启成功" || echo "❌ 重启失败"
}

backup_config() {
    BACKUP_FILE="/tmp/hy2-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$BACKUP_FILE" "$CONFIG_DIR" "$CLIENT_DIR" 2>/dev/null
    [[ -f "$BACKUP_FILE" ]] && echo "✅ 备份: $BACKUP_FILE" || echo "❌ 备份失败"
}

case "$1" in
    status|st) show_status ;;
    config|cfg) show_config ;;
    link|qr) show_link ;;
    security|sec) show_security ;;
    logs|log) view_logs "$2" ;;
    restart|rs) restart_service ;;
    backup|bk) backup_config ;;
    *)
        echo "Hysteria2 管理工具"
        echo ""
        echo "用法: hy2-mgr {command}"
        echo ""
        echo "命令:"
        echo "  status / st      查看状态"
        echo "  config / cfg     显示配置"
        echo "  link / qr        显示链接和二维码"
        echo "  security / sec   安全信息"
        echo "  logs / log       查看日志 (live)"
        echo "  restart / rs     重启服务"
        echo "  backup / bk      备份配置"
        ;;
esac
EOF

    chmod +x /usr/local/bin/hy2-mgr
    green "[*] 管理工具创建完成"
}

# 创建监控
create_monitoring() {
    yellow "[*] 配置监控..."
    
    cat > /usr/local/bin/hy2-monitor <<'EOF'
#!/bin/bash

if ! systemctl is-active --quiet hysteria2; then
    systemctl restart hysteria2
    logger "Hysteria2 auto-restarted"
fi
EOF

    chmod +x /usr/local/bin/hy2-monitor
    
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/hy2-monitor") | crontab -
    
    green "[*] 监控系统已启用"
}

# 清理
cleanup() {
    yellow "[*] 清理..."
    
    history -c
    echo "" > ~/.bash_history
    
    cat > /etc/cron.daily/hy2-cleanup <<'EOF'
#!/bin/bash
find /var/log -name "*hysteria*" -type f -mtime +7 -delete 2>/dev/null
EOF
    
    chmod +x /etc/cron.daily/hy2-cleanup
}

# 生成文档
generate_docs() {
    cat > "$CLIENT_DIR/README.txt" <<EOF
Hysteria2 增强版配置信息
========================

服务器: $SERVER_IP:$PORT
密码: $PASS
伪装: $FAKE_DOMAIN

管理命令:
- hy2-mgr status      查看状态
- hy2-mgr qr          显示二维码
- hy2-mgr security    安全信息
- hy2-mgr restart     重启服务
- hy2-mgr backup      备份配置

配置文件:
- 服务端: $CONFIG_DIR/config.yaml
- 客户端: $CLIENT_DIR/client.yaml
- 链接: $CLIENT_DIR/link.txt

特性:
✅ 256位密码强度
✅ 随机化流量指纹
✅ 蜜罐防护
✅ 自动监控恢复
✅ 高级管理工具

注意: 未启用自动密钥轮换，密码永久有效

生成时间: $(date)
EOF

    chmod 600 "$CLIENT_DIR/README.txt"
}

# 主流程
main() {
    cyan "========================================"
    cyan "  Hysteria2 增强版 v2.0 (修复版)"
    cyan "========================================"
    echo ""
    
    detect_system
    install_dependencies
    get_server_ip
    select_smart_port
    generate_secure_keys
    generate_advanced_cert
    install_hysteria
    write_config
    create_service
    configure_firewall
    setup_honeypot
    optimize_system
    create_management
    create_monitoring
    cleanup
    generate_docs
    
    green "\n========================================"
    green "    Hysteria2 增强版安装成功! ✅"
    green "========================================"
    echo ""
    cyan "服务器信息:"
    echo "  IP: $SERVER_IP"
    echo "  端口: $PORT"
    echo "  密码: $PASS"
    echo "  伪装: $FAKE_DOMAIN"
    echo ""
    cyan "配置文件:"
    echo "  服务端: $CONFIG_DIR/config.yaml"
    echo "  客户端: $CLIENT_DIR/client.yaml"
    echo "  文档: $CLIENT_DIR/README.txt"
    echo ""
    cyan "连接链接:"
    cat "$CLIENT_DIR/link.txt"
    echo ""
    cyan "管理命令:"
    echo "  hy2-mgr status    # 查看状态"
    echo "  hy2-mgr qr        # 显示二维码"
    echo "  hy2-mgr security  # 安全信息"
    echo ""
    yellow "二维码:"
    qrencode -t ANSIUTF8 < "$CLIENT_DIR/link.txt"
    echo ""
    green "安装完成! 🚀"
    echo "详细说明请查看: $CLIENT_DIR/README.txt"
    echo "========================================"
}

main "$@"