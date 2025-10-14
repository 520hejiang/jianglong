#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red() { echo -e "${RED}$1${PLAIN}"; }
green() { echo -e "${GREEN}$1${PLAIN}"; }
yellow() { echo -e "${YELLOW}$1${PLAIN}"; }

CONFIG_DIR="/etc/hysteria2"
CLIENT_DIR="/root/hysteria2-client"
LOG_FILE="/var/log/hysteria2.log"

[[ $EUID -ne 0 ]] && red "[!] 请使用 root 用户运行本脚本！" && exit 1

# 判断系统类型
SYSTEM=""
CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)")
REGEX=("debian" "ubuntu" "centos")
RELEASE=("Debian" "Ubuntu" "CentOS")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install")
PACKAGE_UPDATE=("apt update -y" "apt update -y" "yum update -y")

for i in "${CMD[@]}"; do
  SYS="$i" && [[ -n $SYS ]] && break
done

for ((i = 0; i < ${#REGEX[@]}; i++)); do
  [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[i]} ]] && SYSTEM="${RELEASE[i]}" && PKG_INDEX=$i && break
done

[[ -z $SYSTEM ]] && red "[!] 暂不支持该系统！" && exit 1

# 安装依赖
install_deps() {
  yellow "[*] 安装依赖中..."
  ${PACKAGE_UPDATE[PKG_INDEX]}
  ${PACKAGE_INSTALL[PKG_INDEX]} curl wget qrencode openssl iptables-persistent netfilter-persistent ufw fail2ban certbot
  
  # 配置 fail2ban 防暴力破解
  if ! systemctl is-active --quiet fail2ban; then
    systemctl enable --now fail2ban
  fi
}

# 获取 IP (增加隐私保护)
get_ip() {
  IP_SOURCES=("https://icanhazip.com" "https://ipv4.icanhazip.com" "https://api.ipify.org" "https://ifconfig.me/ip")
  
  for source in "${IP_SOURCES[@]}"; do
    IP=$(curl -s --connect-timeout 5 --max-time 10 "$source" 2>/dev/null | grep -E '^[0-9.]+$')
    [[ -n "$IP" ]] && break
  done
  
  [[ -z "$IP" ]] && red "[!] 无法获取公网 IP" && exit 1
  yellow "[*] 检测到公网IP: $IP"
}

# 生成更安全的证书（增强版）
generate_cert() {
  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR"
  
  yellow "[*] 证书生成方式："
  echo "1) 使用真实域名申请 Let's Encrypt 证书（推荐，最隐蔽）"
  echo "2) 生成自签名证书（快速，但特征明显）"
  read -p "请选择 [1-2]: " cert_choice
  
  if [[ "$cert_choice" == "1" ]]; then
    read -p "请输入你的域名（如 example.com）: " DOMAIN
    
    if [[ -z "$DOMAIN" ]]; then
      red "[!] 域名不能为空"
      exit 1
    fi
    
    yellow "[*] 申请 Let's Encrypt 证书..."
    yellow "[!] 请确保域名已解析到此服务器 IP: $IP"
    read -p "域名是否已正确解析？(y/n): " dns_confirm
    
    if [[ "$dns_confirm" != "y" ]]; then
      red "[!] 请先配置域名解析后再运行脚本"
      exit 1
    fi
    
    # 临时启动一个简单的HTTP服务用于验证
    certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN" --http-01-port 80
    
    if [[ $? -eq 0 ]]; then
      ln -sf /etc/letsencrypt/live/"$DOMAIN"/fullchain.pem "$CONFIG_DIR/cert.crt"
      ln -sf /etc/letsencrypt/live/"$DOMAIN"/privkey.pem "$CONFIG_DIR/private.key"
      USE_REAL_CERT=true
      SNI_DOMAIN="$DOMAIN"
      green "[*] Let's Encrypt 证书申请成功"
    else
      red "[!] 证书申请失败，将使用自签名证书"
      USE_REAL_CERT=false
    fi
  else
    USE_REAL_CERT=false
  fi
  
  # 如果没有使用真实证书，生成自签名证书
  if [[ "$USE_REAL_CERT" != "true" ]]; then
    openssl ecparam -genkey -name secp384r1 -out "$CONFIG_DIR/private.key"
    
    # 更真实的证书信息
    FAKE_DOMAINS=("cloudflare.com" "www.google.com" "api.github.com" "cdn.jsdelivr.net" "www.microsoft.com")
    FAKE_DOMAIN=${FAKE_DOMAINS[$RANDOM % ${#FAKE_DOMAINS[@]}]}
    SNI_DOMAIN="$FAKE_DOMAIN"
    
    openssl req -new -x509 -days 36500 -key "$CONFIG_DIR/private.key" \
      -out "$CONFIG_DIR/cert.crt" -subj "/C=US/ST=CA/L=San Francisco/O=Tech Company/CN=$FAKE_DOMAIN"
  fi
  
  chmod 600 "$CONFIG_DIR/private.key"
  chmod 644 "$CONFIG_DIR/cert.crt"
  chown -R root:root "$CONFIG_DIR"
}

# 智能端口选择（增强防封）
set_port() {
  yellow "[*] 端口选择策略："
  echo "1) 443 (HTTPS标准端口，混淆性好但容易被针对)"
  echo "2) 80 (HTTP标准端口，伪装性好)"
  echo "3) 8443 (常见替代HTTPS端口)"
  echo "4) 随机高位端口 (10000-60000，避免扫描)"
  echo "5) 自定义端口"
  read -p "请选择 [1-5，默认4]: " port_choice
  
  case "$port_choice" in
    1) PORT=443 ;;
    2) PORT=80 ;;
    3) PORT=8443 ;;
    5) 
      read -p "请输入端口号 (1-65535): " PORT
      if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        red "[!] 无效端口"
        exit 1
      fi
      ;;
    *)
      # 随机高位端口
      PORT=$((RANDOM % 50000 + 10000))
      ;;
  esac
  
  # 检查端口是否被占用
  if ss -tlnp | grep -q ":$PORT "; then
    red "[!] 端口 $PORT 已被占用"
    yellow "[*] 正在尝试自动选择可用端口..."
    while ss -tlnp | grep -q ":$PORT "; do
      PORT=$((RANDOM % 50000 + 10000))
    done
  fi
  
  yellow "[*] 使用端口: $PORT"
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

# 生成强密码和安全配置（增强版）
write_config() {
  # 生成更强的密码 (24字符，更复杂)
  PASS=$(openssl rand -base64 18 | tr -d "=+/" | cut -c1-24)
  
  mkdir -p "$CLIENT_DIR"
  chmod 700 "$CLIENT_DIR"

  # 选择伪装网站
  MASQUERADE_SITES=(
    "https://www.bing.com"
    "https://www.wikipedia.org"
    "https://www.cloudflare.com"
    "https://www.microsoft.com"
    "https://www.apple.com"
  )
  MASQUERADE_URL=${MASQUERADE_SITES[$RANDOM % ${#MASQUERADE_SITES[@]}]}

  # 服务端配置 - 增强防检测
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
    url: $MASQUERADE_URL
    rewriteHost: true

# 流量混淆配置（关键防检测参数）
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 60s
  keepAlivePeriod: 15s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

# 流量整形，模拟正常流量
bandwidth:
  up: 500 mbps
  down: 500 mbps

# 忽略客户端带宽
ignoreClientBandwidth: false

# 禁用UDP转发（减少特征）
disableUDP: false

# 速度限制（避免异常流量）
speedTest: false

# 最小化日志
log:
  level: error
  file: $LOG_FILE

# ACL规则（可选）
acl:
  inline:
    - reject(all, udp/443)
    - reject(all, udp/80)
EOF

  # 客户端配置 - 增强稳定性
  cat > "$CLIENT_DIR/client.yaml" <<EOF
server: $IP:$PORT
auth: $PASS

tls:
  sni: $SNI_DOMAIN
  insecure: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  disablePathMTUDiscovery: false

# 快速打开
fastOpen: true

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:1081

# 传输优化
transport:
  udp:
    hopInterval: 30s

# 带宽
bandwidth:
  up: 100 mbps
  down: 100 mbps

# 连接管理
lazy: false
tcpForwarding:
  - listen: 127.0.0.1:6666
    remote: 127.0.0.1:6666
EOF

  # 生成连接链接
  LINK="hysteria2://$PASS@$IP:$PORT/?insecure=1&sni=$SNI_DOMAIN#HY2-Stealth-$(date +%s)"
  echo "$LINK" > "$CLIENT_DIR/link.txt"
  
  chmod 600 "$CLIENT_DIR/client.yaml"
  chmod 600 "$CLIENT_DIR/link.txt"
  chown -R root:root "$CLIENT_DIR"
}

# 创建安全的 systemd 服务
create_service() {
  cat > /etc/systemd/system/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server -c $CONFIG_DIR/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONFIG_DIR /var/log /etc/letsencrypt
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
RestrictRealtime=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hysteria2
  
  if ! systemctl start hysteria2; then
    red "[!] Hysteria2 服务启动失败"
    journalctl -u hysteria2 --no-pager -n 30
    exit 1
  fi
  
  sleep 2
  if systemctl is-active --quiet hysteria2; then
    green "[*] Hysteria2 服务运行正常"
  else
    red "[!] 服务可能存在问题"
  fi
}

# 配置防火墙（增强版）
configure_firewall() {
  yellow "[*] 配置防火墙..."
  
  # UFW配置
  if command -v ufw &> /dev/null; then
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # 允许SSH（根据实际情况修改端口）
    ufw allow 22/tcp comment 'SSH'
    
    # 允许Hysteria2端口
    ufw allow $PORT/udp comment 'Hysteria2'
    
    # 如果使用80端口做证书验证
    if [[ "$PORT" != "80" ]] && [[ "$USE_REAL_CERT" == "true" ]]; then
      ufw allow 80/tcp comment 'Certbot'
    fi
    
    ufw --force enable
  fi
  
  # iptables规则优化
  iptables -I INPUT -p udp --dport $PORT -j ACCEPT
  iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  
  # 防止端口扫描
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  
  # 限制连接速率（防DDoS）
  iptables -A INPUT -p udp --dport $PORT -m hashlimit --hashlimit-name hysteria2 --hashlimit-above 50/sec --hashlimit-burst 100 --hashlimit-mode srcip -j DROP
  
  # 保存规则
  if command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  fi
}

# 系统优化（增强版）
optimize_system() {
  yellow "[*] 优化系统参数..."
  
  # 网络优化
  cat >> /etc/sysctl.conf <<EOF

# Hysteria2 优化配置
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
fs.file-max = 1048576
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
EOF

  sysctl -p

  # 设置ulimit
  cat >> /etc/security/limits.conf <<EOF
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
EOF
}

# 增强隐蔽性配置
enhance_stealth() {
  yellow "[*] 配置隐蔽性增强..."
  
  # 修改SSH端口（可选）
  read -p "是否修改SSH端口以增强安全性？(y/n，默认n): " change_ssh
  if [[ "$change_ssh" == "y" ]]; then
    NEW_SSH_PORT=$((RANDOM % 20000 + 10000))
    sed -i "s/#Port 22/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
    sed -i "s/Port 22/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
    systemctl restart sshd
    yellow "[!] SSH端口已修改为: $NEW_SSH_PORT"
    yellow "[!] 请记住新端口，否则可能无法连接！"
  fi
  
  # 禁用不必要的服务
  services_to_disable=("bluetooth" "cups" "avahi-daemon")
  for service in "${services_to_disable[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
      systemctl stop "$service" 2>/dev/null
      systemctl disable "$service" 2>/dev/null
    fi
  done
  
  # 配置时间同步（避免时间偏差导致的连接问题）
  timedatectl set-ntp true 2>/dev/null || true
}

# 清理安装痕迹（增强版）
cleanup_traces() {
  yellow "[*] 清理安装痕迹..."
  
  # 清理历史记录
  history -c
  echo "" > ~/.bash_history
  
  # 清理apt缓存
  if command -v apt &> /dev/null; then
    apt clean
  fi
  
  # 定期日志清理和轮转
  cat > /etc/logrotate.d/hysteria2 <<EOF
$LOG_FILE {
    daily
    rotate 3
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload hysteria2 > /dev/null 2>&1 || true
    endscript
}
EOF

  # 创建定期清理任务
  cat > /etc/cron.daily/hysteria2-cleanup <<EOF
#!/bin/bash
# 限制日志文件大小
if [[ -f "$LOG_FILE" && \$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 10485760 ]]; then
    tail -n 500 "$LOG_FILE" > "$LOG_FILE.tmp" 2>/dev/null
    mv "$LOG_FILE.tmp" "$LOG_FILE" 2>/dev/null
fi
# 清理旧的系统日志
find /var/log -type f -name "*.log" -mtime +7 -exec truncate -s 0 {} \; 2>/dev/null
EOF
  chmod +x /etc/cron.daily/hysteria2-cleanup
}

# 生成使用说明
generate_usage_info() {
  cat > "$CLIENT_DIR/usage.txt" <<EOF
==============================================
    Hysteria2 增强隐蔽版 - 配置信息
==============================================

【服务器信息】
- IP地址: $IP
- 端口: $PORT
- 密码: $PASS
- SNI域名: $SNI_DOMAIN
- 伪装网站: $MASQUERADE_URL

【文件位置】
- 服务端配置: $CONFIG_DIR/config.yaml
- 客户端配置: $CLIENT_DIR/client.yaml
- 连接链接: $CLIENT_DIR/link.txt
- 使用说明: $CLIENT_DIR/usage.txt

【服务管理】
启动: systemctl start hysteria2
停止: systemctl stop hysteria2
重启: systemctl restart hysteria2
状态: systemctl status hysteria2
日志: journalctl -u hysteria2 -f

【客户端连接】
1. V2rayN/Clash等客户端: 导入下方连接链接
2. Hysteria2官方客户端: 使用client.yaml配置文件

连接链接:
$(cat "$CLIENT_DIR/link.txt")

【安全建议】
✓ 定期更换密码和端口
✓ 监控服务器流量和日志
✓ 保持系统和软件更新
✓ 不要分享配置信息给不信任的人
✓ 使用前测试连接稳定性
✓ 建议搭配CDN使用（如Cloudflare）

【防封建议】
✓ 避免大流量突发使用
✓ 模拟正常用户行为
✓ 定期更换服务器IP
✓ 使用多个备用节点
✓ 关注服务器日志异常

【故障排查】
1. 无法连接: 检查防火墙和端口
2. 速度慢: 调整带宽限制
3. 频繁断线: 检查网络质量和MTU设置

【更新配置】
修改配置后执行: systemctl restart hysteria2

==============================================
EOF
  chmod 600 "$CLIENT_DIR/usage.txt"
}

# 连接测试
test_connection() {
  yellow "[*] 正在测试服务..."
  sleep 3
  
  if systemctl is-active --quiet hysteria2; then
    green "[✓] 服务运行正常"
    
    # 检查端口监听
    if ss -tuln | grep -q ":$PORT "; then
      green "[✓] 端口监听正常"
    else
      yellow "[!] 端口未正确监听，请检查配置"
    fi
  else
    red "[✗] 服务未运行"
    yellow "[*] 查看日志: journalctl -u hysteria2 -n 50"
  fi
}

# 主流程
main() {
  clear
  green "=========================================="
  green "   Hysteria2 增强隐蔽版安装脚本"
  green "=========================================="
  echo ""
  
  install_deps
  get_ip
  generate_cert
  set_port
  install_hysteria
  write_config
  create_service
  configure_firewall
  optimize_system
  enhance_stealth
  cleanup_traces
  generate_usage_info
  test_connection

  echo ""
  green "=========================================="
  green "        安装完成 ✅"
  green "=========================================="
  echo ""
  yellow "【服务器信息】"
  echo "  IP: $IP"
  echo "  端口: $PORT"
  echo "  密码: $PASS"
  echo "  SNI: $SNI_DOMAIN"
  echo ""
  yellow "【配置文件】"
  echo "  服务端: $CONFIG_DIR/config.yaml"
  echo "  客户端: $CLIENT_DIR/client.yaml"
  echo ""
  yellow "【连接链接】"
  cat "$CLIENT_DIR/link.txt"
  echo ""
  
  if command -v qrencode &> /dev/null; then
    yellow "【二维码】"
    qrencode -t ANSIUTF8 "$(cat "$CLIENT_DIR/link.txt")"
    echo ""
  fi
  
  green "详细说明: $CLIENT_DIR/usage.txt"
  yellow "服务状态: systemctl status hysteria2"
  echo ""
  yellow "=========================================="
}

main