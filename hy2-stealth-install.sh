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
  ${PACKAGE_INSTALL[PKG_INDEX]} curl wget qrencode openssl iptables-persistent netfilter-persistent ufw fail2ban
  
  # 配置 fail2ban 防暴力破解
  if ! systemctl is-active --quiet fail2ban; then
    systemctl enable --now fail2ban
  fi
}

# 获取 IP (增加隐私保护)
get_ip() {
  # 使用多个IP检测源，避免单点依赖
  IP_SOURCES=("https://icanhazip.com" "https://ipv4.icanhazip.com" "https://api.ipify.org" "https://ifconfig.me/ip")
  
  for source in "${IP_SOURCES[@]}"; do
    IP=$(curl -s --connect-timeout 5 --max-time 10 "$source" 2>/dev/null | grep -E '^[0-9.]+$')
    [[ -n "$IP" ]] && break
  done
  
  [[ -z "$IP" ]] && red "[!] 无法获取公网 IP" && exit 1
  yellow "[*] 检测到公网IP: $IP"
}

# 生成更安全的证书
generate_cert() {
  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR"
  
  # 生成更强的私钥
  openssl ecparam -genkey -name secp384r1 -out "$CONFIG_DIR/private.key"
  
  # 生成更真实的证书信息，增加隐蔽性
  FAKE_DOMAINS=("cloudflare.com" "google.com" "microsoft.com" "amazon.com" "github.com")
  FAKE_DOMAIN=${FAKE_DOMAINS[$RANDOM % ${#FAKE_DOMAINS[@]}]}
  
  openssl req -new -x509 -days 36500 -key "$CONFIG_DIR/private.key" \
    -out "$CONFIG_DIR/cert.crt" -subj "/C=US/ST=CA/L=San Francisco/O=Tech Company/CN=$FAKE_DOMAIN"
  
  # 设置更严格的权限
  chmod 600 "$CONFIG_DIR/private.key"
  chmod 644 "$CONFIG_DIR/cert.crt"
  chown -R root:root "$CONFIG_DIR"
}

# 固定使用443端口
set_port() {
  PORT=443
  
  # 检查端口是否被占用
  if ss -tlnp | grep -q ":443 "; then
    red "[!] 端口 443 已被占用，请检查并关闭占用该端口的服务"
    yellow "[*] 常见占用443端口的服务："
    yellow "    - Apache: systemctl stop apache2"
    yellow "    - Nginx: systemctl stop nginx"
    yellow "    - 其他Web服务器"
    exit 1
  fi
  
  yellow "[*] 使用端口: $PORT"
}

# 验证Hysteria2安装
install_hysteria() {
  yellow "[*] 安装 Hysteria2..."
  
  # 验证下载的脚本
  INSTALL_SCRIPT=$(mktemp)
  if ! curl -s https://get.hy2.sh -o "$INSTALL_SCRIPT"; then
    red "[!] 下载安装脚本失败"
    exit 1
  fi
  
  # 验证下载的脚本不是 HTML 页面
if grep -q "<html" "$INSTALL_SCRIPT"; then
  red "[!] 安装脚本返回了 HTML 页面，可能被防火墙拦截"
  rm -f "$INSTALL_SCRIPT"
  exit 1
fi
  
  bash "$INSTALL_SCRIPT"
  rm -f "$INSTALL_SCRIPT"
  
  # 验证安装结果
  if ! command -v hysteria &> /dev/null; then
    red "[!] Hysteria2 安装失败"
    exit 1
  fi
}

# 生成强密码和安全配置
write_config() {
  # 生成更强的密码 (16字符)
  PASS=$(openssl rand -base64 12 | tr -d "=+/" | cut -c1-16)
  
  mkdir -p "$CLIENT_DIR"
  chmod 700 "$CLIENT_DIR"

  # 服务端配置 - 增加安全选项
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
    url: https://www.bing.com
    rewriteHost: true

# 安全配置
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 16777216
  maxConnReceiveWindow: 16777216
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s
  maxIncomingStreams: 1024

# 限制并发连接
bandwidth:
  up: 1000 mbps
  down: 1000 mbps

# 日志配置
log:
  level: warn
  file: $LOG_FILE
EOF

  # 客户端配置
  cat > "$CLIENT_DIR/client.yaml" <<EOF
server: $IP:$PORT
auth: $PASS

tls:
  sni: www.bing.com
  insecure: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 16777216
  maxConnReceiveWindow: 16777216

fastOpen: true

socks5:
  listen: 127.0.0.1:1080

transport:
  udp:
    hopInterval: 30s

# 客户端安全配置
lazy: false
EOF

  # 生成连接链接
  LINK="hysteria2://$PASS@$IP:$PORT/?insecure=1&sni=www.bing.com#HY2-$(date +%s)"
  echo "$LINK" > "$CLIENT_DIR/link.txt"
  
  # 设置文件权限
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
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

# 安全配置
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONFIG_DIR /var/log
PrivateTmp=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hysteria2
  
  if ! systemctl start hysteria2; then
    red "[!] Hysteria2 服务启动失败"
    journalctl -u hysteria2 --no-pager -n 20
    exit 1
  fi
}

# 配置防火墙
configure_firewall() {
  yellow "[*] 配置防火墙..."
  
  # UFW配置
  if command -v ufw &> /dev/null; then
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow $PORT/udp comment 'Hysteria2'
    ufw --force enable
  fi
  
  # iptables配置作为备份
  iptables -I INPUT -p udp --dport $PORT -j ACCEPT
  iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  
  # 保存iptables规则
  if command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  fi
}

# 系统优化
optimize_system() {
  yellow "[*] 优化系统参数..."
  
  # 网络优化
  cat >> /etc/sysctl.conf <<EOF

# Hysteria2 优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 4096
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
fs.file-max = 1048576
EOF

  sysctl -p

  # 设置ulimit
  echo "* soft nofile 1048576" >> /etc/security/limits.conf
  echo "* hard nofile 1048576" >> /etc/security/limits.conf
}

# 清理安装痕迹
cleanup_traces() {
  yellow "[*] 清理安装痕迹..."
  
  # 清理历史记录中的敏感信息
  history -c
  echo "" > ~/.bash_history
  
  # 创建定期日志清理任务
  cat > /etc/cron.daily/hysteria2-cleanup <<EOF
#!/bin/bash
# 保留最近7天的日志
find /var/log -name "*hysteria*" -type f -mtime +7 -delete 2>/dev/null
# 限制日志文件大小
if [[ -f "$LOG_FILE" && \$(stat -c%s "$LOG_FILE") -gt 10485760 ]]; then
    tail -n 1000 "$LOG_FILE" > "$LOG_FILE.tmp"
    mv "$LOG_FILE.tmp" "$LOG_FILE"
fi
EOF
  chmod +x /etc/cron.daily/hysteria2-cleanup
}

# 生成使用说明
generate_usage_info() {
  cat > "$CLIENT_DIR/usage.txt" <<EOF
Hysteria2 配置信息
==================

服务器信息：
- IP: $IP
- 端口: $PORT
- 密码: $PASS

客户端配置文件: $CLIENT_DIR/client.yaml
连接链接: $(cat "$CLIENT_DIR/link.txt")

服务管理命令：
- 启动服务: systemctl start hysteria2
- 停止服务: systemctl stop hysteria2
- 重启服务: systemctl restart hysteria2
- 查看状态: systemctl status hysteria2
- 查看日志: journalctl -u hysteria2 -f

配置文件位置：
- 服务端配置: $CONFIG_DIR/config.yaml
- 客户端配置: $CLIENT_DIR/client.yaml

安全建议：
1. 定期更换密码
2. 监控服务日志
3. 保持系统更新
4. 不要在不安全的网络中传输配置信息

EOF
  chmod 600 "$CLIENT_DIR/usage.txt"
}

# 主流程
main() {
  yellow "[*] 开始安装 Hysteria2 (安全增强版)"
  
  install_deps
  get_ip
  set_port
  generate_cert
  install_hysteria
  write_config
  create_service
  configure_firewall
  optimize_system
  cleanup_traces
  generate_usage_info

  green "\n[*] Hysteria2 安装完成 ✅"
  echo "========================================"
  yellow "服务器IP：$IP"
  yellow "端口：$PORT"
  yellow "密码：$PASS"
  yellow "配置目录：$CONFIG_DIR"
  yellow "客户端配置：$CLIENT_DIR"
  echo "========================================"
  yellow "连接链接："
  echo "$(cat "$CLIENT_DIR/link.txt")"
  echo ""
  yellow "二维码："
  qrencode -t ANSIUTF8 "$(cat "$CLIENT_DIR/link.txt")"
  echo ""
  green "[*] 详细使用说明请查看: $CLIENT_DIR/usage.txt"
  yellow "[*] 服务状态检查: systemctl status hysteria2"
}

main