#!/bin/bash

export LANG=en_US.UTF-8

# 颜色函数
RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; PLAIN="\033[0m"
red() { echo -e "${RED}$1${PLAIN}"; }; green() { echo -e "${GREEN}$1${PLAIN}"; }; yellow() { echo -e "${YELLOW}$1${PLAIN}"; }

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
for i in "${CMD[@]}"; do SYS="$i" && [[ -n $SYS ]] && break; done
for ((i = 0; i < ${#REGEX[@]}; i++)); do [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[i]} ]] && SYSTEM="${RELEASE[i]}" && PKG_INDEX=$i && break; done
[[ -z $SYSTEM ]] && red "[!] 暂不支持该系统！" && exit 1

# 安装依赖
install_deps() {
  yellow "[*] 安装依赖中..."
  ${PACKAGE_UPDATE[PKG_INDEX]}
  ${PACKAGE_INSTALL[PKG_INDEX]} curl wget qrencode openssl iptables-persistent netfilter-persistent ufw fail2ban
  systemctl enable --now fail2ban &>/dev/null
}

# 获取公网 IP
get_ip() {
  IP_SOURCES=("https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me")
  for source in "${IP_SOURCES[@]}"; do
    IP=$(curl -s --connect-timeout 5 "$source" | grep -E '^[0-9.]+$')
    [[ -n "$IP" ]] && break
  done
  [[ -z "$IP" ]] && red "[!] 无法获取公网 IP" && exit 1
  yellow "[*] 检测到公网IP: $IP"
}

# 证书生成
generate_cert() {
  mkdir -p "$CONFIG_DIR"; chmod 700 "$CONFIG_DIR"
  openssl ecparam -genkey -name secp384r1 -out "$CONFIG_DIR/private.key"
  FAKE_DOMAINS=("cloudflare.com" "github.com" "amazon.com")
  FAKE_DOMAIN=${FAKE_DOMAINS[$RANDOM % ${#FAKE_DOMAINS[@]}]}
  openssl req -new -x509 -days 36500 -key "$CONFIG_DIR/private.key" \
    -out "$CONFIG_DIR/cert.crt" -subj "/C=US/ST=CA/L=SanFrancisco/O=Tech/CN=$FAKE_DOMAIN"
  chmod 600 "$CONFIG_DIR/private.key"; chmod 644 "$CONFIG_DIR/cert.crt"
}

# 安装 hysteria 二进制
install_hysteria() {
  yellow "[*] 下载 Hysteria2 二进制..."
  ARCH=$(uname -m)
  case $ARCH in
    x86_64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) red "[!] 不支持架构: $ARCH" && exit 1 ;;
  esac
  curl -Lo /usr/local/bin/hysteria https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-$ARCH
  chmod +x /usr/local/bin/hysteria
  command -v hysteria &>/dev/null || { red "[!] Hysteria2 安装失败" && exit 1; }
}

# 写配置
write_config() {
  PORT=443
  if ss -tlnp | grep -q ":443 "; then red "[!] 443端口已被占用"; exit 1; fi
  yellow "[*] 使用端口: $PORT"

  PASS=$(openssl rand -base64 12 | tr -dc A-Za-z0-9 | cut -c1-16)
  mkdir -p "$CLIENT_DIR"; chmod 700 "$CLIENT_DIR"

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
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 16777216
  maxConnReceiveWindow: 16777216
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s
  maxIncomingStreams: 1024
bandwidth:
  up: 1000 mbps
  down: 1000 mbps
log:
  level: warn
  file: $LOG_FILE
EOF

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
lazy: false
EOF

  LINK="hysteria2://$PASS@$IP:$PORT/?insecure=1&sni=www.bing.com#HY2-$(date +%s)"
  echo "$LINK" > "$CLIENT_DIR/link.txt"

  chmod 600 "$CLIENT_DIR/"*.yaml "$CLIENT_DIR/link.txt"
}

# 创建 systemd 服务
create_service() {
  cat > /etc/systemd/system/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c $CONFIG_DIR/config.yaml
Restart=on-failure
LimitNOFILE=1048576
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONFIG_DIR /var/log
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now hysteria2 || { red "[!] 启动失败" && journalctl -u hysteria2 --no-pager -n 20 && exit 1; }
}

# 配置防火墙
configure_firewall() {
  ufw --force reset; ufw default deny incoming; ufw default allow outgoing
  ufw allow ssh; ufw allow 443/udp comment 'Hysteria2'; ufw --force enable
  iptables -I INPUT -p udp --dport 443 -j ACCEPT
  iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
}

# 优化系统
optimize_system() {
  cat >> /etc/sysctl.conf <<EOF
# Hysteria2 优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.netdev_max_backlog = 4096
EOF
  sysctl -p
  echo "* soft nofile 1048576" >> /etc/security/limits.conf
  echo "* hard nofile 1048576" >> /etc/security/limits.conf
}

# 日志清理任务
cleanup_logs() {
  cat > /etc/cron.daily/hysteria2-cleanup <<EOF
#!/bin/bash
find /var/log -name "*hysteria*" -type f -mtime +7 -delete 2>/dev/null
if [[ -f "$LOG_FILE" && \$(stat -c%s "$LOG_FILE") -gt 10485760 ]]; then
  tail -n 1000 "$LOG_FILE" > "$LOG_FILE.tmp"
  mv "$LOG_FILE.tmp" "$LOG_FILE"
fi
EOF
  chmod +x /etc/cron.daily/hysteria2-cleanup
}

# 显示使用信息
generate_info() {
  LINK=$(cat "$CLIENT_DIR/link.txt")
  cat > "$CLIENT_DIR/usage.txt" <<EOF
Hysteria2 配置完成 ✅

服务器IP: $IP
端口: 443
密码: $PASS
客户端配置文件: $CLIENT_DIR/client.yaml
连接链接: $LINK

服务控制命令:
systemctl start hysteria2
systemctl stop hysteria2
systemctl restart hysteria2
systemctl status hysteria2
EOF

  green "\n[*] 安装完成 ✅"
  echo "=========================================="
  yellow "连接链接:"
  echo "$LINK"
  echo ""
  yellow "二维码："
  qrencode -t ANSIUTF8 "$LINK"
  echo ""
  green "[*] 配置信息保存在：$CLIENT_DIR/usage.txt"
}

# 主流程
main() {
  yellow "[*] 安装 Hysteria2 安全版开始..."
  install_deps
  get_ip
  generate_cert
  install_hysteria
  write_config
  create_service
  configure_firewall
  optimize_system
  cleanup_logs
  generate_info
}

main
