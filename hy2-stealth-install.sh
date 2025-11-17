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
  ${PACKAGE_INSTALL[PKG_INDEX]} curl wget qrencode openssl iptables-persistent
}

# 获取 IP
get_ip() {
  IP_SOURCES=("https://api.ipify.org" "https://icanhazip.com" "https://ifconfig.me/ip")
  
  for source in "${IP_SOURCES[@]}"; do
    IP=$(curl -s --connect-timeout 5 --max-time 10 "$source" 2>/dev/null | grep -E '^[0-9.]+$')
    [[ -n "$IP" ]] && break
  done
  
  [[ -z "$IP" ]] && red "[!] 无法获取公网 IP" && exit 1
  yellow "[*] 检测到公网IP: $IP"
}

# 生成证书
generate_cert() {
  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR"
  
  yellow "[*] 生成自签名证书..."
  
  # 生成证书
  openssl ecparam -genkey -name prime256v1 -out "$CONFIG_DIR/private.key"
  
  # 使用常见域名
  FAKE_DOMAINS=("www.microsoft.com" "www.apple.com" "cdn.cloudflare.com")
  SNI_DOMAIN=${FAKE_DOMAINS[$RANDOM % ${#FAKE_DOMAINS[@]}]}
  
  openssl req -new -x509 -days 3650 -key "$CONFIG_DIR/private.key" \
    -out "$CONFIG_DIR/cert.crt" -subj "/C=US/ST=CA/O=Example/CN=$SNI_DOMAIN"
  
  chmod 600 "$CONFIG_DIR/private.key"
  chmod 644 "$CONFIG_DIR/cert.crt"
  
  green "[*] 证书生成成功，SNI: $SNI_DOMAIN"
}

# 选择端口
set_port() {
  yellow "[*] 端口选择："
  echo "1) 443 (HTTPS标准端口)"
  echo "2) 随机高位端口 (推荐)"
  echo "3) 自定义端口"
  read -p "请选择 [1-3，默认2]: " port_choice
  
  case "$port_choice" in
    1) PORT=443 ;;
    3) 
      read -p "请输入端口号 (1-65535): " PORT
      if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        red "[!] 无效端口"
        exit 1
      fi
      ;;
    *)
      PORT=$((RANDOM % 50000 + 10000))
      ;;
  esac
  
  # 检查端口占用
  while ss -tuln | grep -q ":$PORT "; do
    yellow "[!] 端口 $PORT 已被占用，重新选择..."
    PORT=$((RANDOM % 50000 + 10000))
  done
  
  yellow "[*] 使用端口: $PORT"
}

# 安装 Hysteria2
install_hysteria() {
  yellow "[*] 安装 Hysteria2..."
  
  bash <(curl -fsSL https://get.hy2.sh)
  
  if ! command -v hysteria &> /dev/null; then
    red "[!] 安装失败"
    exit 1
  fi
  
  green "[*] Hysteria2 安装成功"
}

# 生成配置文件
write_config() {
  # 生成密码
  PASS=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
  
  mkdir -p "$CLIENT_DIR"
  chmod 700 "$CLIENT_DIR"

  # 伪装网站
  MASQUERADE_URL="https://www.bing.com"

  # 服务端配置（简化版，修复网络问题）
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

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  keepAlivePeriod: 10s

# 关键：允许客户端自定义带宽
ignoreClientBandwidth: false

# 启用UDP（重要）
disableUDP: false

speedTest: false

EOF

  # 客户端配置（简化版）
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

fastOpen: true

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:1081

bandwidth:
  up: 50 mbps
  down: 100 mbps

lazy: false
EOF

  # 生成连接链接
  LINK="hysteria2://$PASS@$IP:$PORT/?insecure=1&sni=$SNI_DOMAIN#HY2-$(date +%s)"
  echo "$LINK" > "$CLIENT_DIR/link.txt"
  
  chmod 600 "$CLIENT_DIR/client.yaml"
  chmod 600 "$CLIENT_DIR/link.txt"
  
  green "[*] 配置文件生成成功"
}

# 创建 systemd 服务
create_service() {
  cat > /etc/systemd/system/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/hysteria server -c $CONFIG_DIR/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hysteria2
  systemctl start hysteria2
  
  sleep 2
  
  if systemctl is-active --quiet hysteria2; then
    green "[*] Hysteria2 服务启动成功"
  else
    red "[!] 服务启动失败，查看日志："
    journalctl -u hysteria2 --no-pager -n 20
    exit 1
  fi
}

# 配置防火墙（修复版）
configure_firewall() {
  yellow "[*] 配置防火墙..."
  
  # 开启IP转发（关键！）
  echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
  echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.conf
  sysctl -p > /dev/null 2>&1
  
  # 配置iptables
  iptables -I INPUT -p udp --dport $PORT -j ACCEPT
  iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  
  # 允许转发（重要！）
  iptables -I FORWARD -j ACCEPT
  
  # 保存规则
  if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
  elif command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null
  fi
  
  green "[*] 防火墙配置完成"
}

# 系统优化
optimize_system() {
  yellow "[*] 优化系统参数..."
  
  cat >> /etc/sysctl.conf <<EOF

# Hysteria2 网络优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
fs.file-max = 1000000
EOF

  sysctl -p > /dev/null 2>&1
  
  green "[*] 系统优化完成"
}

# 生成使用说明
generate_usage_info() {
  cat > "$CLIENT_DIR/README.txt" <<EOF
==============================================
    Hysteria2 配置信息
==============================================

【服务器信息】
IP地址: $IP
端口: $PORT
密码: $PASS
SNI域名: $SNI_DOMAIN

【文件位置】
服务端配置: $CONFIG_DIR/config.yaml
客户端配置: $CLIENT_DIR/client.yaml
连接链接: $CLIENT_DIR/link.txt

【服务管理命令】
启动: systemctl start hysteria2
停止: systemctl stop hysteria2
重启: systemctl restart hysteria2
状态: systemctl status hysteria2
日志: journalctl -u hysteria2 -f

【连接链接】
$(cat "$CLIENT_DIR/link.txt")

【客户端使用】
1. 复制上方链接到支持Hysteria2的客户端
2. 或使用client.yaml配置文件

【故障排查】
1. 检查服务状态: systemctl status hysteria2
2. 查看日志: journalctl -u hysteria2 -n 50
3. 检查端口: ss -tuln | grep $PORT
4. 检查防火墙: iptables -L -n

【安全建议】
- 定期更换密码
- 监控服务器流量
- 保持系统更新

==============================================
EOF
  chmod 600 "$CLIENT_DIR/README.txt"
}

# 测试连接
test_connection() {
  yellow "[*] 测试服务状态..."
  sleep 2
  
  if systemctl is-active --quiet hysteria2; then
    green "[✓] 服务运行正常"
  else
    red "[✗] 服务未运行"
    return 1
  fi
  
  if ss -tuln | grep -q ":$PORT "; then
    green "[✓] 端口监听正常"
  else
    yellow "[!] 端口监听异常"
    return 1
  fi
  
  # 检查IP转发
  if sysctl net.ipv4.ip_forward | grep -q "= 1"; then
    green "[✓] IP转发已启用"
  else
    yellow "[!] IP转发未启用"
  fi
}

# 主流程
main() {
  clear
  green "=========================================="
  green "   Hysteria2 安装脚本 (修复版)"
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
  yellow "【连接链接】"
  cat "$CLIENT_DIR/link.txt"
  echo ""
  
  if command -v qrencode &> /dev/null; then
    yellow "【二维码】"
    qrencode -t ANSIUTF8 "$(cat "$CLIENT_DIR/link.txt")"
    echo ""
  fi
  
  green "详细信息: $CLIENT_DIR/README.txt"
  green "服务状态: systemctl status hysteria2"
  echo ""
  green "=========================================="
}

main