#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red() { echo -e "${RED}$1${PLAIN}"; }
green() { echo -e "${GREEN}$1${PLAIN}"; }
yellow() { echo -e "${YELLOW}$1${PLAIN}"; }

[[ $EUID -ne 0 ]] && red "请使用 root 运行" && exit 1

# 获取IP
get_ip() {
  IP=$(curl -s --max-time 5 https://api.ipify.org)
  [[ -z "$IP" ]] && red "无法获取IP" && exit 1
  yellow "服务器IP: $IP"
}

# 安装 Hysteria2
install() {
  yellow "安装 Hysteria2..."
  bash <(curl -fsSL https://get.hy2.sh) || { red "安装失败"; exit 1; }
  green "安装成功"
}

# 生成证书
gen_cert() {
  mkdir -p /etc/hysteria
  openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/server.key
  openssl req -new -x509 -days 36500 -key /etc/hysteria/server.key \
    -out /etc/hysteria/server.crt -subj "/CN=bing.com"
}

# 选择端口
set_port() {
  PORT=$((RANDOM % 50000 + 10000))
  while ss -tuln | grep -q ":$PORT "; do
    PORT=$((RANDOM % 50000 + 10000))
  done
  yellow "端口: $PORT"
}

# 生成配置
gen_config() {
  PASS=$(openssl rand -base64 12 | tr -d "=+/")
  
  cat > /etc/hysteria/config.yaml <<EOF
listen: :$PORT

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: password
  password: $PASS

masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432
EOF

  mkdir -p /root/hy2
  cat > /root/hy2/client.yaml <<EOF
server: $IP:$PORT
auth: $PASS

tls:
  sni: bing.com
  insecure: true

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:1081
EOF

  echo "hysteria2://$PASS@$IP:$PORT/?insecure=1&sni=bing.com#HY2" > /root/hy2/link.txt
}

# 启动服务
start_service() {
  cat > /etc/systemd/system/hysteria.service <<EOF
[Unit]
Description=Hysteria2
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable hysteria >/dev/null 2>&1
  systemctl restart hysteria
  
  sleep 1
  systemctl is-active --quiet hysteria && green "服务启动成功" || { red "启动失败"; exit 1; }
}

# 配置系统（极简优化）
optimize() {
  # 开启转发（去重检查）
  if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  fi
  if ! grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
  fi
  
  # BBR加速
  if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  fi
  if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  fi
  
  # 提升缓冲区
  if ! grep -q "net.core.rmem_max" /etc/sysctl.conf; then
    echo "net.core.rmem_max=33554432" >> /etc/sysctl.conf
    echo "net.core.wmem_max=33554432" >> /etc/sysctl.conf
  fi
  
  sysctl -p >/dev/null 2>&1
  
  # 防火墙（检查规则是否已存在）
  if ! iptables -C INPUT -p udp --dport $PORT -j ACCEPT 2>/dev/null; then
    iptables -I INPUT -p udp --dport $PORT -j ACCEPT
  fi
  if ! iptables -C FORWARD -j ACCEPT 2>/dev/null; then
    iptables -I FORWARD -j ACCEPT
  fi
}

# 主流程
main() {
  clear
  green "========================================"
  green "    Hysteria2 极简安装"
  green "========================================"
  echo ""
  
  get_ip
  install
  gen_cert
  set_port
  gen_config
  optimize
  start_service
  
  echo ""
  green "========================================"
  green "安装完成！"
  green "========================================"
  echo ""
  echo "IP: $IP"
  echo "端口: $PORT"
  echo "密码: $PASS"
  echo ""
  yellow "连接链接:"
  cat /root/hy2/link.txt
  echo ""
  echo "配置文件: /root/hy2/client.yaml"
  echo "服务管理: systemctl restart hysteria"
  echo ""
}

main