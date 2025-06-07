#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red() { echo -e "${RED}$1${PLAIN}"; }
green() { echo -e "${GREEN}$1${PLAIN}"; }
yellow() { echo -e "${YELLOW}$1${PLAIN}"; }

CONFIG_DIR="/etc/.hysteria2"
CLIENT_DIR="/root/.hy-config"

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
  ${PACKAGE_INSTALL[PKG_INDEX]} curl wget qrencode openssl iptables-persistent netfilter-persistent
}

# 获取 IP
get_ip() {
  IP=$(curl -s4 ip.sb || curl -s6 ip.sb)
  [[ -z "$IP" ]] && red "[!] 无法获取公网 IP" && exit 1
}

# 生成证书
generate_cert() {
  mkdir -p "$CONFIG_DIR"
  openssl ecparam -genkey -name prime256v1 -out "$CONFIG_DIR/private.key"
  openssl req -new -x509 -days 36500 -key "$CONFIG_DIR/private.key" \
    -out "$CONFIG_DIR/cert.crt" -subj "/CN=www.bing.com"
  chmod 600 "$CONFIG_DIR"/*
}

# 选端口
select_port() {
  PORT=$(shuf -i 10000-60000 -n 1)
  until [[ -z $(ss -u -nltp | grep ":$PORT ") ]]; do
    PORT=$(shuf -i 10000-60000 -n 1)
  done
}

# 安装 Hysteria2
install_hysteria() {
  curl -s https://get.hy2.sh | bash
}

# 写配置
write_config() {
  PASS=$(openssl rand -hex 4)
  mkdir -p "$CLIENT_DIR"

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
EOF

  cat > "$CLIENT_DIR/client.yaml" <<EOF
server: $IP:$PORT
auth: $PASS
tls:
  sni: www.bing.com
  insecure: true
quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432
fastOpen: true
socks5:
  listen: 127.0.0.1:1080
transport:
  udp:
    hopInterval: 30s
EOF

  LINK="hysteria2://$PASS@$IP:$PORT/?insecure=1&sni=www.bing.com#hy2-node"
  echo "$LINK" > "$CLIENT_DIR/link.txt"
}

# 创建 systemd 服务
create_service() {
  cat > /etc/systemd/system/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria server -c $CONFIG_DIR/config.yaml
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now hysteria2
}

# 主流程
main() {
  install_deps
  get_ip
  select_port
  generate_cert
  install_hysteria
  write_config
  create_service

  green "\n[*] Hysteria2 安装完成 ✅"
  yellow "端口：$PORT"
  yellow "密码：$PASS"
  yellow "配置路径：$CONFIG_DIR / $CLIENT_DIR"
  yellow "节点链接：$(cat "$CLIENT_DIR/link.txt")"
  qrencode -t ANSIUTF8 "$(cat "$CLIENT_DIR/link.txt")"
}

main
