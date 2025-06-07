#!/bin/bash

set -e
export LANG=en_US.UTF-8

green() { echo -e "\033[32m\033[01m$1\033[0m"; }
yellow() { echo -e "\033[33m\033[01m$1\033[0m"; }
red() { echo -e "\033[31m\033[01m$1\033[0m"; }

[[ $EUID -ne 0 ]] && red "请使用 root 用户运行脚本！" && exit 1

if ! grep -qi "ubuntu" /etc/os-release; then
  red "本脚本仅支持 Ubuntu 系统！"
  exit 1
fi

green "✅ 开始安装 Hysteria 2..."

apt update -y
apt install -y curl wget openssl qrencode iptables-persistent netfilter-persistent

IP=$(curl -s4 ip.sb || curl -s6 ip.sb)

PORT=$(shuf -i 20000-40000 -n 1)
until [[ -z $(ss -u -nltp | grep ":$PORT ") ]]; do
  PORT=$(shuf -i 20000-40000 -n 1)
done

INSTALL_DIR="/etc/.hy2"
mkdir -p $INSTALL_DIR
chmod 700 $INSTALL_DIR

CERT=$INSTALL_DIR/cert.crt
KEY=$INSTALL_DIR/private.key
openssl ecparam -genkey -name prime256v1 -out $KEY
openssl req -new -x509 -days 36500 -key $KEY -out $CERT -subj "/CN=www.bing.com"
chmod 600 $CERT $KEY

curl -s https://get.hy2.sh | bash

PASS=$(openssl rand -hex 8)

CONFIG=$INSTALL_DIR/config.yaml
cat > $CONFIG <<EOF
listen: :$PORT
tls:
  cert: $CERT
  key: $KEY
auth:
  type: password
  password: $PASS
masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com
    rewriteHost: true
EOF

cat > /etc/systemd/system/nginx-core.service <<EOF
[Unit]
Description=Nginx Core Service (Hysteria2)
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria server -c $CONFIG
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nginx-core

CLIENT_DIR="/root/.hy2-client"
mkdir -p $CLIENT_DIR

cat > $CLIENT_DIR/config.yaml <<EOF
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

LINK="hysteria2://$PASS@$IP:$PORT/?insecure=1&sni=www.bing.com#hy2-stealth"
echo "$LINK" > $CLIENT_DIR/link.txt

green "✅ Hysteria2 安装完成！"
yellow "端口: $PORT"
yellow "密码: $PASS"
yellow "节点链接如下:"
echo "$LINK"
qrencode -t ANSIUTF8 "$LINK"
