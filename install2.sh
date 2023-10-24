#!/bin/bash

clear
echo "Hello! 欢迎使用Vless+gRPC+TLS脚本"
echo "有问题联系root@sitao.org"
echo

read -p "请输入你的域名:" domain

if [ -z $domain ]
  then
         clear
         echo "别闹，你还没输入域名"
         sleep 2
         read -p "请输入你的域名:" domain
          if [ -z $domain ]
           then
           echo "? 你还是没输入域名。。不玩了，两秒后退出脚本"
           echo
           sleep 2
           exit
          fi
fi

read -p "你想要什么端口? 默认443:" port
if [ -z $port ]
 then port=443
fi

echo -e "你想要什么样的伪装站?\n"
read -p "[1] 游戏直播;[2] 影视站;[3] 视频分享平台 [默认2]:" checkweb
if [ -z $checkweb ]
 then checkweb=2
fi

clear
echo "OK! 一切已准备就绪，按回车键开始安装!"
read

#下载xray内核
mkdir /xray
chmod 777 /xray
wget https://github.com/XTLS/Xray-core/releases/download/v1.8.4/Xray-linux-64.zip
apt-get install unzip -y
unzip Xray-linux-64.zip -d /xray
cp /xray/xray /usr/bin/xray
id=`xray uuid`

cat << EOF > /etc/systemd/system/xray.service
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target
[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/xray/xray run -config /xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /xray/config.json
{
    "inbounds": [
    {
        "port": 16969,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "settings": {
            "clients": [{
                "id": "${id}"
            }],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "proxy"
            }
        }
    }],
    "outbounds": [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF
systemctl start xray.service
systemctl enable xray.service

#申请证书
apt update
mkdir -p /xray/tls
chmod 777 /xray/tls
apt install socat -y
curl https://get.acme.sh | sh
ln -s  /root/.acme.sh/acme.sh /usr/local/bin/acme.sh
source ~/.bashrc
acme.sh --set-default-ca --server letsencrypt
acme.sh --issue -d $domain --standalone -k ec-256 --force
acme.sh --installcert -d $domain --ecc  --key-file   /xray/tls/server.key   --fullchain-file /xray/tls/server.crt
if `test -s /xray/tls/server.crt` 
  then 
        echo -e "证书申请成功!\n"
        echo -n "证书路径:"
        echo
        echo -e "/xray/tls/server.crt"
        echo -e "/xray/tls/server.key\n"
else
        echo "证书安装失败！请检查原因！有问题可联系telegram @iu536"
        exit
fi

#伪装站
mkdir /web
if [ "$checkweb" -eq "1" ]
 then
         wget https://raw.githubusercontent.com/LSitao/Trojan-gRPC-tls/main/web/game.tar.gz
         tar -zxvf game.tar.gz -C /web
             
elif [ "$checkweb" -eq "2" ]
  then 
           wget https://raw.githubusercontent.com/LSitao/Trojan-gRPC-tls/main/web/movie.tar.gz
             tar -zxvf movie.tar.gz -C /web
           cd /web/movie
           mv ./* ..
           cd

elif [ "$checkweb" -eq "3" ]
  then 
           wget https://raw.githubusercontent.com/LSitao/Trojan-gRPC-tls/main/web/share.tar.gz
             tar -zxvf share.tar.gz -C /web
             cd /web/share
             mv ./* ..
             cd

fi

#编译安装nginx
#安装依赖
apt install build-essential libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev -y
#下载Nginx源码
wget https://nginx.org/download/nginx-1.25.2.tar.gz
tar -xzvf nginx-1.25.2.tar.gz
cd nginx-1.25.2
./configure \
--prefix=/usr/local/nginx \
--user=nginx \
--group=nginx \
--sbin-path=/usr/local/nginx/sbin/nginx \
--conf-path=/usr/local/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--with-file-aio \
--with-threads \
--with-http_addition_module \
--with-http_auth_request_module \
--with-http_dav_module \
--with-http_flv_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_mp4_module \
--with-http_random_index_module \
--with-http_realip_module \
--with-http_secure_link_module \
--with-http_slice_module \
--with-http_ssl_module \
--with-http_stub_status_module \
--with-http_sub_module \
--with-http_v2_module \
--with-mail_ssl_module \
--with-stream \
--with-stream_realip_module \
--with-stream_ssl_module \
--with-stream_ssl_preread_module

make && make install

/usr/sbin/groupadd nginx
/usr/sbin/useradd -g nginx nginx

cat << EOF > /etc/systemd/system/nginx.service
[Unit]
Description=nginx
After=network.target
  
[Service]
Type=forking
ExecStart=/usr/local/nginx/sbin/nginx
ExecReload=/usr/local/nginx/sbin/nginx -s reload
ExecStop=/usr/local/nginx/sbin/nginx -s quit
PrivateTmp=true
  
[Install]
WantedBy=multi-user.target
EOF
cp /usr/local/nginx/sbin/nginx /usr/bin/nginx
systemctl enable nginx
systemctl start nginx
mkdir -p /usr/local/nginx/conf.d
sed -i '/default_type  application\/octet-stream;/a\    include \/usr\/local\/nginx\/conf.d\/\*.conf\;' /usr/local/nginx/nginx.conf
echo
nginx -v
echo "Nginx安装成功!"

#配置nginx
if [ $port -eq 443 ]
 then
cat << EOF > /usr/local/nginx/conf.d/grpc.conf
server {
    listen 80;
    server_name ${domain};
    #charset utf-8;   
    
    location / {
    rewrite (.*) https://${domain}\$1 permanent;
      }
}
server {
    listen 443 ssl http2;
    server_name ${domain};
   location /proxy {
        if (\$content_type !~ "application/grpc") {
                return 404;
        }
        client_max_body_size 512K;
        client_body_timeout 1071906480m;
        grpc_set_header X-Real-IP \$remote_addr;  # cdn $proxy_add_x_forwarded_for
        grpc_read_timeout 2m;
        grpc_send_timeout 5m;
        grpc_pass grpc://127.0.0.1:16969;
    }
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always; # 启用HSTS
    location / {
        if (\$host ~* "\d+\.\d+\.\d+\.\d+") { # 禁止以ip方式访问网站
                return 400;
        }
              root /web;
              index index.html;
    }
    ssl_certificate /xray/tls/server.crt;
    ssl_certificate_key /xray/tls/server.key;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1.3;
    ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
    ssl_prefer_server_ciphers on;
}
EOF
else cat << EOF > /usr/local/nginx/conf.d/grpc.conf
server {
    listen $port ssl http2;
    server_name ${domain};
    error_page 497 https://\$host:$port\$request_uri;

    location /proxy {
        if (\$content_type !~ "application/grpc") {
                return 404;
        }
        client_max_body_size 512K;
        client_body_timeout 1071906480m;
        grpc_set_header X-Real-IP \$remote_addr;  # cdn $proxy_add_x_forwarded_for
        grpc_read_timeout 1071906480m;
        grpc_pass grpc://127.0.0.1:16969;
    }
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always; # 启用HSTS
    location / {
        if (\$host ~* "\d+\.\d+\.\d+\.\d+") { # 禁止以ip方式访问网站
                return 400;
        }
              root /web;
              index index.html;
    }
    ssl_certificate /xray/tls/server.crt;
    ssl_certificate_key /xray/tls/server.key;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1.3;
    ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
    ssl_prefer_server_ciphers on;
}
EOF

fi
systemctl restart nginx
clear
echo -e "安装完成!\n"
cat << EOF > /xray/clash-node
- name: "Vless+gRPC+TLS"
    server: $domain
    port: $port
    type: vless
    uuid: $id
    alterId: 0
    cipher: auto
    network: grpc
    tls: true
    servername: $domain
    # skip-cert-verify: true
    grpc-opts:
      grpc-service-name: "proxy"
EOF

echo "vless://${id}@${domain}:$port?type=grpc&encryption=none&serviceName=proxy&security=tls&sni=${domain}#Vless+gRPC+tls" > /xray/v2rayN-node
echo "V2rayN链接:"
cat /xray/v2rayN-node
echo

echo
echo "clash节点配置:"
cat /xray/clash-node
echo


