# transparent-proxy
下载release.zip，运行trnsprnt-proxy.sh进行测试
防火墙配置规则：
sudo iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port 8888
sudo iptables -t nat -A PREROUTING -p udp -j REDIRECT --to-port 8888
