# transparent-proxy
- download release.zip
- set the iptables rules:
```shell
sudo iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port [port]
sudo iptables -t nat -A PREROUTING -p udp -j REDIRECT --to-port [port]
```
- run trnsprnt-proxy.sh
- filling the ip addresses of your firewall host and the port number in the iptables rules
- click start
