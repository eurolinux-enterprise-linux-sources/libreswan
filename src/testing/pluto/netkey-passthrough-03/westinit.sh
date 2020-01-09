/testing/guestbin/swan-prep
# confirm that the network is alive
ping -n -c 4 -I 192.1.2.45 192.1.2.23
# make sure that clear text does not get through
iptables -A INPUT -i eth0 -s 192.1.2.23/32 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.1.2.45 192.1.2.23
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add west-east-passthrough-a
ipsec auto --add west-east-passthrough-b
ipsec auto --route west-east-passthrough-a
ipsec auto --route west-east-passthrough-b
echo "initdone"
