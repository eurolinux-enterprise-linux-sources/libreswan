/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --debug-all --impair send-zero-gx --impair retransmits
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
