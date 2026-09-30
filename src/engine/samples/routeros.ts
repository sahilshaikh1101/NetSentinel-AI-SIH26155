export const SAMPLE_ROUTEROS = `# 2026-09-16 20:12:44 by RouterOS 7.14.3
# software id = 4N8T-Q2KC
#
# model = RB4011iGS+
# serial number = HD3M0A9F1QP
/interface bridge
add name=bridge-lan protocol-mode=rstp
/interface ethernet
set [ find default-name=ether1 ] comment="ISP-D uplink" name=ether1-wan
set [ find default-name=ether2 ] comment="LAN" name=ether2-lan
set [ find default-name=sfp-sfpplus1 ] comment="Core uplink" name=sfp1-core
/interface list
add name=WAN
add name=LAN
add name=MGMT
/interface list member
add interface=ether1-wan list=WAN
add interface=bridge-lan list=LAN
add interface=sfp1-core list=MGMT
/interface bridge port
add bridge=bridge-lan interface=ether2-lan
/ip pool
add name=lan-pool ranges=10.22.9.100-10.22.9.200
/ip dhcp-server
add address-pool=lan-pool interface=bridge-lan name=lan-dhcp
/ip address
add address=10.22.9.1/24 interface=bridge-lan network=10.22.9.0
add address=198.51.100.9/30 interface=ether1-wan network=198.51.100.8
add address=10.10.0.9/24 interface=sfp1-core network=10.10.0.0
/ip dns
set allow-remote-requests=yes servers=10.10.50.5,10.10.50.6
/ip firewall address-list
add address=10.10.0.0/24 list=mgmt-nets
/ip firewall filter
add action=accept chain=input comment="allow established/related" connection-state=established,related
add action=drop chain=input comment="drop invalid" connection-state=invalid
add action=accept chain=input comment="mgmt from trusted" src-address-list=mgmt-nets
add action=accept chain=input comment="icmp" protocol=icmp
add action=drop chain=input comment="default deny input" in-interface-list=WAN log=yes log-prefix="INPUT-DROP"
add action=accept chain=forward comment="fasttrack" connection-state=established,related
add action=accept chain=forward comment="lan to wan" in-interface-list=LAN out-interface-list=WAN
add action=drop chain=forward comment="deny wan to lan" in-interface-list=WAN log=yes log-prefix="FWD-DROP"
/ip firewall nat
add action=masquerade chain=srcnat out-interface-list=WAN
/ip route
add distance=1 gateway=198.51.100.10
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=no
set ssh address=10.10.0.0/24 port=22
set www-ssl address=10.10.0.0/24 certificate=mgmt-cert disabled=no
set api disabled=no
set api-ssl disabled=yes
set winbox address=10.10.0.0/24
/ip ssh
set strong-crypto=yes host-key-size=2048
/ip settings
set rp-filter=strict send-redirects=no
/ip ipsec profile
set [ find default=yes ] dh-group=modp2048 enc-algorithm=aes-256 hash-algorithm=sha256
/ip ipsec proposal
set [ find default=yes ] auth-algorithms=sha256 enc-algorithms=aes-256-cbc,aes-256-gcm
/snmp
set contact=netops@example.in enabled=yes location="Branch Office APAC-South" trap-community=public trap-target=10.10.50.40 trap-version=2
/snmp community
set [ find default=yes ] addresses=10.10.50.0/24 name=public
/system clock
set time-zone-name=Asia/Kolkata
/system identity
set name=BRANCH-MT-09
/system logging action
set 3 remote=10.10.50.20 remote-port=514 src-address=10.10.0.9
set 0 memory-lines=1000
/system logging
add action=remote topics=info,!debug
add action=remote topics=critical
add action=remote topics=account
/system note
set note="UNAUTHORISED ACCESS PROHIBITED. BRANCH-MT-09 is monitored and all sessions are logged." show-at-login=yes
/system ntp client
set enabled=yes servers=10.10.50.10
/system scheduler
add interval=1d name=backup on-event="/export file=backup" start-time=02:00:00
/tool bandwidth-server
set enabled=yes
/tool mac-server
set allowed-interface-list=all
/tool mac-server mac-winbox
set allowed-interface-list=MGMT
/tool romon
set enabled=no
/user
add group=full name=netops
add group=read name=noc-view
/user settings
set minimum-password-length=8 minimum-categories=2
/user aaa
set use-radius=no
`;
