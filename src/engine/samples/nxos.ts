export const SAMPLE_NXOS = `!Command: show running-config
!Running configuration last done at: Wed Sep 16 20:41:08 2026
!Time: Wed Sep 16 20:44:12 2026

version 9.3(8) Bios:version 05.45
hostname LEAF-NX-04
vdc LEAF-NX-04 id 1
  limit-resource vlan minimum 16 maximum 4094
  limit-resource vrf minimum 2 maximum 4096
  limit-resource port-channel minimum 0 maximum 511
  limit-resource u4route-mem minimum 248 maximum 248
  limit-resource u6route-mem minimum 96 maximum 96

feature telnet
feature nxapi
feature bgp
feature interface-vlan
feature lacp
feature vpc
feature lldp

no password strength-check
username admin password 5 $5$KJ2m8Qxz$Ld9wH3eR7tY1uI5oP0aS3dF6gH9jK2lM4qC7bN1xV5cZ8  role network-admin
username netops password 5 $5$Bn4kP7rt$Qw1eR3tY5uI7oP9aS1dF3gH5jK7lZ9xC1vB3nM5xE2sD8  role network-admin
username noc-view password 5 $5$Cx9lT2vw$Mn2oP4qR6sT8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN8  role network-operator
ip domain-lookup
ip domain-name corp.example.in
copp profile strict
snmp-server user admin network-admin auth md5 0x8d2f1e7c priv 0x8d2f1e7c localizedkey
snmp-server community n9k-ro group network-operator
snmp-server community n9k-rw group network-admin
snmp-server host 10.10.50.40 traps version 2c n9k-ro
rmon event 1 log trap public description FATAL(1) owner PMON@FATAL
ntp server 10.10.50.10 use-vrf management
ntp server 10.10.50.11 use-vrf management
aaa group server tacacs+ ISE
  server 10.10.50.30
  use-vrf management
  source-interface mgmt0
tacacs-server host 10.10.50.30 key 7 "kjhg7643sdf"
aaa authentication login default group ISE local
aaa authentication login console local
aaa accounting default group ISE

ip access-list MGMT-ONLY
  10 permit tcp 10.10.0.0/24 any eq 22
  20 permit tcp 10.10.0.0/24 any eq 443
  30 deny ip any any log

vlan 1,10,20,99
vlan 10
  name SERVERS
vlan 20
  name USERS
vlan 99
  name MGMT

vrf context management
  ip route 0.0.0.0/0 10.10.0.1
vpc domain 4
  peer-switch
  role priority 100
  peer-keepalive destination 10.10.0.45 source 10.10.0.44 vrf management
  peer-gateway
  auto-recovery

interface Vlan10
  no shutdown
  no ip redirects
  ip address 10.44.10.1/24
  no ipv6 redirects
  hsrp 10
    ip 10.44.10.254

interface Vlan20
  no shutdown
  ip address 10.44.20.1/24
  hsrp 20
    ip 10.44.20.254

interface port-channel10
  description vPC peer-link
  switchport mode trunk
  spanning-tree port type network
  vpc peer-link

interface Ethernet1/1
  description server-a1
  switchport access vlan 10
  spanning-tree port type edge

interface Ethernet1/2
  description server-a2
  switchport access vlan 10
  spanning-tree port type edge

interface Ethernet1/49
  description peer-link member
  switchport mode trunk
  channel-group 10 mode active

interface Ethernet1/53
  description uplink SPINE-01
  no switchport
  ip address 10.44.0.2/31
  no ip redirects

interface mgmt0
  vrf member management
  ip address 10.10.0.44/24

interface loopback0
  ip address 10.44.255.4/32

line console
  exec-timeout 0
line vty
  exec-timeout 30
  session-limit 5
  access-class MGMT-ONLY in
boot nxos bootflash:/nxos.9.3.8.bin
router bgp 65044
  router-id 10.44.255.4
  log-neighbor-changes
  neighbor 10.44.0.3
    remote-as 65000
    description SPINE-01
    address-family ipv4 unicast
  neighbor 10.44.0.5
    remote-as 65000
    description SPINE-02
    password 3 a667d47acc18ea6b
    address-family ipv4 unicast
logging server 10.10.50.20 6 use-vrf management
logging source-interface loopback0
logging timestamp milliseconds
logging logfile messages 6 size 4194304
banner motd #
UNAUTHORISED ACCESS PROHIBITED. LEAF-NX-04 is monitored; all sessions are logged.
#
license udi pid N9K-C93180YC-FX sn FDO23110ABC
`;
