export const SAMPLE_ARISTA_EOS = `! Command: show running-config
! device: CORE-SW-02 (DCS-7050SX3-48YC8, EOS-4.30.2F)
!
! boot system flash:/EOS-4.30.2F.swi
!
no aaa root
!
username netops privilege 15 role network-admin secret sha512 $6$Qh1mZ4dK9eL2fT7u$Y3xN8vB1rW5oP0cS6aZ2jD4fH9nQ7kM1lG3tV5yE8wR2uI6bA0
username svc-monitor privilege 1 role network-operator secret sha512 $6$Lp9oK2mN4bV7cX1z$H5jT2sW8qE1rY6uI0pA3dF7gK9lZ4xC2vB8nM1oS6tQ5wR3eY7u
!
transceiver qsfp default-mode 4x10G
!
service routing protocols model multi-agent
!
hostname CORE-SW-02
ip name-server vrf default 10.10.50.5
dns domain corp.example.in
!
spanning-tree mode mstp
!
vlan 10
   name SERVERS
vlan 20
   name USERS
vlan 99
   name MGMT
!
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
aaa accounting commands all default start-stop group tacacs+
!
tacacs-server host 10.10.50.30 key 7 0207014A0E1F1E4E0B
tacacs-server host 10.10.50.31 key 7 0207014A0E1F1E4E0B
!
management security
   password minimum length 8
!
management ssh
   idle-timeout 0
   authentication mode keyboard-interactive
   login timeout 120
!
management telnet
   shutdown
!
management api http-commands
   protocol https
   no shutdown
   vrf MGMT
      no shutdown
!
management console
   idle-timeout 30
!
banner login
UNAUTHORISED ACCESS PROHIBITED. CORE-SW-02 is monitored; all sessions are logged.
EOF
!
logging buffered 64000 informational
logging console critical
logging trap informational
logging host 10.10.50.20
logging source-interface Loopback0
!
ntp server 10.10.50.10 prefer
ntp server 10.10.50.11
!
snmp-server community netm0n-c0re ro MGMT-ACL
snmp-server host 10.10.50.40 version 2c netm0n-c0re
snmp-server location Main Campus Floor 2
!
ip access-list MGMT-ACL
   10 permit ip 10.10.0.0/24 any
   20 deny ip any any log
!
interface Ethernet1
   description Uplink EDGE-RTR-01 Gi0/0/1
   no switchport
   ip address 10.14.0.2/30
   ip ospf authentication message-digest
   ip ospf message-digest-key 1 md5 7 03075A1E0C1D3E
!
interface Ethernet2
   description Server leaf uplink
   switchport mode trunk
   switchport trunk allowed vlan 10,20
!
interface Ethernet3
   description Unused
   shutdown
!
interface Loopback0
   ip address 10.14.255.2/32
!
interface Management1
   vrf MGMT
   ip address 10.10.0.12/24
!
interface Vlan10
   ip address 10.14.10.1/24
!
interface Vlan20
   ip address 10.14.20.1/24
   ip helper-address 10.10.50.6
!
ip routing
ip routing vrf MGMT
!
router ospf 10
   router-id 10.14.255.2
   passive-interface default
   no passive-interface Ethernet1
   network 10.14.0.0/16 area 0.0.0.0
   max-lsa 12000
!
router bgp 64513
   router-id 10.14.255.2
   neighbor 10.14.0.1 remote-as 64513
   neighbor 10.14.0.1 password 7 03075A1E0C1D3E
   neighbor 10.14.0.1 send-community
!
daemon TerminAttr
   exec /usr/bin/TerminAttr -cvaddr=10.10.50.60:9910 -cvauth=token,/tmp/token -smashexcludes=ale,flexCounter,hardware,kni,pulse,strata -ingestexclude=/Sysdb/cell/1/agent,/Sysdb/cell/2/agent -taillogs
   no shutdown
!
end
`;
