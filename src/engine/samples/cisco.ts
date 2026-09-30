export const SAMPLE_CISCO_IOS = `Building configuration...

Current configuration : 6812 bytes
!
! Last configuration change at 09:14:22 IST Thu Sep 17 2026 by netops
! NVRAM config last updated at 09:14:40 IST Thu Sep 17 2026 by netops
!
! Cisco IOS XE Software, Version 17.09.04a
! cisco ISR4451-X/K9 (2RU) processor with 7597184K/6147K bytes of memory.
! Processor board ID FGL2331L0A7
!
version 17.9
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
service password-encryption
service call-home
platform qfp utilization monitor load 80
platform punt-keepalive disable-kernel-core
!
hostname EDGE-RTR-01
!
boot-start-marker
boot system bootflash:isr4400-universalk9.17.09.04a.SPA.bin
boot-end-marker
!
enable secret 9 $9$3kd8Fj2LkQ9zT.$hV4cN1qYw7uQ2yG0bR6sZ8mP5eJ3aX9tK1lD4fH7nC2
enable password 7 0822455D0A16
!
aaa new-model
!
aaa group server tacacs+ ISE-GROUP
 server name ISE-PRIMARY
 server name ISE-SECONDARY
!
aaa authentication login default group ISE-GROUP local
aaa authentication enable default group ISE-GROUP enable
aaa authorization exec default group ISE-GROUP local
aaa accounting exec default start-stop group ISE-GROUP
aaa accounting commands 15 default start-stop group ISE-GROUP
!
aaa session-id common
clock timezone IST 5 30
!
ip domain name corp.example.in
ip name-server 10.10.50.5
no ip domain lookup
!
login on-failure log
login on-success log
!
username netops privilege 15 secret 9 $9$Q1v8sK2mJ6dL2.$pR7uN3yT9wE5oB1xL4kM8vG2cS6aZ0jD5fH9nQ3
username backup-admin privilege 15 password 7 104D000A0618031F5F4B
!
archive
 log config
  logging enable
  hidekeys
!
crypto isakmp policy 10
 encryption 3des
 hash md5
 authentication pre-share
 group 2
crypto ipsec transform-set LEGACY-TS esp-3des esp-md5-hmac
 mode tunnel
!
ip ssh time-out 60
ip ssh authentication-retries 3
ip ssh version 2
ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr
ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-512
!
ip http server
ip http secure-server
ip http authentication aaa
!
no ip bootp server
no service pad
no ip source-route
service tcp-keepalives-in
service tcp-keepalives-out
!
interface Loopback0
 description Management loopback
 ip address 10.14.255.1 255.255.255.255
!
interface GigabitEthernet0/0/0
 description Uplink to ISP-A (AS64512)
 ip address 203.0.113.2 255.255.255.252
 ip access-group EDGE-IN in
 ip verify unicast source reachable-via rx
 no ip proxy-arp
 no ip redirects
 no ip unreachables
 negotiation auto
!
interface GigabitEthernet0/0/1
 description Core downlink to CORE-SW-02
 ip address 10.14.0.1 255.255.255.252
 ip ospf message-digest-key 1 md5 7 0E1A0A16050B1C
 negotiation auto
!
interface GigabitEthernet0/0/2
 description Unused
 shutdown
!
router ospf 10
 router-id 10.14.255.1
 passive-interface default
 no passive-interface GigabitEthernet0/0/1
 network 10.14.0.0 0.0.255.255 area 0
!
router bgp 64513
 bgp log-neighbor-changes
 neighbor 203.0.113.1 remote-as 64512
 neighbor 203.0.113.1 password 7 121A0C041104
 neighbor 203.0.113.1 description ISP-A
!
ip forward-protocol nd
ip route 0.0.0.0 0.0.0.0 203.0.113.1
!
ip access-list extended EDGE-IN
 deny   ip 10.0.0.0 0.255.255.255 any log
 deny   ip 172.16.0.0 0.15.255.255 any log
 deny   ip 192.168.0.0 0.0.255.255 any log
 deny   ip 127.0.0.0 0.255.255.255 any log
 permit tcp any host 203.0.113.2 established
 permit ip any 10.14.0.0 0.0.255.255
 deny   ip any any log
!
ip access-list standard MGMT-ACL
 permit 10.10.0.0 0.0.0.255
 deny   any log
!
logging buffered 64000 informational
logging console critical
logging trap informational
logging source-interface Loopback0
logging host 10.10.50.20
!
snmp-server community public RO
snmp-server community n3tm0n-r0 RO MGMT-ACL
snmp-server location Equinix DC-01 Rack A14
snmp-server contact netops@example.in
snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart
snmp-server host 10.10.50.40 version 2c n3tm0n-r0
!
tacacs server ISE-PRIMARY
 address ipv4 10.10.50.30
 key 7 1511021F07257A767B7A7B
tacacs server ISE-SECONDARY
 address ipv4 10.10.50.31
 key 7 1511021F07257A767B7A7B
!
banner motd ^C
******************************************************************
*  UNAUTHORISED ACCESS PROHIBITED - EDGE-RTR-01                  *
*  This device is the property of Example Corp. All activity is  *
*  monitored and logged. Disconnect immediately if unauthorised. *
******************************************************************
^C
!
line con 0
 exec-timeout 30 0
 logging synchronous
 stopbits 1
line aux 0
 exec-timeout 0 0
 transport input all
line vty 0 4
 exec-timeout 30 0
 access-class MGMT-ACL in
 transport input telnet ssh
line vty 5 15
 exec-timeout 30 0
 access-class MGMT-ACL in
 transport input ssh
!
ntp source Loopback0
ntp server 10.10.50.10 prefer
ntp server 10.10.50.11
!
end
`;
