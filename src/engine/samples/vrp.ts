export const SAMPLE_VRP = `!Software Version V200R022C00SPC500
!Last configuration was updated at 2026-09-16 23:02:11+05:30 by netops
!Last configuration was saved at 2026-09-16 23:02:30+05:30 by netops
!Huawei S6730-H48X6C Routing Switch uptime is 12 weeks, 3 days
!ESN: 2102353VTX10N4000123
#
sysname CORE-HW-01
#
info-center enable
info-center timestamp log date precision-time tenth-second
info-center loghost source-ip 10.30.255.1
info-center loghost 10.10.50.20
info-center source default channel 2 log level informational
info-center logbuffer size 1024
#
clock timezone IST add 05:30
#
header login information "UNAUTHORISED ACCESS PROHIBITED. CORE-HW-01 is monitored; all commands are logged."
#
vlan batch 10 20 99
#
telnet server enable
stelnet server enable
ssh server compatible-ssh1x enable
ssh server cipher aes256_ctr aes128_ctr
ssh server hmac sha2_256 sha2_512
ssh server key-exchange dh_group_exchange_sha256
ssh server timeout 60
ssh server authentication-retries 3
ssh user netops
ssh user netops authentication-type password
ssh user netops service-type stelnet
#
http server enable
http secure-server enable
#
lldp enable
#
dhcp enable
#
ssl policy MGMT-TLS
 ssl minimum version tls1.1
#
hwtacacs-server template ISE
 hwtacacs-server authentication 10.10.50.30
 hwtacacs-server authentication 10.10.50.31 secondary
 hwtacacs-server authorization 10.10.50.30
 hwtacacs-server accounting 10.10.50.30
 hwtacacs-server shared-key cipher %^%#Kq2wE4rT6yU8iO0pA2sD4fG6hJ8kL0zX3cV5bN7mQ9wE1rT3yU5iO7pA%^%#
 hwtacacs-server user-name original
#
aaa
 authentication-scheme default
 authentication-scheme tacacs
  authentication-mode hwtacacs local
 authorization-scheme default
 authorization-scheme tacacs
  authorization-mode hwtacacs local
 accounting-scheme default
 accounting-scheme tacacs
  accounting-mode hwtacacs
 domain default
  authentication-scheme tacacs
  authorization-scheme tacacs
  accounting-scheme tacacs
  hwtacacs-server ISE
 domain default_admin
  authentication-scheme tacacs
  hwtacacs-server ISE
 local-user netops password irreversible-cipher $1c$Z3xN8vB1rW5oP0cS6aZ2jD4fH9nQ7kM1lG3tV5yE8wR2uI6bA0qK9$
 local-user netops privilege level 15
 local-user netops service-type ssh terminal
 local-user noc-view password cipher %^%#Ab1cD3eF5gH7iJ9kL1mN3oP5qR7sT9uV1wX3yZ5%^%#
 local-user noc-view privilege level 1
 local-user noc-view service-type ssh
#
ntp-service authentication enable
ntp-service authentication-keyid 1 authentication-mode hmac-sha256 cipher %^%#Mn2oP4qR6sT8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN8%^%#
ntp-service reliable authentication-keyid 1
ntp-service unicast-server 10.10.50.10 authentication-keyid 1
ntp-service unicast-server 10.10.50.11 authentication-keyid 1
ntp-service source-interface LoopBack0
#
acl number 2000
 rule 5 permit source 10.10.0.0 0.0.0.255
 rule 100 deny
#
acl number 2001
 rule 5 permit source 10.10.50.0 0.0.0.255
 rule 100 deny
#
acl number 3000
 rule 5 deny ip source 10.0.0.0 0.255.255.255 logging
 rule 10 deny ip source 192.168.0.0 0.0.255.255 logging
 rule 100 permit ip
#
interface Vlanif10
 description SERVERS
 ip address 10.30.10.1 255.255.255.0
#
interface Vlanif20
 description USERS
 ip address 10.30.20.1 255.255.255.0
 dhcp select relay
 dhcp relay server-ip 10.10.50.6
#
interface Vlanif99
 description MGMT
 ip address 10.10.0.31 255.255.255.0
#
interface MEth0/0/1
 ip address 10.30.99.31 255.255.255.0
#
interface XGigabitEthernet0/0/1
 description Uplink DC-SRX-01
 undo portswitch
 ip address 10.30.0.2 255.255.255.252
 traffic-filter inbound acl 3000
 undo icmp redirect send
 ospf authentication-mode hmac-sha256 1 cipher %^%#Qw1eR3tY5uI7oP9aS1dF3gH5jK7lZ9xC1vB3nM5%^%#
 urpf strict
#
interface XGigabitEthernet0/0/2
 description Unused
 shutdown
#
interface LoopBack0
 ip address 10.30.255.1 255.255.255.255
#
bgp 64513
 router-id 10.30.255.1
 peer 10.30.0.1 as-number 64513
 peer 10.30.0.1 password cipher %^%#Zx9cV7bN5mQ3wE1rT9yU7iO5pA3sD1fG9hJ7kL5z%^%#
 #
 ipv4-family unicast
  undo synchronization
  peer 10.30.0.1 enable
#
ospf 10 router-id 10.30.255.1
 area 0.0.0.0
  authentication-mode hmac-sha256 1 cipher %^%#Qw1eR3tY5uI7oP9aS1dF3gH5jK7lZ9xC1vB3nM5%^%#
  network 10.30.0.0 0.0.255.255
#
ike proposal 10
 encryption-algorithm des
 dh group2
 authentication-algorithm md5
#
snmp-agent
snmp-agent local-engineid 800007DB03D4B1102E3C21
snmp-agent community read cipher %^%#Kl3mN5oP7qR9sT1uV3wX5yZ7aB9cD1eF3gH5iJ7%^%# acl 2001
snmp-agent sys-info contact netops@example.in
snmp-agent sys-info location "Bengaluru DC-2, Row 3"
snmp-agent sys-info version v2c v3
snmp-agent group v3 SEC-V3 privacy
snmp-agent target-host trap address udp-domain 10.10.50.40 params securityname cipher %^%#Ab1cD3eF5gH7%^%# v3 privacy
snmp-agent usm-user v3 secops group SEC-V3
snmp-agent usm-user v3 secops authentication-mode sha cipher %^%#Pq2rS4tU6vW8xY0zA2bC4dE6fG8hI0jK2lM4nO6%^%#
snmp-agent usm-user v3 secops privacy-mode aes128 cipher %^%#Rs3tU5vW7xY9zA1bC3dE5fG7hI9jK1lM3nO5pQ7%^%#
snmp-agent trap enable
#
user-interface con 0
 authentication-mode aaa
 idle-timeout 10 0
#
user-interface vty 0 4
 acl 2000 inbound
 authentication-mode aaa
 user privilege level 15
 protocol inbound all
 idle-timeout 5 0
#
return
`;
