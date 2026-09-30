export const SAMPLE_PANOS = `# show system info (captured 2026-09-16 21:05 IST)
hostname: PA-DMZ-01
serial: 015351000098765
model: PA-440
sw-version: 11.1.2
app-version: 8893-8825
# running configuration (set format)
set deviceconfig system hostname PA-DMZ-01
set deviceconfig system domain corp.example.in
set deviceconfig system ip-address 10.10.0.21
set deviceconfig system netmask 255.255.255.0
set deviceconfig system default-gateway 10.10.0.1
set deviceconfig system dns-setting servers primary 10.10.50.5
set deviceconfig system dns-setting servers secondary 10.10.50.6
set deviceconfig system timezone Asia/Kolkata
set deviceconfig system login-banner "UNAUTHORISED ACCESS PROHIBITED. PA-DMZ-01 is monitored; all activity is logged."
set deviceconfig system service disable-telnet no
set deviceconfig system service disable-http yes
set deviceconfig system service disable-icmp no
set deviceconfig system service disable-snmp no
set deviceconfig system permitted-ip 10.10.0.0/24
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.10.50.10
set deviceconfig system ntp-servers primary-ntp-server authentication-type none
set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address 10.10.50.11
set deviceconfig system ntp-servers secondary-ntp-server authentication-type none
set deviceconfig system snmp-setting access-setting version v2c snmp-community-string public
set deviceconfig system snmp-setting snmp-system location "R&D Lab, Bengaluru"
set deviceconfig system snmp-setting snmp-system contact netops@example.in
set deviceconfig system update-schedule threats recurring weekly day-of-week wednesday at 01:02
set deviceconfig system device-telemetry device-health-performance yes
set deviceconfig setting management admin-lockout failed-attempts 5
set deviceconfig setting management admin-lockout lockout-time 30
set deviceconfig setting management hostname-type-in-syslog FQDN
set deviceconfig setting management enable-log-high-dp-load yes
set deviceconfig setting session tcp-reject-non-syn yes
set mgt-config password-complexity enabled yes
set mgt-config password-complexity minimum-length 8
set mgt-config password-complexity minimum-uppercase-letters 1
set mgt-config password-complexity minimum-numeric-letters 1
set mgt-config users netops permissions role-based superuser yes
set mgt-config users netops phash $1$kzqbtmdo$YtJiRFqTnAGdxnrDcaEiC1
set mgt-config users netops authentication-profile TACACS-ISE
set mgt-config users auditor permissions role-based superreader yes
set mgt-config users auditor phash $1$pwaaqsuk$UhVi8bnPCPqRvqZJbmHmO/
set shared server-profile tacplus ISE protocol CHAP
set shared server-profile tacplus ISE timeout 3
set shared server-profile tacplus ISE server ISE-1 address 10.10.50.30
set shared server-profile tacplus ISE server ISE-1 secret -AQ==b3Rzd0lCVTJUMk5SUE1kd0dQZUNLdz09
set shared server-profile tacplus ISE server ISE-1 port 49
set shared authentication-profile TACACS-ISE method tacplus server-profile ISE
set shared authentication-profile TACACS-ISE allow-list all
set shared authentication-profile TACACS-ISE lockout failed-attempts 5
set shared authentication-profile TACACS-ISE lockout lockout-time 30
set shared log-settings syslog SIEM server S1 server 10.10.50.20
set shared log-settings syslog SIEM server S1 transport SSL
set shared log-settings syslog SIEM server S1 port 6514
set shared log-settings syslog SIEM server S1 format BSD
set shared log-settings syslog SIEM server S1 facility LOG_USER
set shared log-settings system match-list ALL-SYSTEM filter "All Logs" send-syslog SIEM
set shared log-settings config match-list ALL-CONFIG filter "All Logs" send-syslog SIEM
set shared log-settings snmptrap NMS version v2c server NMS-1 manager 10.10.50.40
set shared log-settings snmptrap NMS version v2c server NMS-1 community public
set shared ssl-tls-service-profile MGMT-TLS protocol-settings min-version tls1-1
set shared ssl-tls-service-profile MGMT-TLS protocol-settings max-version max
set shared ssl-tls-service-profile MGMT-TLS certificate mgmt-cert
set deviceconfig system ssl-tls-service-profile MGMT-TLS
set network profiles interface-management-profile MGMT-ACCESS https yes
set network profiles interface-management-profile MGMT-ACCESS ssh yes
set network profiles interface-management-profile MGMT-ACCESS ping yes
set network profiles interface-management-profile MGMT-ACCESS telnet no
set network profiles interface-management-profile MGMT-ACCESS http no
set network profiles interface-management-profile MGMT-ACCESS permitted-ip 10.10.0.0/24
set network profiles zone-protection-profile ZPP-DEFAULT flood tcp-syn enable yes
set network profiles zone-protection-profile ZPP-DEFAULT flood tcp-syn red alarm-rate 10000
set network profiles zone-protection-profile ZPP-DEFAULT scan 8001 action block-ip track-by source duration 300
set network ike crypto-profiles ike-crypto-profiles LEGACY-IKE encryption [ 3des aes-128-cbc ]
set network ike crypto-profiles ike-crypto-profiles LEGACY-IKE hash [ sha1 ]
set network ike crypto-profiles ike-crypto-profiles LEGACY-IKE dh-group [ group2 ]
set network ike crypto-profiles ike-crypto-profiles LEGACY-IKE lifetime hours 8
set network ike crypto-profiles ipsec-crypto-profiles STRONG-IPSEC esp encryption [ aes-256-gcm ]
set network ike crypto-profiles ipsec-crypto-profiles STRONG-IPSEC esp authentication [ none ]
set network ike crypto-profiles ipsec-crypto-profiles STRONG-IPSEC dh-group group14
set network interface ethernet ethernet1/1 layer3 ip 172.18.5.3/24
set network interface ethernet ethernet1/1 layer3 interface-management-profile MGMT-ACCESS
set network interface ethernet ethernet1/1 comment "Lab DMZ uplink"
set network interface ethernet ethernet1/2 layer3 ip 172.18.6.1/24
set network interface ethernet ethernet1/2 comment "Engineering lab"
set network interface loopback units loopback.1 ip 10.0.255.9/32
set network virtual-router default interface [ ethernet1/1 ethernet1/2 loopback.1 ]
set network virtual-router default routing-table ip static-route DEFAULT nexthop ip-address 172.18.5.1
set network virtual-router default routing-table ip static-route DEFAULT destination 0.0.0.0/0
set network virtual-router default protocol ospf enable yes
set network virtual-router default protocol ospf router-id 10.0.255.9
set network virtual-router default protocol ospf area 0.0.0.0 type normal
set network virtual-router default protocol ospf area 0.0.0.0 interface ethernet1/2 enable yes
set network virtual-router default protocol ospf area 0.0.0.0 interface ethernet1/2 passive no
set zone DMZ network layer3 ethernet1/1
set zone DMZ network zone-protection-profile ZPP-DEFAULT
set zone LAB network layer3 ethernet1/2
set address LAB-NET ip-netmask 172.18.6.0/24
set address DMZ-WEB ip-netmask 172.18.5.10/32
set service SVC-HTTPS-8443 protocol tcp port 8443
set rulebase security rules "Lab to DMZ web" from LAB to DMZ source LAB-NET destination DMZ-WEB application [ ssl web-browsing ] service application-default action allow log-end yes
set rulebase security rules "Lab to DMZ web" profile-setting group default
set rulebase security rules "Block legacy protocols" from any to any source any destination any application [ telnet ftp ] service any action deny log-end yes
set rulebase security rules "Lab internet" from LAB to DMZ source LAB-NET destination any application any service application-default action allow log-end yes
set rulebase default-security-rules rules interzone-default action deny
set rulebase default-security-rules rules interzone-default log-end no
set rulebase default-security-rules rules intrazone-default action allow
`;
