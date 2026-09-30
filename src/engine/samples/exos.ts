/**
 * Extreme Networks EXOS — deliberately NOT covered by a built-in parser.
 * It exercises the Training Studio: the classifier proposes SBM mappings,
 * the administrator confirms them, and the device becomes auditable
 * without a code change.
 */
export const SAMPLE_EXOS = `#
# ExtremeXOS 30.7.1.1 - saved configuration
# Platform: X465-48P   Serial: 2033N-40912   Generated: 2026-09-16 19:30:02 IST
#
# Module devmgr configuration.
#
configure snmp sysName "ACCESS-EX-12"
configure snmp sysLocation "Bengaluru DC-2, Rack 14"
configure snmp sysContact "netops@example.in"
configure sys-recovery-level switch reset
configure timezone name IST 330 autodst off
#
# Module vlan configuration.
#
configure vlan default delete ports all
create vlan "Mgmt"
configure vlan Mgmt tag 99
configure vlan Mgmt ipaddress 10.30.99.12 255.255.255.0
enable ipforwarding vlan Mgmt
create vlan "Users"
configure vlan Users tag 20
configure vlan Users add ports 1-40 untagged
#
# Module aaa configuration.
#
create account admin "netops" encrypted "$5$rounds=5000$xY2z$Lk9jH3gF7dS1aP4oI8uY2tR6eW0qM5nB7vC3xZ9lK1m"
configure account all password-policy min-length 8
configure account all password-policy lockout-on-login-failures on
configure account all password-policy lockout-time-period 10
configure account all password-policy char-validation all-char-groups
configure radius mgmt-access primary server 10.10.50.31 1812 client-ip 10.30.99.12 vr VR-Default
configure radius mgmt-access primary shared-secret encrypted "#$f9r4wLm2xZq8yT1uI5oP0aS3dF6gH9jK2lM4qC7bN1x="
enable radius mgmt-access
#
# Module cli configuration.
#
configure idletimeout 45
enable idletimeout
configure cli max-sessions 4
configure banner before-login
UNAUTHORISED ACCESS PROHIBITED. ACCESS-EX-12 is monitored and all sessions are logged.
#
# Module exsshd configuration.
#
enable ssh2
configure ssh2 ciphers aes256-ctr aes128-ctr
configure ssh2 macs hmac-sha2-256 hmac-sha2-512
disable telnet
#
# Module thttpd configuration.
#
enable web http
enable web https
#
# Module snmpMaster configuration.
#
configure snmp add community readonly public
configure snmp add community readwrite private
enable snmp access snmp-v1v2c
enable snmp access snmpv3
configure snmpv3 add user "secops" authentication sha "s3cops-Auth" privacy aes "s3cops-Priv"
configure snmpv3 add group "SEC-V3" user "secops" sec-model usm
configure snmpv3 add target-addr "siem" param "v3params" ipaddress 10.10.50.40 transport-port 162
#
# Module syslog configuration.
#
configure syslog add 10.10.50.20:514 vr VR-Default local7
enable syslog
configure log target syslog 10.10.50.20:514 vr VR-Default local7 severity Info
enable log target syslog 10.10.50.20:514 vr VR-Default local7
configure log target memory-buffer severity Debug-Data
configure log target console severity Critical
#
# Module sntp configuration.
#
configure sntp-client primary 10.10.50.10 vr VR-Default
configure sntp-client secondary 10.10.50.11 vr VR-Default
enable sntp-client
#
# Module lldp / edp configuration.
#
disable edp ports all
enable lldp ports all
#
# Module acl configuration.
#
create access-list mgmt-in "source-address 10.10.0.0/24;" "permit;"
configure access-list mgmt-in vlan Mgmt ingress
create access-list deny-all "" "deny;"
configure access-list deny-all vlan Users ingress
#
# Module stp configuration.
#
enable stpd s0
configure stpd s0 mode dot1w
enable stpd s0 auto-bind vlan Users
`;
