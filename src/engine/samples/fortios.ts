export const SAMPLE_FORTIOS = `#config-version=FGT60F-7.4.2-FW-build2571-240304:opmode=0:vdom=0:user=netops
#conf_file_ver=1234567890123456
#buildno=2571
#global_vars
#serial-number=FGT60FTK22011234
config system global
    set admin-sport 443
    set admintimeout 30
    set alias "BRANCH-FW-07"
    set hostname "BRANCH-FW-07"
    set strong-crypto disable
    set admin-lockout-threshold 3
    set admin-lockout-duration 60
    set admin-concurrent enable
    set pre-login-banner disable
    set admin-https-ssl-versions tlsv1-2 tlsv1-3
    set timezone "Asia/Kolkata"
    set gui-theme neutrino
    set switch-controller enable
end
config system accprofile
    edit "read-only"
        set secfabgrp read
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set fwgrp read
        set vpngrp read
        set utmgrp read
        set wifi read
    next
end
config system interface
    edit "wan1"
        set vdom "root"
        set ip 192.0.2.7 255.255.255.248
        set allowaccess ping https ssh telnet http
        set type physical
        set alias "ISP-C uplink"
        set role wan
        set snmp-index 1
    next
    edit "internal"
        set vdom "root"
        set ip 10.22.7.1 255.255.255.0
        set allowaccess ping https ssh fgfm
        set type hard-switch
        set role lan
        set snmp-index 2
    next
    edit "dmz"
        set vdom "root"
        set ip 10.22.8.1 255.255.255.0
        set allowaccess ping
        set type physical
        set role dmz
        set snmp-index 3
    next
end
config system admin
    edit "netops"
        set trusthost1 10.10.0.0 255.255.255.0
        set accprofile "super_admin"
        set vdom "root"
        set password ENC SH2nVv+5tW8kL1xZ3pQ7rY9eF2gH4jK6mN8oS0uA1cD3fG5hJ7lZ9xC2vB4nM6
    next
    edit "helpdesk"
        set accprofile "read-only"
        set vdom "root"
        set password ENC SH2QwE4rT6yU8iO0pA2sD4fG6hJ8kL0zX3cV5bN7mQ9wE1rT3yU5iO7pA9sD1
    next
end
config system password-policy
    set status disable
end
config system dns
    set primary 10.10.50.5
    set secondary 10.10.50.6
end
config system ntp
    set ntpsync enable
    set type custom
    set syncinterval 60
    config ntpserver
        edit 1
            set server "10.10.50.10"
            set authentication disable
        next
    end
end
config system snmp sysinfo
    set status enable
    set description "BRANCH-FW-07"
    set contact-info "netops@example.in"
    set location "Branch Office EMEA-North"
end
config system snmp community
    edit 1
        set name "public"
        config hosts
            edit 1
                set ip 10.10.50.40 255.255.255.255
            next
        end
        set query-v1-status disable
    next
end
config system fortiguard
    set fortiguard-anycast enable
end
config log memory setting
    set status enable
end
config log disk setting
    set status enable
end
config log syslogd setting
    set status enable
    set server "10.10.50.20"
    set mode udp
    set port 514
    set facility local7
    set format default
end
config log setting
    set fwpolicy-implicit-log disable
    set local-in-allow disable
    set local-in-deny-unicast disable
end
config log eventfilter
    set event enable
    set system enable
    set user enable
end
config firewall address
    edit "LAN-USERS"
        set subnet 10.22.7.0 255.255.255.0
    next
    edit "DMZ-WEB"
        set subnet 10.22.8.10 255.255.255.255
    next
end
config firewall policy
    edit 1
        set name "LAN-to-Internet"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "LAN-USERS"
        set dstaddr "all"
        set schedule "always"
        set service "HTTP" "HTTPS" "DNS"
        set utm-status enable
        set ssl-ssh-profile "certificate-inspection"
        set av-profile "default"
        set logtraffic all
        set nat enable
    next
    edit 2
        set name "Internet-to-DMZ-Web"
        set srcintf "wan1"
        set dstintf "dmz"
        set action accept
        set srcaddr "all"
        set dstaddr "DMZ-WEB"
        set schedule "always"
        set service "HTTPS"
        set logtraffic all
    next
    edit 3
        set name "Deny-DMZ-to-LAN"
        set srcintf "dmz"
        set dstintf "internal"
        set action deny
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
config router static
    edit 1
        set gateway 192.0.2.1
        set device "wan1"
    next
end
config vpn ipsec phase1-interface
    edit "HQ-VPN"
        set interface "wan1"
        set ike-version 1
        set peertype any
        set proposal aes256-sha256 3des-md5
        set dhgrp 14 5
        set remote-gw 203.0.113.2
        set psksecret ENC 3cD5fG7hJ9kL1zX3cV5bN7mQ9wE1rT3yU5iO7pA9sD1fG3hJ5kL7z
    next
end
config vpn ipsec phase2-interface
    edit "HQ-VPN-P2"
        set phase1name "HQ-VPN"
        set proposal aes256-sha256
        set dhgrp 14
    next
end
config vpn ssl settings
    set ssl-min-proto-ver tls1-2
    set servercert "Fortinet_Factory"
    set port 10443
end
`;
