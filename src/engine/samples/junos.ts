export const SAMPLE_JUNOS = `## Last commit: 2026-09-16 22:41:07 IST by netops
## Chassis   CV4620AF0018   SRX345
version 22.4R2.8;
system {
    host-name DC-SRX-01;
    domain-name corp.example.in;
    time-zone Asia/Kolkata;
    root-authentication {
        encrypted-password "$6$rK3mQ9pL$Zx8vB2nW7yE4tR1uI5oP0aS3dF6gH9jK2lM4qC7bN1xV5cZ8"; ## SECRET-DATA
    }
    authentication-order [ tacplus password ];
    tacplus-server {
        10.10.50.30 {
            secret "$9$AbC1pOEcSrvWxdVw2gJZ"; ## SECRET-DATA
            source-address 10.0.0.254;
        }
    }
    accounting {
        events [ login change-log interactive-commands ];
        destination {
            tacplus {
                server {
                    10.10.50.30 secret "$9$AbC1pOEcSrvWxdVw2gJZ"; ## SECRET-DATA
                }
            }
        }
    }
    login {
        message "UNAUTHORISED ACCESS PROHIBITED. DC-SRX-01 is monitored and all activity is logged.";
        retry-options {
            tries-before-disconnect 3;
            backoff-threshold 2;
            backoff-factor 5;
            lockout-period 15;
        }
        password {
            minimum-length 14;
            format sha512;
            change-type character-sets;
            minimum-changes 3;
        }
        class NETOPS-ADMIN {
            idle-timeout 10;
            permissions all;
        }
        user netops {
            uid 2001;
            class NETOPS-ADMIN;
            authentication {
                encrypted-password "$6$Wq2eR5tY$Lk9jH3gF7dS1aP4oI8uY2tR6eW0qM5nB7vC3xZ9lK1mJ4hG6f"; ## SECRET-DATA
            }
        }
    }
    services {
        ssh {
            root-login deny;
            protocol-version v2;
            ciphers [ aes256-gcm@openssh.com aes256-ctr aes128-ctr ];
            macs [ hmac-sha2-512 hmac-sha2-256 ];
            key-exchange [ ecdh-sha2-nistp384 curve25519-sha256 ];
            connection-limit 5;
            rate-limit 5;
            client-alive-interval 60;
        }
        netconf {
            ssh;
        }
        web-management {
            https {
                system-generated-certificate;
                interface fxp0.0;
            }
        }
    }
    syslog {
        host 10.10.50.20 {
            any info;
            authorization info;
            interactive-commands info;
            transport tls;
            port 6514;
        }
        file messages {
            any notice;
            authorization info;
        }
        file interactive-commands {
            interactive-commands any;
        }
        console {
            any critical;
        }
        source-address 10.0.0.254;
        time-format year millisecond;
    }
    ntp {
        authentication-key 1 type sha256 value "$9$Nd4YoJDkPfT3bs4aJ"; ## SECRET-DATA
        server 10.10.50.10 key 1 prefer;
        server 10.10.50.11 key 1;
        trusted-key 1;
        source-address 10.0.0.254;
    }
}
interfaces {
    ge-0/0/0 {
        description "Untrust - ISP-B";
        unit 0 {
            family inet {
                filter {
                    input UNTRUST-IN;
                }
                rpf-check;
                address 198.51.100.2/30;
            }
        }
    }
    ge-0/0/1 {
        description "Trust - datacenter core";
        unit 0 {
            family inet {
                address 10.0.0.254/24;
            }
        }
    }
    fxp0 {
        unit 0 {
            family inet {
                address 10.10.0.14/24;
            }
        }
    }
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input PROTECT-RE;
                }
                address 10.0.255.1/32;
            }
        }
    }
}
snmp {
    location "Datacenter West Tier-3";
    contact "netops@example.in";
    community n3tm0n-dc {
        authorization read-only;
        clients {
            10.10.50.0/24;
            0.0.0.0/0 restrict;
        }
    }
    v3 {
        usm {
            local-engine {
                user secops {
                    authentication-sha {
                        authentication-key "$9$dfsdf34SDF"; ## SECRET-DATA
                    }
                    privacy-aes128 {
                        privacy-key "$9$fdsSDF23sdf"; ## SECRET-DATA
                    }
                }
            }
        }
    }
    trap-group SIEM {
        version v2;
        targets {
            10.10.50.40;
        }
    }
}
routing-options {
    static {
        route 0.0.0.0/0 next-hop 198.51.100.1;
    }
    autonomous-system 64513;
}
protocols {
    bgp {
        group ISP-B {
            type external;
            authentication-key "$9$xyzABCxyz123"; ## SECRET-DATA
            peer-as 64514;
            neighbor 198.51.100.1;
        }
    }
    lldp {
        interface ge-0/0/1.0;
    }
}
security {
    ike {
        proposal LEGACY-IKE {
            authentication-method pre-shared-keys;
            dh-group group2;
            authentication-algorithm sha1;
            encryption-algorithm aes-128-cbc;
        }
        policy LEGACY-POL {
            mode main;
            proposals LEGACY-IKE;
        }
    }
    screen {
        ids-option UNTRUST-SCREEN {
            icmp {
                ping-death;
            }
            ip {
                source-route-option;
                tear-drop;
            }
            tcp {
                syn-flood {
                    alarm-threshold 1024;
                    attack-threshold 200;
                }
                land;
            }
        }
    }
    policies {
        from-zone TRUST to-zone UNTRUST {
            policy ALLOW-OUT {
                match {
                    source-address any;
                    destination-address any;
                    application [ junos-http junos-https junos-dns-udp ];
                }
                then {
                    permit;
                    log {
                        session-close;
                    }
                }
            }
        }
        from-zone UNTRUST to-zone TRUST {
            policy DENY-IN {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    deny;
                    log {
                        session-init;
                    }
                }
            }
        }
        default-policy {
            deny-all;
        }
    }
    zones {
        security-zone TRUST {
            host-inbound-traffic {
                system-services {
                    ssh;
                    ping;
                    https;
                }
            }
            interfaces {
                ge-0/0/1.0;
            }
        }
        security-zone UNTRUST {
            screen UNTRUST-SCREEN;
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
}
firewall {
    family inet {
        filter PROTECT-RE {
            term MGMT-SSH {
                from {
                    source-address {
                        10.10.0.0/24;
                    }
                    protocol tcp;
                    destination-port [ ssh https ];
                }
                then accept;
            }
            term ROUTING {
                from {
                    protocol [ ospf bgp ];
                }
                then accept;
            }
            term DENY-REST {
                then {
                    log;
                    discard;
                }
            }
        }
        filter UNTRUST-IN {
            term BOGONS {
                from {
                    source-address {
                        10.0.0.0/8;
                        172.16.0.0/12;
                        192.168.0.0/16;
                    }
                }
                then {
                    log;
                    discard;
                }
            }
            term ALLOW {
                then accept;
            }
        }
    }
}
`;
