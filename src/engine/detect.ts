import type { DetectionResult, VendorId } from "./types";
import { VENDOR_META } from "./sbm";

interface Signature {
  re: RegExp;
  weight: number;
  reason: string;
}

/**
 * Vendor signatures are data: add a new vendor by appending patterns.
 * Score = sum of matched weights; confidence = top / (top + runner-up).
 */
export const VENDOR_SIGNATURES: Record<Exclude<VendorId, "generic">, Signature[]> = {
  "cisco-ios": [
    { re: /^Cisco IOS/m, weight: 6, reason: "'Cisco IOS' banner in show version" },
    { re: /^Building configuration|^Current configuration\s*:/m, weight: 4, reason: "IOS 'show running-config' header" },
    { re: /^boot-start-marker/m, weight: 4, reason: "boot-start-marker" },
    { re: /^line (vty|con|aux) \d/m, weight: 3, reason: "IOS line vty/con/aux blocks" },
    { re: /^ip ssh version \d/m, weight: 2, reason: "ip ssh version" },
    { re: /^service password-encryption/m, weight: 2, reason: "service password-encryption" },
    { re: /^enable secret/m, weight: 2, reason: "enable secret" },
    { re: /^aaa new-model/m, weight: 2, reason: "aaa new-model" },
    { re: /^interface (GigabitEthernet|FastEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|Serial|Port-channel)\S*/m, weight: 2, reason: "Cisco interface naming" },
    { re: /^interface (Loopback|Vlan)\d/m, weight: 1, reason: "Loopback/Vlan interfaces (shared with EOS and NX-OS)" },
    { re: /^version \d+\.\d+\s*$/m, weight: 2, reason: "version x.y header" },
    { re: /^!\s*$/m, weight: 1, reason: "'!' separators" },
    { re: /^ip cef|^no ip cef/m, weight: 2, reason: "ip cef" },
    { re: /^snmp-server community/m, weight: 1, reason: "snmp-server community" },
    { re: /^router (ospf|bgp|eigrp)\s/m, weight: 1, reason: "router process" },
    { re: /^hostname \S+/m, weight: 1, reason: "hostname" },
  ],
  "cisco-nxos": [
    { re: /^!Command: show running-config/m, weight: 8, reason: "NX-OS '!Command:' header" },
    { re: /^feature \S+/m, weight: 6, reason: "NX-OS 'feature' statements" },
    { re: /^vdc \S+ id \d/m, weight: 6, reason: "vdc definition" },
    { re: /^boot nxos /m, weight: 8, reason: "boot nxos image" },
    { re: /^version \d+\.\d+\(\d+\)/m, weight: 4, reason: "NX-OS version string" },
    { re: /^interface mgmt0/m, weight: 4, reason: "interface mgmt0" },
    { re: /^line (vty|console)\s*$/m, weight: 3, reason: "number-less line vty/console" },
    { re: /^vrf context management/m, weight: 5, reason: "vrf context management" },
    { re: /^copp profile/m, weight: 4, reason: "copp profile" },
    { re: /^username \S+ password 5 \$5\$/m, weight: 3, reason: "NX-OS $5$ user hashes" },
    { re: /^interface Ethernet\d+\/\d+/m, weight: 1, reason: "Ethernet slot/port naming" },
    { re: /^hostname \S+/m, weight: 1, reason: "hostname" },
  ],
  "arista-eos": [
    { re: /^! device: .*EOS-\d/m, weight: 8, reason: "EOS device banner comment" },
    { re: /^!RANCID-CONTENT-TYPE: arista/m, weight: 6, reason: "RANCID arista content-type header" },
    { re: /^management (ssh|api http-commands|telnet|console|security)\s*$/m, weight: 6, reason: "EOS 'management' blocks" },
    { re: /^no aaa root\s*$/m, weight: 5, reason: "'no aaa root' (rendered in every EOS running-config)" },
    { re: /^daemon TerminAttr/m, weight: 5, reason: "TerminAttr daemon" },
    { re: /^transceiver qsfp default-mode/m, weight: 5, reason: "transceiver qsfp default-mode" },
    { re: /^username \S+ (?:privilege \d+ )?role network-admin secret/m, weight: 4, reason: "role network-admin user with secret" },
    { re: /^(username \S+ .*secret sha512|enable password sha512) /m, weight: 4, reason: "sha512 credential keyword" },
    { re: /^! Command: show running-config/m, weight: 4, reason: "EOS show running-config comment" },
    { re: /^service routing protocols model/m, weight: 4, reason: "service routing protocols model" },
    { re: /^(dns domain|vrf instance|vlan internal order|ip routing vrf|logging vrf \S+ host|ntp server vrf|management api (gnmi|netconf|models))\b/m, weight: 3, reason: "EOS-only global commands" },
    { re: /^interface Port-Channel\d/m, weight: 2, reason: "EOS 'Port-Channel' capitalisation" },
    { re: /^spanning-tree mode mstp/m, weight: 1, reason: "spanning-tree mode mstp" },
    { re: /^interface (Ethernet|Management)\d+(\/\d+)*\s*$/m, weight: 2, reason: "EOS interface naming" },
    { re: /^ip routing\s*$/m, weight: 1, reason: "ip routing" },
    { re: /^hostname \S+/m, weight: 1, reason: "hostname" },
  ],
  "juniper-junos": [
    { re: /^(set|deactivate|delete) (system|interfaces|protocols|security|snmp|firewall|routing-options|routing-instances|policy-options|groups|apply-groups|chassis|vlans|class-of-service|services|access|forwarding-options|event-options|virtual-chassis|switch-options|bridge-domains|logical-systems)\s/m, weight: 6, reason: "Junos set-format statements" },
    { re: /^system \{/m, weight: 6, reason: "system { } stanza" },
    { re: /^## Last (commit|changed):/m, weight: 5, reason: "'## Last commit/changed' header" },
    { re: /^version \d+\.\d+R\d/m, weight: 5, reason: "Junos version string" },
    { re: /host-name \S+;/, weight: 4, reason: "host-name statement" },
    { re: /^interfaces \{/m, weight: 3, reason: "interfaces { } stanza" },
    { re: /root-authentication/, weight: 3, reason: "root-authentication" },
    { re: /encrypted-password/, weight: 2, reason: "encrypted-password" },
    { re: /^security \{/m, weight: 2, reason: "security { } stanza (SRX)" },
    { re: /junos/i, weight: 2, reason: "'junos' keyword" },
  ],
  "fortinet-fortios": [
    { re: /^#config-version=/m, weight: 8, reason: "#config-version header" },
    { re: /^config system global/m, weight: 6, reason: "config system global" },
    { re: /^\s*set allowaccess /m, weight: 4, reason: "set allowaccess" },
    { re: /^\s*set admin-sport /m, weight: 4, reason: "set admin-sport" },
    { re: /^config firewall policy/m, weight: 4, reason: "config firewall policy" },
    { re: /^config system interface/m, weight: 3, reason: "config system interface" },
    { re: /^\s*next\s*$/m, weight: 2, reason: "edit/next blocks" },
    { re: /FortiGate|FortiOS|FGT\d/, weight: 3, reason: "FortiGate keyword" },
    { re: /^end\s*$/m, weight: 1, reason: "end statements" },
  ],
  "paloalto-panos": [
    { re: /^set deviceconfig (system|setting)\s/m, weight: 8, reason: "set deviceconfig" },
    { re: /<config version="[\d.]+" urldb="paloaltonetworks"/, weight: 10, reason: "PAN-OS XML config header" },
    { re: /^set mgt-config users/m, weight: 5, reason: "set mgt-config users" },
    { re: /^set rulebase security rules/m, weight: 5, reason: "set rulebase security rules" },
    { re: /^set network (interface|profiles|virtual-router)/m, weight: 4, reason: "set network" },
    { re: /^set shared (log-settings|authentication-profile|server-profile)/m, weight: 4, reason: "set shared" },
    { re: /PAN-OS|PA-\d{3,4}\b|sw-version:/, weight: 4, reason: "PAN-OS keyword" },
    { re: /^set zone \S+ network layer3/m, weight: 3, reason: "set zone" },
    { re: /<(deviceconfig|mgt-config|rulebase|interface-management-profile|zone-protection-profile|default-security-rules)[\s/>]/, weight: 4, reason: "PAN-OS XML element (API fragment without the config header)" },
    { re: /<(disable-telnet|disable-http|permitted-ip|login-banner|snmp-setting|ike-crypto-profiles|ipsec-crypto-profiles|interzone-default)[\s/>]/, weight: 4, reason: "PAN-OS XML leaf element" },
    { re: /<response[^>]*>\s*<result>/, weight: 1, reason: "PAN-OS XML API response wrapper" },
    { re: /^set (template|template-stack|device-group|log-collector-group) /m, weight: 5, reason: "Panorama template/device-group export" },
  ],
  "mikrotik-routeros": [
    { re: /^# .* by RouterOS/m, weight: 8, reason: "'by RouterOS' export header" },
    { re: /^# model = /m, weight: 5, reason: "'# model =' header" },
    { re: /^# serial number = /m, weight: 5, reason: "'# serial number =' header" },
    { re: /^#\s*software id = /m, weight: 5, reason: "'# software id =' export header" },
    { re: /^\/ip (service|firewall|address|dhcp)/m, weight: 5, reason: "/ip menu paths" },
    { re: /^\/system (identity|ntp|logging|clock)/m, weight: 5, reason: "/system menu paths" },
    // RouterOS 7 accepts (and operators paste) the slash-separated form: /ip/service/set …
    { re: /^\/(ip|system|interface|user|routing|tool|snmp|certificate)\/[\w-]+/m, weight: 5, reason: "RouterOS 7 slash-separated menu path" },
    // A bare block header is "/interface" or "/user" with nothing after it.
    { re: /^\/interface\b/m, weight: 3, reason: "/interface menu" },
    { re: /^\/user\b/m, weight: 3, reason: "/user menu" },
    { re: /^\/tool\b/m, weight: 3, reason: "/tool menu" },
    { re: /^\/snmp/m, weight: 3, reason: "/snmp menu" },
    { re: /^set \[ ?find /m, weight: 3, reason: "set [ find ] syntax" },
    { re: /RouterOS|MikroTik/i, weight: 3, reason: "RouterOS keyword" },
  ],
  "huawei-vrp": [
    { re: /^\s*sysname \S+/m, weight: 6, reason: "sysname" },
    { re: /^\s*user-interface (vty|con|aux)/m, weight: 5, reason: "user-interface blocks" },
    { re: /^\s*(un)?stelnet (ipv6 )?server enable/m, weight: 5, reason: "stelnet server enable" },
    { re: /^\s*(undo )?info-center /m, weight: 4, reason: "info-center" },
    { re: /^\s*(undo )?ntp-service /m, weight: 4, reason: "ntp-service" },
    { re: /^\s*(undo )?snmp-agent/m, weight: 4, reason: "snmp-agent" },
    { re: /^\s*local-user /m, weight: 3, reason: "local-user" },
    { re: /^return\s*$/m, weight: 3, reason: "'return' terminator" },
    { re: /^\s*undo /m, weight: 2, reason: "undo commands" },
    { re: /VRP|Huawei|Versatile Routing Platform/i, weight: 3, reason: "VRP keyword" },
    { re: /^\s*header (login|shell)/m, weight: 3, reason: "header login/shell" },
    // Huawei-only idioms that survive terminal pastes and indented archives.
    { re: /\bV\d{3}R\d{3}C\d{2}\b/, weight: 6, reason: "VRP release string (V2xxRyyyCzz)" },
    { re: /\birreversible-cipher\b/, weight: 5, reason: "irreversible-cipher password form" },
    { re: /%\^%#|%\$%\$/, weight: 4, reason: "VRP encrypted-string markers" },
    { re: /^\s*interface (Vlanif|Eth-Trunk|MEth|XGigabitEthernet|GigabitEthernet\d+\/\d+\/\d+|\d+GE\d+\/\d+\/\d+)/m, weight: 4, reason: "VRP interface naming" },
    { re: /^\s*acl (number|name|ipv6) /m, weight: 4, reason: "'acl number/name' blocks" },
    { re: /^\s*(display|save|system-view) /m, weight: 2, reason: "VRP exec commands in the paste" },
    { re: /^\s*(vlan batch|port link-type|port default vlan)/m, weight: 3, reason: "VRP switching commands" },
    { re: /^\s*(hwtacacs|radius)-server template /m, weight: 4, reason: "AAA server template block" },
    { re: /^\s*authentication-mode (aaa|password)/m, weight: 2, reason: "authentication-mode" },
  ],
};

export function detectVendor(raw: string): DetectionResult {
  const scores: Partial<Record<VendorId, number>> = {};
  const reasonsBy: Partial<Record<VendorId, string[]>> = {};
  for (const [vendor, sigs] of Object.entries(VENDOR_SIGNATURES) as [Exclude<VendorId, "generic">, Signature[]][]) {
    let s = 0;
    const rs: string[] = [];
    for (const sig of sigs) {
      if (sig.re.test(raw)) {
        s += sig.weight;
        rs.push(sig.reason);
      }
    }
    scores[vendor] = s;
    reasonsBy[vendor] = rs;
  }
  const ranked = (Object.entries(scores) as [VendorId, number][]).sort((a, b) => b[1] - a[1]);
  const [top, topScore] = ranked[0];
  const second = ranked[1]?.[1] ?? 0;
  const THRESHOLD = 5;
  if (topScore < THRESHOLD) {
    const hints: string[] = [];
    if (/^\s*[{[]/.test(raw)) hints.push("structured JSON input — flattened into key paths");
    else if (/^\s*</.test(raw)) hints.push("XML input — flattened into element paths");
    else hints.push(`no vendor signature reached the threshold (best: ${VENDOR_META[top].short} ${topScore}/${THRESHOLD})`);
    // Confidence here means "confidence that no known vendor applies", never vendor identification.
    return { vendor: "generic", confidence: 0, reasons: hints, scores };
  }
  const confidence = Math.min(0.99, Math.round((topScore / (topScore + second + 1)) * 100) / 100 + Math.min(0.15, topScore / 100));
  return { vendor: top, confidence, reasons: reasonsBy[top] ?? [], scores };
}
