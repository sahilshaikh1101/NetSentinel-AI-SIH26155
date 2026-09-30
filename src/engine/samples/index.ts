import type { VendorId } from "../types";
import { SAMPLE_ARISTA_EOS } from "./arista";
import { SAMPLE_AWS_SG } from "./aws";
import { SAMPLE_CISCO_IOS } from "./cisco";
import { SAMPLE_EXOS } from "./exos";
import { SAMPLE_FORTIOS } from "./fortios";
import { SAMPLE_JUNOS } from "./junos";
import { SAMPLE_NXOS } from "./nxos";
import { SAMPLE_PANOS } from "./panos";
import { SAMPLE_ROUTEROS } from "./routeros";
import { SAMPLE_VRP } from "./vrp";

export interface SampleConfig {
  id: string;
  fileName: string;
  label: string;
  vendorLabel: string;
  expectedVendor: VendorId;
  raw: string;
  /** part of the default seeded fleet */
  seed: boolean;
  note: string;
  site?: string;
}

export const SAMPLES: SampleConfig[] = [
  { id: "cisco", fileName: "edge-rtr-01.cfg", label: "EDGE-RTR-01", vendorLabel: "Cisco IOS-XE 17.9 (ISR4451)", expectedVendor: "cisco-ios", raw: SAMPLE_CISCO_IOS, seed: true, note: "Internet edge router with Telnet on vty, default SNMP community and legacy IKE." },
  { id: "nxos", fileName: "leaf-nx-04.cfg", label: "LEAF-NX-04", vendorLabel: "Cisco NX-OS 9.3 (Nexus 93180YC-FX)", expectedVendor: "cisco-nxos", raw: SAMPLE_NXOS, seed: true, note: "Datacenter leaf with Telnet feature, SNMPv2c read-write and one unauthenticated BGP peer." },
  { id: "arista", fileName: "core-sw-02.cfg", label: "CORE-SW-02", vendorLabel: "Arista EOS 4.30 (7050SX3)", expectedVendor: "arista-eos", raw: SAMPLE_ARISTA_EOS, seed: true, note: "Core switch with no SSH idle timeout and unauthenticated NTP." },
  { id: "junos", fileName: "dc-srx-01.conf", label: "DC-SRX-01", vendorLabel: "Juniper Junos 22.4 (SRX345)", expectedVendor: "juniper-junos", raw: SAMPLE_JUNOS, seed: true, note: "Hardened datacenter firewall; only a legacy IKE proposal remains." },
  { id: "fortios", fileName: "branch-fw-07.conf", label: "BRANCH-FW-07", vendorLabel: "FortiGate FortiOS 7.4 (FGT60F)", expectedVendor: "fortinet-fortios", raw: SAMPLE_FORTIOS, seed: true, note: "Branch firewall exposing Telnet/HTTP on WAN with weak crypto." },
  { id: "panos", fileName: "pa-dmz-01.set", label: "PA-DMZ-01", vendorLabel: "Palo Alto PAN-OS 11.1 (PA-440)", expectedVendor: "paloalto-panos", raw: SAMPLE_PANOS, seed: true, note: "Lab DMZ firewall with Telnet enabled and SNMPv2c 'public'." },
  { id: "routeros", fileName: "branch-mt-09.rsc", label: "BRANCH-MT-09", vendorLabel: "MikroTik RouterOS 7.14 (RB4011)", expectedVendor: "mikrotik-routeros", raw: SAMPLE_ROUTEROS, seed: true, note: "Branch router with plain-HTTP/API and superfluous services." },
  { id: "vrp", fileName: "core-hw-01.cfg", label: "CORE-HW-01", vendorLabel: "Huawei VRP V200R022 (S6730)", expectedVendor: "huawei-vrp", raw: SAMPLE_VRP, seed: true, note: "Core switch with Telnet, SSHv1 compatibility and TLS 1.1." },
  { id: "exos", fileName: "access-ex-12.xsf", label: "ACCESS-EX-12", vendorLabel: "Extreme EXOS 30.7 (X465) — unknown to the parsers", expectedVendor: "generic", raw: SAMPLE_EXOS, seed: true, note: "No built-in parser: teach the engine in the Training Studio." },
  { id: "aws", fileName: "prod-web-sg.json", label: "prod-web-sg", vendorLabel: "AWS VPC security group (JSON)", expectedVendor: "generic", raw: SAMPLE_AWS_SG, seed: false, note: "Structured JSON export flattened into key paths." },
];

export const SAMPLE_INDEX: Record<string, SampleConfig> = Object.fromEntries(SAMPLES.map((s) => [s.id, s]));
