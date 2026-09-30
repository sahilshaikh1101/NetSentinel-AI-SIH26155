import { describe, it, expect } from "vitest";
import { CONFIDENCE_HIGH, confidenceLabel, proposeExtraction, suggestForLine, tokenize } from "./classifier";
import { applyMappings, captureGroupCount, compileMapping, modeFitsType, polarityOf, testMapping } from "./mappings";
import { parseConfig } from "./parsers/index";
import { SAMPLE_EXOS } from "./samples/exos";
import { SBM_INDEX } from "./sbm";
import { isAssessable } from "./fleet";
import type { Mapping, ParamValue } from "./types";

/**
 * Regression benchmark for the offline training loop.
 *
 * Ground truth for the Extreme EXOS sample is derived from EXOS_STARTER_PACK
 * (the hand-built pack that makes the device fully auditable) plus the
 * parameters named in the adversarial classifier review. Each line lists every
 * parameter a competent analyst would accept, because several lines legitimately
 * carry two meanings ("enable ssh2" is both ssh_enabled and ssh_version).
 */
const TRUTH: Record<number, string[]> = {
  7: ["identity.hostname_set", "identity.hostname"],
  11: ["time.timezone_set"],
  26: ["auth.local_users"],
  27: ["auth.min_password_length"],
  28: ["auth.login_lockout"],
  29: ["auth.login_lockout"],
  30: ["auth.password_complexity"],
  31: ["auth.remote_auth_servers"],
  32: ["auth.remote_auth_servers", "auth.password_encryption"],
  33: ["auth.aaa_enabled", "auth.aaa_authentication_login"],
  37: ["management.idle_timeout_minutes"],
  38: ["management.idle_timeout_minutes"],
  39: ["management.concurrent_sessions_limited"],
  40: ["management.login_banner"],
  45: ["management.ssh_enabled", "management.ssh_version"],
  46: ["crypto.strong_crypto"],
  47: ["crypto.strong_crypto"],
  48: ["management.telnet_enabled"],
  52: ["management.http_enabled"],
  53: ["management.https_enabled"],
  57: ["snmp.v1v2c_communities", "snmp.default_communities"],
  58: ["snmp.v1v2c_communities", "snmp.rw_communities", "snmp.default_communities"],
  59: ["snmp.enabled"],
  60: ["snmp.v3_enabled"],
  61: ["snmp.v3_priv", "snmp.v3_enabled"],
  62: ["snmp.v3_enabled"],
  63: ["snmp.trap_hosts"],
  67: ["logging.remote_hosts"],
  68: ["logging.enabled"],
  69: ["logging.level", "logging.remote_hosts"],
  70: ["logging.remote_hosts", "logging.enabled"],
  71: ["logging.buffered"],
  72: ["logging.console_restricted"],
  76: ["time.ntp_servers"],
  77: ["time.ntp_servers"],
  78: ["time.ntp_servers", "time.ntp_authentication"],
  82: ["services.lldp_enabled"],
  83: ["services.lldp_enabled"],
  87: ["acl.count"],
  88: ["acl.external_ingress_filter", "management.mgmt_acl_applied"],
  89: ["acl.count", "acl.default_deny"],
  90: ["acl.external_ingress_filter"],
};

/** sysLocation/sysContact/VLAN/STP/banner-text lines: no security meaning at all. */
const NO_MEANING = [8, 9, 10, 15, 16, 17, 18, 19, 20, 21, 22, 41, 94, 95, 96];

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV6 = /^(?=(?:[^:]*:){2})[0-9a-f:]+$/i;
const HOSTNAME = /^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+$/i;
const isAddressLike = (v: string) => IPV4.test(v) || IPV6.test(v) || HOSTNAME.test(v);

const baseParse = parseConfig(SAMPLE_EXOS, "generic", []).result;
const exosLines = baseParse.unrecognized;
const lineAt = (n: number) => exosLines.find((l) => l.line === n)!;

/** Mirrors Training.tsx autoAccept(), including its post-review guards. */
function simulateAutoAccept(): Mapping[] {
  const seen = new Set<string>();
  const accepted: Mapping[] = [];
  for (const l of exosLines) {
    const s = suggestForLine(l.text, [], 1)[0];
    if (!s || s.confidence < CONFIDENCE_HIGH) continue;
    if (s.extractionValid === false || !modeFitsType(s.param, s.valueMode)) continue;
    if ((s.valueMode === "capture" || s.valueMode === "list") && !(testMapping(s.pattern, "i", [l])[0]?.groups[(s.captureGroup ?? 1) - 1] ?? "").trim()) continue;
    const key = `${s.param}|${s.pattern}`;
    if (seen.has(key)) continue;
    seen.add(key);
    accepted.push({
      id: `auto-${l.line}`, name: `Auto · ${s.param}`, vendor: "any", pattern: s.pattern, flags: "i",
      param: s.param, valueMode: s.valueMode, constValue: s.constValue, captureGroup: s.captureGroup ?? 1,
      transform: s.transform, createdAt: "", createdBy: "classifier", sampleLine: l.text, hits: 0,
    });
  }
  return accepted;
}

describe("classifier benchmark (EXOS)", () => {
  it("labels the security-relevant unrecognised lines: top-1 >= 75%, top-3 >= 88%", () => {
    const labelled = Object.keys(TRUTH).map(Number);
    expect(labelled.length).toBe(42);
    let top1 = 0;
    let top3 = 0;
    const misses: string[] = [];
    for (const n of labelled) {
      const want = TRUTH[n];
      const s = suggestForLine(lineAt(n).text, [], 3);
      if (s[0] && want.includes(s[0].param)) top1++;
      else misses.push(`L${n} "${lineAt(n).text}" -> ${s[0]?.param ?? "none"} (want ${want.join("|")})`);
      if (s.some((x) => want.includes(x.param))) top3++;
    }
    expect(top1 / labelled.length, `top-1 misses:\n${misses.join("\n")}`).toBeGreaterThanOrEqual(0.75);
    expect(top3 / labelled.length).toBeGreaterThanOrEqual(0.88);
  });

  it("never proposes a no-meaning line with auto-accept confidence", () => {
    for (const n of NO_MEANING) {
      const s = suggestForLine(lineAt(n).text, [], 1)[0];
      if (!s) continue;
      expect(s.confidence, `L${n} "${lineAt(n).text}" -> ${s.param}`).toBeLessThan(CONFIDENCE_HIGH);
      expect(confidenceLabel(s.confidence)).not.toBe("High");
    }
  });

  it("keeps the High bucket precise (no wrong answer above the auto-accept bar)", () => {
    let high = 0;
    let correct = 0;
    const wrong: string[] = [];
    for (const l of exosLines) {
      const s = suggestForLine(l.text, [], 1)[0];
      if (!s || confidenceLabel(s.confidence) !== "High") continue;
      high++;
      if (TRUTH[l.line]?.includes(s.param)) correct++;
      else wrong.push(`L${l.line} @${s.confidence} -> ${s.param} :: ${l.text}`);
    }
    expect(high).toBeGreaterThanOrEqual(12);
    expect(correct / high, `High-label mistakes:\n${wrong.join("\n")}`).toBeGreaterThanOrEqual(0.9);
  });

  it("makes the High label mean exactly the auto-accept bar", () => {
    expect(CONFIDENCE_HIGH).toBe(0.72);
    expect(confidenceLabel(0.72)).toBe("High");
    expect(confidenceLabel(0.71)).toBe("Medium");
  });
});

describe("auto-accept on the EXOS sample stores only well-typed, plausible values", () => {
  const accepted = simulateAutoAccept();
  const { result } = parseConfig(SAMPLE_EXOS, "generic", accepted);
  const params = result.model.params;

  it("produces mappings and makes the device assessable", () => {
    expect(accepted.length).toBeGreaterThan(8);
    expect(Object.keys(params).length).toBeGreaterThan(8);
    expect(isAssessable(result)).toBe(true);
  });

  it("stores a value of the declared SBM type for every parameter", () => {
    for (const [key, obs] of Object.entries(params)) {
      const type = SBM_INDEX[key]?.type;
      const v: ParamValue = obs.value;
      if (type === "list") expect(Array.isArray(v), `${key}=${JSON.stringify(v)}`).toBe(true);
      else if (type === "number") expect(typeof v, `${key}=${JSON.stringify(v)}`).toBe("number");
      else if (type === "boolean") expect(typeof v, `${key}=${JSON.stringify(v)}`).toBe("boolean");
      else expect(typeof v, `${key}=${JSON.stringify(v)}`).toBe("string");
    }
  });

  it("only harvests addresses/hostnames into the NTP and syslog lists", () => {
    for (const key of ["time.ntp_servers", "logging.remote_hosts", "snmp.trap_hosts", "auth.remote_auth_servers"]) {
      const v = params[key]?.value;
      if (v === undefined) continue;
      expect(Array.isArray(v)).toBe(true);
      for (const item of v as string[]) expect(isAddressLike(item), `${key} harvested ${JSON.stringify(item)}`).toBe(true);
    }
    // the specific regression: "enable sntp-client"/"enable syslog"/"enable ssh2" must never become NTP servers
    const ntp = (params["time.ntp_servers"]?.value ?? []) as string[];
    for (const junk of ["sntp-client", "syslog", "ssh2", "idletimeout"]) expect(ntp).not.toContain(junk);
  });

  it("fills booleans only from polarity/flag/const rules, never from a capture", () => {
    for (const [key, obs] of Object.entries(params)) {
      if (SBM_INDEX[key]?.type !== "boolean") continue;
      const m = accepted.find((x) => x.id === obs.mappingId);
      if (!m) continue;
      expect(["polarity", "flag", "const"], `${key} via ${m.valueMode}`).toContain(m.valueMode);
    }
  });

  it("does not read SNMPv3 out of the v1/v2c line, and reads telnet as disabled", () => {
    const v3 = params["snmp.v3_enabled"];
    if (v3) for (const ev of v3.evidence) expect(ev.text).not.toMatch(/snmp-v1v2c/i);
    expect(params["snmp.enabled"]?.value).toBe(true);
    expect(params["management.telnet_enabled"]?.value).toBe(false);
    // two ACL definitions and two bindings must not be counted as four ACLs
    const count = params["acl.count"]?.value;
    if (count !== undefined) expect(count).toBeLessThanOrEqual(2);
  });

  it("accepts mappings that generalise: they match more lines than they were taught from", () => {
    const hitCounts = accepted.map((m) => testMapping(m.pattern, m.flags, exosLines).length);
    for (const n of hitCounts) expect(n).toBeGreaterThanOrEqual(1);
    const covered = hitCounts.reduce((a, b) => a + b, 0);
    expect(covered).toBeGreaterThan(accepted.length);
  });

  it("every accepted pattern still matches the line it was learned from", () => {
    for (const m of accepted) {
      const re = compileMapping(m)!;
      expect(re.test(m.sampleLine!), `${m.pattern} no longer matches ${m.sampleLine}`).toBe(true);
    }
  });
});

describe("scoring fixes", () => {
  it("weights a keyword by word count, so a hyphenated keyword cannot saturate confidence", () => {
    // "enable snmp access snmp-v1v2c" used to score snmp.v3_enabled at 0.95
    const s = suggestForLine("enable snmp access snmp-v1v2c", [], 3);
    expect(s[0].param).toBe("snmp.enabled");
    const v3 = s.find((x) => x.param === "snmp.v3_enabled");
    expect(v3?.confidence ?? 0).toBeLessThan(CONFIDENCE_HIGH);
  });

  it("does not let an ACL binding line outrank the ingress-filter parameter", () => {
    const s = suggestForLine("configure access-list mgmt-in vlan Mgmt ingress", [], 3);
    expect(["acl.external_ingress_filter", "management.mgmt_acl_applied"]).toContain(s[0].param);
  });

  it("separates the lockout lines from generic password policy", () => {
    expect(suggestForLine("configure account all password-policy lockout-on-login-failures on")[0].param).toBe("auth.login_lockout");
    expect(suggestForLine("configure account all password-policy char-validation all-char-groups")[0].param).toBe("auth.password_complexity");
    expect(suggestForLine("configure account all password-policy min-length 8")[0].param).toBe("auth.min_password_length");
  });

  it("keeps console logging out of the remote-host list", () => {
    expect(suggestForLine("configure log target console severity Critical")[0].param).toBe("logging.console_restricted");
    expect(suggestForLine("configure log target memory-buffer severity Debug-Data")[0].param).toBe("logging.buffered");
  });

  it("routes a trap target to trap_hosts rather than v3_enabled", () => {
    expect(suggestForLine('configure snmpv3 add target-addr "siem" param "v3params" ipaddress 10.10.50.40 transport-port 162')[0].param).toBe("snmp.trap_hosts");
  });

  it("collapses addresses and long integers in the tokeniser", () => {
    const t = tokenize("configure syslog add 10.10.50.20:514 vr VR-Default local7");
    expect(t).toContain("<ip>");
    expect(t).toContain("<num>");
    expect(t).not.toContain("10");
    expect(t).not.toContain("50");
    // letter/digit splitting inside real words survives
    expect(tokenize("configure ssh2 ciphers aes256-ctr")).toEqual(expect.arrayContaining(["ssh", "2", "ciphers", "aes256-ctr", "aes", "256", "ctr"]));
  });

  it("ignores a learned mapping whose regex does not match the line", () => {
    const learned: Mapping[] = [{
      id: "L1", name: "bogus", vendor: "any", pattern: "^enable\\s+sntp-client$", flags: "i",
      param: "time.ntp_servers", valueMode: "list", captureGroup: 1, createdAt: "", createdBy: "classifier",
      sampleLine: "enable sntp-client", hits: 0,
    }];
    const without = suggestForLine("enable syslog", [], 1)[0];
    const withIt = suggestForLine("enable syslog", learned, 1)[0];
    expect(withIt.param).toBe(without.param);
    expect(withIt.confidence).toBe(without.confidence);
  });

  it("respects the vendor scope of a learned mapping", () => {
    const learned: Mapping[] = [{
      id: "L2", name: "cisco only", vendor: "cisco-ios", pattern: "^enable\\s+syslog$", flags: "i",
      param: "identity.tunnels", valueMode: "count", createdAt: "", createdBy: "classifier",
      sampleLine: "enable syslog", hits: 0,
    }];
    const scoped = suggestForLine("enable syslog", learned, 3, "juniper-junos");
    expect(scoped.some((s) => s.param === "identity.tunnels")).toBe(false);
  });
});

describe("extraction fixes", () => {
  it("captures an IPv4 address that carries a port", () => {
    const ex = proposeExtraction("configure syslog add 10.10.50.20:514 vr VR-Default local7", "logging.remote_hosts");
    expect(ex.valueMode).toBe("list");
    expect(ex.extractedValue).toEqual(["10.10.50.20"]);
    expect(testMapping(ex.pattern, "i", [{ line: 1, text: "configure syslog add 10.10.50.20:514 vr VR-Default local7" }])[0].groups[0]).toBe("10.10.50.20");
  });

  it("captures IPv6 and hostname values", () => {
    expect(proposeExtraction("set system ntp server 2001:db8::1", "time.ntp_servers").extractedValue).toEqual(["2001:db8::1"]);
    expect(proposeExtraction("ntp server time.nic.in prefer", "time.ntp_servers").extractedValue).toEqual(["time.nic.in"]);
  });

  it("prefers the address that follows a value anchor", () => {
    const ex = proposeExtraction("configure radius mgmt-access primary server 10.10.50.31 1812 client-ip 10.30.99.12 vr VR-Default", "auth.remote_auth_servers");
    expect(ex.extractedValue).toEqual(["10.10.50.31"]);
  });

  it("takes the token after a param keyword when there is no address", () => {
    expect(proposeExtraction("configure snmp add community readonly public", "snmp.v1v2c_communities").extractedValue).toEqual(["public"]);
    expect(proposeExtraction('create account admin "netops" encrypted "$5$x"', "auth.local_users").extractedValue).toEqual(["netops"]);
  });

  it("refuses to invent a list value when the line has none", () => {
    for (const text of ["enable sntp-client", "enable syslog", "enable idletimeout"]) {
      const forList = proposeExtraction(text, "time.ntp_servers");
      expect(forList.extractionValid, `${text} invented a list value`).toBe(false);
      expect(forList.valueMode).not.toBe("list");
    }
  });

  it("never falls back to count for a non-counter number parameter", () => {
    const idle = proposeExtraction("enable idletimeout", "management.idle_timeout_minutes");
    expect(idle.valueMode).not.toBe("count");
    expect(idle.extractionValid).toBe(false);
    // genuine counters keep the count mode
    const acl = proposeExtraction('create access-list mgmt-in "source-address 10.10.0.0/24;" "permit;"', "acl.count");
    expect(acl.valueMode).toBe("count");
    expect(acl.extractionValid).toBe(true);
  });

  it("parses version-like tokens as numbers", () => {
    expect(proposeExtraction("set system services ssh protocol-version v2", "management.ssh_version").extractedValue).toBe(2);
    expect(proposeExtraction("ip ssh version 2", "management.ssh_version").extractedValue).toBe(2);
    expect(proposeExtraction("enable ssh2", "management.ssh_version").extractedValue).toBe(2);
  });

  it("picks the integer that belongs to the parameter's keyword", () => {
    expect(proposeExtraction("login block-for 60 attempts 3 within 60", "auth.max_login_attempts").extractedValue).toBe(3);
    expect(proposeExtraction("crypto key generate rsa modulus 2048", "crypto.rsa_modulus").extractedValue).toBe(2048);
    expect(proposeExtraction("configure idletimeout 45", "management.idle_timeout_minutes").extractedValue).toBe(45);
  });

  it("respects negative-named booleans instead of inverting them", () => {
    const aux = proposeExtraction("no exec", "management.aux_disabled");
    expect(aux.extractedValue).toBe(true);
    const conc = proposeExtraction("set admin-concurrent disable", "management.concurrent_sessions_limited");
    expect(conc.extractedValue).toBe(true);
    const cons = proposeExtraction("no logging console", "logging.console_restricted");
    expect(cons.extractedValue).toBe(true);
    const root = proposeExtraction("set system services ssh root-login deny", "auth.root_login_ssh");
    expect(root.extractedValue).toBe(false);
    // ACL verbs prove presence, they are not a "disabled" state
    expect(proposeExtraction("deny ip any any log", "acl.explicit_deny_logged").extractedValue).toBe(true);
    expect(proposeExtraction("set security policies default-policy deny-all", "acl.default_deny").extractedValue).toBe(true);
  });

  it("only lets a polarity word govern when it leads the line or follows a keyword", () => {
    // the "off" belongs to autodst, not to the timezone
    const tz = proposeExtraction("configure timezone name IST 330 autodst off", "time.timezone_set");
    expect(tz.valueMode).toBe("flag");
    expect(tz.extractedValue).toBe(true);
    // here it does follow the parameter's own keyword
    const lock = proposeExtraction("configure account all password-policy lockout-on-login-failures on", "auth.login_lockout");
    expect(lock.valueMode).toBe("polarity");
    expect(lock.extractedValue).toBe(true);
  });
});

describe("regex generalisation", () => {
  const matches = (pattern: string, text: string) => new RegExp(pattern, "i").test(text);

  it("shares one rule between sntp primary and secondary", () => {
    const ex = proposeExtraction("configure sntp-client primary 10.10.50.10 vr VR-Default", "time.ntp_servers");
    expect(matches(ex.pattern, "configure sntp-client primary 10.10.50.10 vr VR-Default")).toBe(true);
    expect(matches(ex.pattern, "configure sntp-client secondary 10.10.50.11 vr VR-Default")).toBe(true);
  });

  it("shares one rule between readonly and readwrite communities", () => {
    const ex = proposeExtraction("configure snmp add community readonly public", "snmp.v1v2c_communities");
    expect(matches(ex.pattern, "configure snmp add community readwrite private")).toBe(true);
  });

  it("shares one rule between ssh2 ciphers and ssh2 macs", () => {
    const ex = proposeExtraction("configure ssh2 ciphers aes256-ctr aes128-ctr", "crypto.strong_crypto");
    expect(matches(ex.pattern, "configure ssh2 macs hmac-sha2-256 hmac-sha2-512")).toBe(true);
  });

  it("shares one rule between both ACL definitions and both ACL bindings", () => {
    const def = proposeExtraction('create access-list mgmt-in "source-address 10.10.0.0/24;" "permit;"', "acl.count");
    expect(matches(def.pattern, 'create access-list deny-all "" "deny;"')).toBe(true);
    const bind = proposeExtraction("configure access-list mgmt-in vlan Mgmt ingress", "acl.external_ingress_filter");
    expect(matches(bind.pattern, "configure access-list deny-all vlan Users ingress")).toBe(true);
  });

  it("keeps the verb and vocabulary literal so unrelated lines do not match", () => {
    const telnet = proposeExtraction("disable telnet", "management.telnet_enabled");
    expect(telnet.pattern).toBe("^(enable|disable)\\s+telnet$");
    expect(matches(telnet.pattern, "enable ssh2")).toBe(false);
    expect(matches(telnet.pattern, "enable syslog")).toBe(false);
    const sntp = proposeExtraction("enable sntp-client", "time.ntp_servers");
    expect(matches(sntp.pattern, "enable syslog")).toBe(false);
    expect(matches(sntp.pattern, "enable ssh2")).toBe(false);
  });

  it("does not freeze the trailing instance tokens of a syslog target", () => {
    const ex = proposeExtraction("configure syslog add 10.10.50.20:514 vr VR-Default local7", "logging.remote_hosts");
    expect(ex.pattern).not.toContain("VR-Default");
    expect(ex.pattern).not.toContain("local7");
    expect(matches(ex.pattern, "configure syslog add 10.10.50.21:514 vr VR-Other local0")).toBe(true);
  });
});

describe("mapping application fixes", () => {
  const lines = [{ line: 1, text: "configure idletimeout 45" }];
  const base = () => ({
    vendor: "generic" as const,
    identity: { vendor: "generic" as const, vendorName: "Unknown", os: "Generic CLI" },
    model: { params: {} },
    totalLines: 1,
    meaningfulLines: 1,
    recognized: 0,
    unrecognized: lines,
    mappingsApplied: [],
  });
  const map = (extra: Partial<Mapping>): Mapping => ({
    id: "m", name: "m", vendor: "any", pattern: "^configure\\s+idletimeout\\s+(\\d+)$", flags: "i",
    param: "management.idle_timeout_minutes", valueMode: "capture", captureGroup: 1, transform: "number",
    createdAt: "", createdBy: "admin", hits: 0, ...extra,
  });

  it("strips the g/y flags so captures keep working", () => {
    const { result } = applyMappings(base(), [map({ flags: "gi" })]);
    expect(result.model.params["management.idle_timeout_minutes"].value).toBe(45);
    expect(compileMapping(map({ flags: "gy" }))!.flags).not.toMatch(/[gy]/);
    // an empty flags string must not silently become case-sensitive
    expect(compileMapping(map({ flags: "" }))!.flags).toContain("i");
  });

  it("parses numbers strictly instead of prefix-parsing an address", () => {
    const ip = applyMappings(
      { ...base(), unrecognized: [{ line: 1, text: "configure syslog add 10.10.50.10" }] },
      [map({ pattern: "^configure\\s+syslog\\s+add\\s+(\\S+)$" })],
    );
    expect(ip.result.model.params["management.idle_timeout_minutes"]).toBeUndefined();
    expect(ip.result.unrecognized.length).toBe(1);
  });

  it("skips a capture mapping that has no capture group instead of storing true", () => {
    const { result, hits } = applyMappings(base(), [map({ pattern: "^configure\\s+idletimeout\\s+\\d+$" })]);
    expect(result.model.params["management.idle_timeout_minutes"]).toBeUndefined();
    expect(hits.m).toBeUndefined();
  });

  it("refuses a value mode that cannot fill the parameter type", () => {
    expect(modeFitsType("management.idle_timeout_minutes", "flag")).toBe(false);
    expect(modeFitsType("time.ntp_servers", "polarity")).toBe(false);
    expect(modeFitsType("time.ntp_servers", "list")).toBe(true);
    expect(modeFitsType("management.telnet_enabled", "polarity")).toBe(true);
    const { result } = applyMappings(base(), [map({ valueMode: "flag" })]);
    expect(result.model.params["management.idle_timeout_minutes"]).toBeUndefined();
  });

  it("counts capture groups so the UI can block a groupless capture rule", () => {
    expect(captureGroupCount("^configure\\s+idletimeout\\s+(\\d+)$", "i")).toBe(1);
    expect(captureGroupCount("^configure\\s+idletimeout\\s+\\d+$", "i")).toBe(0);
    expect(captureGroupCount("^(?:enable|disable)\\s+telnet$", "i")).toBe(0);
  });

  it("reads polarity from whole state tokens, never from ACL verbs or identifiers", () => {
    expect(polarityOf("no shutdown")).toBe(true);
    expect(polarityOf("shutdown")).toBe(false);
    expect(polarityOf("set telnet disabled=yes")).toBe(false);
    expect(polarityOf("set telnet disabled=no")).toBe(true);
    expect(polarityOf("deny ip any any log")).toBe(true);
    expect(polarityOf("/ip firewall filter add chain=input action=drop")).toBe(true);
    expect(polarityOf("set firewall name WAN-IN default-action drop")).toBe(true);
    expect(polarityOf("ip access-list extended NO-TELNET")).toBe(true);
    expect(polarityOf("hostname no-mad-rtr")).toBe(true);
  });

  it("reads polarity from the captured group when the pattern has one", () => {
    // the trailing "off" belongs to autodst; the captured group is what matters
    expect(polarityOf("configure timezone name IST 330 autodst off", "enable")).toBe(true);
    expect(polarityOf("disable telnet", "disable")).toBe(false);
    expect(polarityOf("configure account all password-policy lockout-on-login-failures on", "on")).toBe(true);
    // a group with no state word falls back to the whole line
    expect(polarityOf("disable telnet", "VR-Default")).toBe(false);
  });
});
