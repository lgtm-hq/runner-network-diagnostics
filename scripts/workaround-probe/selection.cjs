"use strict";
const { classify } = require("../runner-probe/screen.cjs");
const { MAIN, PLATFORM, succeeded } = require("./support.cjs");

function dnsFields(config) {
  if (
    !succeeded(config) ||
    config.stderr ||
    !config.stdout?.endsWith("\n") ||
    Buffer.byteLength(config.stdout) > 256 * 1024 ||
    config.stdout.includes("\0")
  )
    return null;
  // Independently recognize the complete known configuration, not a filtered
  // excerpt. Source and section context survive logical-line assembly. Only
  // the proven empty platform reset can certify an affected host.
  const fields = [];
  const sources = [];
  let current;
  let continuation = "";
  const physical = config.stdout.split(/\r?\n/);
  physical.pop(); // The final newline is not a physical continuation terminator.
  for (const raw of physical) {
    const header = /^# (\/\S+)$/.exec(raw);
    if (header) {
      if (
        continuation ||
        ![MAIN, PLATFORM].includes(header[1]) ||
        sources.some((source) => source.path === header[1])
      )
        return null;
      current = { path: header[1], resolve: false, assignments: 0 };
      sources.push(current);
      fields.push(`# ${header[1]}`);
      continue;
    }
    const trimmed = raw.trim();
    if (!current) {
      if (trimmed) return null;
      continue;
    }
    if (/^[#;]/.test(trimmed) || (!trimmed && !continuation)) continue;
    const suffix = raw.match(/\\+$/)?.[0] || "";
    if (suffix.length % 2 === 1) {
      continuation += raw.slice(0, -1) + " ";
      continue;
    }
    const line = (continuation + raw).trim();
    continuation = "";
    if (line === "[Resolve]") {
      current.resolve = true;
      continue;
    }
    if (!current.resolve || current.path !== PLATFORM || !/^DNS\s*=\s*$/.test(line)) return null;
    current.assignments += 1;
    if (current.assignments !== 1) return null;
    fields.push("DNS=");
  }
  if (
    continuation ||
    sources.length === 0 ||
    sources[0].path !== MAIN ||
    sources.some((source) => !source.resolve) ||
    sources.some((source) => source.path === PLATFORM && source.assignments !== 1)
  )
    return null;
  return fields;
}

function select({ hosted, os, container, facts, config }) {
  const fields = dnsFields(config);
  const checks = {
    hosted: hosted === "github-hosted",
    linux: os === "Linux",
    notContainer: container === false,
    resolverSelf: facts.target === "/etc/resolv.conf",
    nameserver100: /^\s*nameserver\s+127\.0\.0\.100\s*(?:[#;].*)?$/m.test(facts.resolvConf || ""),
    resolverActive: facts.resolverUnit === "active",
    proxyActive: facts.proxyUnit === "active",
    listener100: facts.listener === "present",
    exactConfig: fields?.join("\n") === `# ${MAIN}\n# ${PLATFORM}\nDNS=`,
    completeSources:
      Array.isArray(facts.effectiveSources) &&
      JSON.stringify(
        (fields || []).filter((line) => line.startsWith("# ")).map((line) => line.slice(2)),
      ) === JSON.stringify(facts.effectiveSources),
    resolvedActive: facts.resolvedActive === "active",
    sudo: facts.sudo === true,
    liveDnsEmpty: facts.globalDns === "",
    liveDomainsEmpty: facts.globalDomains === "",
  };
  const eligible = Object.values(checks).every((value) => value === true);
  const broad = classify(facts);
  const knownHost =
    checks.hosted && checks.linux && checks.notContainer && checks.sudo && checks.resolvedActive;
  const knownOrdinaryConfig =
    fields?.join("\n") === `# ${MAIN}` &&
    checks.completeSources &&
    /^\s*nameserver\s+127\.0\.0\.53\s*(?:[#;].*)?$/m.test(facts.resolvConf || "");
  const knownOrdinaryTopology =
    knownHost &&
    knownOrdinaryConfig &&
    facts.target === "/run/systemd/resolve/stub-resolv.conf" &&
    facts.resolverUnit === "inactive" &&
    facts.proxyUnit === "inactive" &&
    facts.listener === "absent" &&
    checks.liveDnsEmpty &&
    checks.liveDomainsEmpty;
  // Placement is a covariate. Positive configuration/topology proof, rather
  // than westus2 or an unavailable IMDS lookup, determines the short path.
  const candidate = eligible || !knownOrdinaryTopology;
  return {
    eligible,
    candidate: Boolean(candidate),
    classification: eligible ? "ELIGIBLE" : candidate ? "PARTIAL" : "UNAFFECTED",
    checks,
    reasons: candidate ? broad.reasons : [],
    regionNotes: broad.reasons.filter((reason) => /region/.test(reason)),
    facts,
    hosted,
    os,
    container,
    config,
    dnsFields: fields,
  };
}

module.exports = { dnsFields, select };
