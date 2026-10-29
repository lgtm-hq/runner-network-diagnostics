"use strict";
const { isIP } = require("node:net");
const { MAIN, PLATFORM, TARGET, LIMIT } = require("./constants.cjs");
const { crosscheck } = require("./config-files.cjs");

// This is deliberately a recognizer for the observed mechanism, not an INI
// interpreter. Unrecognized configurations must remain untouched.
function parseConfig(content) {
  if (typeof content !== "string" || Buffer.byteLength(content) > LIMIT || content.includes("\0"))
    throw new Error("invalid or oversized cat-config");
  const sources = [];
  let source;
  let section;
  let pending = "";
  const lines = content.split("\n");
  if (lines.at(-1) === "") lines.pop();
  for (const raw of lines) {
    const line = raw.replace(/\r$/, "");
    const header = /^# (\/\S+)$/.exec(line);
    if (header) {
      if (pending) throw new Error("source header inside continuation");
      const name = header[1];
      if (
        name !== MAIN &&
        !/^\/(etc|run|usr\/local\/lib|usr\/lib)\/systemd\/resolved\.conf\.d\/[A-Za-z0-9_.-]+\.conf$/.test(
          name,
        )
      )
        throw new Error("unknown source header");
      if (sources.some((entry) => entry.path === name)) throw new Error("duplicate source header");
      source = { path: name, body: [], assignments: [], sections: [] };
      sources.push(source);
      section = undefined;
      continue;
    }
    if (!source) {
      if (line.trim()) throw new Error("content before source header");
      continue;
    }
    source.body.push(line);
    const trimmed = line.trim();
    if ((!trimmed && !pending) || /^[#;]/.test(trimmed)) continue;
    // systemd joins continuations with a space and ignores comment-only lines.
    const trailing = /\\+$/.exec(line)?.[0].length || 0;
    if (trailing % 2) {
      pending += `${line.slice(0, -1)} `;
      continue;
    }
    const logical = `${pending}${line}`.trim();
    pending = "";
    const heading = /^\[([A-Za-z][A-Za-z0-9]*)\]$/.exec(logical);
    if (heading) {
      section = heading[1];
      source.sections.push(section);
      continue;
    }
    const assignment = /^([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)$/.exec(logical);
    if (!assignment || !section) throw new Error("unknown syntax or assignment outside section");
    source.assignments.push({ section, key: assignment[1], value: assignment[2].trim() });
  }
  if (pending) throw new Error("unterminated continuation");
  if (!sources.length || sources[0].path !== MAIN) throw new Error("missing main source");
  return sources;
}

function applicability({ config, main, platform, pathPresent, files, dns, domains }) {
  const no = (reason) => ({ applicable: false, reason });
  if (pathPresent) return no("REFUSED_PATH_PRESENT");
  let sources;
  try {
    sources = parseConfig(config.stdout);
    crosscheck({ config, sources, files, main });
  } catch (error) {
    return { ...no("REFUSED_CONFIG_UNREADABLE"), detail: error.message };
  }
  if (
    sources.some((source) =>
      source.assignments.some(
        (entry) =>
          ["DNS", "Domains"].includes(entry.key) &&
          !(
            source.path === PLATFORM &&
            entry.key === "DNS" &&
            entry.section === "Resolve" &&
            entry.value === ""
          ),
      ),
    )
  )
    return no("REFUSED_UNKNOWN_DNS_SOURCE");
  if (sources.length === 1) return no("REFUSED_UNKNOWN_DNS_SOURCE");
  if (sources.length !== 2 || sources[1].path !== PLATFORM) return no("REFUSED_UNKNOWN_DNS_SOURCE");
  if (
    !main?.sha256 ||
    !platform?.sha256 ||
    sources[0].body.join("\n").trimEnd() !== main.content.replace(/\r\n/g, "\n").trimEnd() ||
    sources[1].body.join("\n").trimEnd() !== platform.content.replace(/\r\n/g, "\n").trimEnd()
  )
    return no("REFUSED_CONFIG_UNREADABLE");
  if (sources.some((source) => source.sections.some((name) => name !== "Resolve")))
    return no("REFUSED_UNKNOWN_DNS_SOURCE");
  if (!sources.every((source) => source.sections.includes("Resolve")))
    return no("REFUSED_UNKNOWN_DNS_SOURCE");
  if (sources[0].assignments.length) return no("REFUSED_UNKNOWN_DNS_SOURCE");
  const entries = sources[1].assignments;
  if (
    entries.length !== 1 ||
    entries[0].section !== "Resolve" ||
    entries[0].key !== "DNS" ||
    entries[0].value !== ""
  )
    return no("REFUSED_UNKNOWN_DNS_SOURCE");
  try {
    if (globalValues(dns).length || globalValues(domains).length)
      return no("REFUSED_LIVE_MISMATCH");
  } catch (error) {
    return { ...no("REFUSED_LIVE_MISMATCH"), detail: error.message };
  }
  return {
    applicable: true,
    reason: "OBSERVED_EMPTY_PLATFORM_DNS_RESET",
    sources: sources.map((s) => s.path),
  };
}

function globalValues(content) {
  const lines = content.split(/\r?\n/).filter((line) => line.startsWith("Global:"));
  if (lines.length !== 1) throw new Error("ambiguous or missing Global field");
  const value = lines[0].slice("Global:".length).trim();
  return value ? value.split(/\s+/) : [];
}

function agentStatus(observation) {
  if (observation.status === 0 && !observation.error && !observation.stderr) {
    const value = observation.stdout.trim();
    if (value === "Initialized") return "initialized";
    if (!value || /^(Starting|Initializing|Pending)$/i.test(value)) return "uninitialized";
    if (/^(Error|Failed|Failure|Stopped|Exited|Terminated)(?:[\s:]|$)/i.test(value))
      return "terminal";
    return "unknown";
  }
  if (
    observation.status === 1 &&
    !observation.error &&
    /No such file or directory/.test(observation.stderr || "")
  )
    return "uninitialized";
  return "unknown";
}

function listenerState(observation = {}, exactAddress) {
  if (observation.status !== 0 || observation.error || observation.stderr) return "unknown";
  const lines = observation.stdout.trim().split(/\r?\n/);
  if (
    !/^State\s+Recv-Q\s+Send-Q\s+Local Address:Port\s+Peer Address:Port/.test(lines.shift() || "")
  )
    return "unknown";
  let live = false;
  for (const line of lines) {
    if (!line.trim()) continue;
    const fields = line.trim().split(/\s+/);
    if (
      fields.length < 5 ||
      !/^(UNCONN|ESTAB)$/.test(fields[0]) ||
      !/^\d+$/.test(fields[1]) ||
      !/^\d+$/.test(fields[2])
    )
      return "unknown";
    const local = fields[3];
    const endpoint = /^(.*):(\d+)$/.exec(local);
    if (!endpoint || Number(endpoint[2]) > 65535) return "unknown";
    const address = endpoint[1].replace(/^\[|\]$/g, "").split("%")[0];
    if (address !== "*" && !isIP(address)) return "unknown";
    // Wildcard UDP sockets can also serve 127.0.0.1. Never remove beneath them.
    if (
      endpoint[2] === "53" &&
      (exactAddress
        ? address === exactAddress
        : ["127.0.0.1", "0.0.0.0", "*"].includes(address) || isIP(address) === 6)
    )
      live = true;
  }
  return live ? "present" : "absent";
}
module.exports = { parseConfig, applicability, globalValues, agentStatus, listenerState, TARGET };
