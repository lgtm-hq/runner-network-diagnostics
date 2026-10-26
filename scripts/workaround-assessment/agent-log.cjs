"use strict";

function second(value) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new Error("invalid gate timestamp");
  return Math.floor(timestamp / 1000);
}
function event(line) {
  const match = /^(.*?GMT):(.*)$/.exec(line.trim());
  if (!match) {
    if (/endpoint called|ip address dropped:/.test(line))
      throw new Error("unrecognized agent event framing");
    return null;
  }
  const timestamp = Date.parse(match[1]);
  if (!Number.isFinite(timestamp)) throw new Error("unparseable timestamp in agent event");
  return { line: line.trim(), second: Math.floor(timestamp / 1000), text: match[2] };
}
function blankConnection(record) {
  const match =
    /^endpoint called ip address:port (.+):(\d+), domain:\s*, pid: ([^,]*), process: ([^,]*), status:/.exec(
      record.text,
    );
  if (
    !match &&
    record.text.startsWith("endpoint called") &&
    !/^endpoint called ip address:port .+:\d+, domain: \S[^,]*, pid: [^,]*, process: [^,]*, status:/.test(
      record.text,
    )
  )
    throw new Error("unrecognized connection record");
  return match
    ? { ...record, ip: match[1], port: match[2], pid: match[3], process: match[4] }
    : null;
}

// The caller supplies ONLY hardener post's authoritative agent-log block.
// Probe snapshots echo these records and must not be merged into that source.
function emptyDomainGate({
  agentLog,
  verifyTime,
  negativeAddress,
  negativeReport,
  negativeEvents,
  negativeStepStart,
  negativeVerdictTime,
}) {
  const verifySecond = second(verifyTime);
  const start = second(negativeStepStart);
  const end = second(negativeVerdictTime);
  if (end < start) throw new Error("negative-control interval is reversed");
  const address = negativeAddress.trim();
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(address))
    throw new Error("negative-control address unavailable");
  const report = /^verdict=(\S+) curl_rc=(\d+) address=(\S+) pid=(\d+) agent=(\S+)\s*$/.exec(
    negativeReport,
  );
  const confirmed = Boolean(
    report &&
    report[1] === "CONFIRMED_BLOCK" &&
    ["7", "28"].includes(report[2]) &&
    report[3] === address &&
    report[5] === "active",
  );
  const events = [...new Set(agentLog.split(/\r?\n/).map((line) => line.trim()))]
    .map(event)
    .filter(Boolean);
  const controlEvents = new Set(negativeEvents.split(/\r?\n/).map((line) => line.trim()));
  const dropInInterval = events.some(
    (record) =>
      record.second >= start &&
      record.second <= end &&
      record.text === `ip address dropped: ${address}`,
  );
  const counted = events
    .map(blankConnection)
    .filter((record) => record && record.second >= verifySecond);
  const excluded = [];
  const remaining = [];
  for (const record of counted) {
    const matchesControl =
      confirmed &&
      record.ip === address &&
      record.port === "443" &&
      record.pid === report[4] &&
      record.process === "curl" &&
      record.second >= start &&
      record.second <= end &&
      dropInInterval &&
      controlEvents.has(record.line);
    (matchesControl ? excluded : remaining).push(record);
  }
  // CONFIRMED_BLOCK without the matching post-log event is an integrity gap,
  // rather than permission to ignore other records or infer a successful gate.
  const outcome =
    confirmed && excluded.length === 0
      ? "INVALID"
      : remaining.length || !confirmed
        ? "FAIL"
        : "PASS";
  return {
    outcome,
    confirmed,
    verifySecond,
    interval: { start, end },
    counted,
    excluded,
    remaining,
  };
}
function postAgentEvents(consoleText) {
  const text = consoleText
    .split(/\r?\n/)
    .map((line) => line.replace(/^\d{4}-\d\d-\d\dT[\d:.]+Z ?/, ""))
    .join("\n");
  const blocks = text.split(/^Post job cleanup\.$/m);
  const candidates = blocks.slice(1).filter((block) => block.includes("GMT:post_event called"));
  if (candidates.length !== 1) throw new Error("authoritative hardener post block unavailable");
  const sections = [...candidates[0].matchAll(/^log:\n([\s\S]*?)^status:\n/gm)];
  if (sections.length !== 1) throw new Error("authoritative agent log delimiters unavailable");
  const content = sections[0][1];
  for (const line of content.split("\n")) {
    // Validate suspicious records, but return the ENTIRE authoritative section.
    // Using a separate retention regex can silently discard accepted evidence.
    if (/endpoint called|ip address dropped:/.test(line)) event(line);
  }
  if (!content.includes("GMT:post_event called")) throw new Error("agent post events unavailable");
  return content;
}
module.exports = { emptyDomainGate, second, postAgentEvents };
