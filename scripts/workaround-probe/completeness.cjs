"use strict";

function packets(wire) {
  const records = [];
  let current;
  for (const line of wire.split(/\r?\n/)) {
    const header =
      /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) (?:\S+\s+(?:In|Out|B|M|P|\?)\s+)?IP6? /.exec(line);
    if (header) {
      current = { timestamp: header[1].replace(" ", "T") + "Z", text: line };
      records.push(current);
    } else if (current && /^\s/.test(line)) current.text += `\n${line}`;
    else if (line.trim()) throw new Error("unrecognized captured packet framing");
  }
  return records;
}

function nonceWindow({ wire, oracle }) {
  if (!/^[pazu]-[a-f0-9]{16}\.example\.com$/.test(oracle.nonce))
    throw new Error("invalid registered nonce");
  const start = Date.parse(oracle.oracleStart);
  const end = Date.parse(oracle.oracleEnd);
  if (
    !Number.isFinite(start) ||
    !Number.isFinite(end) ||
    end < start ||
    oracle.windowToleranceMs !== 1
  )
    throw new Error("invalid registered nonce window");
  const escaped = oracle.nonce.replace(/\./g, "\\.");
  const query = new RegExp(`\\b\\d+\\+ (?:\\[[^\\]\\n]+\\] )?A\\? ${escaped}\\.`);
  const response = new RegExp(`\\bq: A\\? ${escaped}\\.`);
  const inWindow = packets(wire).filter(
    (packet) =>
      Date.parse(packet.timestamp) >= start - 1 && Date.parse(packet.timestamp) <= end + 1,
  );
  const matchingQueries = inWindow.filter((packet) => query.test(packet.text));
  const matchingResponses = inWindow.filter((packet) => response.test(packet.text));
  const to = (ip, packet) => new RegExp(`> ${ip.replace(/\./g, "\\.")}\\.53:`).test(packet.text);
  return {
    nonce: oracle.nonce,
    oracleStart: oracle.oracleStart,
    oracleEnd: oracle.oracleEnd,
    windowToleranceMs: 1,
    queries: matchingQueries.length,
    responses: matchingResponses.length,
    queriesToAgent: matchingQueries.filter((packet) => to("127.0.0.1", packet)).length,
    queriesToForwarder: matchingQueries.filter((packet) => to("127.0.0.100", packet)).length,
    queriesToAzure: matchingQueries.filter((packet) => to("168.63.129.16", packet)).length,
    // A response's echoed question is never counted as a fresh query.
    freshPForwardQuery: matchingQueries.some(
      (packet) =>
        to("127.0.0.100", packet) ||
        to("168.63.129.16", packet) ||
        /\b127\.0\.0\.100\.\d+ > /.test(packet.text),
    ),
  };
}

function nativeCompleteness({ state, wire, oracles }) {
  const engineHealthy =
    state.freezeOutcome === "acknowledged" &&
    state.stage === "frozen" &&
    state.healthyAtFreeze === true;
  const windows = {};
  const errors = [];
  for (const [label, oracle] of Object.entries(oracles)) {
    try {
      windows[label] = nonceWindow({ wire, oracle });
    } catch (error) {
      errors.push(`${label}: ${error.message}`);
    }
  }
  const freshP = windows.P?.freshPForwardQuery === true;
  return {
    native: true,
    engineHealthy,
    freshP,
    complete: engineHealthy && freshP && errors.length === 0,
    windows,
    errors,
    // A/Z agent/sinkhole/bypass checks are treatment outcomes. Never relabel
    // those failures as an invalid capture instrument or require allowed-name
    // packets that the real forwarding resolver may have cached.
    outcomeGates:
      "A/Z fresh-nonce route/response/security gates are assessed externally; missing or wrong-path A/Z traffic cannot become INVALID through this instrument record",
  };
}

module.exports = { packets, nonceWindow, nativeCompleteness };
