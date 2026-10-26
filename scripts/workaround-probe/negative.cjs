"use strict";
const path = require("node:path");
const { readFile, succeeded } = require("./support.cjs");

function negative(r) {
  const start = new Date().toISOString();
  const clock = process.hrtime.bigint();
  const result = r.vendor("negative");
  const end = new Date().toISOString();
  let receipt;
  let error;
  try {
    receipt = readFile(path.join(r.root, "ci1203", "negative.txt")).content;
  } catch (failure) {
    error = failure.message;
  }
  const match =
    /^verdict=(\S+) curl_rc=(\d+) address=(\d+\.\d+\.\d+\.\d+) pid=(\d+) agent=(\S+)\s*$/.exec(
      receipt || "",
    );
  r.write("strict-negative-window.json", {
    native: true,
    start,
    end,
    windowToleranceMs: 1,
    elapsedNs: String(process.hrtime.bigint() - clock),
    result,
    receipt,
    error,
    selectedControl: match
      ? {
          verdict: match[1],
          curlRc: Number(match[2]),
          address: match[3],
          pid: Number(match[4]),
          agent: match[5],
        }
      : null,
    blankDomainException:
      "Only the exact strict-negative curl IP, PID and validated timestamp window may be exempted by external assessment; all other blank-domain connections remain gated",
  });
  if (!succeeded(result)) throw new Error("unchanged vendor strict negative failed");
}

module.exports = { negative };
