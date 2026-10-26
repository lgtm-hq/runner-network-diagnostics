"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { waitForAgent } = require("../synthetic-induce/lifecycle.cjs");
const { observe, succeeded } = require("./support.cjs");

function queryWindow({ label, r }) {
  const name = r.nonce(label.toLowerCase());
  const allowedName = label === "P" ? "objects.githubusercontent.com" : "api.github.com";
  const oracleStart = new Date().toISOString();
  const monotonicStart = process.hrtime.bigint();
  const allowed = r.probe("timeout", ["10", "getent", "ahostsv4", allowedName], {
    timeoutMs: 11000,
  });
  const denied = r.probe("timeout", ["10", "getent", "ahostsv4", name], { timeoutMs: 11000 });
  const oracleEnd = new Date().toISOString();
  const record = {
    nonce: name,
    allowedName,
    oracleStart,
    oracleEnd,
    windowToleranceMs: 1,
    timestampResolution: "milliseconds",
    elapsedNs: String(process.hrtime.bigint() - monotonicStart),
    allowed,
    denied,
  };
  if (label === "P") {
    r.pause(1000);
    record.repeatStart = new Date().toISOString();
    record.repeat = r.probe("timeout", ["10", "getent", "ahostsv4", name], { timeoutMs: 11000 });
    record.repeatEnd = new Date().toISOString();
    record.publicBaselineRequiresWire = true;
    record.baselineInterpretation =
      "NXDOMAIN is valid only with the matching captured response; getent address output alone is not proof";
  }
  return record;
}

function measure({ label, r, readiness }) {
  if (!["P", "A", "Z", "U"].includes(label)) throw new Error("invalid oracle label");
  const observations = observe(r);
  const window = queryWindow({ label, r });
  const record = {
    native: true,
    label,
    timestamp: new Date().toISOString(),
    readiness,
    observations,
    ...window,
  };
  const selection = r.read("selection.json");
  record.placement = {
    classification: selection.classification,
    arm: selection.arm,
    run: selection.run,
    attempt: selection.attempt,
    replicate: selection.replicate,
  };
  if (label === "U")
    record.sinkholeReferenceCandidate =
      selection.classification === "UNAFFECTED" && readiness?.ready === true;
  const prior = label === "P" ? null : r.read("baseline.json");
  record.mainChangedSincePre =
    prior?.main?.sha256 && observations.main.sha256
      ? observations.main.sha256 !== prior.main.sha256
      : null;
  record.platformUnchangedSincePre =
    prior?.platform?.sha256 && observations.platform.sha256
      ? observations.platform.sha256 === prior.platform.sha256
      : null;
  // A failed query or missing agent remains an observation. The external
  // assessment applies the preregistered gates to these raw statuses and wire.
  r.write(`oracle-${label}.json`, record);
  if (label !== "U") {
    try {
      const content = r.topology("snapshot");
      fs.writeFileSync(path.join(r.out, `topology-${label}.txt`), content, { flag: "wx" });
    } catch (error) {
      r.write(`topology-${label}-error.json`, { error: error.message });
      throw error;
    }
  }
  return record;
}

function afterHardener({ label, r }) {
  if (!["A", "U", "Z"].includes(label)) throw new Error("invalid post-hardener label");
  const readiness =
    label === "Z"
      ? undefined
      : waitForAgent({
          timeoutMs: 30000,
          read: (remainingMs) =>
            r.probe("sudo", ["-n", "timeout", "1", "cat", "/home/agent/agent.status"], {
              timeoutMs: Math.max(1, Math.min(2000, remainingMs)),
            }),
        });
  if (readiness) r.write(`readiness-${label}.json`, readiness);
  const record = measure({ label, r, readiness });
  if (readiness && !readiness.ready)
    throw new Error("agent readiness failed; oracle retained for diagnosis");
  if (
    label === "U" &&
    (!succeeded(record.observations.dns) || record.observations.owned.present !== false)
  )
    throw new Error("unaffected resolver observation failed or owned path present");
  return record;
}

module.exports = { queryWindow, measure, afterHardener };
