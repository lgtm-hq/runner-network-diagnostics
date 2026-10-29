"use strict";
const { performance } = require("node:perf_hooks");
const { globalDns } = require("../resolver-counterfactual/control.cjs");
const { probe, mainConfig, platformConfig } = require("./support.cjs");

function waitForAgent({
  read = (remainingMs) =>
    probe("sudo", ["-n", "timeout", "1", "cat", "/home/agent/agent.status"], {
      timeoutMs: Math.max(1, Math.min(2000, remainingMs)),
    }),
  now = () => performance.now(),
  pause = () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250),
  timeoutMs = 20000,
} = {}) {
  const start = now();
  const startedAt = new Date().toISOString();
  let attempts = 0;
  let last;
  let first;
  const counts = { absent: 0, probeError: 0, ready: 0, terminalError: 0 };
  function result(ready, outcome) {
    return {
      ready,
      outcome,
      startedAt,
      finishedAt: new Date().toISOString(),
      attempts,
      elapsedMs: now() - start,
      counts,
      first,
      last,
    };
  }
  do {
    const raw = read(timeoutMs - (now() - start));
    last = {
      status: raw.status,
      stdout: raw.stdout.slice(0, 256),
      stderr: (raw.stderr || "").slice(0, 256),
      error: raw.error?.slice(0, 256) || null,
    };
    first ||= last;
    attempts += 1;
    if (raw.status === 0 && !raw.error) {
      if (/^Initialized\r?\n?$/.test(raw.stdout)) {
        counts.ready += 1;
        return result(true, "READY");
      }
      counts.terminalError += 1;
      return result(false, "TERMINAL_STATUS_ERROR");
    }
    if ((raw.stderr || "").includes("No such file or directory")) counts.absent += 1;
    else counts.probeError += 1;
    if (now() - start >= timeoutMs) break;
    pause();
  } while (now() - start < timeoutMs);
  return result(false, "DEADLINE_EXPIRED");
}

// Shared only by the synthetic arms. The frozen native cleanup assumes that
// hardener post reverts its main config; that assumption is false for this pin.
function removeOwned({ io, state, profile }) {
  const errors = [];
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      io.root("remove", state.token, profile);
    } catch (error) {
      errors.push(error.message);
    }
    const observation = io.root("inspect", state.token, profile);
    if (observation.present === false) return errors;
    if (observation.present !== true) throw new Error("owned file absence unverified");
  }
  throw new Error(`owned ${profile} remains after cleanup`);
}

function observeCleanup({ io, state, expectedDns, overrideAbsent, expectedPlatform }) {
  const observations = {};
  const checks = { overrideAbsent };
  for (const [name, read] of Object.entries({
    mainHash: () => io.hash(mainConfig),
    dns: () => io.dns(),
    ...(expectedPlatform ? { platformHash: () => io.hash(platformConfig) } : {}),
  })) {
    try {
      observations[name] = read();
    } catch (error) {
      observations[`${name}Error`] = error.message;
    }
  }
  checks.oracleAMainBaselineKnown = typeof state.observedMainAtOracleA?.sha256 === "string";
  checks.oracleAMainUnchanged =
    checks.oracleAMainBaselineKnown && observations.mainHash === state.observedMainAtOracleA.sha256;
  observations.expectedGlobalDns = expectedDns;
  if (expectedPlatform) checks.platformUnchanged = observations.platformHash === expectedPlatform;
  try {
    observations.globalDns = globalDns(observations.dns || "");
    checks.expectedGlobalDns = observations.globalDns === expectedDns;
  } catch (error) {
    observations.globalDnsError = error.message;
    checks.expectedGlobalDns = false;
  }
  checks.azureLinkRetained = /^Link .*:.*\b168\.63\.129\.16\b/m.test(observations.dns || "");
  return { observations, checks };
}

function verifyCleanup(result, errors = []) {
  const failures = Object.entries(result.checks)
    .filter(([, passed]) => passed !== true)
    .map(([name]) => name);
  if (failures.length || errors.length) {
    const error = new Error(`synthetic cleanup failed: ${[...failures, ...errors].join("; ")}`);
    error.details = { ...result, failures, errors };
    throw error;
  }
  return result;
}

function restartObserved(io) {
  const record = { requested: true };
  for (const phase of ["before", "after"]) {
    try {
      record[`${phase}Pid`] = io.pid();
    } catch (error) {
      record[`${phase}Error`] = error.message;
    }
    if (phase === "before") {
      try {
        io.restart();
      } catch (error) {
        record.restartError = error.message;
      }
    }
  }
  record.verified =
    !record.restartError &&
    /^\d+$/.test(record.beforePid) &&
    /^\d+$/.test(record.afterPid) &&
    record.afterPid !== "0" &&
    record.beforePid !== record.afterPid;
  return record;
}

function treatmentCleanup({ phase, state, io }) {
  if (!["guard", "fallback"].includes(phase)) throw new Error("invalid cleanup phase");
  if (!state?.mutationIntent) return { phase, disposition: "NO_MUTATION" };
  const before =
    phase === "fallback"
      ? observeCleanup({
          io,
          state,
          expectedDns: "",
          overrideAbsent: false,
          expectedPlatform: state.originalPlatform,
        }).observations
      : undefined;
  const errors = removeOwned({ io, state, profile: "override" });
  if (phase === "guard") {
    if (errors.length) throw new Error(`guard removal errors: ${errors.join("; ")}`);
    return { phase, disposition: "REMOVED_WITHOUT_RESTART" };
  }
  if (io.root("inspect", state.platformToken, "reset").present !== true)
    throw new Error("owned reset unavailable; refusing restart");
  // Post does not reload DNS. Always reload after removing our override while
  // the owned reset is still present, even when guard removed it successfully.
  const restart = restartObserved(io);
  const result = observeCleanup({
    io,
    state,
    expectedDns: "",
    overrideAbsent: true,
    expectedPlatform: state.originalPlatform,
  });
  result.observations.beforeCleanup = before;
  result.observations.restart = restart;
  result.checks.restartVerified = restart.verified;
  verifyCleanup(result, errors);
  return { phase, disposition: "SYNTHETIC_OVERRIDE_REMOVED", ...result };
}

module.exports = {
  waitForAgent,
  removeOwned,
  observeCleanup,
  verifyCleanup,
  treatmentCleanup,
  restartObserved,
};
