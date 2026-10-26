"use strict";
const { createHash } = require("node:crypto");
const { applicability } = require("./config.cjs");
const { waitInitialized, observe, rollback } = require("./lifecycle.cjs");

function pre(r) {
  if (!["apply", "observe"].includes(r.mode)) throw new Error("mode must be apply or observe");
  if (r.load()) throw new Error("shim state already exists; only one invocation is supported");
  const state = {
    schema: 1,
    mode: r.mode,
    applicable: false,
    applied: false,
    mutationIntent: false,
  };
  try {
    state.environment = r.environment();
  } catch (error) {
    state.environment = { allowed: false, reason: "PLATFORM_UNKNOWN", error: error.message };
  }
  r.save(state, true);
  if (!state.environment.allowed) {
    state.reason = state.environment.reason;
    r.save(state);
    return { disposition: "NOT_APPLICABLE", ...state };
  }
  try {
    state.topology = r.topology();
  } catch (error) {
    state.topology = { allowed: false, error: error.message };
  }
  if (!state.topology.allowed) {
    state.reason = "NOT_KNOWN_TOPOLOGY";
    r.save(state);
    return { disposition: "NOT_APPLICABLE", ...state };
  }
  try {
    state.config = r.config();
  } catch (error) {
    state.config = { status: null, error: error.message };
  }
  state.config.sha256 = createHash("sha256")
    .update(state.config.stdout || "")
    .digest("hex");
  for (const name of ["main", "platform", "files", "dns", "domains"]) {
    try {
      state[name] = r[name]();
    } catch (error) {
      state[`${name}Error`] = error.message;
    }
  }
  const decision = applicability({
    config: state.config,
    main: state.main,
    platform: state.platform,
    pathPresent: r.pathPresent(),
    files: state.files,
    dns: state.dns,
    domains: state.domains,
  });
  Object.assign(state, decision);
  r.save(state);
  if (!state.applicable || state.mode === "observe")
    return { disposition: state.applicable ? "WOULD_APPLY" : "NOT_APPLICABLE", ...state };
  return install(r, state);
}
// The drill imports this same installer, bypassing only pre's applicability
// decision. There is deliberately no action input that can bypass that decision.
function install(r, state) {
  if (r.mode !== "apply" || state.mode !== "apply" || state.mutationIntent)
    throw new Error("install requires fresh apply state");
  state.token = r.token();
  state.mutationIntent = true;
  // This save must be durable before the first privileged create. The token
  // survives a lost sudo acknowledgement or process death.
  r.save(state);
  try {
    state.owned = r.root("create", state.token);
    if (state.owned?.present !== true)
      throw new Error("privileged creation acknowledgement missing");
    state.createdBootUpperMicros = r.bootMicros();
    state.applied = true;
    r.save(state);
  } catch (error) {
    const failure = {
      disposition: "PRE_INSTALL_FAILED",
      ...state,
      error: error.message,
      failed: true,
    };
    try {
      failure.recovery = rollback({ r, state });
    } catch (recoveryError) {
      failure.recovery = {
        disposition: "ROLLBACK_FAILED",
        error: recoveryError.message,
        ...recoveryError.details,
      };
    }
    return failure;
  }
  return { disposition: "APPLIED_PENDING_AGENT_RESTART", ...state };
}
function main(r, state) {
  if (!state.environment.allowed) return { disposition: "NOT_APPLICABLE", reason: state.reason };
  const readiness = waitInitialized(r);
  if (!state.mutationIntent) {
    // Control and unaffected paths never acquire ownership. Collect readiness
    // for the canary without treating an observed control bypass as a failure.
    return {
      disposition: state.applicable ? "WOULD_APPLY" : "NOT_APPLICABLE",
      reason: state.reason,
      readiness,
      ...observe({ r, state }),
    };
  }
  if (!readiness.ready) {
    let recovery;
    try {
      recovery = rollback({ r, state });
    } catch (error) {
      recovery = { disposition: "ROLLBACK_FAILED", error: error.message, ...error.details };
    }
    if (recovery.disposition === "ROLLED_BACK_UNINITIALIZED") {
      state.rollbackCompleted = recovery;
      r.save(state);
    }
    // Rollback certifies connectivity safety only. Hardener initialization
    // remains unverified, so even a successful rollback fails main.
    return { ...recovery, readiness, policyClearance: false, failed: true };
  }
  const result = observe({ r, state });
  const effective = Object.values(result.checks).every((value) => value === true);
  if (effective) {
    state.mainVerified = result.observations.main;
    r.save(state);
  }
  return {
    disposition: effective ? "SHIM_EFFECTIVE" : "SHIM_INEFFECTIVE",
    readiness,
    ...result,
    failed: !effective,
  };
}
function post(r, state) {
  if (!state.environment.allowed) return { disposition: "NOT_APPLICABLE", reason: state.reason };
  const result = observe({ r, state, post: true });
  if (!state.mutationIntent)
    return { disposition: state.applicable ? "POST_OBSERVE" : "NOT_APPLICABLE", ...result };
  if (
    state.rollbackCompleted &&
    result.observations.owned?.present === false &&
    Array.isArray(result.observations.globalDns) &&
    !result.observations.globalDns.includes("127.0.0.1")
  )
    return {
      disposition: "POST_AGENT_PATH_LOST",
      ...result,
      priorRollback: state.rollbackCompleted,
      policyClearance: false,
      failed: true,
    };
  if (result.observations.listenerState === "absent") {
    let recovery;
    try {
      recovery = rollback({ r, state, post: true });
    } catch (error) {
      recovery = { disposition: "ROLLBACK_FAILED", error: error.message, ...error.details };
    }
    return {
      disposition: "POST_AGENT_PATH_LOST",
      recovery,
      beforeRollback: result,
      policyClearance: false,
      failed: true,
    };
  }
  const retained = Object.values(result.checks).every((value) => value === true);
  return {
    disposition: retained ? "POST_AGENT_PATH_RETAINED" : "POST_AGENT_PATH_LOST",
    ...result,
    fileRetained: true,
    failed: !retained,
  };
}
function runPhase(phase, r) {
  let state;
  let record;
  try {
    if (phase === "pre") record = pre(r);
    else {
      state = r.load();
      if (!state || state.schema !== 1 || !["apply", "observe"].includes(state.mode))
        throw new Error("missing or invalid pre state");
      record = phase === "main" ? main(r, state) : post(r, state);
    }
  } catch (error) {
    record = {
      disposition: phase === "post" ? "POST_AGENT_PATH_LOST" : "SHIM_UNVERIFIED",
      failed: true,
      error: error.message,
      ...error.details,
    };
  }
  // Console receipt precedes all errors, including output/evidence I/O errors.
  r.receipt(phase, {
    applicable: state?.applicable ?? record.applicable,
    applied: state?.applied ?? record.applied,
    ...record,
  });
  if (phase === "main") r.outputs(state, record.disposition);
  if (record.failed)
    throw new Error(`${phase}: ${record.disposition}${record.error ? `: ${record.error}` : ""}`);
  return record;
}
module.exports = { pre, install, main, post, runPhase };
