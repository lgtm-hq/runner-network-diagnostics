"use strict";
const { agentStatus, listenerState, globalValues, parseConfig } = require("./config.cjs");
const { MAIN, PLATFORM, TARGET } = require("./constants.cjs");
const { crosscheck } = require("./config-files.cjs");
const { bytes } = require("./root-file.cjs");

function waitInitialized(r) {
  const start = r.now();
  let attempts = 0;
  let last;
  while (r.now() - start < 30000) {
    last = r.status(Math.max(1, Math.floor(Math.min(2000, 30000 - (r.now() - start)))));
    attempts += 1;
    const status = agentStatus(last);
    if (r.now() - start <= 30000 && status === "initialized")
      return { ready: true, outcome: "INITIALIZED", attempts, elapsedMs: r.now() - start, last };
    if (status === "terminal")
      return {
        ready: false,
        outcome: "TERMINAL_STATUS",
        attempts,
        elapsedMs: r.now() - start,
        last,
      };
    const remaining = 30000 - (r.now() - start);
    if (remaining > 0) r.pause(Math.min(250, remaining));
  }
  return { ready: false, outcome: "DEADLINE_EXPIRED", attempts, elapsedMs: r.now() - start, last };
}
function identityMatches(left, right) {
  return (
    left?.present === true &&
    right?.present === true &&
    ["ino", "dev", "ctimeNs", "sha256"].every((key) => left[key] === right[key])
  );
}
function observe({ r, state, post = false }) {
  const observations = {};
  const checks = {};
  const readers = {
    status: r.status,
    listener: r.listener,
    dns: r.dns,
    domains: r.domains,
    main: r.main,
    platform: r.platform,
    service: r.service,
    config: r.config,
    files: r.files,
    ...(state.mutationIntent ? { owned: () => r.root("inspect", state.token) } : {}),
    ...(post ? { getent: r.getent } : {}),
  };
  for (const [name, read] of Object.entries(readers)) {
    try {
      observations[name] = read();
    } catch (error) {
      observations[`${name}Error`] = error.message;
    }
  }
  observations.agentState = observations.status ? agentStatus(observations.status) : "unknown";
  observations.listenerState = observations.listener
    ? listenerState(observations.listener)
    : "unknown";
  checks.agentInitialized = observations.agentState === "initialized";
  // A wildcard listener blocks removal, but does not prove the pinned agent.
  checks.localUdpListener =
    observations.listenerState === "present" &&
    /^UNCONN\s+\d+\s+\d+\s+127\.0\.0\.1:53\s+/m.test(observations.listener?.stdout || "");
  try {
    observations.globalDns = globalValues(observations.dns || "");
    checks.globalLocalDns =
      observations.globalDns.length === 1 && observations.globalDns[0] === "127.0.0.1";
  } catch (error) {
    observations.dnsParseError = error.message;
    checks.globalLocalDns = false;
  }
  try {
    checks.globalRouteDomain = globalValues(observations.domains || "").includes("~.");
  } catch (error) {
    observations.domainParseError = error.message;
    checks.globalRouteDomain = false;
  }
  const main = observations.main;
  checks.agentMainConfig = false;
  try {
    const source = parseConfig(`# ${MAIN}\n${main.content}`)[0];
    checks.agentMainConfig =
      main.content === "[Resolve]\nDNS=127.0.0.1\nDomains=~.\n" &&
      source.sections.every((section) => section === "Resolve") &&
      source.assignments.length === 2 &&
      source.assignments.some(
        (a) => a.section === "Resolve" && a.key === "DNS" && a.value === "127.0.0.1",
      ) &&
      source.assignments.some(
        (a) => a.section === "Resolve" && a.key === "Domains" && a.value === "~.",
      );
  } catch (error) {
    observations.mainParseError = error.message;
  }
  if (state.mutationIntent) {
    checks.ownedIdentityUnchanged = identityMatches(state.owned, observations.owned);
    checks.platformUnchanged = observations.platform?.sha256 === state.platform?.sha256;
    const match = /^ExecMainStartTimestampMonotonic=(\d+)$/m.exec(observations.service || "");
    checks.resolvedStartedAfterCreation = Boolean(
      match &&
      Number.isSafeInteger(state.createdBootUpperMicros) &&
      Number(match[1]) > state.createdBootUpperMicros,
    );
    try {
      const config = observations.config;
      if (!config || config.status !== 0 || config.error || config.stderr)
        throw new Error("incomplete cat-config");
      const sources = parseConfig(config.stdout);
      crosscheck({ config, sources, files: observations.files, main });
      checks.effectiveSourcesUnchanged =
        sources.length === 3 &&
        sources[0].path === MAIN &&
        sources[1].path === PLATFORM &&
        sources[2].path === TARGET &&
        observations.owned.content === bytes(state.token) &&
        sources[0].body.join("\n").trimEnd() === main.content.trimEnd() &&
        sources[1].body.join("\n").trimEnd() === observations.platform.content.trimEnd() &&
        sources[2].body.join("\n").trimEnd() === observations.owned.content.trimEnd();
    } catch (error) {
      observations.configParseError = error.message;
      checks.effectiveSourcesUnchanged = false;
    }
  }
  if (post) {
    checks.getentSucceeded =
      observations.getent?.status === 0 &&
      !observations.getent.error &&
      !observations.getent.stderr &&
      Boolean(observations.getent.stdout.trim());
    if (state.mainVerified)
      checks.verifiedMainUnchanged = main?.sha256 === state.mainVerified.sha256;
  }
  return { observations, checks };
}

function rollback({ r, state, post = false }) {
  const result = { observations: {}, checks: {} };
  const { observations, checks } = result;
  try {
    observations.status = r.status();
    observations.listener = r.listener();
    observations.agentState = agentStatus(observations.status);
    observations.listenerState = listenerState(observations.listener);
    // Successful empty `ss` is positive absence, even during startup. Failure to
    // inspect is not absence. Initialized-but-dead is eligible only in post.
    if (
      observations.listenerState !== "absent" ||
      !(
        ["uninitialized", "terminal"].includes(observations.agentState) ||
        (post && observations.agentState === "initialized")
      )
    )
      return { ...result, disposition: "SHIM_UNVERIFIED", refused: true };
    observations.dnsBefore = r.dns();
    observations.globalDnsBefore = globalValues(observations.dnsBefore);
    // Verify ownership before retrying removals. Token-only recovery is allowed
    // when privileged creation succeeded but its acknowledgement was lost.
    observations.ownedBefore = r.root("inspect", state.token);
    if (
      state.owned &&
      observations.ownedBefore.present !== false &&
      !identityMatches(state.owned, observations.ownedBefore)
    )
      throw new Error("refusing rollback of replaced owned inode");
    for (let attempt = 0; attempt < 2; attempt += 1) {
      observations.statusAtRemoval = r.status();
      observations.listenerAtRemoval = r.listener();
      const statusAtRemoval = agentStatus(observations.statusAtRemoval);
      if (
        listenerState(observations.listenerAtRemoval) !== "absent" ||
        !(
          ["uninitialized", "terminal"].includes(statusAtRemoval) ||
          (post && statusAtRemoval === "initialized")
        )
      )
        return { ...result, disposition: "SHIM_UNVERIFIED", refused: true };
      try {
        r.root("remove", state.token);
      } catch (error) {
        observations[`removeError${attempt}`] = error.message;
      }
      observations.ownedAfter = r.root("inspect", state.token);
      if (observations.ownedAfter.present === false) break;
    }
    checks.removalVerified = observations.ownedAfter?.present === false;
    if (!checks.removalVerified) return { ...result, disposition: "ROLLBACK_FAILED" };
    observations.dnsAtReload = r.dns();
    if (globalValues(observations.dnsAtReload).includes("127.0.0.1")) {
      observations.serviceBefore = r.service();
      r.restart();
      observations.serviceAfter = r.service();
      const pid = (value) => /^ExecMainPID=([1-9]\d*)$/m.exec(value)?.[1];
      checks.restartVerified = Boolean(
        pid(observations.serviceAfter) &&
        pid(observations.serviceBefore) &&
        pid(observations.serviceBefore) !== pid(observations.serviceAfter),
      );
    }
    observations.dnsAfter = r.dns();
    checks.noDeadLocalDns = !globalValues(observations.dnsAfter).includes("127.0.0.1");
    observations.configAfter = r.config();
    observations.filesAfter = r.files();
    observations.mainAfter = r.main();
    const remaining = parseConfig(observations.configAfter.stdout);
    crosscheck({
      config: observations.configAfter,
      sources: remaining,
      files: observations.filesAfter,
      main: observations.mainAfter,
    });
    let expectedDns = [];
    for (const source of remaining) {
      for (const entry of source.assignments) {
        if (entry.section !== "Resolve" || entry.key !== "DNS") continue;
        if (!entry.value) expectedDns = [];
        else expectedDns.push(...entry.value.split(/\s+/));
      }
    }
    observations.expectedGlobalDnsAfter = [...new Set(expectedDns)];
    checks.remainingConfigDnsMatches =
      JSON.stringify(globalValues(observations.dnsAfter)) ===
      JSON.stringify(observations.expectedGlobalDnsAfter);
    observations.getent = r.getent();
    checks.getentSucceeded =
      observations.getent.status === 0 &&
      !observations.getent.error &&
      !observations.getent.stderr &&
      Boolean(observations.getent.stdout.trim());
    return {
      ...result,
      disposition: Object.values(checks).every(Boolean)
        ? "ROLLED_BACK_UNINITIALIZED"
        : "ROLLBACK_FAILED",
    };
  } catch (error) {
    error.details = result;
    throw error;
  }
}
module.exports = { waitInitialized, identityMatches, observe, rollback };
