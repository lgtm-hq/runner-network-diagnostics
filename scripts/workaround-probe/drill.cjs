"use strict";
// This is the sole native probe module allowed to import the portable shim.
const { runtime: shimRuntime } = require("../agent-dns-shim/runtime.cjs");
const control = require("../agent-dns-shim/control.cjs");
const { rollback } = require("../agent-dns-shim/lifecycle.cjs");
const {
  parseConfig,
  listenerState,
  agentStatus,
  globalValues,
} = require("../agent-dns-shim/config.cjs");
const { MAIN } = require("./support.cjs");
const { crosscheck } = require("../agent-dns-shim/config-files.cjs");

const pid = (service) => /^ExecMainPID=([1-9]\d*)$/m.exec(service)?.[1];

function safeHost({ r, probe }) {
  const observations = { environment: r.environment() };
  const checks = { environment: observations.environment.allowed === true };
  if (!checks.environment) return { observations, checks, safe: false };
  observations.listener = r.listener();
  observations.status = r.status();
  observations.config = r.config();
  observations.main = r.main();
  observations.files = r.files();
  observations.pathPresent = r.pathPresent();
  observations.dns = r.dns();
  observations.service = r.service();
  checks.listenerAbsent = listenerState(observations.listener) === "absent";
  checks.agentAbsent =
    agentStatus(observations.status) === "uninitialized" &&
    observations.status.status === 1 &&
    /No such file or directory/.test(observations.status.stderr || "");
  checks.noOwnedPath = observations.pathPresent === false;
  checks.pidKnown = Boolean(pid(observations.service));
  checks.noDeadLocalDns = !globalValues(observations.dns).includes("127.0.0.1");
  const config = observations.config;
  checks.ordinaryConfig = false;
  if (config.status === 0 && !config.error && !config.stderr && config.stdout.endsWith("\n")) {
    const sources = parseConfig(config.stdout);
    crosscheck({ config, sources, files: observations.files, main: observations.main });
    checks.ordinaryConfig =
      sources.length === 1 &&
      observations.files.effective.length === 0 &&
      sources[0].path === MAIN &&
      sources[0].assignments.length === 0 &&
      sources[0].sections.every((name) => name === "Resolve") &&
      sources[0].body.join("\n").trimEnd() === observations.main.content.trimEnd();
  }
  for (const unit of [
    "systemd-resolved",
    "egress-dns-resolver",
    "egress-outbound-proxy",
    "agent.service",
  ]) {
    const result = probe(
      "timeout",
      ["3", "systemctl", "show", unit, "--value", "-p", "ActiveState"],
      { timeoutMs: 4000 },
    );
    observations[unit] = result;
    checks[unit] =
      result.status === 0 &&
      !result.error &&
      !result.stderr &&
      result.stdout.trim() === (unit === "systemd-resolved" ? "active" : "inactive");
  }
  const target = probe("timeout", ["3", "readlink", "-f", "/etc/resolv.conf"], { timeoutMs: 4000 });
  observations.resolverTarget = target;
  checks.ordinaryResolver =
    target.status === 0 &&
    !target.error &&
    !target.stderr &&
    target.stdout.trim() === "/run/systemd/resolve/stub-resolv.conf";
  if (Object.values(checks).every((value) => value === true)) {
    observations.getent = r.getent();
    checks.baselineConnectivity =
      observations.getent.status === 0 &&
      !observations.getent.error &&
      !observations.getent.stderr &&
      Boolean(observations.getent.stdout.trim());
  }
  return { observations, checks, safe: Object.values(checks).every((value) => value === true) };
}

function runDrill({
  r,
  probe,
  install = control.install,
  runMain = (runtime) => control.runPhase("main", runtime),
}) {
  if (typeof install !== "function")
    return {
      disposition: "DRILL_NOT_EXECUTED",
      inconclusive: true,
      reason: "interface gap: control.install(r, state) is not exported",
    };
  let before;
  try {
    before = safeHost({ r, probe });
  } catch (error) {
    return { disposition: "DRILL_NOT_EXECUTED", inconclusive: true, reason: error.message };
  }
  if (!before.safe) return { disposition: "DRILL_NOT_EXECUTED", inconclusive: true, before };
  const record = { before, disposition: "DRILL_FAILED", passed: false };
  const state = {
    schema: 1,
    mode: "apply",
    environment: before.observations.environment,
    applicable: true,
    applied: false,
    mutationIntent: false,
    main: before.observations.main,
    reason: "DRILL_OWNED_INSTALL_ONLY",
  };
  const originalReceipt = r.receipt;
  r.receipt = (phase, receipt) => {
    if (phase === "main") record.mainReceipt = receipt;
    originalReceipt(phase, receipt);
  };
  try {
    r.save(state, true);
    record.installer = install(r, state);
    if (record.installer?.failed) throw new Error("portable installer reported failure");
    record.installed = r.root("inspect", state.token);
    if (!state.applied || record.installed.present !== true)
      throw new Error("drill owned installation unconfirmed");
    // The only emulation: resolved's reload stands in for a failed hardener.
    // Recheck positive absence immediately before this deliberate dead path.
    if (listenerState(r.listener()) !== "absent" || agentStatus(r.status()) !== "uninitialized")
      throw new Error("agent appeared before drill restart");
    r.restart();
    record.inducedService = r.service();
    record.inducedDns = r.dns();
    if (
      !globalValues(record.inducedDns).includes("127.0.0.1") ||
      !pid(record.inducedService) ||
      pid(record.inducedService) === pid(before.observations.service)
    )
      throw new Error("drill induction not verified");
    try {
      runMain(r);
      record.mainFailedAsExpected = false;
      record.mainExitCode = 0;
    } catch (error) {
      record.mainFailedAsExpected = true;
      // Same contract as the shim's unchanged entry: a runPhase throw exits 1.
      record.mainExitCode = 1;
      record.mainError = error.message;
    }
    record.after = {
      owned: r.root("inspect", state.token),
      dns: r.dns(),
      service: r.service(),
      main: r.main(),
      getent: r.getent(),
    };
    const after = record.after;
    record.checks = {
      failClosedMain:
        record.mainFailedAsExpected &&
        record.mainReceipt?.failed === true &&
        record.mainReceipt?.policyClearance === false,
      safetyReceipt: record.mainReceipt?.disposition === "ROLLED_BACK_UNINITIALIZED",
      ownedAbsent: after.owned.present === false,
      pidChanged: Boolean(pid(after.service) && pid(after.service) !== pid(record.inducedService)),
      dnsRestored:
        JSON.stringify(globalValues(after.dns)) ===
        JSON.stringify(globalValues(before.observations.dns)),
      mainUnchanged: after.main.sha256 === before.observations.main.sha256,
      connectivity:
        after.getent.status === 0 &&
        !after.getent.error &&
        !after.getent.stderr &&
        Boolean(after.getent.stdout.trim()),
    };
    record.passed = Object.values(record.checks).every((value) => value === true);
    record.disposition = record.passed ? "DRILL_PASS" : "DRILL_FAILED";
  } catch (error) {
    record.error = error.message;
  } finally {
    r.receipt = originalReceipt;
    // Unexpected paths must restore only our positively owned mutation using
    // the unchanged shim safety rules. Never touch a foreign/native drop-in.
    if (!record.passed && state.mutationIntent) {
      try {
        const owned = r.root("inspect", state.token);
        if (
          owned.present === false &&
          JSON.stringify(globalValues(r.dns())) ===
            JSON.stringify(globalValues(before.observations.dns))
        )
          record.recovery = { disposition: "ALREADY_RESTORED", owned };
        else record.recovery = rollback({ r, state });
      } catch (error) {
        record.recovery = { disposition: "ROLLBACK_FAILED", error: error.message };
      }
    }
  }
  return record;
}

function execute(nativeRuntime) {
  const r = shimRuntime();
  r.mode = "apply";
  const record = runDrill({ r, probe: nativeRuntime.probe });
  nativeRuntime.write("drill.json", record);
  if (!record.passed)
    throw new Error(
      record.inconclusive ? "drill not executed: INCONCLUSIVE" : "rollback drill failed",
    );
}

module.exports = { safeHost, runDrill, execute };
