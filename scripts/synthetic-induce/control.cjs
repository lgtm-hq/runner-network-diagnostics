"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { applicable, globalDns } = require("../resolver-counterfactual/control.cjs");
const { classify } = require("../runner-probe/screen.cjs");
const {
  runtime,
  checked,
  exists,
  topology,
  observeConfig,
  measure,
  mainConfig,
  platformConfig,
  overrideConfig,
} = require("./support.cjs");
function ordinaryConfig(observation) {
  if (
    !observation ||
    observation.status !== 0 ||
    observation.error ||
    typeof observation.stdout !== "string" ||
    typeof observation.stderr !== "string" ||
    observation.stderr.trim()
  )
    return false;
  const lines = observation.stdout.split(/\r?\n/).map((line) => line.trim());
  const headers = lines.filter((line) => /^# \/.+\.conf$/.test(line));
  if (headers.length !== 1 || headers[0] !== `# ${mainConfig}`) return false;
  // Accept only the ordinary main file's comments and [Resolve] section. This
  // rejects all active settings (including "DNS = ..."), continuations and any
  // unknown source/section instead of implementing a partial systemd parser.
  return lines.every((line) => !line || /^[#;]/.test(line) || line === "[Resolve]");
}
function inducibility({ hosted, facts, configObservation, dns, platformExists, overrideExists }) {
  const reasons = [];
  if (hosted !== "github-hosted") reasons.push("not positively github-hosted");
  for (const [field, wanted] of Object.entries({
    target: "/run/systemd/resolve/stub-resolv.conf",
    resolverUnit: "inactive",
    proxyUnit: "inactive",
    listener: "absent",
  }))
    if (facts[field] !== wanted) reasons.push(`unexpected ${field}`);
  if (!ordinaryConfig(configObservation))
    reasons.push("complete ordinary resolver config unverified");
  if (platformExists || overrideExists) reasons.push("platform/override path already present");
  if (globalDns(dns) !== "" || !/^Link .*:.*\b168\.63\.129\.16\b/m.test(dns))
    reasons.push("unexpected original DNS routing");
  return reasons;
}
function prepare({
  arm,
  facts,
  config,
  configObservation,
  selection,
  hosted,
  io,
  platformExists,
  overrideExists,
}) {
  if (!["C0", "I1", "I2", "I3"].includes(arm)) throw new Error("invalid synthetic arm");
  const state = { synthetic: true, arm, inScope: false };
  io.save(state);
  state.realEligible = applicable(selection, config);
  state.configObservation = configObservation;
  const dns = io.dns();
  state.reasons = inducibility({
    hosted,
    facts,
    configObservation,
    dns,
    platformExists,
    overrideExists,
  });
  if (state.realEligible || state.reasons.length) {
    state.disposition = state.realEligible
      ? "REAL_TOPOLOGY_ENCOUNTERED"
      : "SYNTHETIC_NOT_INDUCIBLE";
    io.save(state);
    return state;
  }
  state.originalMain = io.hash(mainConfig);
  state.originalDns = globalDns(dns);
  state.inScope = true;
  state.disposition = "SYNTHETIC_BASELINE";
  if (arm !== "C0") {
    state.token = io.token();
    state.mutationIntent = true;
    io.save(state);
    io.root("create", state.token, "reset");
    state.disposition = "SYNTHETIC_INDUCED";
  }
  io.save(state);
  return state;
}
function restore({ state, io, overrideExists, resolve }) {
  if (!state?.inScope) return { disposition: "SYNTHETIC_NO_MUTATION" };
  const errors = [];
  if (state.mutationIntent) {
    function remove() {
      try {
        io.root("remove", state.token, "reset");
      } catch (e) {
        errors.push(e.message);
        console.error(`ci1203-synthetic-REMOVE_ERROR: ${e.message}`);
      }
    }
    remove();
    let observation = io.root("inspect", state.token, "reset");
    if (typeof observation.present !== "boolean") throw new Error("synthetic absence unverified");
    if (observation.present) {
      remove();
      observation = io.root("inspect", state.token, "reset");
    }
    if (observation.present !== false) throw new Error("synthetic reset remains");
    if (overrideExists())
      throw new Error("override still present after treatment fallback; refusing restart");
    io.restart();
  }
  if (
    overrideExists() ||
    io.hash(mainConfig) !== state.originalMain ||
    globalDns(io.dns()) !== state.originalDns ||
    !/^Link .*:.*\b168\.63\.129\.16\b/m.test(io.dns())
  )
    throw new Error("synthetic original state not restored");
  const resolution = resolve();
  if (resolution.status !== 0 || !resolution.stdout.trim())
    throw new Error("post-cleanup resolution failed");
  if (errors.length)
    throw new Error(`synthetic restored after cleanup errors: ${errors.join("; ")}`);
  return { disposition: "SYNTHETIC_RESTORATION_VERIFIED", arm: state.arm, resolution };
}
function entry(
  phase,
  setup = () => runtime("ci1203-synthetic-induce"),
  collectBaseline = () => require("../../vendor/network-probe/entry.cjs").execute("prepare"),
) {
  const r = setup();
  try {
    if (phase === "pre") {
      if (r.load()) throw new Error("synthetic state already exists");
      const config = topology("before");
      const dir = path.join(process.env.RUNNER_TEMP, "ci1203");
      const read = (f) => fs.readFileSync(path.join(dir, `${f}.txt`), "utf8").trim();
      const facts = {
        region: read("region"),
        target: read("resolver-target"),
        resolverUnit: read("resolver-unit"),
        proxyUnit: read("proxy-unit"),
        listener: read("listener"),
      };
      const selection = { ...classify(facts), facts };
      // A diagnostic excerpt is never authorization for mutation. Retain the
      // separate bounded full read, including status and stderr, even on refusal.
      const configObservation = observeConfig();
      fs.writeFileSync(path.join(r.out, "resolved-config-before.txt"), configObservation.stdout);
      r.receipt("config-observation", configObservation);
      // Collect every arm without weakening native runner selection or eligibility.
      collectBaseline();
      if (process.exitCode) throw new Error("synthetic baseline capture failed");
      const state = prepare({
        arm: process.env.INPUT_ARM,
        hosted: process.env.INPUT_HOSTED,
        facts,
        config,
        configObservation,
        selection,
        io: r.io,
        platformExists: (r.pathExists || exists)(platformConfig),
        overrideExists: (r.pathExists || exists)(overrideConfig),
      });
      state.originalPid = checked("systemctl", [
        "show",
        "systemd-resolved",
        "--value",
        "-p",
        "ExecMainPID",
      ]).trim();
      r.io.save(state);
      fs.writeFileSync(path.join(r.out, "topology-induced.txt"), topology("snapshot"));
      r.receipt("pre", state);
    } else if (phase === "main") {
      const state = r.load();
      if (!state) throw new Error("synthetic pre did not save state");
      fs.appendFileSync(process.env.GITHUB_OUTPUT, `in_scope=${state.inScope}\n`);
      if (state.inScope) measure("A", r);
      else r.receipt("oracle-A", { disposition: state.disposition });
    } else if (phase === "post") {
      r.receipt(
        "post",
        restore({
          state: r.load(),
          io: r.io,
          overrideExists: () => exists(overrideConfig),
          resolve: () =>
            require("./support.cjs").probe("timeout", ["10", "getent", "ahostsv4", "github.com"]),
        }),
      );
    } else throw new Error("invalid synthetic phase");
  } catch (error) {
    console.error(`ci1203-synthetic-FAILURE phase=${phase}: ${error.message}`);
    process.exitCode = 1;
  }
}
module.exports = { ordinaryConfig, inducibility, prepare, restore, entry };
