"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { createHash, randomBytes } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const mainConfig = "/etc/systemd/resolved.conf";
const platformConfig = "/etc/systemd/resolved.conf.d/90-egress-proxy.conf";
function globalDns(text) {
  const lines = text.split(/\r?\n/).filter((line) => line.startsWith("Global:"));
  if (lines.length !== 1) throw new Error("global DNS observation unavailable");
  return lines[0].slice("Global:".length).trim();
}
function applicable(selection, topology) {
  const facts = selection.facts;
  if (
    !selection.candidate ||
    !facts ||
    facts.region !== "westus2" ||
    facts.target !== "/etc/resolv.conf" ||
    facts.resolverUnit !== "active" ||
    facts.proxyUnit !== "active" ||
    facts.listener !== "present"
  )
    return false;
  const section = topology
    .split("EFFECTIVE RESOLVED CONFIG (DNS fields only)\n")[1]
    ?.split(/\n(?:NETWORK FILE|UNIT) /)[0];
  if (!section) return false;
  // cat-config headers are absolute .conf paths. The collector also retains
  // ordinary comments such as "# /etc/ if ..."; these are not source headers.
  const fields = section
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && (!line.startsWith("#") || /^# \/.+\.conf$/.test(line)));
  return fields.join("\n") === `# ${mainConfig}\n# ${platformConfig}\nDNS=`;
}
function prepare({ sample, selection, topology, io }) {
  if (!/^(?:[1-9]|1[0-9]|2[0-4])$/.test(sample)) throw new Error("sample must be 1..24");
  const state = { sample: Number(sample), arm: Number(sample) % 2 ? "treatment" : "control" };
  io.save(state);
  if (state.arm === "control" || !applicable(selection, topology)) {
    state.disposition = state.arm === "control" ? "CONTROL_UNCHANGED" : "NOT_APPLICABLE";
    io.save(state);
    return state;
  }
  state.originalDns = globalDns(io.dns());
  if (state.originalDns !== "") throw new Error("baseline global DNS is not empty");
  state.originalMain = io.hash(mainConfig);
  state.originalPlatform = io.hash(platformConfig);
  state.token = io.token();
  state.mutationIntent = true;
  // Persist intent before privileged creation: a lost create acknowledgement still cleans up.
  io.save(state);
  io.root("create", state.token);
  state.disposition = "OVERRIDE_INSTALLED_NO_RESTART";
  io.save(state);
  return state;
}
function absent(io, token) {
  const observation = io.root("inspect", token);
  if (typeof observation.present !== "boolean") throw new Error("override absence unverified");
  return !observation.present;
}
function cleanup({ phase, state, io }) {
  if (!["guard", "fallback"].includes(phase)) throw new Error("invalid cleanup phase");
  if (!state?.mutationIntent) return { phase, disposition: "NO_MUTATION" };
  if (phase === "guard") {
    const { removed } = io.root("remove", state.token);
    if (!absent(io, state.token)) throw new Error("guard left owned override present");
    state.guardRemovalVerified = true;
    io.save(state);
    return { phase, removed, disposition: "REMOVED_WITHOUT_RESTART" };
  }
  // Durable mutation intent means reload is required unless the guard positively
  // verified removal BEFORE hardener post. Determine that before unlinking:
  // a lost unlink acknowledgement must not erase the need to reload live state.
  const reloadRequired = !state.guardRemovalVerified;
  const errors = [];
  let removed = false;
  function attemptRemoval() {
    try {
      removed = Boolean(io.root("remove", state.token).removed) || removed;
    } catch (error) {
      errors.push(error.message);
      console.error(`COUNTERFACTUAL_REMOVE_ERROR: ${error.message}`);
    }
  }
  attemptRemoval();
  // Inspect checks ownership if present. Foreign/replaced files abort inspection;
  // only a positively owned remaining file gets one bounded reconciliation attempt.
  if (!absent(io, state.token)) {
    attemptRemoval();
    if (!absent(io, state.token)) throw new Error("owned override remains after cleanup");
  }
  const restarted = reloadRequired || removed || errors.length > 0;
  if (restarted) io.restart();
  const dns = globalDns(io.dns());
  if (
    dns !== state.originalDns ||
    io.hash(mainConfig) !== state.originalMain ||
    io.hash(platformConfig) !== state.originalPlatform
  )
    throw new Error("original resolver state not restored");
  if (errors.length)
    throw new Error(`original DNS restored after cleanup error: ${errors.join("; ")}`);
  return { phase, removed, restarted, globalDns: dns, disposition: "RESTORATION_VERIFIED" };
}

function command(executable, args) {
  const result = spawnSync(executable, args, {
    encoding: "utf8",
    timeout: 20000,
    maxBuffer: 1024 * 1024,
  });
  if (result.error || result.status !== 0)
    throw new Error(
      `${path.basename(executable)} failed: ${result.error?.message || result.stderr}`,
    );
  return result.stdout;
}
function runtime() {
  if (!process.env.RUNNER_TEMP) throw new Error("RUNNER_TEMP required");
  const out = path.join(process.env.RUNNER_TEMP, "ci1203-counterfactual");
  fs.mkdirSync(out, { recursive: true });
  const stateFile = path.join(out, "state.json");
  const io = {
    save(state) {
      const temp = `${stateFile}.tmp`;
      fs.writeFileSync(temp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
      fs.renameSync(temp, stateFile);
    },
    dns: () => command("sudo", ["-n", "timeout", "10", "resolvectl", "dns"]),
    hash: (file) => createHash("sha256").update(fs.readFileSync(file)).digest("hex"),
    token: () => randomBytes(32).toString("hex"),
    root: (mode, token) =>
      JSON.parse(
        command("sudo", [
          "-n",
          "timeout",
          "10",
          process.execPath,
          path.join(__dirname, "root-file.cjs"),
          mode,
          token,
        ]),
      ),
    restart: () =>
      command("sudo", ["-n", "timeout", "10", "systemctl", "restart", "systemd-resolved"]),
  };
  const load = () =>
    fs.existsSync(stateFile) ? JSON.parse(fs.readFileSync(stateFile, "utf8")) : null;
  function receipt(phase, data) {
    const record = { timestamp: new Date().toISOString(), phase, ...data };
    const content = `${JSON.stringify(record, null, 2)}\n`;
    fs.writeFileSync(path.join(out, `${phase}.json`), content, { flag: "wx" });
    console.log(
      `COUNTERFACTUAL_RECEIPT ${content.trim()}\nsha256=${createHash("sha256").update(content).digest("hex")}`,
    );
  }
  return { out, io, load, receipt };
}
function entry(phase, setup = runtime) {
  const { io, load, receipt } = setup();
  try {
    if (phase === "pre") {
      if (load()) throw new Error("counterfactual state already exists");
      const baseline = path.join(process.env.RUNNER_TEMP, "ci1203");
      const state = prepare({
        sample: process.env.INPUT_SAMPLE,
        selection: JSON.parse(fs.readFileSync(path.join(baseline, "selection.json"), "utf8")),
        topology: fs.readFileSync(path.join(baseline, "topology-before.txt"), "utf8"),
        io,
      });
      receipt(phase, { arm: state.arm, disposition: state.disposition });
    } else if (phase === "main") {
      const state = load();
      if (!state) throw new Error("counterfactual pre did not save state");
      if (state.mutationIntent) {
        if (
          state.disposition !== "OVERRIDE_INSTALLED_NO_RESTART" ||
          globalDns(io.dns()) !== "127.0.0.1"
        )
          throw new Error("override not effective after hardener pre");
      }
      receipt(phase, { arm: state.arm, disposition: state.disposition });
    } else if (phase === "register-guard") {
      // This action deliberately has no pre: registering post in main puts it above
      // hardener's pre-registered post in the runner's LIFO stack.
      receipt(phase, { disposition: "GUARD_MAIN_REACHED" });
    } else {
      receipt(phase, cleanup({ phase, state: load(), io }));
    }
  } catch (error) {
    console.error(`COUNTERFACTUAL_FAILURE phase=${phase}: ${error.message}`);
    process.exitCode = 1;
  }
}
module.exports = { globalDns, applicable, prepare, cleanup, entry, runtime };
