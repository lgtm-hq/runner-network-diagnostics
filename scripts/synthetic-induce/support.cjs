"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { runtime: originalRuntime } = require("../resolver-counterfactual/control.cjs");
const mainConfig = "/etc/systemd/resolved.conf";
const platformConfig = "/etc/systemd/resolved.conf.d/90-egress-proxy.conf";
const overrideConfig = "/etc/systemd/resolved.conf.d/99-ci1203-counterfactual.conf";
function probe(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    timeout: 20000,
    maxBuffer: 1024 * 1024,
  });
  return {
    status: result.status,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    error: result.error?.message || null,
  };
}
function checked(command, args) {
  const result = probe(command, args);
  if (result.status !== 0 || result.error)
    throw new Error(`${command}: ${result.error || result.stderr}`);
  return result.stdout;
}
function exists(file) {
  try {
    fs.lstatSync(file);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}
function runtime(name) {
  const original = originalRuntime();
  const out = path.join(process.env.RUNNER_TEMP, name);
  fs.mkdirSync(out, { recursive: true });
  const stateFile = path.join(out, "state.json");
  const io = {
    ...original.io,
    save(state) {
      const temp = `${stateFile}.tmp`;
      fs.writeFileSync(temp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
      fs.renameSync(temp, stateFile);
    },
    root(mode, token, profile = "override") {
      return JSON.parse(
        checked("sudo", [
          "-n",
          "timeout",
          "10",
          process.execPath,
          path.join(__dirname, "../resolver-counterfactual/root-file.cjs"),
          mode,
          token,
          profile,
        ]),
      );
    },
  };
  return {
    out,
    io,
    load: () => (exists(stateFile) ? JSON.parse(fs.readFileSync(stateFile, "utf8")) : null),
    receipt(phase, data) {
      const record = {
        synthetic: true,
        run: process.env.GITHUB_RUN_ID,
        attempt: process.env.GITHUB_RUN_ATTEMPT,
        replicate: process.env.SYNTHETIC_REPLICATE,
        timestamp: new Date().toISOString(),
        phase,
        ...data,
      };
      const content = `${JSON.stringify(record, null, 2)}\n`;
      fs.writeFileSync(path.join(out, `${phase}.json`), content, { flag: "wx" });
      console.log(
        `ci1203-synthetic-RECEIPT ${content.trim()}\nsha256=${createHash("sha256").update(content).digest("hex")}`,
      );
    },
  };
}
function observeConfig() {
  const args = ["5", "systemd-analyze", "cat-config", "systemd/resolved.conf"];
  const observation = probe("timeout", args);
  return {
    timestamp: new Date().toISOString(),
    command: ["timeout", ...args],
    ...observation,
    sha256: createHash("sha256").update(observation.stdout).digest("hex"),
  };
}
function topology(stage) {
  checked("bash", [path.join(__dirname, "../runner-probe/topology.sh"), stage]);
  return fs.readFileSync(
    path.join(process.env.RUNNER_TEMP, "ci1203", `topology-${stage}.txt`),
    "utf8",
  );
}
function measure(label, r) {
  const start = new Date().toISOString();
  const dns = r.io.dns();
  const domains = checked("sudo", ["-n", "timeout", "10", "resolvectl", "domain"]);
  const status = checked("sudo", ["-n", "timeout", "10", "cat", "/home/agent/agent.status"]);
  if (!status.split(/\r?\n/).includes("Initialized"))
    throw new Error("agent not initialized for oracle");
  const pid = checked("systemctl", [
    "show",
    "systemd-resolved",
    "--value",
    "-p",
    "ExecMainPID",
  ]).trim();
  const oracleStart = new Date().toISOString();
  const allowed = probe("timeout", ["10", "getent", "ahostsv4", "api.github.com"]);
  const denied = probe("timeout", ["10", "getent", "ahostsv4", "example.com"]);
  const oracleEnd = new Date().toISOString();
  const snapshot = topology("snapshot");
  fs.writeFileSync(path.join(r.out, `topology-${label}.txt`), snapshot);
  r.receipt(`oracle-${label}`, {
    start,
    oracleStart,
    oracleEnd,
    arm: r.load().arm,
    dns,
    domains,
    pid,
    status,
    allowed,
    denied,
  });
}
module.exports = {
  runtime,
  probe,
  checked,
  exists,
  topology,
  observeConfig,
  measure,
  mainConfig,
  platformConfig,
  overrideConfig,
};
