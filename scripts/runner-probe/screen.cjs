"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { spawnSync } = require("node:child_process");

function classify({ region, target, resolverUnit, proxyUnit, listener }) {
  const reasons = [];
  if (region === "westus2") reasons.push("historically affected region");
  if (target !== "/run/systemd/resolve/stub-resolv.conf")
    reasons.push("non-stub or unknown resolver topology");
  if (resolverUnit !== "inactive") reasons.push("resolver experiment active or unknown");
  if (proxyUnit !== "inactive") reasons.push("proxy experiment active or unknown");
  if (listener !== "absent") reasons.push("experiment listener present or unknown");
  if (region === "unknown" || !/^[a-z][a-z0-9]+$/.test(region)) reasons.push("region unavailable");
  return { candidate: reasons.length > 0, reasons };
}

function directory() {
  if (!process.env.RUNNER_TEMP) throw new Error("RUNNER_TEMP is required");
  return path.join(process.env.RUNNER_TEMP, "ci1203");
}

function collect(stage) {
  const result = spawnSync("bash", [path.join(__dirname, "topology.sh"), stage], {
    stdio: "inherit",
    timeout: 60000,
  });
  if (result.error || result.status !== 0) throw new Error(`topology ${stage} failed`);
}

function prepare() {
  const out = directory();
  fs.mkdirSync(out, { recursive: true });
  if (fs.existsSync(path.join(out, "selection.json"))) throw new Error("screen already exists");
  collect("before");
  const read = (name) => fs.readFileSync(path.join(out, `${name}.txt`), "utf8").trim();
  const facts = {
    region: read("region"),
    target: read("resolver-target"),
    resolverUnit: read("resolver-unit"),
    proxyUnit: read("proxy-unit"),
    listener: read("listener"),
  };
  const selection = { ...classify(facts), facts, timestamp: new Date().toISOString() };
  fs.writeFileSync(path.join(out, "selection.json"), `${JSON.stringify(selection, null, 2)}\n`);
  console.log(JSON.stringify(selection));
  if (selection.candidate) require("../../vendor/network-probe/entry.cjs").execute("prepare");
}

function selected() {
  return JSON.parse(fs.readFileSync(path.join(directory(), "selection.json"), "utf8"));
}

function execute(mode) {
  const selection = selected();
  if (mode === "prepare") {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `candidate=${selection.candidate}\n`);
    if (selection.candidate) require("../../vendor/network-probe/entry.cjs").execute("confirm");
    return;
  }
  if (!selection.candidate) {
    if (mode !== "finish") throw new Error("operation requested on screened-out runner");
    fs.writeFileSync(
      path.join(directory(), "disposition.txt"),
      "NOT_SAMPLED: no detailed capture; not evidence of recovery or healthy enforcement.\n",
    );
  } else {
    if (mode === "snapshot") collect(mode);
    if (mode === "finish") {
      try {
        collect(mode);
      } catch (error) {
        console.error(error.message);
        process.exitCode = 1;
      }
    }
    // Even a failed final topology read must not prevent capture freeze.
    const priorFailure = process.exitCode;
    require("../../vendor/network-probe/entry.cjs").execute(mode);
    if (priorFailure) process.exitCode = priorFailure;
  }
  if (mode === "finish") {
    const out = directory();
    const manifest = fs
      .readdirSync(out)
      .filter((name) => /\.(txt|json)$/.test(name))
      .sort()
      .map(
        (name) =>
          `${createHash("sha256")
            .update(fs.readFileSync(path.join(out, name)))
            .digest("hex")}  ${name}\n`,
      )
      .join("");
    fs.writeFileSync(path.join(out, "SHA256SUMS"), manifest);
    console.log(manifest);
  }
}

module.exports = { classify, prepare, execute };
