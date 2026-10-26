"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { MAIN, PLATFORM, succeeded } = require("./support.cjs");
const { select } = require("./selection.cjs");
const { measure } = require("./oracle.cjs");
const { effectiveSources } = require("./config.cjs");

function prepare(r) {
  const arm = process.env.INPUT_ARM;
  if (!["T", "C"].includes(arm)) throw new Error("arm must be assigned T or C before placement");
  const errors = [];
  try {
    r.topology("before");
  } catch (error) {
    errors.push(error.message);
  }
  const read = (name) => {
    try {
      return fs.readFileSync(path.join(r.root, "ci1203", `${name}.txt`), "utf8").trim();
    } catch (error) {
      errors.push(`${name}: ${error.code || error.message}`);
      return "unknown";
    }
  };
  const config = r.probe(
    "timeout",
    ["5", "systemd-analyze", "cat-config", "systemd/resolved.conf"],
    { timeoutMs: 6000 },
  );
  const container = r.probe("timeout", ["3", "systemd-detect-virt", "--container", "--quiet"], {
    timeoutMs: 4000,
  });
  const systemd = r.probe("timeout", ["3", "test", "-d", "/run/systemd/system"], {
    timeoutMs: 4000,
  });
  const pid1 = r.file("/proc/1/comm");
  const markers = [r.file("/.dockerenv"), r.file("/run/.containerenv")];
  const facts = {
    region: read("region"),
    target: read("resolver-target"),
    resolverUnit: read("resolver-unit"),
    proxyUnit: read("proxy-unit"),
    listener: read("listener"),
    resolvConf: r.file("/etc/resolv.conf").content,
  };
  try {
    facts.effectiveSources = (r.effectiveSources || effectiveSources)();
  } catch (error) {
    facts.sourceInventoryError = error.message;
  }
  const resolved = r.probe(
    "timeout",
    ["3", "systemctl", "show", "systemd-resolved", "--value", "-p", "ActiveState"],
    { timeoutMs: 4000 },
  );
  facts.resolvedActive =
    succeeded(resolved) && !resolved.stderr ? resolved.stdout.trim() : "unknown";
  const privilege = r.probe("sudo", ["-n", "true"], { timeoutMs: 3000 });
  facts.sudo = succeeded(privilege) && !privilege.stderr;
  const live = {};
  for (const [key, command] of [
    ["globalDns", "dns"],
    ["globalDomains", "domain"],
  ]) {
    const result = r.probe("timeout", ["3", "resolvectl", command], { timeoutMs: 4000 });
    live[key] = result;
    const lines = result.stdout.split(/\r?\n/).filter((line) => line.startsWith("Global:"));
    facts[key] =
      succeeded(result) && !result.stderr && lines.length === 1 ? lines[0].slice(7).trim() : null;
  }
  // resolv.conf may legitimately be a symlink on ordinary hosts. Follow it only
  // through a bounded command observation; eligibility still requires self.
  const resolvConf = r.probe("timeout", ["3", "cat", "/etc/resolv.conf"], { timeoutMs: 4000 });
  facts.resolvConf = succeeded(resolvConf) ? resolvConf.stdout : "";
  const nonContainer =
    container.status === 1 &&
    !container.error &&
    container.stdout === "" &&
    !container.stderr &&
    succeeded(systemd) &&
    pid1.content?.trim() === "systemd" &&
    markers.every((marker) => marker.present === false);
  const selection = select({
    hosted: process.env.INPUT_HOSTED,
    os: process.env.RUNNER_OS,
    container: nonContainer
      ? false
      : succeeded(container) || markers.some((marker) => marker.present === true)
        ? true
        : null,
    facts,
    config,
  });
  selection.platformEvidence = { container, systemd, pid1, markers, resolved, privilege, live };
  Object.assign(selection, {
    native: true,
    arm,
    replicate: process.env.WORKAROUND_REPLICATE,
    run: process.env.GITHUB_RUN_ID,
    attempt: process.env.GITHUB_RUN_ATTEMPT,
    timestamp: new Date().toISOString(),
  });
  // Freeze placement before starting capture, performing DNS queries or reading
  // any hardener/shim outcome. The same classification is included in upload.
  r.write("selection.json", selection);
  fs.mkdirSync(path.join(r.root, "ci1203"), { recursive: true });
  fs.writeFileSync(
    path.join(r.root, "ci1203", "selection.json"),
    `${JSON.stringify(selection, null, 2)}\n`,
    { flag: "wx" },
  );
  const baseline = r.write("baseline.json", {
    timestamp: new Date().toISOString(),
    main: r.file(MAIN),
    platform: r.file(PLATFORM),
    config,
    resolvConf,
  });
  if (!baseline.main.sha256 || !succeeded(config) || config.stderr)
    errors.push("pre baseline main/config unavailable");
  if (selection.eligible && !baseline.platform.sha256)
    errors.push("eligible platform baseline unavailable");
  if (selection.candidate) {
    r.write("capture-intent.json", { requested: true, timestamp: new Date().toISOString() });
    const capture = r.vendor("prepare");
    r.write("capture-prepare.json", capture);
    if (!succeeded(capture)) errors.push("vendor capture preparation failed");
    // P is after capture preparation. Preserve it even when prepare failed so
    // missing wire coverage cannot be mistaken for a successful baseline.
    try {
      measure({ label: "P", r });
    } catch (error) {
      errors.push(error.message);
    }
  }
  r.write("pre.json", {
    classificationSaved: true,
    baselineSaved: true,
    captureRequested: selection.candidate,
    errors,
  });
  if (errors.length) throw new Error(`screen pre incomplete: ${errors.join("; ")}`);
}

function main(r) {
  const selection = r.read("selection.json");
  fs.appendFileSync(
    process.env.GITHUB_OUTPUT,
    `eligible=${selection.eligible}\ncandidate=${selection.candidate}\nclassification=${selection.classification}\n`,
  );
  const baseline = r.read("baseline.json");
  const pre = r.read("pre.json");
  const record = {
    eligible: selection.eligible,
    candidate: selection.candidate,
    baselinePresent: Boolean(baseline.main.sha256),
    pre,
  };
  r.write("screen-main.json", record);
  if (pre.errors.length || !record.baselinePresent)
    throw new Error("pre-hardener baseline incomplete");
  if (selection.candidate && !succeeded(r.vendor("confirm")))
    throw new Error("capture baseline marker missing");
}

module.exports = { prepare, main };
