"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createHash, randomBytes } = require("node:crypto");
const { performance } = require("node:perf_hooks");
const { MAIN, PLATFORM, TARGET, LIMIT } = require("./constants.cjs");
const { snapshot } = require("./root-file.cjs");
const { inventory } = require("./config-files.cjs");
const { listenerState } = require("./config.cjs");

function probe(command, args, timeoutMs = 2000) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    // spawnSync requires integer milliseconds; zero disables its timeout.
    timeout: Math.min(10000, Math.max(1, Math.floor(timeoutMs) || 1)),
    maxBuffer: LIMIT,
    env: { ...process.env, LC_ALL: "C", SYSTEMD_COLORS: "0", SYSTEMD_PAGER: "cat" },
  });
  return {
    status: result.status,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    error: result.error?.code || (result.signal ? `signal ${result.signal}` : null),
  };
}
function checked(result) {
  if (result.status !== 0 || result.error || result.stderr)
    throw new Error(`probe failed: ${JSON.stringify(result)}`);
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
function durableWrite({ file, content, exclusive = false }) {
  const temporary = `${file}.${randomBytes(16).toString("hex")}.tmp`;
  const fd = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    if (exclusive) fs.linkSync(temporary, file);
    else fs.renameSync(temporary, file);
  } finally {
    if (exists(temporary)) fs.unlinkSync(temporary);
  }
  const directory = fs.openSync(
    path.dirname(file),
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  );
  try {
    fs.fsyncSync(directory);
  } finally {
    fs.closeSync(directory);
  }
}
function consoleReceipt(record, print = console.log) {
  const content = `${JSON.stringify(record)}\n`;
  print(
    `lgtm-agent-dns-shim RECEIPT ${content.trimEnd()} sha256=${createHash("sha256").update(content).digest("hex")}`,
  );
  print(`lgtm-agent-dns-shim: ${record.disposition}`);
  return content;
}
function environmentGate({ platform, runnerOs, hosted, exists: hasFile, run, sudo }) {
  if (platform !== "linux" || runnerOs !== "Linux") return { allowed: false, reason: "NON_LINUX" };
  if (hosted !== "github-hosted")
    return { allowed: false, reason: "NOT_EXPLICIT_GITHUB_HOSTED_EPHEMERAL" };
  if (hasFile("/.dockerenv") || hasFile("/run/.containerenv"))
    return { allowed: false, reason: "CONTAINER" };
  if (!hasFile("/run/systemd/system")) return { allowed: false, reason: "NO_SYSTEMD_RUNTIME" };
  const pid1 = run("cat", ["/proc/1/comm"]);
  if (pid1.status !== 0 || pid1.error || pid1.stderr || pid1.stdout !== "systemd\n")
    return { allowed: false, reason: "PID1_NOT_SYSTEMD_OR_UNKNOWN", pid1 };
  const container = run("systemd-detect-virt", ["--container", "--quiet"]);
  if (container.status !== 1 || container.error || container.stdout || container.stderr)
    return { allowed: false, reason: "CONTAINER_OR_UNKNOWN", container };
  const privilege = sudo(["true"]);
  return {
    allowed: privilege.status === 0 && !privilege.error && !privilege.stderr,
    reason: "HOSTED_PRIVILEGE_CHECK",
    privilege,
  };
}
function topologyGate({ resolv, services, listener }) {
  const checks = {
    resolvSelf: resolv?.canonical === "/etc/resolv.conf" && resolv?.file?.present === true,
    forwarderNameserver: /^\s*nameserver\s+127\.0\.0\.100\s*(?:[#;].*)?$/m.test(
      resolv?.file?.content || "",
    ),
    forwarderListener: listenerState(listener, "127.0.0.100") === "present",
  };
  for (const name of ["systemd-resolved", "egress-dns-resolver", "egress-outbound-proxy"]) {
    const value = services[name];
    checks[name] =
      value?.status === 0 && !value.error && !value.stderr && value.stdout === "active\n";
  }
  return { allowed: Object.values(checks).every(Boolean), checks, resolv, services, listener };
}
function runtime() {
  if (!process.env.RUNNER_TEMP || !path.isAbsolute(process.env.RUNNER_TEMP))
    throw new Error("absolute RUNNER_TEMP required");
  const out = path.join(process.env.RUNNER_TEMP, "lgtm-agent-dns-shim");
  try {
    fs.mkdirSync(out, { mode: 0o700 });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  const directory = fs.lstatSync(out);
  if (!directory.isDirectory() || directory.uid !== process.getuid() || directory.mode & 0o077)
    throw new Error("unsafe shim state directory");
  const stateFile = path.join(out, "state.json");
  const sudo = (args, timeout = 2000) => probe("sudo", ["-n", ...args], timeout);
  const r = {
    mode: process.env.INPUT_MODE || "apply",
    token: () => randomBytes(32).toString("hex"),
    now: () => performance.now(),
    pause: (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms),
    load: () => (exists(stateFile) ? JSON.parse(fs.readFileSync(stateFile, "utf8")) : null),
    save: (state, exclusive = false) =>
      durableWrite({ file: stateFile, content: `${JSON.stringify(state)}\n`, exclusive }),
    receipt(phase, record) {
      const content = consoleReceipt({
        schema: 1,
        phase,
        timestamp: new Date().toISOString(),
        ...record,
      });
      durableWrite({ file: path.join(out, `${phase}.json`), content, exclusive: true });
    },
    outputs(state, disposition) {
      if (process.env.GITHUB_OUTPUT)
        fs.appendFileSync(
          process.env.GITHUB_OUTPUT,
          `applicable=${state?.applicable === true}\napplied=${state?.applied === true}\ndisposition=${disposition}\n`,
        );
    },
    environment() {
      return environmentGate({
        platform: process.platform,
        runnerOs: process.env.RUNNER_OS,
        hosted: process.env.INPUT_HOSTED,
        exists,
        run: probe,
        sudo,
      });
    },
    config: () => probe("systemd-analyze", ["cat-config", "systemd/resolved.conf"], 5000),
    files: () => inventory(),
    topology() {
      const resolv = {
        canonical: fs.realpathSync("/etc/resolv.conf"),
        file: snapshot({ target: "/etc/resolv.conf" }),
      };
      const services = Object.fromEntries(
        ["systemd-resolved", "egress-dns-resolver", "egress-outbound-proxy"].map((name) => [
          name,
          probe("systemctl", ["is-active", name]),
        ]),
      );
      return topologyGate({ resolv, services, listener: sudo(["ss", "-lnu"]) });
    },
    pathPresent: () => exists(TARGET),
    main: () => snapshot({ target: MAIN }),
    platform: () => snapshot({ target: PLATFORM }),
    root(mode, token) {
      return JSON.parse(
        checked(
          sudo([process.execPath, path.join(__dirname, "root-file.cjs"), mode, token], 10000),
        ),
      );
    },
    status: (remainingMs = 2000) =>
      sudo(["cat", "/home/agent/agent.status"], Math.min(2000, remainingMs)),
    listener: () => sudo(["ss", "-lnu"]),
    dns: () => checked(probe("resolvectl", ["dns"])),
    domains: () => checked(probe("resolvectl", ["domain"])),
    service: () =>
      checked(
        probe("systemctl", [
          "show",
          "systemd-resolved",
          "--property=ExecMainStartTimestampMonotonic,ExecMainPID",
        ]),
      ),
    // /proc/uptime shares systemd's boot-relative clock. Record a conservative
    // upper bound AFTER owned creation, avoiding wall-clock/date precision loss.
    bootMicros: () => {
      const value = fs.readFileSync("/proc/uptime", "utf8").split(" ")[0];
      if (!/^\d+\.\d{2}$/.test(value)) throw new Error("unknown boot clock");
      return Math.ceil(Number(value) * 1e6) + 10000;
    },
    restart: () => checked(sudo(["systemctl", "restart", "systemd-resolved"], 10000)),
    getent: () => probe("getent", ["ahostsv4", "github.com"], 10000),
  };
  return r;
}
module.exports = {
  runtime,
  createRuntime: runtime,
  probe,
  checked,
  durableWrite,
  consoleReceipt,
  environmentGate,
  topologyGate,
};
