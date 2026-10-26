"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { createHash, randomBytes } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { probe, topology } = require("../synthetic-induce/support.cjs");
const MAIN = "/etc/systemd/resolved.conf";
const PLATFORM = "/etc/systemd/resolved.conf.d/90-egress-proxy.conf";
const OWNED = "/etc/systemd/resolved.conf.d/99-lgtm-agent-dns.conf";
const digest = (data) => createHash("sha256").update(data).digest("hex");

function readFile(file) {
  const fd = fs.openSync(
    file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
  );
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > 256 * 1024)
      throw new Error("unbounded or nonregular observation");
    const buffer = Buffer.alloc(256 * 1024 + 1);
    let size = 0;
    let count;
    while (
      size < buffer.length &&
      (count = fs.readSync(fd, buffer, size, buffer.length - size, null)) > 0
    )
      size += count;
    if (size > 256 * 1024) throw new Error("observation grew beyond limit");
    const data = buffer.subarray(0, size);
    return {
      present: true,
      content: data.toString("utf8"),
      sha256: digest(data),
      ino: String(stat.ino),
      ctimeMs: stat.ctimeMs,
    };
  } finally {
    fs.closeSync(fd);
  }
}

function fileObservation(file) {
  try {
    return readFile(file);
  } catch (error) {
    return { present: error.code === "ENOENT" ? false : null, error: error.code || error.message };
  }
}

function nonce(label, entropy = randomBytes) {
  if (!["p", "a", "z", "u"].includes(label)) throw new Error("invalid nonce label");
  const hex = entropy(8).toString("hex");
  if (!/^[a-f0-9]{16}$/.test(hex)) throw new Error("invalid nonce entropy");
  return `${label}-${hex}.example.com`;
}

function runtime() {
  const root = process.env.RUNNER_TEMP;
  if (!root || !path.isAbsolute(root)) throw new Error("absolute RUNNER_TEMP required");
  const out = path.join(root, "ci1203-workaround");
  fs.mkdirSync(out, { recursive: true });
  const write = (name, data) => {
    if (!/^[\w-]+\.json$/.test(name)) throw new Error("invalid receipt name");
    const content = `${JSON.stringify(data, null, 2)}\n`;
    fs.writeFileSync(path.join(out, name), content, { flag: "wx", mode: 0o600 });
    // Raw command/config bytes are printed only through the bounded, screened
    // console-copy profile at finish. Early receipts commit to their bytes.
    console.log(
      `ci1203-workaround-RECEIPT ${JSON.stringify({ name, bytes: Buffer.byteLength(content), sha256: digest(content), classification: data.classification, eligible: data.eligible, candidate: data.candidate, label: data.label, disposition: data.disposition })}`,
    );
    return data;
  };
  return {
    root,
    out,
    write,
    read: (name) => JSON.parse(readFile(path.join(out, name)).content),
    probe,
    file: fileObservation,
    topology,
    pause: (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms),
    nonce,
    freeze() {
      const result = spawnSync(
        process.execPath,
        [
          path.join(__dirname, "../../vendor/network-probe/capture.cjs"),
          "freeze",
          path.join(root, "ci1203"),
        ],
        { stdio: "inherit", timeout: 10000 },
      );
      return { status: result.status, error: result.error?.message || null };
    },
    vendor(mode) {
      // The vendor entry and probe remain byte-frozen. Preserve the caller's failure.
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          "require(process.argv[1]).execute(process.argv[2])",
          path.join(__dirname, "../../vendor/network-probe/entry.cjs"),
          mode,
        ],
        { stdio: "inherit", timeout: 120000 },
      );
      return { status: result.status, error: result.error?.message || null };
    },
  };
}

function succeeded(result) {
  return result?.status === 0 && !result.error;
}

function observe(r) {
  const call = (command, args) => r.probe(command, args, { timeoutMs: 5000 });
  return {
    dns: call("timeout", ["5", "resolvectl", "dns"]),
    domains: call("timeout", ["5", "resolvectl", "domain"]),
    config: call("timeout", ["5", "systemd-analyze", "cat-config", "systemd/resolved.conf"]),
    resolved: call("timeout", [
      "5",
      "systemctl",
      "show",
      "systemd-resolved",
      "-p",
      "ExecMainPID",
      "-p",
      "ExecMainStartTimestamp",
      "-p",
      "ExecMainStartTimestampMonotonic",
    ]),
    status: call("sudo", ["-n", "timeout", "2", "cat", "/home/agent/agent.status"]),
    listener: call("sudo", ["-n", "timeout", "3", "ss", "-lnu"]),
    main: r.file(MAIN),
    platform: r.file(PLATFORM),
    owned: r.file(OWNED),
  };
}

module.exports = {
  MAIN,
  PLATFORM,
  OWNED,
  digest,
  readFile,
  fileObservation,
  nonce,
  runtime,
  succeeded,
  observe,
};
