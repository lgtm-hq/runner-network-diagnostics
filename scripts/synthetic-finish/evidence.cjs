"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const directoryNames = ["ci1203", "ci1203-synthetic-induce", "ci1203-synthetic-treatment"];
const nativeDirectoryNames = ["ci1203", "ci1203-workaround", "lgtm-agent-dns-shim"];
function evidenceProfile(profile) {
  if (profile === "synthetic") return { directories: directoryNames, prefix: "ci1203-synthetic" };
  if (profile === "native")
    return { directories: nativeDirectoryNames, prefix: "ci1203-workaround" };
  throw new Error("unknown evidence profile");
}
const digest = (buffer) => createHash("sha256").update(buffer).digest("hex");
const tokenPattern =
  /gh[pousr]_|github_pat_|Authorization\s*:|Bearer\s+|OneTimeKey|ACTIONS_RUNTIME|\bsecret\b/i;

function printEvidence({
  directory,
  name,
  manifest,
  emit = console.log,
  budget = { files: 0, bytes: 0 },
  profile = "synthetic",
}) {
  const { directories, prefix } = evidenceProfile(profile);
  if (!directories.includes(name)) throw new Error("unknown evidence directory");
  if (!fs.lstatSync(directory).isDirectory()) throw new Error("evidence directory is not regular");
  const entries = new Map();
  for (const line of profile === "native" && manifest === "" ? [] : manifest.trim().split("\n")) {
    const match = /^([a-f0-9]{64})  (?:\.\/)?([\w.-]+\.(?:json|txt))$/.exec(line);
    if (!match || entries.has(match[2])) throw new Error("invalid evidence manifest entry");
    entries.set(match[2], match[1]);
  }
  const selected = fs
    .readdirSync(directory)
    .filter(
      (f) =>
        f === "SHA256SUMS" ||
        (profile === "synthetic" && name === "ci1203" ? /\.txt$/ : /\.(?:txt|json)$/).test(f),
    )
    .sort();
  if (
    JSON.stringify(selected.filter((f) => f !== "SHA256SUMS")) !==
      JSON.stringify([...entries.keys()].sort()) ||
    !selected.includes("SHA256SUMS")
  )
    throw new Error("upload set differs from frozen manifest");
  const begins = [];
  for (const file of selected) {
    if (!/^[A-Za-z0-9._-]+$/.test(file)) throw new Error("invalid evidence filename");
    budget.files += 1;
    if (budget.files > 64) throw new Error("evidence file-count limit exceeded");
    const target = path.join(directory, file);
    const fd = fs.openSync(
      target,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
    );
    let data;
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.size > 256 * 1024) {
        emit(
          `${prefix}-FILE-REFUSED ${JSON.stringify({ directory: name, name: file, bytes: stat.size, expectedSha256: entries.get(file), reason: "file type or size" })}`,
        );
        throw new Error("evidence must be a bounded regular file");
      }
      // Bounded even if an unexpected writer grows a file after fstat.
      const buffer = Buffer.alloc(256 * 1024 + 1);
      let size = 0;
      let count;
      while (
        size < buffer.length &&
        (count = fs.readSync(fd, buffer, size, buffer.length - size, null)) > 0
      )
        size += count;
      data = buffer.subarray(0, size);
    } finally {
      fs.closeSync(fd);
    }
    budget.bytes += data.length;
    const sha256 = digest(data);
    if (
      data.length > 256 * 1024 ||
      budget.bytes > 1024 * 1024 ||
      tokenPattern.test(data.toString("utf8"))
    ) {
      emit(
        `${prefix}-FILE-REFUSED ${JSON.stringify({ directory: name, name: file, bytes: data.length, sha256, reason: "byte limit or token pattern" })}`,
      );
      throw new Error("evidence copy incomplete");
    }
    if (file === "SHA256SUMS" ? !data.equals(Buffer.from(manifest)) : entries.get(file) !== sha256)
      throw new Error(`evidence changed after freeze: ${file}`);
    const base64 = data.toString("base64");
    const parts = Math.max(1, Math.ceil(base64.length / 4096));
    const begin = `${prefix}-FILE-BEGIN ${JSON.stringify({ directory: name, name: file, bytes: data.length, sha256, parts })}`;
    begins.push(begin);
    emit(begin);
    for (let index = 0; index < parts; index += 1)
      emit(
        `${prefix}-FILE ${JSON.stringify({ directory: name, name: file, bytes: data.length, sha256, index, parts, base64: base64.slice(index * 4096, (index + 1) * 4096) })}`,
      );
    emit(`${prefix}-FILE-END ${JSON.stringify({ directory: name, name: file, sha256 })}`);
  }
  return begins;
}

function copyEvidence({ root, emit = console.log, profile = "synthetic" }) {
  const { directories, prefix } = evidenceProfile(profile);
  const budget = { files: 0, bytes: 0 };
  const begins = [];
  let complete = false;
  let error;
  try {
    const unknown = fs
      .readdirSync(root)
      .filter(
        (name) =>
          name.startsWith(profile === "native" ? "ci1203-workaround" : "ci1203-synthetic-") &&
          !directories.includes(name),
      );
    if (unknown.length)
      throw new Error(
        profile === "native"
          ? "unknown native upload directory"
          : "unknown synthetic upload directory",
      );
    for (const name of directories) {
      const directory = path.join(root, name);
      if (
        !fs.lstatSync(directory).isDirectory() ||
        !fs.lstatSync(path.join(directory, "SHA256SUMS")).isFile()
      )
        throw new Error("non-regular evidence directory or manifest");
      printEvidence({
        directory,
        name,
        manifest: fs.readFileSync(path.join(directory, "SHA256SUMS"), "utf8"),
        budget,
        profile,
        emit: (line) => {
          if (line.startsWith(`${prefix}-FILE-BEGIN `)) begins.push(line);
          emit(line);
        },
      });
    }
    complete = true;
  } catch (e) {
    error = e.message;
  }
  const record = {
    complete,
    ...budget,
    beginsSha256: digest(Buffer.from(begins.join("\n") + "\n")),
    error,
  };
  emit(`${prefix}-COPY ${JSON.stringify(record)}`);
  if (!complete) throw new Error(`console evidence incomplete: ${error}`);
  return record;
}
module.exports = { printEvidence, copyEvidence };
