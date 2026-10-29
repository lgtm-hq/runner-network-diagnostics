"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { MAIN, LIMIT } = require("./constants.cjs");
const { snapshot, secureDirectory } = require("./root-file.cjs");

// Highest priority first; sorting happens only after same-name selection.
const ROOTS = ["/etc", "/run", "/usr/local/lib", "/usr/lib"];
const DIRECTORIES = ROOTS.map((root) => `${root}/systemd/resolved.conf.d`);
const fingerprint = (stat) => [stat.dev, stat.ino, stat.ctimeNs, stat.mtimeNs].join(":");

// Alternate roots, uid and boundary are for unprivileged imported tests only.
function inventory({ directories = DIRECTORIES, uid = 0, boundary = "/", io = fs } = {}) {
  const records = [];
  const selected = new Map();
  let total = 0;
  let count = 0;
  for (const directory of directories) {
    let before;
    try {
      before = io.lstatSync(directory, { bigint: true });
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      records.push({ path: directory, absent: true });
      continue;
    }
    // An absent leaf contributes no configuration. Only present directories
    // need ancestor ownership checks; absence is checked again below.
    secureDirectory({ root: directory, uid, boundary });
    const names = io.readdirSync(directory).sort();
    const entries = [];
    for (const name of names) {
      if (!name.endsWith(".conf")) continue;
      if (!/^[A-Za-z0-9_.-]+\.conf$/.test(name) || ++count > 256)
        throw new Error("unexpected or excessive drop-in names");
      const target = path.join(directory, name);
      const stat = io.lstatSync(target, { bigint: true });
      let entry;
      if (stat.isSymbolicLink()) {
        if (stat.uid !== BigInt(uid) || io.readlinkSync(target) !== "/dev/null")
          throw new Error("unexpected drop-in symlink");
        entry = { path: target, name, masked: true, identity: fingerprint(stat) };
      } else {
        const file = snapshot({ target, uid });
        total += Buffer.byteLength(file.content);
        if (total > LIMIT) throw new Error("oversized drop-in inventory");
        entry = { path: target, name, masked: false, file };
      }
      entries.push(entry);
      if (!selected.has(name)) selected.set(name, entry);
    }
    records.push({ path: directory, identity: fingerprint(before), names, entries });
  }
  // A successful partial listing or a configuration changed during enumeration
  // must never authorize a write. Recheck every directory, including absent ones.
  for (const record of records) {
    if (record.absent) {
      try {
        io.lstatSync(record.path);
      } catch (error) {
        if (error.code === "ENOENT") continue;
        throw error;
      }
      throw new Error("drop-in directory appeared during enumeration");
    }
    if (
      fingerprint(io.lstatSync(record.path, { bigint: true })) !== record.identity ||
      JSON.stringify(io.readdirSync(record.path).sort()) !== JSON.stringify(record.names)
    )
      throw new Error("drop-in directory changed during enumeration");
    for (const entry of record.entries) {
      const stat = io.lstatSync(entry.path, { bigint: true });
      if (entry.masked) {
        if (fingerprint(stat) !== entry.identity || io.readlinkSync(entry.path) !== "/dev/null")
          throw new Error("drop-in mask changed during enumeration");
      } else if (
        String(stat.ino) !== entry.file.ino ||
        String(stat.dev) !== entry.file.dev ||
        String(stat.ctimeNs) !== entry.file.ctimeNs
      )
        throw new Error("drop-in file changed during enumeration");
    }
  }
  const effective = [...selected.values()]
    .filter((entry) => !entry.masked)
    .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  return { directories: records, effective };
}

function crosscheck({ config, sources, files, main }) {
  if (
    !config ||
    config.status !== 0 ||
    config.error ||
    config.stderr ||
    !config.stdout?.endsWith("\n")
  )
    throw new Error("incomplete cat-config");
  if (
    !files ||
    files.directories?.length !== DIRECTORIES.length ||
    files.directories.some((entry, index) => entry.path !== DIRECTORIES[index]) ||
    !Array.isArray(files.effective)
  )
    throw new Error("missing complete independent inventory");
  const expected = [{ path: MAIN, file: main }, ...files.effective];
  if (
    sources.length !== expected.length ||
    sources.some((entry, index) => entry.path !== expected[index].path)
  )
    throw new Error("cat-config source set disagrees with independent inventory");
  for (let index = 0; index < sources.length; index += 1) {
    const file = expected[index].file;
    if (
      !file?.sha256 ||
      sources[index].body.join("\n").trimEnd() !== file.content.replace(/\r\n/g, "\n").trimEnd()
    )
      throw new Error("cat-config source body disagrees with independent snapshot");
  }
}
module.exports = { ROOTS, DIRECTORIES, inventory, crosscheck };
