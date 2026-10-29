"use strict";
// Self-contained adaptation of resolver-counterfactual/root-file.cjs at
// cab5432bb579d9fe2014df4be6646b7911aaccd3: wx + fsync + exclusive hard link.
// No frozen experimental module is imported. CLI paths and operations are fixed;
// alternate roots/uids/boundaries exist only for unprivileged imported tests.
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { DIRECTORY, FILENAME, LIMIT } = require("./constants.cjs");

function bytes(token) {
  if (!/^[a-f0-9]{64}$/.test(token)) throw new Error("invalid ownership token");
  return `# lgtm agent-dns shim; owner ${token}\n[Resolve]\nDNS=\nDNS=127.0.0.1\n`;
}
function syncDirectory(root) {
  const fd = fs.openSync(root, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}
function secureDirectory({ root, uid, boundary = "/", create = false }) {
  if (root !== boundary) secureDirectory({ root: path.dirname(root), uid, boundary });
  try {
    const stat = fs.lstatSync(root);
    if (!stat.isDirectory() || stat.uid !== uid || stat.mode & 0o022)
      throw new Error(
        `unsafe directory ownership, permissions, or symlink: path=${root} uid=${stat.uid} mode=0${(stat.mode & 0o7777).toString(8)} type=${stat.isDirectory() ? "directory" : stat.isSymbolicLink() ? "symlink" : "other"}`,
      );
  } catch (error) {
    if (error.code !== "ENOENT" || !create) throw error;
    fs.mkdirSync(root, { mode: 0o755 });
    syncDirectory(path.dirname(root));
    secureDirectory({ root, uid, boundary });
  }
}
function snapshot({ target, uid = 0 }) {
  const stat = fs.lstatSync(target, { bigint: true });
  if (!stat.isFile() || stat.uid !== BigInt(uid) || stat.mode & 0o022n || stat.size > BigInt(LIMIT))
    throw new Error(
      `unsafe file ownership, permissions, symlink, or size: path=${target} uid=${stat.uid} mode=0${(stat.mode & 0o7777n).toString(8)} type=${stat.isFile() ? "file" : stat.isSymbolicLink() ? "symlink" : "other"} bytes=${stat.size}`,
    );
  const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const actual = fs.fstatSync(fd, { bigint: true });
    if (stat.ino !== actual.ino || stat.dev !== actual.dev) throw new Error("file replaced");
    const buffer = Buffer.alloc(LIMIT + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = fs.readSync(fd, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    const content = buffer.subarray(0, length);
    const after = fs.fstatSync(fd, { bigint: true });
    if (content.length > LIMIT || after.ctimeNs !== actual.ctimeNs || after.size !== actual.size)
      throw new Error("file changed during read");
    return {
      present: true,
      content: content.toString("utf8"),
      sha256: createHash("sha256").update(content).digest("hex"),
      ino: String(actual.ino),
      dev: String(actual.dev),
      ctimeNs: String(actual.ctimeNs),
      uid: Number(actual.uid),
      mode: Number(actual.mode & 0o777n),
      nlink: Number(actual.nlink),
    };
  } finally {
    fs.closeSync(fd);
  }
}
function owned({ target, token, uid }) {
  let result;
  try {
    result = snapshot({ target, uid });
  } catch (error) {
    if (error.code === "ENOENT") return { present: false };
    throw error;
  }
  if (result.content !== bytes(token) || result.mode !== 0o644 || result.nlink !== 1)
    throw new Error("foreign file: ownership bytes, mode, or links differ");
  return result;
}
function removeOwned({ target, token, uid }) {
  const stat = owned({ target, token, uid });
  if (!stat.present) return false;
  const current = fs.lstatSync(target, { bigint: true });
  if (
    String(current.ino) !== stat.ino ||
    String(current.dev) !== stat.dev ||
    String(current.ctimeNs) !== stat.ctimeNs
  )
    throw new Error("file replaced before unlink");
  fs.unlinkSync(target);
  return true;
}
function operate({ mode, token, root = DIRECTORY, uid = 0, boundary = "/" }) {
  const content = bytes(token);
  if (!["create", "inspect", "remove"].includes(mode)) throw new Error("invalid root operation");
  try {
    secureDirectory({ root, uid, boundary, create: mode === "create" });
  } catch (error) {
    if (error.code === "ENOENT" && mode !== "create") return { present: false, removed: false };
    throw error;
  }
  const target = path.join(root, FILENAME);
  const temporary = `${target}.${token}.tmp`;
  if (mode === "create") {
    // Refuse even dangling symlinks. link() provides the final exclusive check.
    try {
      fs.lstatSync(target);
      throw new Error("target path already present");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    const fd = fs.openSync(temporary, "wx", 0o644);
    try {
      fs.fchmodSync(fd, 0o644);
      fs.writeFileSync(fd, content);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    let creationError;
    try {
      fs.linkSync(temporary, target);
      syncDirectory(root);
    } catch (error) {
      creationError = error;
    }
    let cleanupError;
    try {
      // The inode may have two links after successful creation. Unlink this
      // known temporary inode only, after checking its exact owned bytes.
      const temp = snapshot({ target: temporary, uid });
      if (temp.content !== content) throw new Error("foreign temporary file");
      fs.unlinkSync(temporary);
      syncDirectory(root);
    } catch (error) {
      cleanupError = error;
    }
    if (creationError && cleanupError)
      throw new AggregateError([creationError, cleanupError], "creation and owned cleanup failed");
    if (creationError) throw creationError;
    if (cleanupError) throw cleanupError;
    return owned({ target, token, uid });
  }
  // A process killed between link() and temp unlink leaves two links to the
  // same owned inode. Recognize that precise state; never unlink an unrelated
  // temporary file. Inspection remains read-only.
  let temporaryObservation;
  try {
    temporaryObservation = snapshot({ target: temporary, uid });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (temporaryObservation) {
    if (temporaryObservation.content !== content || temporaryObservation.mode !== 0o644)
      throw new Error("foreign temporary file");
    let targetObservation;
    try {
      targetObservation = snapshot({ target, uid });
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (targetObservation) {
      if (
        targetObservation.ino !== temporaryObservation.ino ||
        targetObservation.dev !== temporaryObservation.dev ||
        targetObservation.nlink !== 2
      )
        throw new Error("foreign or unexpected temporary links");
      if (mode === "inspect") return { ...targetObservation, pendingTemporary: true };
    } else if (temporaryObservation.nlink !== 1) throw new Error("unexpected temporary links");
    if (mode === "remove") {
      fs.unlinkSync(temporary);
      syncDirectory(root);
    }
  }
  if (mode === "inspect") return owned({ target, token, uid });
  const removed = removeOwned({ target, token, uid });
  removeOwned({ target: temporary, token, uid });
  syncDirectory(root);
  if (owned({ target, token, uid }).present) throw new Error("removal not verified");
  return { present: false, removed };
}
if (require.main === module) {
  try {
    if (process.argv.length !== 4) throw new Error("expected operation and ownership token only");
    console.log(JSON.stringify(operate({ mode: process.argv[2], token: process.argv[3] })));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
module.exports = { bytes, operate, snapshot, secureDirectory };
