"use strict";
// CLI paths are fixed. Only imported tests can substitute an unprivileged directory.
const fs = require("node:fs");
const path = require("node:path");
const directory = "/etc/systemd/resolved.conf.d";
const filename = "99-ci1203-counterfactual.conf";
function bytes(token, profile = "override") {
  if (!/^[a-f0-9]{64}$/.test(token)) throw new Error("invalid ownership token");
  if (!["override", "reset"].includes(profile)) throw new Error("invalid file profile");
  return `# ci1203 ownership ${token}\n[Resolve]\nDNS=${profile === "override" ? "127.0.0.1" : ""}\n`;
}
function owned({ target, token, uid, profile = "override" }) {
  let stat;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (!stat.isFile() || stat.uid !== uid) throw new Error("unowned file or symlink");
  const fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const actual = fs.fstatSync(fd);
    if (stat.ino !== actual.ino || stat.dev !== actual.dev) throw new Error("file replaced");
    if (fs.readFileSync(fd, "utf8") !== bytes(token, profile))
      throw new Error("ownership bytes differ");
  } finally {
    fs.closeSync(fd);
  }
  return stat;
}
function removeOwned({ target, token, uid, profile = "override" }) {
  const stat = owned({ target, token, uid, profile });
  if (!stat) return false;
  const current = fs.lstatSync(target);
  if (current.ino !== stat.ino || current.dev !== stat.dev) throw new Error("file replaced");
  fs.unlinkSync(target);
  return true;
}
function operate({ mode, token, root = directory, uid = 0, profile = "override" }) {
  const content = bytes(token, profile);
  const target = path.join(root, profile === "reset" ? "90-egress-proxy.conf" : filename);
  const temporary = `${target}.${token}.tmp`;
  if (mode === "create") {
    // A complete fsynced inode is linked exclusively into place, never overwritten.
    // A killed create can leave a .tmp file, which resolved does not read.
    fs.mkdirSync(root, { recursive: true });
    const fd = fs.openSync(temporary, "wx", 0o644);
    try {
      fs.writeFileSync(fd, content);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    try {
      fs.linkSync(temporary, target);
    } finally {
      removeOwned({ target: temporary, token, uid, profile });
    }
    return { created: true };
  }
  if (mode === "inspect") return { present: Boolean(owned({ target, token, uid, profile })) };
  if (mode === "remove") {
    const removed = removeOwned({ target, token, uid, profile });
    removeOwned({ target: temporary, token, uid, profile });
    return { removed };
  }
  throw new Error("invalid root operation");
}
if (require.main === module) {
  try {
    const result = operate({
      mode: process.argv[2],
      token: process.argv[3],
      profile: process.argv[4] || "override",
    });
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
module.exports = { bytes, operate, filename, directory };
