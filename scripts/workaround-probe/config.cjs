"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { MAIN } = require("./support.cjs");
const locations = ["/etc", "/run", "/usr/local/lib", "/usr/lib"];

// Independent, passive inventory for the complete cat-config observation.
// Earlier directories win by basename; /dev/null masks the winning basename.
function effectiveSources(io = fs) {
  const winners = new Map();
  for (const location of locations) {
    const directory = `${location}/systemd/resolved.conf.d`;
    let entries;
    try {
      entries = io.readdirSync(directory, { withFileTypes: true });
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    for (const entry of entries) {
      if (!entry.name.endsWith(".conf") || winners.has(entry.name)) continue;
      const file = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        if (io.readlinkSync(file) !== "/dev/null") throw new Error("unknown configuration symlink");
        winners.set(entry.name, null);
      } else {
        if (!entry.isFile()) throw new Error("nonregular configuration source");
        winners.set(entry.name, file);
      }
    }
  }
  return [
    MAIN,
    ...[...winners]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([, file]) => file)
      .filter(Boolean),
  ];
}

module.exports = { effectiveSources };
