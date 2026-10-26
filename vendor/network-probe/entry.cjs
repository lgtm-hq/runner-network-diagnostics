"use strict";
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function execute(mode) {
  const result = spawnSync("bash", [path.join(__dirname, "probe.sh")], {
    env: { ...process.env, PROBE_MODE: mode, PROBE_NODE: process.execPath },
    stdio: "inherit",
  });
  if (result.error) console.error(result.error.message);
  process.exitCode = result.status ?? 1;
}
module.exports = { execute };
