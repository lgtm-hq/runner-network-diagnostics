"use strict";
const { runtime, consoleReceipt } = require("./runtime.cjs");
const { runPhase } = require("./control.cjs");
function entry(phase) {
  let r;
  try {
    r = runtime();
    runPhase(phase, r);
  } catch (error) {
    if (!r)
      consoleReceipt({
        schema: 1,
        phase,
        disposition: "RUNTIME_UNAVAILABLE",
        failed: true,
        error: error.message,
      });
    console.error(`::error::lgtm-agent-dns-shim ${phase} failed`);
    process.exitCode = 1;
  }
}
module.exports = { entry };
