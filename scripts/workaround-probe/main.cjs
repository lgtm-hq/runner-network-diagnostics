"use strict";
const r = require("./support.cjs").runtime();
const mode = process.env.INPUT_MODE;
try {
  if (mode === "screen") require("./screen.cjs").main(r);
  else if (["A", "U", "Z"].includes(mode))
    require("./oracle.cjs").afterHardener({ label: mode, r });
  else if (mode === "finish") require("./finish.cjs").finish(r);
  else if (mode === "negative") require("./negative.cjs").negative(r);
  else if (mode === "drill") require("./drill.cjs").execute(r);
  else throw new Error("unknown native probe mode");
} catch (error) {
  // Finish already froze and printed its error record. Never add an artifact
  // after that manifest/console boundary.
  if (mode !== "finish")
    r.write(
      `${["screen", "A", "U", "Z", "drill", "negative"].includes(mode) ? mode : "unknown"}-error.json`,
      { error: error.message },
    );
  console.error(error.message);
  process.exitCode = 1;
}
