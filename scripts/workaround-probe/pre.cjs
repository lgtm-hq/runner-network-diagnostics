"use strict";
if (process.env.INPUT_MODE === "screen") {
  const r = require("./support.cjs").runtime();
  try {
    require("./screen.cjs").prepare(r);
  } catch (error) {
    r.write("pre-error.json", { error: error.message });
    console.error(error.message);
    process.exitCode = 1;
  }
}
