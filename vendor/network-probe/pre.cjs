"use strict";
const { execute } = require("./entry.cjs");
// Only the first helper invocation gets a baseline pre hook. Later invocations
// are pre-scheduled too, and must not restart collection or reset evidence.
if (process.env.INPUT_MODE === "prepare") execute("prepare");
