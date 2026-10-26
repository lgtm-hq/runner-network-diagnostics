"use strict";
const { execute } = require("./entry.cjs");
execute(process.env.INPUT_MODE === "prepare" ? "confirm" : process.env.INPUT_MODE);
