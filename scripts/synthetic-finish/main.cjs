"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { topology } = require("../synthetic-induce/support.cjs");
const { copyEvidence } = require("./evidence.cjs");
try {
  topology("finish");
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
const failure = process.exitCode;
require("../../vendor/network-probe/entry.cjs").execute("finish");
if (failure) process.exitCode = failure;
for (const name of ["ci1203-synthetic-induce", "ci1203-synthetic-treatment"]) {
  const directory = path.join(process.env.RUNNER_TEMP, name);
  if (!fs.existsSync(directory)) {
    console.error(`ci1203-synthetic-MISSING ${name}`);
    process.exitCode = 1;
    continue;
  }
  const manifest = fs
    .readdirSync(directory)
    .filter((f) => /\.(?:json|txt)$/.test(f))
    .sort()
    .map(
      (f) =>
        `${createHash("sha256")
          .update(fs.readFileSync(path.join(directory, f)))
          .digest("hex")}  ${f}\n`,
    )
    .join("");
  fs.writeFileSync(path.join(directory, "SHA256SUMS"), manifest);
  console.log(`ci1203-synthetic-MANIFEST ${name}\n${manifest}`);
}
// Print every committed pre/main body even when the induced fault prevents
// artifact upload. Chunks are bounded and byte-exact; the original run's gates
// are never retroactively changed by this future preservation format.
try {
  copyEvidence({ root: process.env.RUNNER_TEMP });
} catch (error) {
  console.error(`ci1203-synthetic-PRESERVATION_FAILED: ${error.message}`);
  process.exitCode = 1;
}
