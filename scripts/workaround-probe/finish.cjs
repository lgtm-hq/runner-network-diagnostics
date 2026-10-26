"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { digest, readFile, succeeded } = require("./support.cjs");
const { copyEvidence } = require("../synthetic-finish/evidence.cjs");
const { nativeCompleteness } = require("./completeness.cjs");
const directories = ["ci1203", "ci1203-workaround", "lgtm-agent-dns-shim"];

function manifest(directory) {
  if (!fs.lstatSync(directory).isDirectory()) throw new Error("nonregular evidence directory");
  const names = fs
    .readdirSync(directory)
    .filter((name) => /\.(?:txt|json)$/.test(name))
    .sort();
  const content = names
    .map((name) => {
      if (!/^[\w.-]+\.(?:txt|json)$/.test(name)) throw new Error("invalid evidence filename");
      return `${readFile(path.join(directory, name)).sha256}  ${name}\n`;
    })
    .join("");
  const target = path.join(directory, "SHA256SUMS");
  // Only the native fixed txt+json inventory is published by this route.
  if (fs.existsSync(target) && !fs.lstatSync(target).isFile())
    throw new Error("nonregular manifest");
  fs.writeFileSync(target, content, { flag: "w", mode: 0o600 });
  return { files: names.length, sha256: digest(content) };
}

function finish(r) {
  const errors = [];
  let captureRequested = false;
  let classification = "UNKNOWN";
  try {
    classification = r.read("selection.json").classification;
  } catch {
    try {
      r.read("drill.json");
      classification = "DRILL";
    } catch {
      errors.push("pre-outcome selection and drill record unavailable");
    }
  }
  try {
    captureRequested = r.read("capture-intent.json").requested === true;
  } catch (error) {
    if (error.code !== "ENOENT") errors.push(error.message);
  }
  if (!captureRequested && ["ELIGIBLE", "PARTIAL"].includes(classification))
    errors.push("selected candidate has no persisted capture intent");
  let capture;
  let completeness;
  if (captureRequested) {
    // Freeze unchanged capture directly. Legacy vendor finish/verify requires
    // allowed GitHub packets and is invalid for real forwarder-cache paths.
    capture = r.freeze();
    if (!succeeded(capture)) errors.push("native capture freeze failed");
    try {
      const state = JSON.parse(readFile(path.join(r.root, "ci1203", "capture-status.txt")).content);
      const wire = readFile(path.join(r.root, "ci1203", "dns-wire.txt")).content;
      const oracles = {};
      for (const label of ["P", "A", "Z"]) {
        try {
          oracles[label] = r.read(`oracle-${label}.json`);
        } catch (error) {
          if (error.code !== "ENOENT") errors.push(error.message);
        }
      }
      completeness = nativeCompleteness({ state, wire, oracles });
      r.write("native-completeness.json", completeness);
      if (!completeness.complete) errors.push("native capture instrument incomplete");
      fs.writeFileSync(
        path.join(r.root, "ci1203", "completeness.txt"),
        completeness.complete
          ? "COMPLETE_NATIVE_CAPTURE_INSTRUMENT; A/Z outcome gates require assessment\n"
          : "INCOMPLETE_NATIVE_CAPTURE_INSTRUMENT\n",
        { flag: "wx" },
      );
    } catch (error) {
      errors.push(error.message);
    }
    // The unchanged snapshot mode is passive. At this point hardened.txt is
    // explicitly the final post-freeze snapshot; it does not run old verify.
    const snapshot = r.vendor("snapshot");
    r.write("final-snapshot.json", {
      timestamp: new Date().toISOString(),
      file: "ci1203/hardened.txt",
      result: snapshot,
    });
    if (!succeeded(snapshot)) errors.push("final vendor snapshot failed");
  } else {
    fs.mkdirSync(path.join(r.root, "ci1203"), { recursive: true });
    fs.writeFileSync(
      path.join(r.root, "ci1203", "completeness.txt"),
      `NOT_CAPTURED: path=${classification}; captureCompleteness=false\n`,
      { flag: "wx" },
    );
  }
  try {
    r.topology("finish");
  } catch (error) {
    errors.push(error.message);
  }
  const shimDirectory = path.join(r.root, "lgtm-agent-dns-shim");
  if (!fs.existsSync(shimDirectory)) {
    errors.push("shim pre/main evidence directory missing");
    fs.mkdirSync(shimDirectory);
  }
  r.write("finish.json", {
    native: true,
    classification,
    timestamp: new Date().toISOString(),
    captureRequested,
    captureCompleteness: captureRequested ? completeness?.complete === true : false,
    capture,
    errors,
    postReceipts: "shim post follows upload: console-only, outside frozen artifact equality",
  });
  for (const name of directories) {
    try {
      manifest(path.join(r.root, name));
    } catch (error) {
      errors.push(`${name}: ${error.message}`);
    }
  }
  try {
    copyEvidence({ root: r.root, profile: "native" });
  } catch (error) {
    errors.push(error.message);
  }
  if (errors.length) throw new Error(`native finish incomplete: ${errors.join("; ")}`);
}

module.exports = { manifest, finish };
