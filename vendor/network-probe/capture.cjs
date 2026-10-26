"use strict";

// Fixture-owned bounded DNS-text collector; Node built-ins only.
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { setTimeout: delay } = require("node:timers/promises");

const DNS_FILTER = "(udp port 53 or tcp port 53) and (net 127.0.0.0/8 or host 168.63.129.16)";
const DOMAIN =
  /(?:^|[\s,])(?:[a-zA-Z0-9_-]+\.)*(?:github\.com|githubapp\.com|githubusercontent\.com|blob\.core\.windows\.net|example\.com)\.(?:[\s,]|$)/;
// Linux -i any uses SLL2: interface and packet direction precede IP/IP6.
const HEADER = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ (?:\S+\s+(?:In|Out|B|M|P|\?)\s+)?IP6? /;
const utcNow = () => new Date().toISOString();

function writeState({ directory, state }) {
  const target = path.join(directory, "capture-state.live");
  fs.writeFileSync(`${target}.tmp`, `${JSON.stringify(state)}\n`);
  fs.renameSync(`${target}.tmp`, target);
}

function readState(directory) {
  try {
    return JSON.parse(fs.readFileSync(path.join(directory, "capture-state.live"), "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return { stage: "missing" };
    throw error;
  }
}

// tcpdump -vv puts the UTC timestamp on a separate header line. Retain the
// entire matching DNS record, including addresses/direction and query ID.
function createDecoder(emit) {
  let pending = "";
  let record = [];
  const flush = () => {
    const text = record.join("\n");
    if (record.length && DOMAIN.test(text)) emit(`${text}\n`);
    record = [];
  };
  return {
    feed(chunk) {
      pending += chunk;
      let newline;
      while ((newline = pending.indexOf("\n")) !== -1) {
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        if (HEADER.test(line)) {
          flush();
          record.push(line);
        } else if (record.length && /^\s/.test(line)) record.push(line);
      }
    },
    flush,
  };
}

function completeness({ state, wire, agent }) {
  const reasons = [];
  if (state.freezeOutcome !== "acknowledged" || state.stage !== "frozen" || !state.healthyAtFreeze)
    reasons.push("capture did not cover the observation window");
  if (!HEADER.test(wire.split("\n")[0] || ""))
    reasons.push("timestamped infrastructure DNS records missing");
  if (!/\b\d+\+ (?:\[[^\]\n]+\] )?A\? (?:api\.)?github\.com\./.test(wire))
    reasons.push("GitHub DNS query missing (cache/route may be unobserved)");
  if (!/\b(?:api\.)?github\.com\..*\bA \d+\./.test(wire)) reasons.push("GitHub DNS answer missing");
  if (!agent.includes("agent-status=Initialized")) reasons.push("agent initialization missing");
  if (!agent.includes("endpoint called ip address:port"))
    reasons.push("agent application-connection evidence missing");
  return reasons;
}

function supervise(directory) {
  const state = {
    stage: "starting",
    startedAt: utcNow(),
    healthyAtFreeze: false,
  };
  let accepting = true;
  let hasExited = false;
  const live = path.join(directory, "dns-wire.live");
  fs.writeFileSync(live, "");
  writeState({ directory, state });
  const decoder = createDecoder((record) => {
    if (accepting) fs.appendFileSync(live, record);
  });
  const child = spawn(
    "sudo",
    ["-n", "timeout", "420", "tcpdump", "-i", "any", "-l", "-nn", "-tttt", "-vv", DNS_FILTER],
    {
      env: { ...process.env, TZ: "UTC", LC_ALL: "C" },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  child.stdout.on("data", (chunk) => decoder.feed(chunk.toString()));
  child.stderr.on("data", (chunk) => {
    const message = chunk.toString();
    state.stderr = `${state.stderr || ""}${message}`.slice(-4096);
    if (state.stage === "starting" && state.stderr.includes("listening on")) {
      state.stage = "running";
      state.listeningAt = utcNow();
      writeState({ directory, state });
    }
  });
  child.on("error", (error) => {
    hasExited = true;
    state.stage = "failed";
    state.errorCode = error.code;
    writeState({ directory, state });
    clearInterval(control);
    clearTimeout(deadline);
  });
  child.on("exit", (code, signal) => {
    hasExited = true;
    if (accepting) {
      decoder.flush();
      state.stage = "ended";
      state.exitCode = code;
      state.signal = signal;
      state.endedAt = utcNow();
      writeState({ directory, state });
    }
    clearInterval(control);
    clearTimeout(deadline);
  });
  // The request is a job-local marker, never a persisted PID to signal.
  const control = setInterval(() => {
    if (!fs.existsSync(path.join(directory, "freeze.request"))) return;
    decoder.flush();
    accepting = false;
    state.healthyAtFreeze = state.stage === "running" && !hasExited;
    state.stage = "frozen";
    state.frozenAt = utcNow();
    // Internal result only. The caller exclusively owns published .txt files,
    // including timeout fallbacks; a delayed acknowledgement cannot rewrite them.
    const result = path.join(directory, "capture-result.internal");
    fs.writeFileSync(
      `${result}.tmp`,
      JSON.stringify({ state, wire: fs.readFileSync(live, "utf8") }),
    );
    fs.renameSync(`${result}.tmp`, result);
    writeState({ directory, state });
    clearInterval(control);
    // Only our still-owned child; timeout independently bounds orphan lifetime.
    if (!hasExited) child.kill("SIGINT");
  }, 100);
  const deadline = setTimeout(() => {
    clearInterval(control);
    accepting = false;
    state.stage = "ended";
    state.endedAt = utcNow();
    writeState({ directory, state });
    if (!hasExited) child.kill("SIGINT");
  }, 425000);
  deadline.unref();
}

async function start(directory) {
  const child = spawn(process.execPath, [__filename, "supervise", directory], {
    detached: true,
    stdio: "ignore",
    env: process.env,
  });
  child.unref();
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const state = readState(directory);
    if (state.stage === "running") return;
    if (["failed", "ended"].includes(state.stage))
      throw new Error(`DNS capture startup failed: ${JSON.stringify(state)}`);
    await delay(100);
  }
  throw new Error("DNS capture did not confirm startup within five seconds");
}

function publishCapture({ directory, state, wire, freezeOutcome }) {
  // Write once. No background process ever writes these final artifact names.
  fs.writeFileSync(path.join(directory, "dns-wire.txt"), wire, { flag: "wx" });
  fs.writeFileSync(
    path.join(directory, "capture-status.txt"),
    `${JSON.stringify({ ...state, freezeOutcome })}\n`,
    { flag: "wx" },
  );
}

async function freeze(directory) {
  // One publication attempt per job. An incomplete fallback is terminal even
  // if a stalled supervisor subsequently acknowledges the outstanding request.
  fs.writeFileSync(path.join(directory, "publication.lock"), utcNow(), { flag: "wx" });
  fs.writeFileSync(path.join(directory, "freeze.request"), utcNow());
  const result = path.join(directory, "capture-result.internal");
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (fs.existsSync(result)) {
      const captured = JSON.parse(fs.readFileSync(result, "utf8"));
      publishCapture({ directory, ...captured, freezeOutcome: "acknowledged" });
      return;
    }
    await delay(100);
  }
  const state = readState(directory);
  const live = path.join(directory, "dns-wire.live");
  const wire = fs.existsSync(live) ? fs.readFileSync(live, "utf8") : "";
  publishCapture({ directory, state, wire, freezeOutcome: "timeout" });
  throw new Error("DNS capture did not acknowledge freeze; evidence incomplete");
}

function verify(directory) {
  const read = (name) => {
    const file = path.join(directory, name);
    return fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  };
  const status = read("capture-status.txt");
  const reasons = completeness({
    state: status ? JSON.parse(status) : { stage: "missing" },
    wire: read("dns-wire.txt"),
    agent: read("final.txt"),
  });
  const result = reasons.length ? `UNCONFIRMED: ${reasons.join("; ")}` : "COMPLETE_DNS_EVIDENCE";
  fs.writeFileSync(path.join(directory, "completeness.txt"), `${result}\n`);
  console.log(result);
  return reasons.length ? 1 : 0;
}

async function main() {
  const [, , mode, directory] = process.argv;
  if (!directory || !path.isAbsolute(directory))
    throw new Error("Absolute evidence directory required");
  if (mode === "supervise") supervise(directory);
  else if (mode === "start") await start(directory);
  else if (mode === "freeze") await freeze(directory);
  else if (mode === "verify") process.exitCode = verify(directory);
  else throw new Error("Unknown capture mode");
}

module.exports = {
  createDecoder,
  completeness,
  supervise,
  start,
  freeze,
  verify,
};
if (require.main === module)
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
