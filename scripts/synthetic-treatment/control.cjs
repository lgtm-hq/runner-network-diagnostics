"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { globalDns, cleanup } = require("../resolver-counterfactual/control.cjs");
const { runtime, measure, mainConfig, platformConfig } = require("../synthetic-induce/support.cjs");
function prepare({ induction, io }) {
  const state = { synthetic: true, arm: induction?.arm, disposition: "SYNTHETIC_NO_MUTATION" };
  io.save(state);
  if (!induction?.inScope || !["I2", "I3"].includes(induction.arm)) return state;
  if (induction.disposition !== "SYNTHETIC_INDUCED" || !induction.mutationIntent)
    throw new Error("synthetic induction incomplete");
  const owned = io.root("inspect", induction.token, "reset");
  if (owned.present !== true) throw new Error("synthetic platform reset not owned/present");
  state.originalDns = globalDns(io.dns());
  if (state.originalDns !== "") throw new Error("synthetic pre global DNS not empty");
  state.originalMain = io.hash(mainConfig);
  state.originalPlatform = io.hash(platformConfig);
  state.token = io.token();
  state.disposition = "SYNTHETIC_PREPARED";
  io.save(state);
  if (state.arm === "I2") install(state, io);
  return state;
}
function install(state, io) {
  state.mutationIntent = true;
  io.save(state);
  io.root("create", state.token);
  state.disposition = "SYNTHETIC_OVERRIDE_INSTALLED";
  io.save(state);
}
function entry(phase, setup = () => runtime("ci1203-synthetic-treatment")) {
  const r = setup();
  try {
    if (phase === "pre") {
      if (r.load()) throw new Error("synthetic treatment state already exists");
      r.receipt(phase, prepare({ induction: runtime("ci1203-synthetic-induce").load(), io: r.io }));
    } else if (phase === "main") {
      const state = r.load();
      if (!state) throw new Error("synthetic treatment pre did not save state");
      if (state.disposition === "SYNTHETIC_NO_MUTATION") {
        r.receipt(phase, { disposition: state.disposition });
        return;
      }
      if (state.arm === "I3") {
        const oracle = JSON.parse(
          fs.readFileSync(
            path.join(runtime("ci1203-synthetic-induce").out, "oracle-A.json"),
            "utf8",
          ),
        );
        if (globalDns(oracle.dns) !== "" || !oracle.status.split(/\r?\n/).includes("Initialized"))
          throw new Error("I3 baseline oracle unavailable");
        if (state.disposition !== "SYNTHETIC_PREPARED" || globalDns(r.io.dns()) !== "")
          throw new Error("I3 initial defect not observed");
        install(state, r.io);
        r.io.restart();
      }
      if (globalDns(r.io.dns()) !== "127.0.0.1")
        throw new Error("synthetic override not effective");
      r.receipt(phase, { arm: state.arm, disposition: state.disposition });
      if (state.arm === "I3") measure("B", r);
    } else if (phase === "register-guard")
      r.receipt(phase, { disposition: "SYNTHETIC_GUARD_REGISTERED" });
    else r.receipt(phase, cleanup({ phase, state: r.load(), io: r.io }));
  } catch (error) {
    console.error(`ci1203-synthetic-FAILURE phase=${phase}: ${error.message}`);
    process.exitCode = 1;
  }
}
module.exports = { prepare, install, entry };
