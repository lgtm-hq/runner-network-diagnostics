"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { emptyDomainGate, postAgentEvents } = require("./agent-log.cjs");
const time = (clock) => `Mon, 26 Oct 2026 ${clock} GMT:`;
function inputs({ address = "104.20.23.154", pid = "3645", clock = "12:43:02" } = {}) {
  const record = `${time(clock)}endpoint called ip address:port ${address}:443, domain: , pid: ${pid}, process: curl, status: `;
  const dropped = `${time(clock)}ip address dropped: ${address}`;
  return {
    agentLog: `${record}\n${dropped}\n${record}\n`,
    verifyTime: `2026-10-26T${clock}.100Z`,
    negativeAddress: `${address}\n`,
    negativeReport: `verdict=CONFIRMED_BLOCK curl_rc=7 address=${address} pid=${pid} agent=active\n`,
    negativeEvents: `${record}\n${dropped}\n`,
    negativeStepStart: `2026-10-26T${clock}.340Z`,
    negativeVerdictTime: `2026-10-26T${clock}.900Z`,
  };
}
// Fields copied from each healthy corrected-run C0 job's own strict-control
// evidence. These fixtures check record format; they are not new canary data.
for (const [job, address, pid, clock] of [
  ["121578043047", "104.20.23.154", "3645", "12:43:02"],
  ["121578043311", "172.66.147.243", "3625", "12:43:01"],
  ["121578043357", "104.20.23.154", "3643", "12:43:03"],
  ["121578043531", "172.66.147.243", "3418", "12:43:09"],
])
  test(`healthy C0 format ${job} excludes only its own verified control`, () => {
    const result = emptyDomainGate(inputs({ address, pid, clock }));
    assert.equal(result.outcome, "PASS");
    assert.equal(result.excluded.length, 1);
    assert.equal(result.counted.length, 1);
  });

test("bypass records from an induced host remain failures", () => {
  const data = inputs();
  data.agentLog += `${time("12:43:03")}endpoint called ip address:port 168.63.129.16:53, domain: , pid: 2296, process: systemd-resolved, status: \n`;
  const result = emptyDomainGate(data);
  assert.equal(result.outcome, "FAIL");
  assert.equal(result.remaining[0].process, "systemd-resolved");
});
for (const replacement of [
  [":443, domain:", ":80, domain:"],
  ["pid: 3645", "pid: 3646"],
  ["process: curl", "process: node"],
  ["104.20.23.154:443", "104.20.23.155:443"],
])
  test(`same-control resemblance does not exclude ${replacement[1]}`, () => {
    const data = inputs();
    data.agentLog += data.negativeEvents.split("\n")[0].replace(...replacement) + "\n";
    assert.equal(emptyDomainGate(data).outcome, "FAIL");
  });
test("confirmed verdict without the authoritative record is INVALID", () => {
  const data = inputs();
  data.agentLog = "";
  assert.equal(emptyDomainGate(data).outcome, "INVALID");
});
test("a matching PID outside the declared interval is not excluded", () => {
  const data = inputs();
  data.agentLog += data.negativeEvents.split("\n")[0].replace("12:43:02", "12:43:03") + "\n";
  assert.equal(emptyDomainGate(data).outcome, "FAIL");
});
test("missing interval drop or negative-agent membership cannot pass", () => {
  for (const key of ["negativeEvents", "agentLog"]) {
    const data = inputs();
    data[key] = data[key]
      .split("\n")
      .filter((line) => !line.includes("ip address dropped:"))
      .join("\n");
    // A missing post drop invalidates correlation; a missing control-membership
    // drop does not remove the independently required membership of its event.
    const result = emptyDomainGate(data);
    if (key === "agentLog") assert.equal(result.outcome, "INVALID");
  }
  const data = inputs();
  data.negativeEvents = "";
  assert.equal(emptyDomainGate(data).outcome, "INVALID");
});
test("an unconfirmed negative verdict never permits the exception", () => {
  const data = inputs();
  data.negativeReport = data.negativeReport.replace("CONFIRMED_BLOCK", "UNCONFIRMED");
  const result = emptyDomainGate(data);
  assert.equal(result.outcome, "FAIL");
  assert.equal(result.excluded.length, 0);
});
test("the whole second containing verification is checked fail-closed", () => {
  const data = inputs();
  data.agentLog += `${time("12:43:02")}endpoint called ip address:port 140.82.116.3:443, domain: , pid: 7, process: Runner.Worker, status: \n`;
  data.verifyTime = "2026-10-26T12:43:02.999Z";
  assert.equal(emptyDomainGate(data).outcome, "FAIL");
});
test("invalid timestamps and reversed intervals refuse assessment", () => {
  const data = inputs();
  assert.throws(() => emptyDomainGate({ ...data, verifyTime: "unknown" }));
  assert.throws(() => emptyDomainGate({ ...data, negativeStepStart: "2026-10-26T12:43:04Z" }));
});

test("post extraction ignores snapshot echoes and refuses ambiguous blocks", () => {
  const { postAgentEvents } = require("./agent-log.cjs");
  const log =
    "2026-10-26T12:43:00.000Z Mon, 26 Oct 2026 12:43:00 GMT:endpoint echo\n" +
    "2026-10-26T12:43:01.000Z Post job cleanup.\n" +
    "2026-10-26T12:43:01.000Z log:\n" +
    "2026-10-26T12:43:01.001Z Mon, 26 Oct 2026 12:43:01 GMT:post_event called\n" +
    "2026-10-26T12:43:01.002Z status:\nInitialized\n" +
    "2026-10-26T12:43:02.000Z Post job cleanup.\nother post\n";
  assert.equal(postAgentEvents(log), "Mon, 26 Oct 2026 12:43:01 GMT:post_event called\n");
  assert.throws(() => postAgentEvents("snapshot only"));
  assert.throws(() => postAgentEvents(log + log));
});

for (const fixture of require("./historical-agent-cases.json"))
  test(`frozen historical event calibration ${fixture.name}`, () => {
    assert.equal(emptyDomainGate(fixture.inputs).outcome, fixture.expected);
  });

test("unknown or malformed connection framing cannot silently disappear", () => {
  for (const extra of [
    "unknown timestamp:endpoint called ip address:port 1.2.3.4:443, domain: , pid: 7, process: node, status: ",
    `${time("12:43:03")}endpoint called malformed domain: , pid: 7`,
    `${time("12:43:03")}endpoint called ip address:port 1.2.3.4:443, domain:`,
  ]) {
    const data = inputs();
    data.agentLog += extra + "\n";
    assert.throws(() => emptyDomainGate(data));
  }
});

for (const malformed of [
  "unknown timestamp:endpoint called ip address:port 168.63.129.16:53, domain: , pid: 7, process: systemd-resolved, status: ",
  "unknown timestamp:ip address dropped: 168.63.129.16",
])
  test(`composed extraction refuses ${malformed.split(":")[1]}`, () => {
    const data = inputs();
    const consoleText =
      "Post job cleanup.\n[harden-runner] post-step\nlog:\n" +
      data.agentLog +
      "Mon, 26 Oct 2026 12:43:10 GMT:post_event called\n" +
      malformed +
      "\nstatus:\nInitialized\nagent.service log:\njournal text\nPost job cleanup.\n";
    assert.throws(() => emptyDomainGate({ ...data, agentLog: postAgentEvents(consoleText) }));
  });

for (const prefix of ["26 Oct 2026 12:43:03 GMT:", " Mon, 26 Oct 2026 12:43:03 GMT:"])
  test(`composed extraction retains parseable noncanonical connection ${JSON.stringify(prefix)}`, () => {
    const data = inputs();
    const extra = `${prefix}endpoint called ip address:port 168.63.129.16:53, domain: , pid: 7, process: systemd-resolved, status: `;
    const consoleText =
      "Post job cleanup.\n[harden-runner] post-step\nlog:\n" +
      data.agentLog +
      "Mon, 26 Oct 2026 12:43:10 GMT:post_event called\n" +
      extra +
      "\nstatus:\nInitialized\nPost job cleanup.\n";
    const extracted = postAgentEvents(consoleText);
    assert.ok(extracted.includes(extra));
    const result = emptyDomainGate({ ...data, agentLog: extracted });
    assert.equal(result.outcome, "FAIL");
    assert.equal(result.remaining.length, 1);
  });

test("the first GMT delimiter is the timestamp even when the process field contains GMT", () => {
  const data = inputs();
  data.agentLog += `${time("12:43:03")}endpoint called ip address:port 168.63.129.16:53, domain: , pid: 7, process: node GMT:worker, status: \n`;
  const result = emptyDomainGate(data);
  assert.equal(result.outcome, "FAIL");
  assert.equal(result.remaining[0].process, "node GMT:worker");
});
