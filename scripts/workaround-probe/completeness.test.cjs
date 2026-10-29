"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { nativeCompleteness, nonceWindow, packets } = require("./completeness.cjs");
const state = { stage: "frozen", freezeOutcome: "acknowledged", healthyAtFreeze: true };
const oracle = {
  nonce: "p-0123456789abcdef.example.com",
  oracleStart: "2026-10-26T12:00:00.100Z",
  oracleEnd: "2026-10-26T12:00:00.200Z",
  windowToleranceMs: 1,
};
const query = (name = oracle.nonce, destination = "127.0.0.100", time = "123456") =>
  `2026-10-26 12:00:00.${time} lo Out IP (proto UDP (17), length 60)\n    127.0.0.1.40000 > ${destination}.53: 1234+ A? ${name}. (32)\n`;

test("fresh P packet and engine acknowledgement suffice even with no allowed-name packet or DNS answer", () => {
  const record = nativeCompleteness({ state, wire: query(), oracles: { P: oracle } });
  assert.equal(record.complete, true);
  assert.equal(record.windows.P.queriesToForwarder, 1);
  assert.equal(record.windows.P.responses, 0);
});

test("legacy allowed-name traffic, reply-only question sections and stale nonces cannot fake P coverage", () => {
  const reply = `2026-10-26 12:00:00.123456 IP (proto UDP (17), length 90)\n    127.0.0.100.53 > 127.0.0.1.40000: 1234 NXDomain q: A? ${oracle.nonce}. 0/1/0\n`;
  for (const wire of [
    query("api.github.com"),
    query("p-aaaaaaaaaaaaaaaa.example.com"),
    query(oracle.nonce, "127.0.0.100", "000000"),
    reply,
    "",
  ]) {
    const record = nativeCompleteness({ state, wire, oracles: { P: oracle } });
    assert.equal(record.complete, false);
    assert.equal(record.freshP, false);
  }
  assert.equal(nonceWindow({ wire: reply, oracle }).responses, 1);
  assert.equal(nonceWindow({ wire: reply, oracle }).queries, 0);
});

test("wrong or absent A/Z traffic stays an outcome failure instead of being masked as invalid capture", () => {
  const a = { ...oracle, nonce: "a-0123456789abcdef.example.com" };
  const z = { ...oracle, nonce: "z-0123456789abcdef.example.com" };
  const record = nativeCompleteness({
    state,
    wire: query() + query(a.nonce, "168.63.129.16"),
    oracles: { P: oracle, A: a, Z: z },
  });
  assert.equal(record.complete, true);
  assert.equal(record.windows.A.queriesToAzure, 1);
  assert.equal(record.windows.A.queriesToAgent, 0);
  assert.equal(record.windows.Z.queries, 0);
});

test("unhealthy freeze, missing P and malformed registered windows cannot claim complete instrument", () => {
  for (const change of [
    { stage: "ended" },
    { freezeOutcome: "timeout" },
    { healthyAtFreeze: false },
  ])
    assert.equal(
      nativeCompleteness({ state: { ...state, ...change }, wire: query(), oracles: { P: oracle } })
        .complete,
      false,
    );
  assert.equal(nativeCompleteness({ state, wire: query(), oracles: {} }).complete, false);
  for (const change of [
    { nonce: "example.com" },
    { oracleStart: "invalid" },
    { windowToleranceMs: 1000 },
    { oracleEnd: "2026-10-26T11:00:00Z" },
  ])
    assert.equal(
      nativeCompleteness({ state, wire: query(), oracles: { P: { ...oracle, ...change } } })
        .complete,
      false,
    );
  assert.throws(() => packets("tcpdump failed\n"), /framing/);
});

test("registered 1 ms tolerance is explicit and does not admit packets two ms away", () => {
  assert.equal(
    nonceWindow({ wire: query(oracle.nonce, "127.0.0.100", "099000"), oracle }).queries,
    1,
  );
  assert.equal(
    nonceWindow({ wire: query(oracle.nonce, "127.0.0.100", "098000"), oracle }).queries,
    0,
  );
});
