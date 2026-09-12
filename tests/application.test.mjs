import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("production worker renders PolicyGuard metadata and application copy", async () => {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  const response = await worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /PolicyGuard/);
  assert.match(html, /Turn written policy into an enforceable decision/);
  assert.match(html, /GenLayer Policy Compliance/);
  assert.doesNotMatch(html, /Starter Project/);
});

test("wallet client uses real GenLayer methods and never labels demo data live", async () => {
  const source = await readFile(new URL("../components/policyguard-app.tsx", import.meta.url), "utf8");
  for (const token of ["eth_requestAccounts", "wallet_switchEthereumChain", "readContract", "writeContract", "TransactionStatus.FINALIZED", "leaderOnly: false"]) {
    assert.match(source, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(source, /No sample verdict is presented as contract state/);
});

test("fresh proposal actions use the active proposal and expose reviewer-roster setup", async () => {
  const source = await readFile(new URL("../components/policyguard-app.tsx", import.meta.url), "utf8");
  assert.match(source, /const \[activeProposalId, setActiveProposalId\]/);
  assert.match(source, /"add_reviewer"/);
  assert.match(source, /Load demo case/);
  for (const action of ["start_evaluation", "add_evidence", "authorize_action", "execute_action"]) {
    assert.match(source, new RegExp(`"${action}"[^\\n]*activeProposalId`));
  }
  assert.doesNotMatch(source, /start_evaluation", \[DEMO_ID\]/);
  assert.doesNotMatch(source, /add_evidence", \[DEMO_ID/);
  assert.doesNotMatch(source, /authorize_action", \[DEMO_ID\]/);
  assert.doesNotMatch(source, /execute_action", \[DEMO_ID/);
});

test("deployment configuration targets stable Studionet", async () => {
  const deployment = JSON.parse(await readFile(new URL("../config/deployment.json", import.meta.url), "utf8"));
  assert.equal(deployment.chainId, 61999);
  assert.equal(deployment.rpcUrl, "https://studio.genlayer.com/api");
  assert.equal(deployment.demoProposalId, "policyguard-demo-35000");
  assert.match(deployment.contractAddress, /^0x[0-9a-fA-F]{40}$/);
  assert.match(deployment.deploymentTransaction, /^0x[0-9a-fA-F]{64}$/);
  assert.match(deployment.missingAuditEvaluationTransaction, /^0x[0-9a-fA-F]{64}$/);
  assert.match(deployment.correctedEvaluationTransaction, /^0x[0-9a-fA-F]{64}$/);
  assert.equal(deployment.missingAuditVerdict, "NON_COMPLIANT");
  assert.equal(deployment.correctedVerdict, "COMPLIANT");
  assert.equal(deployment.finalProposalState, "EXECUTED");
  assert.equal(deployment.deploymentStatus, "FINALIZED");
});
