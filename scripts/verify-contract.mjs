import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../contracts/policy_guard.py", import.meta.url), "utf8");
const required = [
  "class PolicyGuard(gl.Contract)",
  "def create_organization(",
  "def add_reviewer(",
  "def register_source_authority(",
  "def revoke_source_authority(",
  "def register_policy_version(",
  "def create_proposal(",
  "def rebind_proposal_policy(",
  "def add_evidence(",
  "def approve_proposal(",
  "def open_remediation_window(",
  "def start_evaluation(",
  "def authorize_action(",
  "def execute_action(",
  "gl.vm.run_nondet_unsafe",
  "gl.nondet.web.get",
  "gl.nondet.exec_prompt",
  "Required security audit is missing.",
  "binding_digest",
  "previous_evaluation_id",
  "source_authority_id",
  "SOURCE_UNAUTHORIZED",
  "citations_valid",
  "reliable_adjudication",
  "Reliable adjudication cannot begin before the evidence deadline",
];

const missing = required.filter((token) => !source.includes(token));
if (missing.length) {
  console.error("Contract verification failed. Missing:", missing.join(", "));
  process.exit(1);
}

if (/private.?key|seed.?phrase/i.test(source)) {
  console.error("Contract source contains forbidden secret-language pattern.");
  process.exit(1);
}

const forbidden = [
  'citations = allowed_urls',
  'host.endswith(allowed_host)',
  'allowed_host in host',
  'Only the organization owner or proposer can add evidence',
];
const unsafe = forbidden.filter((token) => source.includes(token));
if (unsafe.length) {
  console.error("Contract verification failed. Unsafe legacy control found:", unsafe.join(", "));
  process.exit(1);
}

console.log(`PolicyGuard contract verification passed (${required.length} controls checked).`);
