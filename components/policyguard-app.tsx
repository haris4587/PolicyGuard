"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertCircle, ArrowUpRight, BadgeCheck, BookOpenCheck, Check, CheckCircle2,
  CircleDot, Clock3, Code2, Copy, FileCheck2, FileLock2, Fingerprint, Gavel,
  History, KeyRound, Link2, LoaderCircle, LockKeyhole, Network, Plus, RefreshCw,
  Scale, ShieldCheck, TriangleAlert, Unplug, Wallet, XCircle,
} from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import deployment from "@/config/deployment.json";
import manifest from "@/demo/manifest.json";

type Data = Record<string, unknown>;
type TxStage = "idle" | "wallet" | "submitted" | "accepted" | "finalized" | "failed";
type TxState = { stage: TxStage; label: string; hash: string; error: string };
interface EthereumProvider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: string, callback: (...args: unknown[]) => void): void;
  removeListener?(event: string, callback: (...args: unknown[]) => void): void;
}
declare global { interface Window { ethereum?: EthereumProvider } }

const CHAIN_ID = 61999;
const CHAIN_HEX = "0xf22f";
const RPC_URL = process.env.NEXT_PUBLIC_GENLAYER_RPC_URL || "https://studio.genlayer.com/api";
const EXPLORER = "https://explorer-studio.genlayer.com";
const GITHUB = "https://github.com/haris4587/PolicyGuard";
const ADDRESS = (process.env.NEXT_PUBLIC_POLICYGUARD_CONTRACT_ADDRESS || deployment.contractAddress).trim();
const CONTRACT_READY = /^0x[0-9a-fA-F]{40}$/.test(ADDRESS);
const DEMO_ID = deployment.demoProposalId || "policyguard-demo-35000";
const doc = (id: string) => manifest.documents.find((item) => item.id === id);
const POLICY_DOC = doc("dao-policy-v1");
const PROPOSAL_DOC = doc("grant-35000");
const APPROVALS_DOC = doc("reviewer-approvals");
const AUDIT_DOC = doc("security-audit");
const RAW_BASE = manifest.evidenceCommit
  ? `https://raw.githubusercontent.com/haris4587/PolicyGuard/${manifest.evidenceCommit}/demo/`
  : "https://raw.githubusercontent.com/haris4587/PolicyGuard/main/demo/";
const rawUrl = (path: string) => RAW_BASE + path;

function parseRecord(value: unknown): Data | null {
  if (!value) return null;
  if (typeof value === "string") {
    try { const parsed: unknown = JSON.parse(value); return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Data : null; }
    catch { return null; }
  }
  return typeof value === "object" && !Array.isArray(value) ? value as Data : null;
}
function parseHistory(value: unknown): Data[] {
  if (typeof value === "string") { try { value = JSON.parse(value) as unknown; } catch { return []; } }
  return Array.isArray(value) ? value.filter((item): item is Data => Boolean(item && typeof item === "object")) : [];
}
function short(value: unknown, left = 8, right = 6) {
  const text = String(value || "");
  if (!text) return "Not recorded";
  return text.length > left + right + 3 ? `${text.slice(0, left)}…${text.slice(-right)}` : text;
}
function human(value: unknown) { return String(value || "—").replaceAll("_", " "); }
function formatDate(value: unknown) { const time = Number(value || 0); return time ? new Date(time * 1000).toLocaleString() : "—"; }
function tone(value: unknown) {
  const status = String(value || "").toUpperCase();
  if (["COMPLIANT", "AUTHORIZED", "EXECUTED"].includes(status)) return "success";
  return status === "NON_COMPLIANT" ? "danger" : "review";
}
function errorMessage(error: unknown) {
  const item = error as { code?: number; message?: string; shortMessage?: string; cause?: { code?: number; message?: string } };
  const code = item?.code ?? item?.cause?.code;
  const message = item?.shortMessage || item?.message || item?.cause?.message || "The operation could not be completed.";
  if (code === 4001 || /reject|denied/i.test(message)) return "The MetaMask request was rejected. Nothing was submitted.";
  if (/insufficient funds/i.test(message)) return "The connected wallet does not have enough test GEN.";
  if (/chain|network/i.test(message)) return "MetaMask is on the wrong network. Switch to GenLayer Studionet.";
  return message.replace(/^Error:\s*/, "").slice(0, 420);
}

function External({ href, children }: { href: string; children: React.ReactNode }) {
  return <a className="external" href={href} target="_blank" rel="noreferrer">{children}<ArrowUpRight /></a>;
}
function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return <Button type="button" variant="ghost" size="icon-xs" disabled={!value} aria-label="Copy value" onClick={async () => {
    await navigator.clipboard.writeText(value); setCopied(true); window.setTimeout(() => setCopied(false), 1200);
  }}>{copied ? <Check /> : <Copy />}</Button>;
}
function Status({ value }: { value: unknown }) {
  return <span className={`status ${tone(value)}`}><CircleDot />{human(value)}</span>;
}
function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return <div className="field"><Label>{label}</Label>{children}{hint ? <small>{hint}</small> : null}</div>;
}
function Proof({ label, digest, href }: { label: string; digest: string; href: string }) {
  return <div className="proof"><div><CheckCircle2 /><span>{label}</span></div><div><code>{short(digest)}</code><CopyButton value={digest} /><External href={href}><span className="sr-only">Open {label}</span></External></div></div>;
}
function HashLine({ label, value }: { label: string; value: unknown }) {
  const text = String(value || "");
  return <div className="hash-line"><span>{label}</span><code title={text}>{short(text, 11, 8)}</code><CopyButton value={text} /></div>;
}
function Requirements({ title, icon, items, empty }: { title: string; icon: React.ReactNode; items: unknown[]; empty: string }) {
  return <div className="requirements"><h3>{icon}{title}</h3>{items.length ? <ul>{items.map((item, index) => <li key={`${String(item)}-${index}`}>{String(item)}</li>)}</ul> : <p>{empty}</p>}</div>;
}
function JsonView({ value, empty }: { value: Data | null; empty: string }) {
  return value ? <pre className="json-view">{JSON.stringify(value, null, 2)}</pre> : <div className="empty-inline"><FileLock2 />{empty}</div>;
}

function Verdict({ value }: { value: Data | null }) {
  if (!value) return <div className="empty-state"><Gavel /><div><h3>No finalized on-chain evaluation</h3><p>A verdict appears only after finalized contract state is read.</p></div></div>;
  const satisfied = Array.isArray(value.satisfied_requirements) ? value.satisfied_requirements : [];
  const missing = Array.isArray(value.missing_requirements) ? value.missing_requirements : [];
  const violated = Array.isArray(value.violated_requirements) ? value.violated_requirements : [];
  const citations = Array.isArray(value.citations) ? value.citations : [];
  return <div className={`verdict ${tone(value.status)}`}>
    <div className="verdict-head"><div><p className="eyebrow">Finalized evaluation #{String(value.evaluation_sequence || "—")}</p><div className="verdict-title"><h2>{human(value.status)}</h2><Status value={value.status} /></div><p>{String(value.reason || "No reason returned.")}</p></div>
      <div className="score"><strong>{String(value.evidence_quality_score ?? 0)}</strong><span>evidence quality</span><Progress value={Number(value.evidence_quality_score || 0)} /></div></div>
    <div className="verdict-grid"><Requirements title="Satisfied" icon={<CheckCircle2 />} items={satisfied} empty="No satisfied requirement returned." /><Requirements title="Missing or violated" icon={<TriangleAlert />} items={[...missing, ...violated]} empty="No missing requirement returned." /></div>
    <Separator /><div className="verdict-meta"><span>Policy v{String(value.policy_version || "—")}</span><span>Approvals {String(value.approval_count ?? "—")}</span><span>Confidence {String(value.confidence || "—")}</span><span>Revision {String(value.input_revision ?? "—")}</span></div>
    {citations.length ? <div className="citations">{citations.map((url) => <External href={String(url)} key={String(url)}><Link2 />Source</External>)}</div> : null}
    <div className="hashes"><HashLine label="Binding" value={value.binding_digest} /><HashLine label="Policy" value={value.policy_digest} /><HashLine label="Proposal" value={value.proposal_digest} /></div>
  </div>;
}

function Timeline({ items }: { items: Data[] }) {
  if (!items.length) return <div className="empty-inline"><History />No immutable evaluation history yet.</div>;
  return <div className="timeline">{[...items].reverse().map((item, index) => <article key={String(item.evaluation_id || index)}><i className={tone(item.status)}>{index ? <Check /> : <CircleDot />}</i><div><div><strong>{String(item.evaluation_id || "Evaluation")}</strong><Status value={item.status} /></div><p>{String(item.reason || "No reason returned.")}</p><small>{formatDate(item.evaluated_at)} · previous {short(item.previous_evaluation_id)}</small></div></article>)}</div>;
}
function TxPanel({ tx }: { tx: TxState }) {
  const steps: TxStage[] = ["wallet", "submitted", "accepted", "finalized"];
  if (tx.stage === "idle") return <div className="empty-inline"><ShieldCheck />Wallet confirmation and Full Consensus progress will appear here.</div>;
  if (tx.stage === "failed") return <Alert variant="destructive"><XCircle /><AlertTitle>{tx.label} did not complete</AlertTitle><AlertDescription>{tx.error}{tx.hash ? <code className="block break-all pt-2 text-xs">{tx.hash}</code> : null}</AlertDescription></Alert>;
  const active = steps.indexOf(tx.stage);
  return <div className="tx-panel" aria-live="polite"><div className="tx-head"><span>{tx.stage === "finalized" ? <CheckCircle2 /> : <LoaderCircle className="animate-spin" />}{tx.label}</span>{tx.hash ? <External href={`${EXPLORER}/tx/${tx.hash}`}>{short(tx.hash)}</External> : null}</div><div className="tx-steps">{steps.map((step, index) => <div className={index <= active ? "active" : ""} key={step}><i>{index < active || tx.stage === "finalized" ? <Check /> : index + 1}</i><span>{human(step)}</span></div>)}</div></div>;
}

export function PolicyGuardApp() {
  const [account, setAccount] = useState("");
  const [chain, setChain] = useState("");
  const [walletBusy, setWalletBusy] = useState(false);
  const [walletError, setWalletError] = useState("");
  const [proposalId, setProposalId] = useState(DEMO_ID);
  const [proposal, setProposal] = useState<Data | null>(null);
  const [organization, setOrganization] = useState<Data | null>(null);
  const [policy, setPolicy] = useState<Data | null>(null);
  const [verdict, setVerdict] = useState<Data | null>(null);
  const [authorization, setAuthorization] = useState<Data | null>(null);
  const [history, setHistory] = useState<Data[]>([]);
  const [stats, setStats] = useState<Data | null>(null);
  const [readBusy, setReadBusy] = useState(false);
  const [readError, setReadError] = useState("");
  const [tx, setTx] = useState<TxState>({ stage: "idle", label: "", hash: "", error: "" });
  const [org, setOrg] = useState({ id: "my-dao", name: "My DAO" });
  const [policyForm, setPolicyForm] = useState({ org: "my-dao", id: "treasury-policy", version: "1", title: "Treasury Operations Policy", url: rawUrl("policy/dao-grant-policy-v1.md"), sha: POLICY_DOC?.sha256 || "", threshold: "20000", approvals: "3", docs: "AUDIT", baseline: "" });
  const [proposalForm, setProposalForm] = useState({ id: "grant-request-001", org: "my-dao", policy: "treasury-policy", version: "1", type: "TREASURY_GRANT", description: "Authorize a USD 35,000 treasury grant for security tooling.", amount: "35000", url: rawUrl("proposals/grant-35000.md"), sha: PROPOSAL_DOC?.sha256 || "", executor: "" });
  const [evidenceForm, setEvidenceForm] = useState({ proposal: DEMO_ID, id: "audit-remediation-001", type: "AUDIT", url: rawUrl("evidence/security-audit.md"), sha: AUDIT_DOC?.sha256 || "" });
  const [approvalForm, setApprovalForm] = useState({ proposal: DEMO_ID, url: rawUrl("evidence/reviewer-approvals.md"), sha: APPROVALS_DOC?.sha256 || "" });
  const [executionRef, setExecutionRef] = useState("treasury-execution-demo-001");
  const correctNetwork = chain.toLowerCase() === CHAIN_HEX;
  const walletReady = Boolean(account && correctNetwork);
  const latestStatus = String(verdict?.status || proposal?.latest_verdict || "UNEVALUATED");
  const counts = useMemo<Array<[string, string]>>(() => [
    ["Policies", String(stats?.policy_versions ?? 0)],
    ["Proposals", String(stats?.proposals ?? 0)],
    ["Evaluations", String(stats?.evaluations ?? 0)],
    ["Authorizations", String(stats?.authorizations ?? 0)],
  ], [stats]);

  const refreshWallet = useCallback(async () => {
    if (!window.ethereum) return;
    try { const [accounts, chainId] = await Promise.all([window.ethereum.request({ method: "eth_accounts" }), window.ethereum.request({ method: "eth_chainId" })]); setAccount(Array.isArray(accounts) ? String(accounts[0] || "") : ""); setChain(String(chainId || "")); } catch { /* passive */ }
  }, []);
  useEffect(() => {
    void refreshWallet(); if (!window.ethereum) return;
    const accountsChanged = (items: unknown) => setAccount(Array.isArray(items) ? String(items[0] || "") : "");
    const chainChanged = (value: unknown) => setChain(String(value || ""));
    window.ethereum.on?.("accountsChanged", accountsChanged); window.ethereum.on?.("chainChanged", chainChanged);
    return () => { window.ethereum?.removeListener?.("accountsChanged", accountsChanged); window.ethereum?.removeListener?.("chainChanged", chainChanged); };
  }, [refreshWallet]);
  const switchNetwork = useCallback(async () => {
    if (!window.ethereum) throw new Error("MetaMask is required for live PolicyGuard writes.");
    try { await window.ethereum.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_HEX }] }); }
    catch (error) {
      if ((error as { code?: number })?.code !== 4902) throw error;
      await window.ethereum.request({ method: "wallet_addEthereumChain", params: [{ chainId: CHAIN_HEX, chainName: "GenLayer Studionet", nativeCurrency: { name: "GEN", symbol: "GEN", decimals: 18 }, rpcUrls: [RPC_URL], blockExplorerUrls: [EXPLORER] }] });
    }
    setChain(String(await window.ethereum.request({ method: "eth_chainId" })));
  }, []);
  const connect = useCallback(async () => {
    setWalletBusy(true); setWalletError("");
    try { if (!window.ethereum) throw new Error("MetaMask was not detected. Install or open MetaMask and try again."); const accounts = await window.ethereum.request({ method: "eth_requestAccounts" }); const address = Array.isArray(accounts) ? String(accounts[0] || "") : ""; if (!address) throw new Error("MetaMask did not return an account."); setAccount(address); await switchNetwork(); }
    catch (error) { setWalletError(errorMessage(error)); } finally { setWalletBusy(false); }
  }, [switchNetwork]);

  const read = useCallback(async (functionName: string, args: unknown[] = []) => {
    if (!CONTRACT_READY) throw new Error("The verified Studionet contract address has not been recorded yet.");
    const [{ createClient }, { studionet }, types] = await Promise.all([import("genlayer-js"), import("genlayer-js/chains"), import("genlayer-js/types")]);
    const client = createClient({ chain: studionet }) as unknown as { readContract(input: Data): Promise<unknown> };
    return client.readContract({ address: ADDRESS, functionName, args, transactionHashVariant: types.TransactionHashVariant.LATEST_FINAL, jsonSafeReturn: true });
  }, []);
  const load = useCallback(async (override?: string) => {
    const id = String(override || proposalId).trim(); if (!id) return;
    setReadBusy(true); setReadError("");
    try {
      const p = parseRecord(await read("get_proposal", [id])); if (!p) throw new Error("No finalized proposal was found with that ID.");
      const [o, pol, v, h, a, s] = await Promise.all([read("get_organization", [String(p.organization_id)]), read("get_policy", [String(p.organization_id), String(p.policy_id), Number(p.policy_version)]), read("get_latest_evaluation", [id]), read("get_evaluation_history", [id]), read("get_authorization", [id]), read("get_protocol_stats")]);
      setProposalId(id); setProposal(p); setOrganization(parseRecord(o)); setPolicy(parseRecord(pol)); setVerdict(parseRecord(v)); setHistory(parseHistory(h)); setAuthorization(parseRecord(a)); setStats(parseRecord(s));
    } catch (error) { setReadError(errorMessage(error)); } finally { setReadBusy(false); }
  }, [proposalId, read]);
  useEffect(() => { if (CONTRACT_READY) void load(DEMO_ID); }, [load]);

  const write = useCallback(async (label: string, functionName: string, args: unknown[]) => {
    setTx({ stage: "wallet", label, hash: "", error: "" });
    try {
      if (!CONTRACT_READY) throw new Error("Live writes are disabled until the verified contract address is published.");
      if (!window.ethereum || !account) throw new Error("Connect MetaMask before submitting a transaction.");
      if (!correctNetwork) await switchNetwork();
      const [{ createClient }, { studionet }, types] = await Promise.all([import("genlayer-js"), import("genlayer-js/chains"), import("genlayer-js/types")]);
      const client = createClient({ chain: studionet, account: account as `0x${string}`, provider: window.ethereum as never }) as unknown as { writeContract(input: Data): Promise<unknown>; waitForTransactionReceipt(input: Data): Promise<Data> };
      const returned = await client.writeContract({ address: ADDRESS, functionName, args, leaderOnly: false, consensusMaxRotations: 3 });
      const hash = typeof returned === "string" ? returned : String((returned as Data)?.hash || returned); setTx({ stage: "submitted", label, hash, error: "" });
      const accepted = await client.waitForTransactionReceipt({ hash: returned, status: types.TransactionStatus.ACCEPTED, interval: 4000, retries: 180 }); if (String(accepted.txExecutionResultName || "").includes("ERROR")) throw new Error("The contract execution failed after consensus acceptance."); setTx({ stage: "accepted", label, hash, error: "" });
      const finalized = await client.waitForTransactionReceipt({ hash: returned, status: types.TransactionStatus.FINALIZED, interval: 4000, retries: 180 }); if (String(finalized.txExecutionResultName || "").includes("ERROR")) throw new Error("The transaction finalized with an execution error."); setTx({ stage: "finalized", label, hash, error: "" }); if (proposalId) await load(proposalId); return hash;
    } catch (error) { setTx((current) => ({ stage: "failed", label, hash: current.hash, error: errorMessage(error) })); return null; }
  }, [account, correctNetwork, load, proposalId, switchNetwork]);
  const integer = (value: string, label: string) => { if (!/^\d+$/.test(value.trim())) throw new Error(`${label} must be a whole number.`); return Number(value); };
  const submit = async (event: React.FormEvent, label: string, method: string, args: () => unknown[]) => { event.preventDefault(); try { await write(label, method, args()); } catch (error) { setTx({ stage: "failed", label, hash: "", error: errorMessage(error) }); } };

  return <main className="min-h-screen pb-14">
    <header className="topbar"><div className="shell topbar-inner"><a className="brand" href="#workspace"><span><ShieldCheck /></span><div><strong>PolicyGuard</strong><small>Policy compliance protocol</small></div></a><div className="wallet-area"><Badge variant="outline" className="network-badge"><Network />Studionet · {CHAIN_ID}</Badge>{account ? <div className="wallet-chip"><i className={correctNetwork ? "online" : "wrong"} /><span>{short(account)}</span><Button variant="ghost" size="icon-xs" aria-label="Disconnect local wallet session" onClick={() => { setAccount(""); setWalletError(""); }}><Unplug /></Button></div> : <Button className="connect" onClick={() => void connect()} disabled={walletBusy}>{walletBusy ? <LoaderCircle className="animate-spin" /> : <Wallet />}Connect MetaMask</Button>}</div></div></header>
    <div className="shell" id="workspace">
      <section className="hero"><div><div className="protocol-tags"><span><Fingerprint />Consensus-bound compliance</span><span><FileLock2 />Append-only evidence</span></div><h1>Turn written policy into an enforceable decision.</h1><p>Register exact policy bytes, gather reviewer approvals, authenticate real-world evidence, and let GenLayer validators determine whether an action may proceed.</p><div className="hero-links"><External href={GITHUB}><Code2 />Source</External><External href={CONTRACT_READY ? `${EXPLORER}/address/${ADDRESS}` : "https://studio.genlayer.com"}><Scale />{CONTRACT_READY ? "Contract" : "GenLayer Studio"}</External><External href={rawUrl("policy/dao-grant-policy-v1.md")}><BookOpenCheck />Demo policy</External></div></div>
        <div className="case"><div><div><p className="eyebrow">Primary case</p><h2>USD 35,000 grant</h2></div><Status value={latestStatus} /></div><dl><div><dt>Policy threshold</dt><dd>&gt; USD 20,000</dd></div><div><dt>Reviewer approvals</dt><dd>{String(proposal?.approval_count ?? 3)} / 3</dd></div><div><dt>Published audit</dt><dd className={history.length > 1 ? "ok" : "blocked"}>{history.length > 1 ? "Authenticated" : "Required"}</dd></div></dl><div className="guardrail"><LockKeyhole /><span>{latestStatus === "COMPLIANT" ? "Eligible for owner authorization" : "Execution remains blocked"}</span></div></div></section>
      {!CONTRACT_READY ? <Alert className="notice"><Clock3 /><AlertTitle>Deployment record pending</AlertTitle><AlertDescription>The production interface is live-ready, but reads and writes remain disabled until the verified Studionet address is recorded. No sample verdict is presented as contract state.</AlertDescription></Alert> : null}
      {walletError ? <Alert variant="destructive" className="notice"><AlertCircle /><AlertTitle>Wallet connection needs attention</AlertTitle><AlertDescription>{walletError}</AlertDescription></Alert> : null}
      {account && !correctNetwork ? <Alert className="notice warning"><TriangleAlert /><AlertTitle>Wrong network</AlertTitle><AlertDescription><span>Switch MetaMask to GenLayer Studionet, chain 61999.</span><Button size="sm" onClick={() => void switchNetwork()}>Switch network</Button></AlertDescription></Alert> : null}
      <section className="stats">{counts.map(([label, value]) => <div key={String(label)}><span>{label}</span><strong>{String(value)}</strong></div>)}<div><span>Network</span><strong className="text-base">Studionet</strong></div></section>

      <Tabs defaultValue="desk" className="workspace-tabs"><TabsList variant="line" className="tab-list"><TabsTrigger value="desk"><Gavel />Case desk</TabsTrigger><TabsTrigger value="policy"><BookOpenCheck />Policies</TabsTrigger><TabsTrigger value="proposal"><FileCheck2 />Proposals</TabsTrigger><TabsTrigger value="evidence"><Fingerprint />Evidence & approvals</TabsTrigger><TabsTrigger value="protocol"><ShieldCheck />Protocol</TabsTrigger></TabsList>
        <TabsContent value="desk" className="tab-content"><div className="desk-grid"><div className="stack">
          <Card className="surface"><CardHeader className="card-head"><div><CardTitle>Finalized compliance verdict</CardTitle><CardDescription>Read directly from the latest finalized contract state.</CardDescription></div><div className="lookup"><Input aria-label="Proposal ID" value={proposalId} onChange={(event) => setProposalId(event.target.value)} /><Button variant="outline" disabled={!CONTRACT_READY || readBusy} onClick={() => void load()}>{readBusy ? <LoaderCircle className="animate-spin" /> : <RefreshCw />}Load</Button></div></CardHeader><CardContent>{readError ? <Alert variant="destructive" className="mb-5"><AlertCircle /><AlertTitle>Read failed</AlertTitle><AlertDescription>{readError}</AlertDescription></Alert> : null}<Verdict value={verdict} /></CardContent></Card>
          <Card className="surface"><CardHeader><CardTitle>Immutable evaluation timeline</CardTitle><CardDescription>Every recheck links to, and preserves, its predecessor.</CardDescription></CardHeader><CardContent><Timeline items={history} /></CardContent></Card>
        </div><div className="stack">
          <Card className="surface"><CardHeader><CardTitle>Missing-audit demonstration</CardTitle><CardDescription>Commit-pinned inputs make this case independently reproducible.</CardDescription></CardHeader><CardContent className="stack small"><Proof label="Policy" digest={POLICY_DOC?.sha256 || ""} href={rawUrl("policy/dao-grant-policy-v1.md")} /><Proof label="Proposal" digest={PROPOSAL_DOC?.sha256 || ""} href={rawUrl("proposals/grant-35000.md")} /><Proof label="3 approvals" digest={APPROVALS_DOC?.sha256 || ""} href={rawUrl("evidence/reviewer-approvals.md")} /><div className="missing"><XCircle /><div><strong>Security audit absent</strong><span>Expected first result: NON COMPLIANT</span></div></div><Button disabled={!walletReady || !CONTRACT_READY || !manifest.evidenceCommit} onClick={() => void write("Bootstrap missing-audit demo", "bootstrap_demo", [manifest.evidenceCommit, POLICY_DOC?.sha256 || "", PROPOSAL_DOC?.sha256 || "", APPROVALS_DOC?.sha256 || ""])}><Plus />Bootstrap demo case</Button><Button className="consensus" disabled={!walletReady || !CONTRACT_READY} onClick={() => void write("Run Full Consensus evaluation", "start_evaluation", [DEMO_ID])}><Gavel />Start Full Consensus</Button></CardContent></Card>
          <Card className="surface remediation"><CardHeader><CardTitle>Remediate and re-evaluate</CardTitle><CardDescription>Append the audit, then record evaluation #2 without deleting #1.</CardDescription></CardHeader><CardContent className="stack small"><Proof label="Published audit" digest={AUDIT_DOC?.sha256 || ""} href={rawUrl("evidence/security-audit.md")} /><Button variant="outline" disabled={!walletReady || !CONTRACT_READY} onClick={() => void write("Append security audit", "add_evidence", [DEMO_ID, "audit-remediation-001", "AUDIT", rawUrl("evidence/security-audit.md"), AUDIT_DOC?.sha256 || ""])}><FileCheck2 />Append audit evidence</Button><Button className="success-button" disabled={!walletReady || !CONTRACT_READY} onClick={() => void write("Re-evaluate remediated proposal", "start_evaluation", [DEMO_ID])}><RefreshCw />Run re-evaluation</Button></CardContent></Card>
          <Card className="surface"><CardHeader><CardTitle>Authorization lock</CardTitle><CardDescription>The latest compliant binding must still match every current input.</CardDescription></CardHeader><CardContent className="stack small"><div className="auth-state"><KeyRound /><div><strong>{human(proposal?.status || "BLOCKED")}</strong><span>{authorization ? `Bound to ${short(authorization.evaluation_id)}` : "No active authorization"}</span></div></div><Button disabled={!walletReady || latestStatus !== "COMPLIANT"} onClick={() => void write("Authorize governed action", "authorize_action", [DEMO_ID])}><BadgeCheck />Authorize action</Button><Field label="Execution reference"><Input value={executionRef} onChange={(event) => setExecutionRef(event.target.value)} /></Field><Button variant="outline" disabled={!walletReady || proposal?.status !== "AUTHORIZED"} onClick={() => void write("Record authorized execution", "execute_action", [DEMO_ID, executionRef])}>Mark executed</Button></CardContent></Card>
        </div></div><Card className="surface tx-card"><CardHeader><CardTitle>Transaction lifecycle</CardTitle><CardDescription>Consensus status and execution result are checked separately.</CardDescription></CardHeader><CardContent><TxPanel tx={tx} /></CardContent></Card></TabsContent>

        <TabsContent value="policy" className="tab-content"><div className="two-grid"><Card className="surface"><CardHeader><CardTitle>Create an organization</CardTitle><CardDescription>The connected wallet becomes its policy owner.</CardDescription></CardHeader><CardContent><form className="form" onSubmit={(event) => void submit(event, "Create organization", "create_organization", () => [org.id, org.name])}><Field label="Organization ID"><Input value={org.id} onChange={(event) => setOrg({ ...org, id: event.target.value })} /></Field><Field label="Organization name"><Input value={org.name} onChange={(event) => setOrg({ ...org, name: event.target.value })} /></Field><Button type="submit" disabled={!walletReady}><Plus />Create organization</Button></form></CardContent></Card>
          <Card className="surface"><CardHeader><CardTitle>Register a policy version</CardTitle><CardDescription>Versions are immutable, sequential, and digest-bound.</CardDescription></CardHeader><CardContent><form className="form" onSubmit={(event) => void submit(event, "Register policy version", "register_policy_version", () => [policyForm.org, policyForm.id, integer(policyForm.version, "Version"), policyForm.title, policyForm.url, policyForm.sha.toLowerCase(), integer(policyForm.threshold, "Threshold"), integer(policyForm.approvals, "Approval count"), policyForm.docs, policyForm.baseline])}><div className="form-grid"><Field label="Organization ID"><Input value={policyForm.org} onChange={(event) => setPolicyForm({ ...policyForm, org: event.target.value })} /></Field><Field label="Policy ID"><Input value={policyForm.id} onChange={(event) => setPolicyForm({ ...policyForm, id: event.target.value })} /></Field></div><div className="form-grid"><Field label="Version"><Input value={policyForm.version} onChange={(event) => setPolicyForm({ ...policyForm, version: event.target.value })} /></Field><Field label="Title"><Input value={policyForm.title} onChange={(event) => setPolicyForm({ ...policyForm, title: event.target.value })} /></Field></div><Field label="Policy URL"><Input value={policyForm.url} onChange={(event) => setPolicyForm({ ...policyForm, url: event.target.value })} /></Field><Field label="Policy SHA-256"><Input className="font-mono text-xs" value={policyForm.sha} onChange={(event) => setPolicyForm({ ...policyForm, sha: event.target.value })} /></Field><div className="form-grid"><Field label="USD threshold"><Input value={policyForm.threshold} onChange={(event) => setPolicyForm({ ...policyForm, threshold: event.target.value })} /></Field><Field label="Required approvals"><Input value={policyForm.approvals} onChange={(event) => setPolicyForm({ ...policyForm, approvals: event.target.value })} /></Field></div><div className="form-grid"><Field label="Threshold documents" hint="Comma separated, e.g. AUDIT"><Input value={policyForm.docs} onChange={(event) => setPolicyForm({ ...policyForm, docs: event.target.value })} /></Field><Field label="Baseline documents"><Input value={policyForm.baseline} onChange={(event) => setPolicyForm({ ...policyForm, baseline: event.target.value })} /></Field></div><Button type="submit" disabled={!walletReady}><FileLock2 />Register version</Button></form></CardContent></Card></div><Card className="surface top-gap"><CardHeader><CardTitle>Loaded organization and policy</CardTitle></CardHeader><CardContent><div className="two-grid"><JsonView value={organization} empty="Load a finalized proposal to inspect its organization." /><JsonView value={policy} empty="Load a finalized proposal to inspect its policy." /></div></CardContent></Card></TabsContent>

        <TabsContent value="proposal" className="tab-content"><Card className="surface"><CardHeader><CardTitle>Create a governed proposal</CardTitle><CardDescription>Bind the request to the current policy version, document bytes, and executor.</CardDescription></CardHeader><CardContent><form className="form" onSubmit={(event) => void submit(event, "Create proposal", "create_proposal", () => [proposalForm.id, proposalForm.org, proposalForm.policy, integer(proposalForm.version, "Version"), proposalForm.type, proposalForm.description, integer(proposalForm.amount, "Amount"), proposalForm.url, proposalForm.sha.toLowerCase(), proposalForm.executor || account])}><div className="form-grid"><Field label="Proposal ID"><Input value={proposalForm.id} onChange={(event) => setProposalForm({ ...proposalForm, id: event.target.value })} /></Field><Field label="Organization ID"><Input value={proposalForm.org} onChange={(event) => setProposalForm({ ...proposalForm, org: event.target.value })} /></Field></div><div className="form-grid"><Field label="Policy ID"><Input value={proposalForm.policy} onChange={(event) => setProposalForm({ ...proposalForm, policy: event.target.value })} /></Field><Field label="Policy version"><Input value={proposalForm.version} onChange={(event) => setProposalForm({ ...proposalForm, version: event.target.value })} /></Field></div><div className="form-grid"><Field label="Action type"><Input value={proposalForm.type} onChange={(event) => setProposalForm({ ...proposalForm, type: event.target.value })} /></Field><Field label="Requested USD"><Input value={proposalForm.amount} onChange={(event) => setProposalForm({ ...proposalForm, amount: event.target.value })} /></Field></div><Field label="Action description"><Textarea value={proposalForm.description} onChange={(event) => setProposalForm({ ...proposalForm, description: event.target.value })} /></Field><Field label="Proposal URL"><Input value={proposalForm.url} onChange={(event) => setProposalForm({ ...proposalForm, url: event.target.value })} /></Field><Field label="Proposal SHA-256"><Input className="font-mono text-xs" value={proposalForm.sha} onChange={(event) => setProposalForm({ ...proposalForm, sha: event.target.value })} /></Field><Field label="Authorized executor" hint="Uses the connected wallet if blank."><Input placeholder={account || "0x…"} value={proposalForm.executor} onChange={(event) => setProposalForm({ ...proposalForm, executor: event.target.value })} /></Field><Button type="submit" disabled={!walletReady}><FileCheck2 />Create proposal</Button></form></CardContent></Card><Card className="surface top-gap"><CardHeader><CardTitle>Loaded proposal state</CardTitle><CardDescription>The frontend never invents this state.</CardDescription></CardHeader><CardContent><JsonView value={proposal} empty="Load a finalized proposal from the case desk." /></CardContent></Card></TabsContent>

        <TabsContent value="evidence" className="tab-content"><div className="two-grid"><Card className="surface"><CardHeader><CardTitle>Append evidence</CardTitle><CardDescription>Every input change invalidates the old binding and requires re-evaluation.</CardDescription></CardHeader><CardContent><form className="form" onSubmit={(event) => void submit(event, "Append evidence", "add_evidence", () => [evidenceForm.proposal, evidenceForm.id, evidenceForm.type, evidenceForm.url, evidenceForm.sha.toLowerCase()])}><div className="form-grid"><Field label="Proposal ID"><Input value={evidenceForm.proposal} onChange={(event) => setEvidenceForm({ ...evidenceForm, proposal: event.target.value })} /></Field><Field label="Evidence ID"><Input value={evidenceForm.id} onChange={(event) => setEvidenceForm({ ...evidenceForm, id: event.target.value })} /></Field></div><Field label="Evidence type"><Input value={evidenceForm.type} onChange={(event) => setEvidenceForm({ ...evidenceForm, type: event.target.value.toUpperCase() })} /></Field><Field label="Public HTTPS URL"><Input value={evidenceForm.url} onChange={(event) => setEvidenceForm({ ...evidenceForm, url: event.target.value })} /></Field><Field label="SHA-256 digest"><Input className="font-mono text-xs" value={evidenceForm.sha} onChange={(event) => setEvidenceForm({ ...evidenceForm, sha: event.target.value })} /></Field><Button type="submit" disabled={!walletReady}><Plus />Append evidence</Button></form></CardContent></Card>
          <Card className="surface"><CardHeader><CardTitle>Reviewer approval</CardTitle><CardDescription>Each registered wallet can approve once; duplicates are rejected on-chain.</CardDescription></CardHeader><CardContent><form className="form" onSubmit={(event) => void submit(event, "Record reviewer approval", "approve_proposal", () => [approvalForm.proposal, approvalForm.url, approvalForm.sha.toLowerCase()])}><Field label="Proposal ID"><Input value={approvalForm.proposal} onChange={(event) => setApprovalForm({ ...approvalForm, proposal: event.target.value })} /></Field><Field label="Approval proof URL"><Input value={approvalForm.url} onChange={(event) => setApprovalForm({ ...approvalForm, url: event.target.value })} /></Field><Field label="Approval proof SHA-256"><Input className="font-mono text-xs" value={approvalForm.sha} onChange={(event) => setApprovalForm({ ...approvalForm, sha: event.target.value })} /></Field><div className="reviewer"><Wallet /><div><strong>{account ? short(account, 11, 8) : "Wallet not connected"}</strong><span>This signer becomes the reviewer identity.</span></div></div><Button type="submit" disabled={!walletReady}><BadgeCheck />Approve with MetaMask</Button></form></CardContent></Card></div><Card className="surface top-gap"><CardHeader><CardTitle>Evidence trust boundary</CardTitle></CardHeader><CardContent><div className="security-grid"><Security icon={<Fingerprint />} title="SHA-256 byte binding" text="Changed pages cannot reuse an earlier verdict." /><Security icon={<Network />} title="Public HTTPS only" text="Private-network and malformed URLs are rejected." /><Security icon={<ShieldCheck />} title="Prompt isolation" text="Document instructions remain untrusted evidence." /><Security icon={<History />} title="Append-only history" text="Remediation never overwrites a verdict." /></div></CardContent></Card></TabsContent>

        <TabsContent value="protocol" className="tab-content"><div className="protocol-grid"><Card className="surface"><CardHeader><CardTitle>Why GenLayer is essential</CardTitle><CardDescription>This is not a Boolean checklist wrapped in a contract.</CardDescription></CardHeader><CardContent><p className="protocol-copy">Deterministic code locks identities, versions, digests, approval uniqueness, and authorization safety. GenLayer consensus handles the part ordinary smart contracts cannot: interpreting human-written policy against real documents and ambiguous real-world facts.</p><div className="flow"><Flow n="01" title="Commit" text="Store policy, proposal, and evidence URLs with exact digests." /><Flow n="02" title="Authenticate" text="Leader and validators independently fetch the same bytes." /><Flow n="03" title="Interpret" text="Apply written rules and compare normalized decision fields." /><Flow n="04" title="Authorize" text="Unlock only while the latest compliant binding is current." /></div></CardContent></Card><div className="stack"><Card className="surface"><CardHeader><CardTitle>Deployment record</CardTitle></CardHeader><CardContent className="stack small"><Deploy label="Network" value="GenLayer Studionet" /><Deploy label="Chain ID" value="61999" /><Deploy label="Contract" value={ADDRESS || "Pending verified deployment"} href={CONTRACT_READY ? `${EXPLORER}/address/${ADDRESS}` : undefined} /><Deploy label="Deployment tx" value={deployment.deploymentTransaction || "Pending"} href={deployment.deploymentTransaction ? `${EXPLORER}/tx/${deployment.deploymentTransaction}` : undefined} /><Deploy label="Full Consensus tx" value={deployment.missingAuditEvaluationTransaction || "Pending"} href={deployment.missingAuditEvaluationTransaction ? `${EXPLORER}/tx/${deployment.missingAuditEvaluationTransaction}` : undefined} /></CardContent></Card><Card className="surface"><CardHeader><CardTitle>Open evidence</CardTitle></CardHeader><CardContent className="evidence-links"><External href={rawUrl("policy/dao-grant-policy-v1.md")}>Governing policy</External><External href={rawUrl("proposals/grant-35000.md")}>USD 35,000 proposal</External><External href={rawUrl("evidence/reviewer-approvals.md")}>Reviewer approvals</External><External href={rawUrl("evidence/security-audit.md")}>Published audit</External></CardContent></Card></div></div></TabsContent>
      </Tabs>
    </div>
    <footer className="shell"><span>PolicyGuard · GenLayer Builder Project · Open-source prototype</span><span>Wallet-signed writes · Full Consensus · No private keys</span></footer>
  </main>;
}

function Security({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) { return <div className="security"><i>{icon}</i><div><strong>{title}</strong><p>{text}</p></div></div>; }
function Flow({ n, title, text }: { n: string; title: string; text: string }) { return <div><i>{n}</i><section><strong>{title}</strong><p>{text}</p></section></div>; }
function Deploy({ label, value, href }: { label: string; value: string; href?: string }) { return <div className="deploy"><span>{label}</span><div>{href ? <External href={href}>{short(value, 12, 8)}</External> : <strong>{short(value, 18, 10)}</strong>}<CopyButton value={value.startsWith("Pending") ? "" : value} /></div></div>; }
