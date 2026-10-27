#!/usr/bin/env node
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";

const receiptUrl = "https://api.chit402.com/receipt/chit-56e3ee6d-2acb-4cab-8fa4-dfd5f9f31e6f?format=json";
const inclusionUrl = "https://api.chit402.com/v1/receipts/xfuel-56e3ee6d-2acb-4cab-8fa4-dfd5f9f31e6f/inclusion";
const historyUrl = "https://api.chit402.com/.well-known/issuer-history.json";
const jwksUrl = "https://api.chit402.com/.well-known/jwks.json";
const baseRpc = "https://mainnet.base.org";
const transferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

async function getJson(url) {
  const response = await fetch(url, { redirect: "error" });
  if (!response.ok) throw new Error(url + " HTTP " + response.status);
  return await response.json();
}
async function rpc(method, params) {
  const response = await fetch(baseRpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  });
  if (!response.ok) throw new Error("RPC HTTP " + response.status);
  const body = await response.json();
  if (body.error) throw new Error("RPC " + JSON.stringify(body.error));
  return body.result;
}
function b64url(value) { return Buffer.from(value, "base64url"); }
function rawEcdsaToDer(raw) {
  const integer = (bytes) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    let value = bytes.subarray(start);
    if (value[0] & 0x80) value = Buffer.concat([Buffer.from([0]), value]);
    return Buffer.concat([Buffer.from([2, value.length]), value]);
  };
  const r = integer(raw.subarray(0, 32));
  const s = integer(raw.subarray(32, 64));
  return Buffer.concat([Buffer.from([0x30, r.length + s.length]), r, s]);
}
function verifyJws(jws, jwk) {
  const parts = jws.split(".");
  if (parts.length !== 3) return { valid: false, header: null, payload: null };
  const header = JSON.parse(b64url(parts[0]));
  const payload = JSON.parse(b64url(parts[1]));
  const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: "jwk" });
  const valid = verifySignature("sha256", Buffer.from(parts[0] + "." + parts[1]), key, rawEcdsaToDer(b64url(parts[2])));
  return { valid, header, payload };
}
function sha256(...parts) {
  return createHash("sha256").update(Buffer.concat(parts)).digest();
}
function foldProof(leafHex, proof, leafIndex, treeSize) {
  if (!/^[0-9a-f]{64}$/.test(leafHex)) throw new Error("bad leaf hash");
  let fn = leafIndex;
  let sn = treeSize - 1;
  let current = Buffer.from(leafHex, "hex");
  const positions = [];
  for (const step of proof) {
    if (!/^[0-9a-f]{64}$/.test(step.hash)) throw new Error("bad proof hash");
    const expected = (fn % 2 === 1 || fn === sn) ? "left" : "right";
    positions.push({ expected, observed: step.position });
    if (step.position !== expected) throw new Error("proof position mismatch");
    const sibling = Buffer.from(step.hash, "hex");
    current = step.position === "left"
      ? sha256(Buffer.from([1]), sibling, current)
      : sha256(Buffer.from([1]), current, sibling);
    if (fn === sn && fn % 2 === 0) {
      while (fn !== 0 && fn % 2 === 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return { root: current.toString("hex"), final_fn: fn, final_sn: sn, positions };
}

const [shell, inclusion, history, jwks] = await Promise.all([
  getJson(receiptUrl), getJson(inclusionUrl), getJson(historyUrl), getJson(jwksUrl)
]);
const headJws = shell.inclusion.signed_head.signature;
const headParts = headJws.split(".");
const headHeader = JSON.parse(b64url(headParts[0]));
const historyEntry = (history.entries || []).find((entry) => entry.kid === headHeader.kid);
const jwksKey = (jwks.keys || []).find((key) => key.kid === headHeader.kid);
if (!historyEntry || !jwksKey) throw new Error("trusted key not found");
const historyJws = verifyJws(history.issuer_signature.jws, historyEntry.jwk);
const head = verifyJws(headJws, historyEntry.jwk);
const issuedAt = Date.parse(shell.issued_at);
const activeAtIssue = issuedAt >= Date.parse(historyEntry.not_before) &&
  (!historyEntry.not_after || issuedAt <= Date.parse(historyEntry.not_after)) &&
  (!historyEntry.revoked_at || issuedAt < Date.parse(historyEntry.revoked_at));
const rootMatches = shell.inclusion.leaf_hash === inclusion.leaf &&
  shell.inclusion.signed_head.root === inclusion.root &&
  shell.inclusion.signed_head.tree_size === inclusion.tree_size &&
  head.payload.root === shell.inclusion.signed_head.root &&
  head.payload.tree_size === shell.inclusion.signed_head.tree_size;
const folded = foldProof(inclusion.leaf, inclusion.proof, inclusion.leaf_index, inclusion.tree_size);
const inclusionValid = folded.root === inclusion.root && folded.final_fn === 0 && folded.final_sn === 0;

const paymentReceipt = await rpc("eth_getTransactionReceipt", [shell.payment_tx]);
const paymentLogs = (paymentReceipt.logs || []).filter((log) =>
  log.address.toLowerCase() === shell.asset.toLowerCase() &&
  log.topics?.[0]?.toLowerCase() === transferTopic
);
const matchingTransfer = paymentLogs.find((log) =>
  ("0x" + log.topics[2].slice(-40)).toLowerCase() === shell.pay_to.toLowerCase() &&
  BigInt(log.data).toString() === String(shell.amount_settled)
);
const anchorHash = head.payload.anchor_tx;
const anchorTx = await rpc("eth_getTransactionByHash", [anchorHash]);
const anchorReceipt = await rpc("eth_getTransactionReceipt", [anchorHash]);
const anchorCalldataMatches = (anchorTx.input || "").toLowerCase().includes(head.payload.root.toLowerCase());

const tampered = { ...shell, amount_settled: String(Number(shell.amount_settled) + 1) };
const tamperedStillHasSameProof = tampered.inclusion.leaf_hash === shell.inclusion.leaf_hash && inclusionValid;

const result = {
  receipt_url: receiptUrl,
  public_shell: {
    unsigned: shell.unsigned === true,
    issuer_signature_present: Boolean(shell.issuer_signature),
    public_attestation_present: Boolean(shell.public_attestation)
  },
  issuer_history: {
    history_jws_valid: historyJws.valid,
    history_entry_count_matches: history.issuer_signature.jws ? history.entries.length === historyJws.payload.entry_count : false,
    kid: headHeader.kid,
    jwks_kid_match: jwksKey.kid === historyEntry.kid,
    jwks_key_matches_history: jwksKey.x === historyEntry.jwk.x && jwksKey.y === historyEntry.jwk.y,
    active_at_issued_at: activeAtIssue
  },
  signed_tree_head: {
    jws_valid: head.valid,
    root_matches_shell: head.payload.root === shell.inclusion.signed_head.root,
    tree_size: head.payload.tree_size,
    anchor_tx_success: anchorReceipt?.status === "0x1",
    anchor_calldata_matches_root: anchorCalldataMatches
  },
  inclusion: {
    leaf_index: inclusion.leaf_index,
    tree_size: inclusion.tree_size,
    leaf_matches_shell: inclusion.leaf === shell.inclusion.leaf_hash,
    positions_valid: folded.positions.every((x) => x.expected === x.observed),
    root_matches: inclusionValid
  },
  base_payment: {
    tx_success: paymentReceipt?.status === "0x1",
    matching_usdc_transfer: Boolean(matchingTransfer),
    amount_atomic: String(shell.amount_settled),
    payee_matches: Boolean(matchingTransfer)
  },
  design_review_repro: {
    shell_fields_are_signed: false,
    reason: "The public shell has no issuer_signature or public_attestation; the signed object is the tree head, while row_hash/preimage is owner-held.",
    changing_unsigned_amount_keeps_tree_proof: tamperedStillHasSameProof
  },
  overall: "TREE_HEAD_AND_INCLUSION_AND_BASE_TRANSFER_CHECKED; RECEIPT_PAYLOAD_SIGNATURE_NOT_AVAILABLE"
};
console.log(JSON.stringify(result));
