// Pure decision logic + witness builders for zkVerify Agent Games.
// Gatekeeper mapping verified against the official wasm/zkey (12/12 local tests):
//   taskId = BigInt(utf8 bytes of task_id); vk hashes reduced mod field prime;
//   public[0] = Poseidon(salt, taskId) computed inside the circuit.
// No I/O here — everything is unit-testable.

import { randomBytes } from "node:crypto";

export const FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const field = (v) => (BigInt(v) % FIELD).toString();

export const REASON = Object.freeze({
  VALID: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
});

const HEX_RE = /^0x[0-9a-fA-F]+$/;

function toBigInt(value, name) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`bad number for ${name}`);
    return BigInt(value);
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (HEX_RE.test(s)) return BigInt(s);
    if (/^\d+$/.test(s)) return BigInt(s);
    throw new Error(`bad numeric string for ${name}`);
  }
  throw new Error(`bad type for ${name}: ${typeof value}`);
}

function normHex(value, name) {
  if (typeof value !== "string" || !HEX_RE.test(value.trim())) throw new Error(`bad hex for ${name}`);
  return value.trim().toLowerCase();
}

/** Validate an incoming gatekeeper envelope; throws on malformed input. */
export function parseTask(envelope) {
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) throw new Error("envelope is not an object");
  if (typeof envelope.task_id !== "string" || envelope.task_id.length === 0) throw new Error("missing task_id");
  const input = envelope.input;
  if (!input || typeof input !== "object") throw new Error("missing input");

  return {
    taskId: envelope.task_id,
    mode: envelope.mode,
    registeredVk: normHex(input.registered_vk, "registered_vk"),
    proofVk: normHex(input.proof_vk, "proof_vk"),
    minimum: toBigInt(input.minimum, "minimum"),
    publicBalance: toBigInt(input.public_balance, "public_balance"),
    expiryBlock: toBigInt(input.expiry_block, "expiry_block"),
    currentBlock: toBigInt(input.current_block, "current_block"),
    recipient: normHex(input.recipient, "recipient"),
    conditionRecipient: normHex(input.condition_recipient, "condition_recipient"),
    amount: toBigInt(input.amount, "amount"),
    maxTransfer: toBigInt(input.max_transfer, "max_transfer"),
    proofTx: normHex(input.proof_tx, "proof_tx"),
  };
}

/**
 * Deterministic decision. `seenProofTx` = Set of proof_tx already used by OTHER
 * task_ids. Returns { decision, reasonCode, needsProof }.
 */
export function gatekeeperPolicy(task, seenProofTx) {
  if (seenProofTx.has(task.proofTx))
    return { decision: "REJECT", reasonCode: REASON.PROOF_REUSED, needsProof: false };
  if (task.proofVk !== task.registeredVk)
    return { decision: "REJECT", reasonCode: REASON.VK_SUBSTITUTION, needsProof: true };
  if (task.publicBalance < task.minimum)
    return { decision: "REJECT", reasonCode: REASON.THRESHOLD_MISMATCH, needsProof: true };
  if (task.recipient !== task.conditionRecipient)
    return { decision: "REJECT", reasonCode: REASON.RECIPIENT_MISMATCH, needsProof: true };
  if (task.amount > task.maxTransfer)
    return { decision: "REJECT", reasonCode: REASON.AMOUNT_OVERFLOW, needsProof: true };
  if (task.currentBlock > task.expiryBlock)
    return { decision: "REJECT", reasonCode: REASON.EXPIRED_CONDITION, needsProof: true };
  return { decision: "APPROVE", reasonCode: REASON.VALID, needsProof: true };
}

/** The 13 circuit inputs for a decided task (salt fresh unless provided). */
export function gatekeeperWitness(task, decision, saltHex) {
  const salt = saltHex ?? randomBytes(16).toString("hex");
  const reduce = (hex) => (BigInt(hex) % FIELD).toString();
  return {
    taskId: BigInt("0x" + Buffer.from(String(task.taskId), "utf8").toString("hex")).toString(),
    minimum: task.minimum.toString(),
    publicBalance: task.publicBalance.toString(),
    expiryBlock: task.expiryBlock.toString(),
    currentBlock: task.currentBlock.toString(),
    recipient: BigInt(task.recipient).toString(),
    conditionRecipient: BigInt(task.conditionRecipient).toString(),
    amount: task.amount.toString(),
    maxTransfer: task.maxTransfer.toString(),
    registeredVkHash: reduce(task.registeredVk),
    proofVkHash: reduce(task.proofVk),
    salt: BigInt("0x" + salt).toString(),
    decision: decision === "APPROVE" ? "1" : "0",
  };
}

// ---------- Steal the VFY ----------

// Committed strategy: [extractAmount, fortifyThreshold, extractThreshold,
// holdPriority, 0, 0, 0, 0]. Ours: extract the max (10) whenever the
// opponent holds anything; never fortify (costs 2, forgoes a free extract).
export const STEAL_PARAMS = ["10", "0", "0", "0", "0", "0", "0", "0"];

// The circuit's deterministic policy, mirrored in plain code:
//   self < fortifyThreshold            -> FORTIFY
//   opp > extractThreshold && !holdPri -> EXTRACT(extractAmount)
//   else                               -> HOLD
export function stealPolicy(params, selfBalance, opponentBalance) {
  const [extractAmount, fortifyThreshold, extractThreshold, holdPriority] =
    params.map((x) => BigInt(x));
  const self = BigInt(selfBalance);
  const opp = BigInt(opponentBalance);
  if (self < fortifyThreshold) return { type: "FORTIFY" };
  if (opp > extractThreshold && holdPriority === 0n)
    return { type: "EXTRACT", amount: Number(extractAmount) };
  return { type: "HOLD" };
}

export const ACTION_CODE = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

// The 8 public input words (uint256, NOT field-reduced), in /build order.
export function stealPublicWords(turn, action) {
  return [
    BigInt(turn.strategyCommitment.hash),
    BigInt("0x" + String(turn.matchId).replaceAll("-", "")),
    BigInt(turn.turn),
    BigInt(turn.state.selfBalance),
    BigInt(turn.state.opponentBalance),
    ACTION_CODE[action.type],
    BigInt(action.type === "EXTRACT" ? action.amount : 0),
    1n, // circuitVersion "v1"
  ];
}

export function stealWitness(turn, action, params, salt) {
  const w = stealPublicWords(turn, action).map((x) => (x % FIELD).toString());
  return {
    strategyParams: [...params],
    salt: field(salt),
    commitment: w[0],
    matchId: w[1],
    turnNumber: w[2],
    selfBalance: w[3],
    opponentBalance: w[4],
    action: w[5],
    amount: w[6],
    circuitVersion: w[7],
  };
}
