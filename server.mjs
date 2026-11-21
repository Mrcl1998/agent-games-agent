// zkVerify Agent Games — combined agent endpoint.
// One HTTPS service (behind the tunnel) handling:
//   - preflight handshakes           (agent-games.preflight.v1)
//   - Proof Gatekeeper tasks         (agent-games.proof-gatekeeper.v1)
//   - Steal the VFY turns            (eventId: steal-the-vfy)
// Every response is HMAC-SHA256 signed over its raw body.
// Fail closed: any doubt on a Gatekeeper task is a REJECT.
import http from "node:http";
import { createHmac, createHash, timingSafeEqual, randomUUID } from "node:crypto";
import { readFileSync, existsSync, appendFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseTask,
  gatekeeperPolicy,
  gatekeeperWitness,
  stealPolicy,
  stealWitness,
  stealPublicWords,
  STEAL_PARAMS,
} from "./policy.mjs";
import {
  proveAndVerify,
  randomSalt,
  stealCommitment,
  stealPublicInputsHash,
} from "./prover.mjs";
import { State } from "./state.mjs";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8791);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
if (!SECRET) {
  console.error("AGENT_GAMES_HMAC_SECRET is required");
  process.exit(1);
}

// Steal strategy secret (params + salt), generated once by setup-steal.mjs.
let STEAL = null;
const stealFile = path.join(DIR, "steal-secret.json");
if (existsSync(stealFile)) {
  STEAL = JSON.parse(readFileSync(stealFile, "utf8"));
  if (!STEAL.params) STEAL.params = STEAL_PARAMS;
}
let OUR_COMMITMENT = null;
if (STEAL) OUR_COMMITMENT = await stealCommitment(STEAL.params, STEAL.salt);

const state = new State();
const log = (obj) => {
  const line = JSON.stringify({ t: new Date().toISOString(), ...obj });
  console.log(line);
  try {
    appendFileSync(path.join(DIR, "agent.log"), line + "\n");
  } catch {}
};

const sign = (raw) => createHmac("sha256", SECRET).update(raw).digest("hex");
const authentic = (raw, sig) =>
  typeof sig === "string" &&
  /^[a-f0-9]{64}$/i.test(sig) &&
  timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(sign(raw), "hex"));
const sha256 = (raw) => createHash("sha256").update(raw).digest("hex");
const fresh = (iso, now = Date.now()) => {
  const t = Date.parse(iso);
  return Number.isFinite(t) && t <= now + 5000 && now - t <= 60000;
};

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms)),
  ]);
}

async function handleGatekeeper(envelope, startedAt) {
  const deadlineMs = Math.min(
    startedAt + 55000,
    Date.parse(envelope.deadline_at) - 500
  );
  const budget = Math.max(1000, deadlineMs - Date.now());
  const claim = state.taskClaim(envelope.task_id, envelope._rawHash);
  if (claim.kind === "conflict")
    return { decision: "REJECT", reason_code: "TASK_ID_CONFLICT" };
  if (claim.kind === "cached") return claim.reply;

  let task;
  try {
    task = parseTask(envelope);
  } catch (e) {
    log({ ev: "gk_invalid_task", task: envelope.task_id, err: String(e).slice(0, 120) });
    return { decision: "REJECT", reason_code: "INVALID_TASK" };
  }

  const decision = gatekeeperPolicy(task, state.seen);
  let reply = {
    decision: decision.decision,
    reason_code: decision.reasonCode,
    proof_tx: task.proofTx,
  };
  if (decision.needsProof) {
    state.markProof(task.proofTx);
    try {
      const evidence = await withTimeout(
        proveAndVerify("gatekeeper", gatekeeperWitness(task, decision.decision)),
        budget
      );
      reply = { ...reply, ...evidence };
    } catch (e) {
      log({ ev: "gk_prove_failed", task: envelope.task_id, err: String(e).slice(0, 120) });
      // Fail closed: never ship an APPROVE we could not prove.
      if (decision.decision === "APPROVE")
        reply = {
          decision: "REJECT",
          reason_code: "PROOF_GENERATION_FAILED",
          proof_tx: task.proofTx,
        };
    }
  }
  state.taskSave(envelope.task_id, reply);
  log({
    ev: "gk_decision",
    task: envelope.task_id,
    mode: envelope.mode,
    decision: reply.decision,
    reason: reply.reason_code,
    proved: Boolean(reply.proof),
  });
  return reply;
}

async function handleSteal(turn) {
  const key = `${turn.matchId}:${turn.turn}`;
  const cached = state.stealClaim(key);
  if (cached) return cached;
  const action = stealPolicy(
    STEAL.params,
    turn.state.selfBalance,
    turn.state.opponentBalance
  );
  const reply = {
    matchId: turn.matchId,
    turn: turn.turn,
    action:
      action.type === "EXTRACT"
        ? { type: "EXTRACT", amount: action.amount }
        : { type: action.type },
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: randomUUID(),
  };
  const commitmentMatches =
    OUR_COMMITMENT &&
    String(turn.strategyCommitment.hash).toLowerCase() ===
      OUR_COMMITMENT.toLowerCase();
  if (commitmentMatches) {
    try {
      const evidence = await withTimeout(
        proveAndVerify(
          "steal",
          stealWitness(turn, action, STEAL.params, STEAL.salt)
        ),
        240000
      );
      reply.policyProof = {
        circuitVersion: "v1",
        proof: evidence.proof,
        public_signals: evidence.public_signals,
        publicInputsHash: stealPublicInputsHash(stealPublicWords(turn, action)),
      };
    } catch (e) {
      // Omit the proof rather than send an invalid one (turn scores as HOLD).
      log({ ev: "steal_prove_failed", key, err: String(e).slice(0, 120) });
    }
  } else {
    log({ ev: "steal_commitment_mismatch", key, got: turn.strategyCommitment.hash });
  }
  state.stealSave(key, reply);
  log({
    ev: "steal_turn",
    key,
    mode: turn.mode,
    action: reply.action.type,
    amount: reply.action.amount || 0,
    proved: Boolean(reply.policyProof),
  });
  return reply;
}

const server = http.createServer(async (req, res) => {
  const startedAt = Date.now();
  const send = (status, body) => {
    if (res.writableEnded) return;
    const raw = JSON.stringify(body);
    res.writeHead(status, {
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-agent-games-signature": sign(raw),
    });
    res.end(raw);
  };
  try {
    const url = new URL(req.url, "http://localhost");
    if (req.method === "GET" && (url.pathname === "/healthz" || url.pathname === "/demo" || url.pathname === "/")) {
      send(200, {
        ok: true,
        agent: "suki-liar",
        tracks: ["proof-gatekeeper", "steal-the-vfy"],
        writeup: `https://${req.headers.host || "printable-wonderful-sleeping-relating.trycloudflare.com"}/case-study`,
      });
      return;
    }
    if (req.method === "GET" && url.pathname === "/case-study") {
      const html = readFileSync(path.join(DIR, "case-study.html"));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end(html);
      return;
    }
    if (req.method !== "POST" || url.pathname !== "/agent") {
      send(404, { decision: "REJECT", reason_code: "NOT_FOUND" });
      return;
    }
    const chunks = [];
    let length = 0;
    for await (const chunk of req) {
      length += chunk.length;
      if (length > 65536) {
        send(413, { decision: "REJECT", reason_code: "BODY_TOO_LARGE" });
        return;
      }
      chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks);
    if (!authentic(raw, req.headers["x-agent-games-signature"])) {
      send(401, { decision: "REJECT", reason_code: "INVALID_SIGNATURE" });
      return;
    }
    let msg;
    try {
      msg = JSON.parse(raw.toString("utf8"));
    } catch {
      send(400, { decision: "REJECT", reason_code: "INVALID_JSON" });
      return;
    }

    if (msg.type === "agent-games.preflight.v1") {
      if (!fresh(msg.issued_at) || !state.nonceUse(sha256(msg.agent_id + ":" + msg.nonce))) {
        send(400, { ok: false, reason_code: "STALE_PREFLIGHT" });
        return;
      }
      log({ ev: "preflight", agent: msg.agent_id });
      send(200, { ok: true, protocolVersion: "v1" });
      return;
    }

    if (msg.type === "agent-games.proof-gatekeeper.v1") {
      msg._rawHash = sha256(raw);
      if (!fresh(msg.issued_at) || Date.parse(msg.deadline_at) <= Date.now()) {
        send(200, { decision: "REJECT", reason_code: "STALE_TASK" });
        return;
      }
      send(200, await handleGatekeeper(msg, startedAt));
      return;
    }

    if (msg.eventId === "steal-the-vfy" && msg.matchId) {
      if (!STEAL) {
        send(200, { matchId: msg.matchId, turn: msg.turn, action: { type: "HOLD" }, agentTimestamp: new Date().toISOString(), idempotencyKey: randomUUID() });
        return;
      }
      send(200, await handleSteal(msg));
      return;
    }

    send(400, { decision: "REJECT", reason_code: "UNKNOWN_TYPE" });
  } catch (e) {
    log({ ev: "handler_error", err: String(e).slice(0, 200) });
    send(200, { decision: "REJECT", reason_code: "INTERNAL_ERROR" });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  log({ ev: "listening", port: PORT, stealCommitment: OUR_COMMITMENT });
});
