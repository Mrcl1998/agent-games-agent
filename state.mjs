// Durable on-disk state: seen proof references, task reply cache,
// preflight nonces, steal turn cache. Survives restarts (VM swaps).
import { readFileSync, writeFileSync, existsSync, renameSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const FILE = path.join(DIR, "state.json");

export class State {
  constructor() {
    this.data = { seenProofTx: [], tasks: {}, nonces: [], stealTurns: {} };
    if (existsSync(FILE)) {
      try {
        this.data = { ...this.data, ...JSON.parse(readFileSync(FILE, "utf8")) };
      } catch {
        /* corrupt state must not kill the agent; start clean */
      }
    }
    this.seen = new Set(this.data.seenProofTx);
    this.nonceSet = new Set(this.data.nonces);
  }

  save() {
    this.data.seenProofTx = [...this.seen].slice(-5000);
    this.data.nonces = [...this.nonceSet].slice(-2000);
    const tmp = FILE + ".tmp";
    writeFileSync(tmp, JSON.stringify(this.data));
    renameSync(tmp, FILE);
  }

  // Returns true if this proof reference was already accepted earlier.
  proofSeen(tx) {
    return this.seen.has(tx);
  }

  markProof(tx) {
    this.seen.add(tx);
    this.save();
  }

  // Task dedupe: identical redelivery returns the cached reply.
  taskClaim(taskId, rawHash) {
    const t = this.data.tasks[taskId];
    if (!t) {
      this.data.tasks[taskId] = { rawHash, reply: null };
      this.save();
      return { kind: "new" };
    }
    if (t.rawHash !== rawHash) return { kind: "conflict" };
    if (t.reply) return { kind: "cached", reply: t.reply };
    return { kind: "new" };
  }

  taskSave(taskId, reply) {
    if (this.data.tasks[taskId]) this.data.tasks[taskId].reply = reply;
    this.save();
  }

  nonceUse(key) {
    if (this.nonceSet.has(key)) return false;
    this.nonceSet.add(key);
    this.save();
    return true;
  }

  stealClaim(key) {
    return this.data.stealTurns[key]?.reply || null;
  }

  stealSave(key, reply) {
    this.data.stealTurns[key] = { reply };
    this.save();
  }
}
