// snarkjs proving wrappers + Poseidon (circomlibjs) + keccak (ethers).
import { readFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import { ethers } from "ethers";

const DIR = path.dirname(fileURLToPath(import.meta.url));
export const CIRCUITS = {
  gatekeeper: {
    wasm: path.join(DIR, "circuits", "gatekeeper.wasm"),
    zkey: path.join(DIR, "circuits", "gatekeeper_final.zkey"),
  },
  steal: {
    wasm: path.join(DIR, "circuits", "vfy-policy.wasm"),
    zkey: path.join(DIR, "circuits", "vfy-policy_final.zkey"),
  },
};

const vkCache = {};
export async function verificationKey(kind) {
  if (!vkCache[kind])
    vkCache[kind] = await snarkjs.zKey.exportVerificationKey(CIRCUITS[kind].zkey);
  return vkCache[kind];
}

// Generate a Groth16 proof and verify it locally against the circuit VK.
// Returns { proof, public_signals } with public signals as strings.
export async function proveAndVerify(kind, witness) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witness,
    CIRCUITS[kind].wasm,
    CIRCUITS[kind].zkey
  );
  const vk = await verificationKey(kind);
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  if (!ok) throw new Error("local proof verification failed");
  return { proof, public_signals: publicSignals.map(String) };
}

let poseidonFn = null;
export async function poseidon(inputs) {
  if (!poseidonFn) poseidonFn = await buildPoseidon();
  const F = poseidonFn.F;
  return F.toString(poseidonFn(inputs.map((x) => BigInt(x))));
}

// Steal strategy commitment: Poseidon(params[0..7], salt) as 0x-hex.
export async function stealCommitment(params, salt) {
  const h = await poseidon([...params, salt]);
  return "0x" + BigInt(h).toString(16).padStart(64, "0");
}

// publicInputsHash per /build: keccak256 of the 8 words as 32-byte BE.
export function stealPublicInputsHash(words) {
  const packed = ethers.concat(words.map((w) => ethers.toBeHex(w, 32)));
  return ethers.keccak256(packed);
}

export function artifactHashes() {
  // Integrity check against the pinned hashes from the official site.
  const out = {};
  for (const v of Object.values(CIRCUITS))
    for (const p of [v.wasm, v.zkey])
      out[path.basename(p)] = createHash("sha256")
        .update(readFileSync(p))
        .digest("hex");
  return out;
}

export function randomSalt() {
  return (BigInt("0x" + randomBytes(31).toString("hex"))).toString();
}
