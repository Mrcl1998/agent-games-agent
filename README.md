# suki-liar — Proof Gatekeeper agent

AI agent for the [zkVerify Agent Games](https://agentgames.zkverify.io) (Season 01).
It judges proof-backed payment requests and then writes its **own** zero-knowledge
proof that the decision followed the rule — so the judgment is checkable without
trusting the agent's word.

## The problem

A zero-knowledge proof can verify perfectly and still back the wrong payment. In
the Proof Gatekeeper arena roughly half of all tasks are traps:

| Trap | What is wrong |
| --- | --- |
| `VK_SUBSTITUTION` | proof verifies, but its verification key is not the registered one |
| `PROOF_REUSED` | a proof reference already accepted in an earlier task |
| `THRESHOLD_MISMATCH` | public balance below the required minimum |
| `EXPIRED_CONDITION` | condition's block-height window has passed |
| `RECIPIENT_MISMATCH` | recipient differs from the payment condition |
| `AMOUNT_OVERFLOW` | amount exceeds the single-transfer cap |

Asking only "does this proof verify?" approves about half of them. Every field has
to be checked before anything is approved.

## What the agent does

- Authenticates every inbound request with HMAC-SHA256 over the **raw** body
  (`x-agent-games-signature`) before any JSON parsing.
- Applies deterministic checks in fixed order: reuse → VK match → threshold →
  recipient → amount cap → expiry. Fails closed on malformed or ambiguous input.
- For each provable decision, generates a Groth16 proof locally with `snarkjs`
  from the official gatekeeper circuit, verifies it against the circuit
  verification key, and returns `proof` + `public_signals` next to the decision.
- Signs every response, deduplicates retries by task id, and keeps a durable
  seen-set so replayed proof references are rejected.
- No language model makes the final call.

## Live evidence

Practice mode on the platform (real delivery path): **CORRECT DECISION**, with the
agent's Groth16 proof **VERIFIED offline by the platform** against its registered
key, at ~1.3 s end-to-end latency.

## Architecture

```
server.mjs   transport: HTTP, HMAC verify/sign, preflight, idempotency
policy.mjs   pure decisions + circuit witnesses (no I/O)
prover.mjs   snarkjs Groth16 prove + local verify, Poseidon commitment helpers
state.mjs    on-disk seen-set / reply cache / nonce store
case-study.html  public write-up
```

## Circuit mapping (verified against the official wasm/zkey)

Gatekeeper witness inputs:
`taskId, minimum, publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, registeredVkHash, proofVkHash, salt,
decision`

- `taskId` = BigInt of the UTF-8 bytes of the task id (not keccak, not uuid suffix).
- `registered_vk` / `proof_vk` = BigInt(hex) reduced mod the bn128 field prime.
- `salt` = fresh random, private.
- Public signals (13): `[Poseidon(salt, taskId), registeredVkHash, proofVkHash,
  minimum, publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision, taskId]`.

The circuit enforces the same logic as `policy.mjs`: a witness for a wrong
decision fails generation, so a valid proof can never certify a trap.

## Run

```sh
npm install
cp .env.example .env      # set AGENT_GAMES_HMAC_SECRET from the dashboard
npm start                 # serves POST /agent and GET /healthz
```

Serve behind a public HTTPS URL (no custom ports), e.g.:

```sh
cloudflared tunnel --url http://127.0.0.1:8791
```

## Security

Secrets live only in environment variables / `.env` (gitignored, mode 600). The
agent never logs secrets and fails closed: timeouts, malformed envelopes and
proving errors resolve to REJECT (Gatekeeper) rather than a guess.

## Tracks entered

Proof Gatekeeper, Wildcard.
