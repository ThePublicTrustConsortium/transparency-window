# The Transparency Window

A window into the Public Trust Consortium's decision log: the signed tree heads
over that log, and the Bitcoin timestamp proofs for them.

**A window shows; it does not open.** The log's *contents* are not published
here — its *commitments* are. What you can check from this repository is that a
specific key committed to a specific decision log, of a specific size, at a
specific time, and that those commitments existed by a specific Bitcoin block.
What the log actually says is a separate decision, not yet taken.

This repository is generated. It is written by `scripts/log/publish-transparency.mjs`
in the Consortium's working repository and carries nothing but signed heads,
anchor proofs, consistency proofs, the operator's public key, and this file.

---

## What you can verify without trusting anyone

Everything in this section you can check yourself, offline except where noted,
using only the files in this repository.

1. **Each head's signature**, against `keys/ptc-log-operator-1.spki.pem`. The key
   is committed here; you do not have to ask us for it.
2. **Each head's existence-by time**, from its OpenTimestamps proof in
   `anchors/ots/`. For `attested` anchors this is a Bitcoin block. For
   `submitted` anchors it is a calendar server's receipt, which is a promise
   rather than a proof — the register says which is which and never blurs them.
3. **That tree sizes increase monotonically** across `seq`, so the log is not
   shrinking.
4. **That the log is genuinely append-only** — that the tree at each head is a
   PREFIX of the next, with no leaf moved, removed or edited. `consistency-proofs.yaml`
   carries an RFC 6962 consistency proof for every adjacent pair, and the snippet
   below checks the whole chain from the published roots alone.

## What you CANNOT verify from this repository alone

Stated plainly, because a transparency page that lists only its strengths is
marketing.

- **What the tree contains.** These are hashes and signatures over a decision
  log you cannot read here. A head proves commitment, not content, and certainly
  not that the decisions are good ones.
- **That the calendar servers are honest**, for `submitted` anchors. Only a
  Bitcoin attestation settles that, and it takes hours to a day.
- **Anything about who holds the key.** The key lives in a hardware module and
  every signature required a human gesture, but this repository cannot prove that
  to you — it is a claim about our operating practice.
- **That anyone outside the Consortium has checked any of this.** Every head
  carries `countersignatures: []`. The machinery for external overseers is built
  and verified on every run; **no seat is filled**. Consistency proofs show we did
  not rewrite history *in this published sequence* — they cannot show that the
  sequence you are reading is the one everyone else was given. Only an independent
  witness closes that, and there is not one yet.

---

## The signed head serialization

A signature covers exactly these bytes, and nothing else:

```
"PTC-STH-v1" LF <treeSize> LF <rootHash> LF <timestamp> LF <keyId> LF
```

Five LF-terminated lines, **including the last**. `treeSize` is decimal.
`rootHash` and `keyId` are lowercase hex. `timestamp` is ISO 8601 UTC to the
second with a literal `Z`. `keyId` is the SHA-256 of the DER
SubjectPublicKeyInfo in `keys/ptc-log-operator-1.spki.pem`.

Algorithm `rsa2048-pkcs1v15-sha256`: RSASSA-PKCS1-v1_5 over SHA-256 **of those
bytes**. The message is hashed during verification — this is not a signature over
a pre-computed digest.

The anchored digest, for the OpenTimestamps proofs, is:

```
SHA-256( canonical_STH_bytes || raw_signature_bytes )
```

where the signature is the base64-**decoded** bytes from `tree-heads.yaml`. Both
halves together, so the timestamp binds one claim: this key committed to this
tree at this size.

---

## Verify it yourself

Requires Node 18+ and `js-yaml` (either 4.x or 5.x). No network, no trust in us.

```sh
npm install js-yaml
node verify.mjs
```

Note the **named** import below. js-yaml 5 ships an ESM build with named exports
and no default, so a default import fails there while working on 4.x — this
snippet uses `import { load }`, which runs on both.

```js
// verify.mjs — run: node verify.mjs
import { readFileSync } from 'node:fs'
import crypto from 'node:crypto'
import { load } from 'js-yaml'

const pem = readFileSync('keys/ptc-log-operator-1.spki.pem', 'utf8')
const key = crypto.createPublicKey(pem)
const der = Buffer.from(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64')
const keyId = crypto.createHash('sha256').update(der).digest('hex')

const heads = load(readFileSync('tree-heads.yaml', 'utf8'))
let previous = 0
let failures = 0

for (const h of heads) {
  const bytes = Buffer.from(
    `PTC-STH-v1\n${h.treeSize}\n${h.rootHash}\n${h.timestamp}\n${h.keyId}\n`,
    'utf8',
  )
  const ok = crypto.verify(
    'sha256', bytes,
    { key, padding: crypto.constants.RSA_PKCS1_PADDING },
    Buffer.from(h.signature, 'base64'),
  )
  const keyOk = h.keyId === keyId
  const grew = h.treeSize >= previous
  previous = h.treeSize
  if (!ok || !keyOk || !grew) failures++
  console.log(
    `seq ${h.seq}  size ${h.treeSize}  ${h.timestamp}  ` +
    `signature ${ok ? 'OK' : 'FAIL'}  key ${keyOk ? 'OK' : 'FAIL'}  ` +
    `monotonic ${grew ? 'OK' : 'FAIL'}`,
  )
}

// ---- append-only: RFC 6962 consistency proofs -----------------------------
// Rebuilds BOTH roots from the proof's node list, using only published roots and
// hashes. The decision log is not needed here and is not published.
const sha = (b) => crypto.createHash('sha256').update(b).digest()
const nodeHash = (l, r) => sha(Buffer.concat([Buffer.from([0x01]), l, r]))

function verifyConsistency(m, n, rootM, rootN, proof) {
  if (m > n) return false
  if (m === n) return proof.length === 0 && rootM.equals(rootN)
  if (m === 0) return proof.length === 0
  if (proof.length === 0) return false

  let i = 0, n1, n2
  let p = m - 1, last = n - 1
  while (p % 2 === 1) { p = Math.floor(p / 2); last = Math.floor(last / 2) }

  if (p > 0) { n1 = proof[i]; n2 = proof[i]; i++ } else { n1 = rootM; n2 = rootM }

  while (p > 0) {
    if (i >= proof.length) return false
    if (p % 2 === 1) { n1 = nodeHash(proof[i], n1); n2 = nodeHash(proof[i], n2); i++ }
    else if (p < last) { n2 = nodeHash(n2, proof[i]); i++ }
    p = Math.floor(p / 2); last = Math.floor(last / 2)
  }
  while (last > 0) {
    if (i >= proof.length) return false
    n2 = nodeHash(n2, proof[i]); i++; last = Math.floor(last / 2)
  }
  return i === proof.length && n1.equals(rootM) && n2.equals(rootN)
}

const proofs = load(readFileSync('consistency-proofs.yaml', 'utf8'))
for (let j = 0; j < heads.length - 1; j++) {
  const from = heads[j], to = heads[j + 1]
  const row = proofs.find((r) => r.fromSeq === from.seq && r.toSeq === to.seq)
  const ok = !!row &&
    row.fromSize === from.treeSize && row.toSize === to.treeSize &&
    verifyConsistency(
      row.fromSize, row.toSize,
      Buffer.from(from.rootHash, 'hex'), Buffer.from(to.rootHash, 'hex'),
      row.proof.map((h) => Buffer.from(h, 'hex')),
    )
  if (!ok) failures++
  console.log(
    `seq ${from.seq}->${to.seq}  ${from.treeSize}->${to.treeSize} leaves  ` +
    `append-only ${ok ? 'PROVEN' : 'FAILED'}`,
  )
}

// ---- who else has vouched -------------------------------------------------
const witnesses = heads.reduce((acc, h) => acc + (h.countersignatures?.length ?? 0), 0)
console.log(`\ncountersignatures: ${witnesses}` +
  (witnesses === 0 ? '  - nobody outside the Consortium has vouched for this log' : ''))

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`)
process.exit(failures === 0 ? 0 : 1)
```

To check the Bitcoin timestamps, use any OpenTimestamps client against the
`.ots` files in `anchors/ots/` — they are standard detached proofs and commit to
the `digest` field recorded in `anchors.yaml`.

---

## Files

| Path | What it is |
|---|---|
| `tree-heads.yaml` | Every signed tree head, append-only, oldest first |
| `anchors.yaml` | One anchor per head: digest, calendars, status, Bitcoin block |
| `consistency-proofs.yaml` | RFC 6962 consistency proof for every adjacent head pair |
| `anchors/ots/sth-NNNN.ots` | Detached OpenTimestamps proof for head `NNNN` |
| `keys/ptc-log-operator-1.spki.pem` | The operator's public key. Public only — the private key is non-exportable and exists solely inside a hardware module |

Chartered by D-22, the Public Record & Provenance Protocol.
