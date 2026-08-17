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
anchor proofs, the operator's public key, and this file.

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

## What you CANNOT verify from this repository alone

Stated plainly, because a transparency page that lists only its strengths is
marketing.

- **What the tree contains.** These are hashes and signatures over a decision
  log you cannot read here. A head proves commitment, not content, and certainly
  not that the decisions are good ones.
- **Cryptographic append-only consistency between heads.** Nothing here proves
  that the tree at size 15 *contains* the tree at size 13 — only that both were
  signed by the same key. RFC 6962 consistency proofs are **planned and not
  present**. Until they ship, "append-only" is a claim backed by process, not by
  mathematics you can check.
- **That the calendar servers are honest**, for `submitted` anchors. Only a
  Bitcoin attestation settles that, and it takes hours to a day.
- **Anything about who holds the key.** The key lives in a hardware module and
  every signature required a human gesture, but this repository cannot prove that
  to you — it is a claim about our operating practice.

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

Requires Node 18+ and `js-yaml`. No network, no trust in us.

```js
// verify.mjs — run: node verify.mjs
import { readFileSync } from 'node:fs'
import crypto from 'node:crypto'
import yaml from 'js-yaml'

const pem = readFileSync('keys/ptc-log-operator-1.spki.pem', 'utf8')
const key = crypto.createPublicKey(pem)
const der = Buffer.from(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64')
const keyId = crypto.createHash('sha256').update(der).digest('hex')

const heads = yaml.load(readFileSync('tree-heads.yaml', 'utf8'))
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
console.log(failures === 0 ? '\nALL HEADS VERIFIED' : `\n${failures} HEAD(S) FAILED`)
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
| `anchors/ots/sth-NNNN.ots` | Detached OpenTimestamps proof for head `NNNN` |
| `keys/ptc-log-operator-1.spki.pem` | The operator's public key. Public only — the private key is non-exportable and exists solely inside a hardware module |

Chartered by D-22, the Public Record & Provenance Protocol.
