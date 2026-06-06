# Anonymous Age Verification

A TypeScript library for blind, anonymous online age verification.

Users prove they hold a government-approved ID without revealing who they are. Websites verify proofs offline using a signed registry snapshot and a trusted government public key.

## Quick Start

```bash
npm install
npm run demo
```

## Import

```typescript
import { Gov, User, Website } from "age-verification"
```

## Roles

### Government

Issues blind enrollment tickets, maintains the valid-ID registry, and publishes signed snapshots.

```typescript
const gov = await Gov.create()
const public_keys = gov.get_public_keys()

const approval = await gov.sign_blinded_ticket(blinded_ticket)
await gov.redeem_credential(credential, commitment)
gov.nullify_commitment(old_commitment)

const snapshot = await gov.publish_registry_snapshot()
```

### User

Creates a private wallet, enrolls through blind signing, and generates site-specific ZK proofs.

```typescript
const user = User.create("your-password")

const blind_request = await user.begin_enrollment(public_keys.enrollmentPublicKey)
const approval = await gov.sign_blinded_ticket(blind_request.blindedTicket)
const credential = await user.complete_enrollment(public_keys.enrollmentPublicKey, approval)
await gov.redeem_credential(credential, user.get_commitment())

const proof = await user.create_proof(snapshot, challenge)
```

### Website

Downloads registry snapshots, creates challenges, and verifies proofs locally.

```typescript
const site = Website.create({
  siteOrigin: "https://your-site.example",
  trustedRegistryPublicKeyHex: public_keys.registryPublicKeyHex
})

await site.download_registry_snapshot(snapshot)
const challenge = site.create_challenge()
const result = await site.verify_proof(challenge, proof)
```

Websites do not need to contact the government during verification. They only need:

1. The trusted government registry public key
2. A downloaded signed registry snapshot
3. The user's proof

## How It Works

```text
User --blinded ticket--> Gov
Gov --blind signature--> User
User --anonymous redeem--> Gov registry
Gov --signed snapshot--> Website
User --ZK proof--> Website
Website verifies locally
```

## Notes

This is production-intended demo code, not a finished legal identity system. A qualified crypto research team should review the protocol before real-world use.

Future review: non-crypto privacy leaks like IP address, timing, and browser fingerprinting.
