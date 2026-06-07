# Anonymous Age Verification

A TypeScript library for anonymous online age verification.

Users prove they hold a government-issued private credential without revealing who they are. Websites verify proofs offline using trusted government public key material, their own domain, and an optional invalid-ID accumulator.

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

Issues anonymous credentials and publishes an invalid-ID accumulator. It does not publish a valid-user registry.

```typescript
const gov = await Gov.create("your-password")
const public_keys = gov.get_public_keys()

const request = await user.begin_enrollment()
const issued_credential = gov.issue_credential(request)
user.complete_enrollment(issued_credential)

const revocation_witness = await gov.create_revocation_witness(user.get_credential_id())
user.set_revocation_witness(revocation_witness)

await gov.nullify_credential(credential_id)
const accumulator = gov.publish_invalid_id_accumulator()
```

### User

Creates a private wallet from one password, enrolls anonymously, and generates site-specific ZK proofs.

```typescript
const user = User.create("your-password")

const request = await user.begin_enrollment()
const issued_credential = gov.issue_credential(request)
user.complete_enrollment(issued_credential)
const revocation_witness = await gov.create_revocation_witness(user.get_credential_id())
user.set_revocation_witness(revocation_witness)

const proof = user.create_proof(accumulator, challenge)
```

### Website

Creates challenges and verifies proofs locally. It does not need a list of valid users.

```typescript
const site = Website.create({
  siteOrigin: "https://your-site.example",
  trustedGovPublicKeyHex: public_keys.credentialPublicKeyHex
})

const challenge = site.create_challenge()
const result = await site.verify_proof(challenge, proof, accumulator)
```

Websites do not need to contact the government during verification. They only need:

1. The trusted government credential public key
2. Their own domain and challenge
3. The user's proof
4. The latest invalid-ID accumulator, if revocation checking is required

## How It Works

```text
User --blind credential request--> Gov
Gov --anonymous credential--> User
Gov --invalid-ID accumulator--> Website
User --site-specific ZK proof--> Website
Website verifies gov signature, site nullifier, and non-revocation
```

## Conversion And Storage

Live methods return live objects by default:

```typescript
const accumulator = gov.publish_invalid_id_accumulator()
```

Call `.json()` or `.csv()` only when you want text that is ready to save to a file, database, or API response:

```typescript
const accumulator_json = accumulator.json()
const accumulator_csv = accumulator.csv()
```

### Save And Load Files

Gov and User state are encrypted with their passwords. Website nullifiers and public accumulators are plain text.

```typescript
await gov.save("./gov-state.json")
await user.save("./user-wallet.json")
await site.save("./site-nullifiers.csv")
await accumulator.save("./accumulator.json")
```

Load them later:

```typescript
const gov = await Gov.create("gov-password")
await gov.load("./gov-state.json")

const user = User.create("user-password")
await user.load("./user-wallet.json")

const site = Website.create({
  siteOrigin: "https://your-site.example",
  trustedGovPublicKeyHex: public_keys.credentialPublicKeyHex
})
await site.load("./site-nullifiers.csv")
```

File format is detected from the path:

```text
.json -> JSON
.csv  -> CSV
other -> JSON
```

### Database Example

Store encrypted Gov/User text in one column:

```typescript
await db.govState.upsert({
  id: "main",
  value: gov.json()
})

await db.userWallet.upsert({
  userId: "local-user",
  value: user.json()
})
```

Store website nullifiers as rows:

```typescript
for (const row of site.csv().split("\n").slice(1)) {
  const [nullifierHex, siteOrigin] = row.split(",")
  await db.nullifiers.create({ siteOrigin, nullifierHex })
}
```

### API Example

Gov can publish a public accumulator:

```typescript
app.get("/invalid-id-accumulator", (_request, response) => {
  response.type("json").send(gov.publish_invalid_id_accumulator().json())
})
```

A website can fetch that public object:

```typescript
const accumulator = await fetch("https://gov.example/invalid-id-accumulator")
  .then((response) => response.json())
```

### Password Warning

Gov/User save and load require the object password:

```typescript
const gov = await Gov.create("gov-password")
await gov.load("./gov-state.json")
```

If Gov/User state is converted or loaded without a password, the library throws a clear error. Websites do not have passwords because they only store local nullifiers.

### Safe API Defaults

Enrollment and persistence are designed to avoid accidental leaks:

```typescript
// Safe to send to gov — no blinding secret included
const request = await user.begin_enrollment()

// Credential stays inside the wallet — no return value
user.complete_enrollment(issued_credential)

// Encrypted by default for API/DB transfer
const encrypted_wallet = user.wallet_package()
const encrypted_state = gov.state_package()

// Explicitly unsafe — only for debugging or custom tooling
const raw_wallet = user.unencrypted_wallet_package()
const raw_state = gov.unencrypted_state_package()
```

## Notes

This is production-intended demo code, not a finished legal identity system. A qualified crypto research team should review the protocol before real-world use.

Future review: non-crypto privacy leaks like IP address, timing, and browser fingerprinting.
