# Anonymous Age Verification

Prove "I am a verified adult" to any website, without revealing who you are.

A user holds a government-issued credential and proves it to a website. The website learns
only a yes/no answer and a per-site pseudonym. It never sees a name, birth date, ID, or face.

## Try it

```bash
npm install

# Terminal walkthrough
npm run demo

# Browser demo: all three roles on one page
npm run demo:web   # then open http://localhost:5173
```

The browser demo builds `demo/app.js` with esbuild, then serves `demo/` locally. It walks you
through verifying an ID, getting an anonymous credential, and using it at a fake website — and
shows that the site learns a unique pseudonym but never your identity. Everything runs in your
browser; nothing is sent anywhere.

## The three roles

| Role | What it does | What it never sees |
| --- | --- | --- |
| **Gov** | Issues anonymous credentials, revokes them, publishes an invalid-ID list | — |
| **User** | Holds a credential and proves it to sites | — |
| **Website** | Verifies proofs offline and gets a per-site pseudonym | The user's identity |

Checking that a person is a real adult (ID + face scan) happens at the **Gov** before this
library is used. That part is out of scope.

## Example

```ts
import { Gov, User, Website, initialize } from "age-verification"

// Load the crypto once at startup. This is the only async step.
await initialize()

// Gov creates keys and issues credentials. It never publishes a list of valid users.
const gov = await Gov.create()
const govKeys = gov.get_public_keys()

// Website trusts the gov credential key, learned out-of-band.
const site = Website.create({
  siteOrigin: "https://your-site.example",
  trustedGovPublicKeyHex: govKeys.credentialPublicKeyHex
})

// User enrolls anonymously. Only the gov knows who they are.
const user = User.create()
const request = await user.begin_enrollment()
user.complete_enrollment(gov.issue_credential(request))
user.set_revocation_witness(await gov.create_revocation_witness(user.get_credential_id()))

// User proves they are a verified adult. The website fetches the accumulator from gov.
const accumulator = gov.publish_invalid_id_accumulator()
const challenge = site.create_challenge()
const proof = user.create_proof(accumulator, challenge)
const result = site.verify_proof(challenge, proof, accumulator)

if (result.accepted) {
  result.nullifierHex // a stable, site-specific pseudonym for this person
}
```

## One person per site

The same user always gets the **same pseudonym** at a given site, and a **different one** at
every other site. This means:

- A stolen or reposted credential cannot register a thousand accounts on one site.
- Two sites cannot compare pseudonyms to link the same person.

The website must store each accepted `nullifierHex` and reject repeats. That is a `UNIQUE`
constraint in your own database — the library holds no state of its own.

## Revocation

```ts
await gov.nullify_credential(credentialId)
const accumulator = gov.publish_invalid_id_accumulator()
```

Websites fetch the accumulator from gov and pass it to `verify_proof`. A revoked credential
fails verification. Users who are not revoked should refresh their witness whenever gov
publishes a new accumulator.

## Secrets and saving state

Pass a secret to `Gov.create` to get the same keys on every launch, so a server restart never
forces users to re-enroll:

```ts
const gov = await Gov.create(process.env.GOV_SECRET)
```

If you omit it, gov generates a random secret, readable from `gov.export()`.

The library never touches files or databases. Export plain objects and store them wherever
you already keep secrets.

```ts
// Save
const govState = gov.export()   // { secret, invalidCredentialIds, sequence }
const userState = user.export()

// Restore
const gov2 = await Gov.import(govState)
const user2 = User.import(userState)
```

`gov.export()` contains secret key material. Protect it.

## Notes

Load the crypto once with `await initialize()` before anything else. After that, enrolling,
proving, and verifying are all synchronous; only loading a Government's keys or a revocation
list is async.

Demo-grade code, not a finished identity system. Have the protocol reviewed by cryptographers
before real-world use. Network-level leaks (IP address, timing, cookies) are outside this
library.
