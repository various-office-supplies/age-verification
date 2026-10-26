// Demo flow logic. Pure: no DOM, no terminal. app.ts renders it, flow-test.ts checks it.
//
//   create_demo(secret) -> { boot, enroll, visit, revoke, credential_id }
//
// boot()   Gateway: loads wasm, builds the gov's keys.
// enroll() Gateway: Alice receives an anonymous credential. Returns its id (gov-visible only).
// visit()  Pilot:   a website asks for proof; returns what that website learned.
// revoke() Gateway: gov revokes Alice's credential and republishes the invalid-ID list.

import { Gov, User, Website, initialize } from "../src/index.js"
import type { InvalidIdAccumulator } from "../src/index.js"

export type VisitStatus = "verified" | "duplicate" | "rejected"

export type VisitResult = {
  origin: string
  pseudonymHex: string
  reason: string
  status: VisitStatus
}

type FakeSite = {
  accounts: Set<string>
  website: Website
}

export function create_demo(gov_secret: string) {
  let accumulator: InvalidIdAccumulator
  let credential_id = ""
  let gov: Gov
  let gov_public_key = ""
  let user: User
  const sites = new Map<string, FakeSite>()

  async function boot(): Promise<void> {
    await initialize()
    gov = await Gov.create(gov_secret)
    gov_public_key = gov.get_public_keys().credentialPublicKeyHex
    user = User.create()
    accumulator = gov.publish_invalid_id_accumulator()
  }

  async function enroll(): Promise<string> {
    const request = user.begin_enrollment()
    const issued = gov.issue_credential(request)
    user.complete_enrollment(issued)
    credential_id = issued.credentialIdHex
    user.set_revocation_witness(await gov.create_revocation_witness(credential_id))
    return credential_id
  }

  // A website: create a challenge, take the proof, then enforce one account per pseudonym.
  function visit(origin: string): VisitResult {
    const site = get_site(origin)
    const challenge = site.website.create_challenge()
    const proof = user.create_proof(accumulator, challenge)
    const result = site.website.verify_proof(challenge, proof, accumulator)
    const base = { origin, pseudonymHex: proof.nullifierHex }

    if (!result.accepted) {
      return { ...base, reason: result.reason, status: "rejected" }
    }

    if (site.accounts.has(result.nullifierHex)) {
      return { ...base, reason: "this person already has an account here", status: "duplicate" }
    }

    site.accounts.add(result.nullifierHex)
    return { ...base, reason: "", status: "verified" }
  }

  async function revoke(): Promise<void> {
    await gov.nullify_credential(credential_id)
    accumulator = gov.publish_invalid_id_accumulator()
  }

  function get_site(origin: string): FakeSite {
    const existing = sites.get(origin)
    if (existing) return existing

    const created: FakeSite = {
      accounts: new Set(),
      website: Website.create({ siteOrigin: origin, trustedGovPublicKeyHex: gov_public_key })
    }
    sites.set(origin, created)
    return created
  }

  return { boot, credential_id: () => credential_id, enroll, revoke, visit }
}
