import assert from "node:assert/strict"

import { Gov, User, Website, initialize } from "./src/index.js"

const SITE_A = "https://a.example"
const SITE_B = "https://b.example"

async function main() {
  await initialize()
  const gov = await Gov.create("gov-server-secret")
  const gov_keys = gov.get_public_keys()

  // A pre-determined secret reproduces the same keys, so a restart keeps existing credentials valid.
  const restarted_gov = await Gov.create("gov-server-secret")
  assert.deepEqual(restarted_gov.get_public_keys(), gov_keys)
  const site = Website.create({
    siteOrigin: SITE_A,
    trustedGovPublicKeyHex: gov_keys.credentialPublicKeyHex
  })

  const user = User.create()
  const request = user.begin_enrollment()
  user.complete_enrollment(gov.issue_credential(request))
  const credential_id = user.get_credential_id()
  user.set_revocation_witness(await gov.create_revocation_witness(credential_id))

  const accumulator = gov.publish_invalid_id_accumulator()
  const challenge = site.create_challenge()
  const result = site.verify_proof(challenge, user.create_proof(accumulator, challenge), accumulator)
  assert.equal(result.accepted, true)
  const pseudonym = result.accepted ? result.nullifierHex : ""

  // Same person: same pseudonym on the same site, a different one on another site.
  const other_site = Website.create({
    siteOrigin: SITE_B,
    trustedGovPublicKeyHex: gov_keys.credentialPublicKeyHex
  })
  const other_challenge = other_site.create_challenge()
  const other_result = other_site.verify_proof(
    other_challenge,
    user.create_proof(accumulator, other_challenge),
    accumulator
  )
  assert.equal(other_result.accepted, true)
  assert.notEqual(other_result.accepted ? other_result.nullifierHex : "", pseudonym)

  // Export/import preserves keys, credential, and witness end to end.
  const restored_gov = await Gov.import(gov.export())
  const restored_user = User.import(user.export())
  const restored_challenge = site.create_challenge()
  const restored_result = site.verify_proof(
    restored_challenge,
    restored_user.create_proof(accumulator, restored_challenge),
    accumulator
  )
  assert.deepEqual(restored_result, result)

  // Revocation survives export/import.
  await restored_gov.nullify_credential(credential_id)
  const revoked_accumulator = restored_gov.publish_invalid_id_accumulator()
  const revoked_challenge = site.create_challenge()
  const revoked_result = site.verify_proof(
    revoked_challenge,
    restored_user.create_proof(revoked_accumulator, revoked_challenge),
    revoked_accumulator
  )
  assert.equal(revoked_result.accepted, false)

  console.log("all checks passed")
}

main().catch((error: unknown) => {
  console.error(error)
  process.exit(1)
})
