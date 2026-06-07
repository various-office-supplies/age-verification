import { Gov, User, Website } from "./src/index.js"
import { short_hex } from "./src/protocol/crypto.js"

const SITE_ORIGIN = "https://example-age-gate.test"

async function run_demo() {
  print_step("1. Government starts on its own platform.")
  const gov = await Gov.create("gov-platform-password")
  const gov_keys = gov.get_public_keys()

  print_step("2. Website starts with the gov credential public key it trusts out-of-band.")
  const site = Website.create({
    siteOrigin: SITE_ORIGIN,
    trustedGovPublicKeyHex: gov_keys.credentialPublicKeyHex
  })

  print_step("3. Alice creates a user wallet on her device.")
  const alice = User.create("correct horse battery staple")

  print_step("4. Alice anonymously receives a gov-issued credential.")
  const alice_credential_id = await enroll_user(alice, gov)
  print_field("Credential id kept out of website proof", short_hex(alice_credential_id))

  print_step("5. Gov publishes an invalid-ID accumulator, not a valid-user registry.")
  const accumulator = gov.publish_invalid_id_accumulator()
  print_field("Accumulator sequence", String(accumulator.sequence))

  const challenge = site.create_challenge()

  print_step("6. Alice creates a proof and sends it to the website.")
  const first_proof = alice.create_proof(accumulator, challenge)
  const first_result = await site.verify_proof(challenge, first_proof, accumulator)
  print_result("First proof", first_result.accepted, first_result.reason)

  print_step("7. Alice tries the same proof again and is rejected.")
  const duplicate_result = await site.verify_proof(challenge, first_proof, accumulator)
  print_result("Duplicate proof", duplicate_result.accepted, duplicate_result.reason)

  print_step("8. Gov adds Alice's credential id to the invalid-ID accumulator.")
  await gov.nullify_credential(alice_credential_id)
  const revoked_accumulator = gov.publish_invalid_id_accumulator()

  print_step("9. A different website rejects Alice after revocation.")
  const other_site = Website.create({
    siteOrigin: "https://other-age-gate.test",
    trustedGovPublicKeyHex: gov_keys.credentialPublicKeyHex
  })
  const new_challenge = other_site.create_challenge()
  const revoked_proof = alice.create_proof(revoked_accumulator, new_challenge)
  const revoked_result = await other_site.verify_proof(
    new_challenge,
    revoked_proof,
    revoked_accumulator
  )
  print_result("Proof after revocation", revoked_result.accepted, revoked_result.reason)
}

async function enroll_user(user: User, gov: Gov) {
  const request = await user.begin_enrollment()
  const issued_credential = gov.issue_credential(request)
  user.complete_enrollment(issued_credential)
  const credential_id = user.get_credential_id()
  const revocation_witness = await gov.create_revocation_witness(credential_id)

  user.set_revocation_witness(revocation_witness)
  return credential_id
}

function print_step(message: string) {
  console.log(`\n${message}`)
}

function print_field(label: string, value: string) {
  console.log(`  ${label}: ${value}`)
}

function print_result(label: string, accepted: boolean, reason: string) {
  console.log(`${label}: ${accepted ? "ACCEPTED" : "REJECTED"} (${reason})`)
}

run_demo()
  .then(() => process.exit(0))
  .catch((error: unknown) => {
    console.error(error)
    process.exit(1)
  })
