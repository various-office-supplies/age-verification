import { Gov, User, Website, initialize } from "./src/index.js"
import type { VerificationResult } from "./src/index.js"

const SITE_ORIGIN = "https://example-age-gate.test"

async function run_demo() {
  await initialize()

  print_step("1. Government creates its keys from a stored secret. It issues credentials but never publishes a list of valid users.")
  const gov = await Gov.create("gov-platform-secret")
  const gov_keys = gov.get_public_keys()

  print_step("2. Website trusts the gov credential public key it learned out-of-band.")
  const site = Website.create({
    siteOrigin: SITE_ORIGIN,
    trustedGovPublicKeyHex: gov_keys.credentialPublicKeyHex
  })

  print_step("3. Alice gets an anonymous credential. Only the gov knows who she is.")
  const alice = User.create()
  const alice_credential_id = await enroll_user(alice, gov)

  print_step("4. Gov publishes the invalid-ID accumulator that the website fetches from gov.")
  const accumulator = gov.publish_invalid_id_accumulator()
  print_field("Accumulator sequence", String(accumulator.sequence))

  print_step("5. Alice proves she is a verified adult. The website learns only a per-site pseudonym.")
  const challenge = site.create_challenge()
  const first_proof = alice.create_proof(accumulator, challenge)
  const first_result = site.verify_proof(challenge, first_proof, accumulator)
  print_result("First proof", first_result)

  print_step("6. Alice tries a second account. Her pseudonym is identical, so the website rejects it.")
  const second_challenge = site.create_challenge()
  const second_proof = alice.create_proof(accumulator, second_challenge)
  const second_result = site.verify_proof(second_challenge, second_proof, accumulator)
  print_field("First pseudonym", shorten(pseudonym_of(first_result)))
  print_field("Second pseudonym", shorten(pseudonym_of(second_result)))
  console.log(`Second account: ${same_person(first_result, second_result) ? "REJECTED (same person already registered)" : "ACCEPTED"}`)

  print_step("7. Gov revokes Alice's credential.")
  await gov.nullify_credential(alice_credential_id)
  const revoked_accumulator = gov.publish_invalid_id_accumulator()

  print_step("8. A different website rejects Alice after revocation.")
  const other_site = Website.create({
    siteOrigin: "https://other-age-gate.test",
    trustedGovPublicKeyHex: gov_keys.credentialPublicKeyHex
  })
  const other_challenge = other_site.create_challenge()
  const revoked_proof = alice.create_proof(revoked_accumulator, other_challenge)
  print_result(
    "Proof after revocation",
    other_site.verify_proof(other_challenge, revoked_proof, revoked_accumulator)
  )

  print_step("9. Gov restarts with the same secret and keeps its keys, so nobody re-enrolls.")
  const restarted_gov = await Gov.create("gov-platform-secret")
  print_field(
    "Same public key after restart",
    String(restarted_gov.get_public_keys().credentialPublicKeyHex === gov_keys.credentialPublicKeyHex)
  )
}

async function enroll_user(user: User, gov: Gov) {
  const request = user.begin_enrollment()
  const issued_credential = gov.issue_credential(request)
  user.complete_enrollment(issued_credential)

  const credential_id = user.get_credential_id()
  user.set_revocation_witness(await gov.create_revocation_witness(credential_id))
  return credential_id
}

function pseudonym_of(result: VerificationResult): string {
  return result.accepted ? result.nullifierHex : ""
}

function same_person(first: VerificationResult, second: VerificationResult): boolean {
  return pseudonym_of(first) !== "" && pseudonym_of(first) === pseudonym_of(second)
}

function print_step(message: string) {
  console.log(`\n${message}`)
}

function print_field(label: string, value: string) {
  console.log(`  ${label}: ${value}`)
}

function print_result(label: string, result: VerificationResult) {
  const verdict = result.accepted
    ? `ACCEPTED (site pseudonym ${shorten(result.nullifierHex)})`
    : `REJECTED (${result.reason})`
  console.log(`${label}: ${verdict}`)
}

function shorten(hex: string) {
  return hex === "" ? "(none)" : `${hex.slice(0, 12)}...`
}

run_demo()
  .then(() => process.exit(0))
  .catch((error: unknown) => {
    console.error(error)
    process.exit(1)
  })
