import { Gov, User, Website } from "./src/index.js"
import { short_hex } from "./src/protocol/crypto.js"

const SITE_ORIGIN = "https://example-age-gate.test"

async function run_demo() {
  print_step("1. Government starts on its own platform.")
  const gov = await Gov.create()
  const gov_keys = gov.get_public_keys()

  print_step("2. Website starts with the gov registry public key it trusts out-of-band.")
  const site = Website.create({
    siteOrigin: SITE_ORIGIN,
    trustedRegistryPublicKeyHex: gov_keys.registryPublicKeyHex
  })

  print_step("3. Alice creates a user wallet on her device.")
  const alice = User.create("correct horse battery staple")

  print_step("4. Alice and two background users enroll through blind tickets.")
  await enroll_user(alice, gov, gov_keys.enrollmentPublicKey)
  await enroll_user(User.create("background user one"), gov, gov_keys.enrollmentPublicKey)
  await enroll_user(User.create("background user two"), gov, gov_keys.enrollmentPublicKey)

  print_blindness_proof(gov)

  print_step("5. Website downloads the latest signed registry snapshot from gov.")
  const snapshot = await gov.publish_registry_snapshot()
  const snapshot_saved = await site.download_registry_snapshot(snapshot)
  print_field("Snapshot saved locally", String(snapshot_saved))

  const challenge = site.create_challenge()

  print_step("6. Alice creates a proof and sends it to the website.")
  const first_proof = await alice.create_proof(snapshot, challenge)
  const first_result = await site.verify_proof(challenge, first_proof)
  print_result("First proof", first_result.accepted, first_result.reason)

  print_step("7. Alice tries the same proof again and is rejected.")
  const duplicate_result = await site.verify_proof(challenge, first_proof)
  print_result("Duplicate proof", duplicate_result.accepted, duplicate_result.reason)

  print_step("8. Alice nullifies her old ID and enrolls again.")
  gov.nullify_commitment(alice.get_commitment())
  const new_alice = User.create("correct horse battery staple")
  await enroll_user(new_alice, gov, gov_keys.enrollmentPublicKey)

  const updated_snapshot = await gov.publish_registry_snapshot()
  await site.download_registry_snapshot(updated_snapshot)

  print_step("9. Alice proves again with her new anonymous ID.")
  const new_challenge = site.create_challenge()
  const new_proof = await new_alice.create_proof(updated_snapshot, new_challenge)
  const new_result = await site.verify_proof(new_challenge, new_proof)
  print_result("New proof", new_result.accepted, new_result.reason)

  print_step("10. The old proof is retried against the updated registry.")
  const old_proof_result = await site.verify_proof(challenge, first_proof)
  print_result("Old proof after nullification", old_proof_result.accepted, old_proof_result.reason)
}

async function enroll_user(
  user: User,
  gov: Gov,
  enrollment_public_key: CryptoKey
) {
  const blind_request = await user.begin_enrollment(enrollment_public_key)
  const approval = await gov.sign_blinded_ticket(blind_request.blindedTicket)
  const credential = await user.complete_enrollment(enrollment_public_key, approval)
  const redeemed = await gov.redeem_credential(credential, user.get_commitment())

  if (!redeemed) {
    throw new Error("anonymous credential redemption failed")
  }
}

function print_blindness_proof(gov: Gov) {
  const audit_trail = gov.get_blind_enrollment_audit_trail()

  print_step("Blindness check: signed blinded tickets do not match redeemed tickets.")
  print_field("Government signed blinded ticket hash", short_hex(audit_trail.signedBlindTicketHashes[0]))
  print_field("Redeemed ticket hash", short_hex(audit_trail.redeemedTicketHashes[0]))
  print_field(
    "Known link exists",
    String(audit_trail.signedBlindTicketHashes[0] === audit_trail.redeemedTicketHashes[0])
  )
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
