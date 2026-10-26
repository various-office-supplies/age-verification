import assert from "node:assert/strict"

import { create_demo } from "./flow.js"

const SITE = "https://fakesocial.example"
const OTHER_SITE = "https://another-app.example"
const FRESH_SITE = "https://brand-new.example"

async function main() {
  const demo = create_demo("demo-test-secret")
  await demo.boot()
  await demo.enroll()

  const first = demo.visit(SITE)
  assert.equal(first.status, "verified")

  // Same person, same site: identical pseudonym, so a second account is refused.
  const second = demo.visit(SITE)
  assert.equal(second.status, "duplicate")
  assert.equal(second.pseudonymHex, first.pseudonymHex)

  // Same person, different site: a different pseudonym, so sites cannot link her.
  const other = demo.visit(OTHER_SITE)
  assert.equal(other.status, "verified")
  assert.notEqual(other.pseudonymHex, first.pseudonymHex)

  // Revocation reaches a fresh site without it ever contacting the government.
  await demo.revoke()
  assert.equal(demo.visit(FRESH_SITE).status, "rejected")

  console.log("demo flow checks passed")
}

main().catch((error: unknown) => {
  console.error(error)
  process.exit(1)
})
