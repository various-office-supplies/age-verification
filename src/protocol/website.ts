import { verify_website_proof } from "./anonymous-credential.js"
import {
  load_website,
  save_website,
  website_csv,
  website_json
} from "./convert.js"
import { random_hex } from "./crypto.js"
import type {
  HexString,
  InvalidIdAccumulator,
  VerificationResult,
  WebsiteChallenge,
  WebsiteNullifierPackage,
  WebsiteProof
} from "./types.js"

type WebsiteOptions = {
  acceptedNullifiers?: string[]
  siteOrigin: string
  trustedGovPublicKeyHex: HexString
}

export class Website {
  private readonly accepted_nullifiers: Set<string>
  private readonly site_origin: string
  private readonly trusted_gov_public_key_hex: HexString

  private constructor(options: WebsiteOptions) {
    this.accepted_nullifiers = new Set(options.acceptedNullifiers ?? [])
    this.site_origin = options.siteOrigin
    this.trusted_gov_public_key_hex = options.trustedGovPublicKeyHex
  }

  static create(options: WebsiteOptions): Website {
    return new Website(options)
  }

  csv(): string {
    return website_csv(this.export_nullifier_package())
  }

  json(): string {
    return website_json(this.export_nullifier_package())
  }

  async load(source: string): Promise<void> {
    const nullifier_package = await load_website(source)

    if (nullifier_package.siteOrigin && nullifier_package.siteOrigin !== this.site_origin) {
      throw new Error("nullifier data belongs to a different website")
    }

    this.accepted_nullifiers.clear()

    for (const nullifier of nullifier_package.nullifiers) {
      this.accepted_nullifiers.add(nullifier)
    }
  }

  async save(file_path: string): Promise<void> {
    await save_website(file_path, this.export_nullifier_package())
  }

  export_nullifier_package(): WebsiteNullifierPackage {
    return {
      nullifiers: Array.from(this.accepted_nullifiers),
      siteOrigin: this.site_origin
    }
  }

  create_challenge(): WebsiteChallenge {
    return {
      challengeId: random_hex(16),
      siteOrigin: this.site_origin
    }
  }

  async verify_proof(
    challenge: WebsiteChallenge,
    website_proof: WebsiteProof,
    accumulator: InvalidIdAccumulator
  ): Promise<VerificationResult> {
    const basic_error = this.find_basic_error(challenge, website_proof, accumulator)

    if (basic_error) {
      return reject(basic_error)
    }

    const nullifier = website_proof.nullifierHex

    if (this.accepted_nullifiers.has(nullifier)) {
      return reject("same site nullifier was already accepted")
    }

    this.accepted_nullifiers.add(nullifier)
    return { accepted: true, reason: "valid anonymous gov credential proof" }
  }

  private find_basic_error(
    challenge: WebsiteChallenge,
    website_proof: WebsiteProof,
    accumulator: InvalidIdAccumulator
  ): string | null {
    if (challenge.siteOrigin !== this.site_origin || website_proof.siteOrigin !== this.site_origin) {
      return "proof was made for a different website"
    }

    if (!verify_website_proof(
      website_proof,
      challenge,
      accumulator,
      this.trusted_gov_public_key_hex
    )) {
      return "anonymous credential proof is invalid or revoked"
    }

    return null
  }
}

function reject(reason: string): VerificationResult {
  return { accepted: false, reason }
}
