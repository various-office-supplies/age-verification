import { verify_website_proof } from "./anonymous-credential.js"
import { random_hex } from "./crypto.js"
import type {
  HexString,
  InvalidIdAccumulator,
  VerificationResult,
  WebsiteChallenge,
  WebsiteProof
} from "./types.js"

type WebsiteOptions = {
  siteOrigin: string
  trustedGovPublicKeyHex: HexString
}

export class Website {
  private readonly site_origin: string
  private readonly trusted_gov_public_key_hex: HexString

  private constructor(options: WebsiteOptions) {
    this.site_origin = options.siteOrigin
    this.trusted_gov_public_key_hex = options.trustedGovPublicKeyHex
  }

  static create(options: WebsiteOptions): Website {
    return new Website(options)
  }

  create_challenge(): WebsiteChallenge {
    return {
      challengeId: random_hex(16),
      siteOrigin: this.site_origin
    }
  }

  verify_proof(
    challenge: WebsiteChallenge,
    website_proof: WebsiteProof,
    accumulator: InvalidIdAccumulator
  ): VerificationResult {
    if (challenge.siteOrigin !== this.site_origin || website_proof.siteOrigin !== this.site_origin) {
      return { accepted: false, reason: "proof was made for a different website" }
    }

    if (!verify_website_proof(
      website_proof,
      challenge,
      accumulator,
      this.trusted_gov_public_key_hex
    )) {
      return { accepted: false, reason: "anonymous credential proof is invalid or revoked" }
    }

    return { accepted: true, nullifierHex: website_proof.nullifierHex }
  }
}
