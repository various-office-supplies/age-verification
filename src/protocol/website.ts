import { verifyProof } from "@semaphore-protocol/proof"

import { hash_text_to_field, random_hex, verify_registry_snapshot } from "./crypto.js"
import type {
  HexString,
  SignedRegistrySnapshot,
  VerificationResult,
  WebsiteChallenge,
  WebsiteProof
} from "./types.js"

type WebsiteOptions = {
  siteOrigin: string
  trustedRegistryPublicKeyHex: HexString
}

export class Website {
  private cached_snapshot: SignedRegistrySnapshot | null = null
  private readonly accepted_nullifiers = new Set<string>()
  private readonly site_origin: string
  private readonly trusted_registry_public_key_hex: HexString

  private constructor(options: WebsiteOptions) {
    this.site_origin = options.siteOrigin
    this.trusted_registry_public_key_hex = options.trustedRegistryPublicKeyHex
  }

  static create(options: WebsiteOptions): Website {
    return new Website(options)
  }

  async download_registry_snapshot(snapshot: SignedRegistrySnapshot): Promise<boolean> {
    const valid = await verify_registry_snapshot(snapshot, this.trusted_registry_public_key_hex)

    if (valid) {
      this.cached_snapshot = snapshot
    }

    return valid
  }

  create_challenge(): WebsiteChallenge {
    const challenge_id = random_hex(16)

    return {
      challengeId: challenge_id,
      message: hash_text_to_field("challenge-message", `${this.site_origin}:${challenge_id}`),
      scope: hash_text_to_field("site-scope", this.site_origin),
      siteOrigin: this.site_origin
    }
  }

  async verify_proof(
    challenge: WebsiteChallenge,
    website_proof: WebsiteProof
  ): Promise<VerificationResult> {
    const basic_error = await this.find_basic_error(challenge, website_proof)

    if (basic_error) {
      return reject(basic_error)
    }

    const nullifier = website_proof.proof.nullifier

    if (this.accepted_nullifiers.has(nullifier)) {
      return reject("same site nullifier was already accepted")
    }

    this.accepted_nullifiers.add(nullifier)
    return { accepted: true, reason: "valid anonymous ID proof" }
  }

  get_cached_snapshot(): SignedRegistrySnapshot | null {
    return this.cached_snapshot
  }

  private async find_basic_error(
    challenge: WebsiteChallenge,
    website_proof: WebsiteProof
  ): Promise<string | null> {
    if (!this.cached_snapshot) {
      return "no registry snapshot has been downloaded"
    }

    if (challenge.siteOrigin !== this.site_origin || website_proof.siteOrigin !== this.site_origin) {
      return "proof was made for a different website"
    }

    const snapshot_valid = await verify_registry_snapshot(
      this.cached_snapshot,
      this.trusted_registry_public_key_hex
    )

    if (!snapshot_valid) {
      return "cached government registry snapshot is invalid"
    }

    return this.verify_proof_fields(challenge, website_proof)
  }

  private async verify_proof_fields(
    challenge: WebsiteChallenge,
    website_proof: WebsiteProof
  ): Promise<string | null> {
    const snapshot = this.cached_snapshot
    const proof = website_proof.proof

    if (!snapshot) {
      return "no registry snapshot has been downloaded"
    }

    if (proof.merkleTreeRoot !== snapshot.snapshot.registryRoot) {
      return "proof was made against an old or unknown registry"
    }

    if (proof.message !== challenge.message.toString() || proof.scope !== challenge.scope.toString()) {
      return "proof does not match the website challenge"
    }

    return (await verifyProof(proof)) ? null : "zero-knowledge proof is invalid"
  }
}

function reject(reason: string): VerificationResult {
  return { accepted: false, reason }
}
