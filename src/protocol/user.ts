import { utf8ToBytes } from "@noble/hashes/utils.js"
import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { generateProof } from "@semaphore-protocol/proof"

import { domain_hash, from_hex, get_blind_suite, random_hex } from "./crypto.js"
import type {
  AnonymousCredential,
  ApprovedEnrollment,
  EnrollmentRequest,
  SignedRegistrySnapshot,
  UserWallet,
  WebsiteChallenge,
  WebsiteProof
} from "./types.js"

export class User {
  private pending_enrollment: EnrollmentRequest | null = null
  private readonly wallet: UserWallet

  private constructor(wallet: UserWallet) {
    this.wallet = wallet
  }

  static create(password: string, password_salt_hex = random_hex()): User {
    const private_key = domain_hash(
      "wallet-private-key",
      utf8ToBytes(password),
      from_hex(password_salt_hex)
    )
    const identity = new Identity(private_key)

    return new User({
      identity,
      passwordSaltHex: password_salt_hex,
      commitment: identity.commitment
    })
  }

  get_commitment(): string {
    return this.wallet.commitment.toString()
  }

  async begin_enrollment(enrollment_public_key: CryptoKey) {
    this.pending_enrollment = await this.create_enrollment_request(enrollment_public_key)
    return { blindedTicket: this.pending_enrollment.blindedTicket }
  }

  async complete_enrollment(
    enrollment_public_key: CryptoKey,
    approval: ApprovedEnrollment
  ): Promise<AnonymousCredential> {
    if (!this.pending_enrollment) {
      throw new Error("call begin_enrollment before complete_enrollment")
    }

    const credential = await this.finalize_enrollment(
      enrollment_public_key,
      this.pending_enrollment,
      approval
    )
    this.pending_enrollment = null
    return credential
  }

  async create_proof(
    registry_snapshot: SignedRegistrySnapshot,
    challenge: WebsiteChallenge
  ): Promise<WebsiteProof> {
    const group = new Group(registry_snapshot.snapshot.commitments.map(BigInt))
    const proof = await generateProof(
      this.wallet.identity,
      group,
      challenge.message,
      challenge.scope
    )

    return {
      proof,
      siteOrigin: challenge.siteOrigin
    }
  }

  private async create_enrollment_request(
    enrollment_public_key: CryptoKey
  ): Promise<EnrollmentRequest> {
    const suite = get_blind_suite()
    const ticket = domain_hash("enrollment-ticket", from_hex(random_hex(64)))
    const prepared_ticket = suite.prepare(ticket)
    const blind_output = await suite.blind(enrollment_public_key, prepared_ticket)

    return {
      blindedTicket: blind_output.blindedMsg,
      inverse: blind_output.inv,
      preparedTicket: prepared_ticket
    }
  }

  private async finalize_enrollment(
    enrollment_public_key: CryptoKey,
    request: EnrollmentRequest,
    approval: ApprovedEnrollment
  ): Promise<AnonymousCredential> {
    const suite = get_blind_suite()
    const ticket_signature = await suite.finalize(
      enrollment_public_key,
      request.preparedTicket,
      approval.blindSignature,
      request.inverse
    )

    return {
      preparedTicket: request.preparedTicket,
      ticketSignature: ticket_signature
    }
  }
}
