import {
  compute_registry_root,
  create_enrollment_key_pair,
  create_registry_key_pair,
  get_blind_suite,
  hash_bytes_to_hex,
  sign_snapshot,
  to_hex
} from "./crypto.js"
import type {
  AnonymousCredential,
  ApprovedEnrollment,
  GovPublicKeys,
  GovState,
  RegistrySnapshot,
  SignedRegistrySnapshot
} from "./types.js"

export class Gov {
  private readonly state: GovState

  private constructor(state: GovState) {
    this.state = state
  }

  static async create(): Promise<Gov> {
    const registry_keys = await create_registry_key_pair()

    return new Gov({
      commitments: new Set(),
      enrollmentKeys: await create_enrollment_key_pair(),
      redeemedTicketHashes: new Set(),
      registryPrivateKey: registry_keys.private_key,
      registryPublicKey: registry_keys.public_key,
      revokedCommitments: new Set(),
      sequence: 0,
      signedBlindTicketHashes: []
    })
  }

  get_public_keys(): GovPublicKeys {
    return {
      enrollmentPublicKey: this.state.enrollmentKeys.publicKey,
      registryPublicKeyHex: to_hex(this.state.registryPublicKey)
    }
  }

  async sign_blinded_ticket(blinded_ticket: Uint8Array): Promise<ApprovedEnrollment> {
    const suite = get_blind_suite()
    const blind_signature = await suite.blindSign(
      this.state.enrollmentKeys.privateKey,
      blinded_ticket
    )

    this.state.signedBlindTicketHashes.push(
      hash_bytes_to_hex("signed-blinded-ticket", blinded_ticket)
    )

    return { blindSignature: blind_signature }
  }

  async redeem_credential(credential: AnonymousCredential, commitment: string): Promise<boolean> {
    const ticket_hash = hash_bytes_to_hex("redeemed-ticket", credential.preparedTicket)
    const verified = await this.verify_credential(credential)

    if (!verified || this.state.redeemedTicketHashes.has(ticket_hash)) {
      return false
    }

    if (this.state.commitments.has(commitment)) {
      return false
    }

    this.state.redeemedTicketHashes.add(ticket_hash)
    this.state.commitments.add(commitment)
    return true
  }

  nullify_commitment(commitment: string): boolean {
    const removed = this.state.commitments.delete(commitment)

    if (removed) {
      this.state.revokedCommitments.add(commitment)
    }

    return removed
  }

  async publish_registry_snapshot(): Promise<SignedRegistrySnapshot> {
    this.state.sequence += 1

    const snapshot = this.create_snapshot()
    const signature_hex = await sign_snapshot(snapshot, this.state.registryPrivateKey)

    return {
      publicKeyHex: to_hex(this.state.registryPublicKey),
      signatureHex: signature_hex,
      snapshot
    }
  }

  get_blind_enrollment_audit_trail() {
    return {
      redeemedTicketHashes: Array.from(this.state.redeemedTicketHashes),
      signedBlindTicketHashes: [...this.state.signedBlindTicketHashes]
    }
  }

  private create_snapshot(): RegistrySnapshot {
    const commitments = Array.from(this.state.commitments)

    return {
      commitments,
      issuedAt: new Date().toISOString(),
      registryRoot: compute_registry_root(commitments),
      revokedCommitments: Array.from(this.state.revokedCommitments),
      sequence: this.state.sequence
    }
  }

  private async verify_credential(credential: AnonymousCredential): Promise<boolean> {
    const suite = get_blind_suite()
    return suite.verify(
      this.state.enrollmentKeys.publicKey,
      credential.ticketSignature,
      credential.preparedTicket
    )
  }
}
