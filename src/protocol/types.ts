import type { Identity } from "@semaphore-protocol/identity"

export type HexString = string

export type SemaphoreProof = {
  merkleTreeDepth: number
  merkleTreeRoot: string
  message: string
  nullifier: string
  points: unknown
  scope: string
}

export type GovPublicKeys = {
  enrollmentPublicKey: CryptoKey
  registryPublicKeyHex: HexString
}

export type AnonymousCredential = {
  preparedTicket: Uint8Array
  ticketSignature: Uint8Array
}

export type RegistrySnapshot = {
  commitments: string[]
  issuedAt: string
  registryRoot: string
  revokedCommitments: string[]
  sequence: number
}

export type SignedRegistrySnapshot = {
  publicKeyHex: HexString
  signatureHex: HexString
  snapshot: RegistrySnapshot
}

export type WebsiteChallenge = {
  challengeId: string
  message: bigint
  scope: bigint
  siteOrigin: string
}

export type WebsiteProof = {
  proof: SemaphoreProof
  siteOrigin: string
}

export type VerificationResult = {
  accepted: boolean
  reason: string
}

export type EnrollmentRequest = {
  blindedTicket: Uint8Array
  inverse: Uint8Array
  preparedTicket: Uint8Array
}

export type ApprovedEnrollment = {
  blindSignature: Uint8Array
}

export type UserWallet = {
  identity: Identity
  passwordSaltHex: HexString
  commitment: bigint
}

export type GovState = {
  commitments: Set<string>
  enrollmentKeys: CryptoKeyPair
  redeemedTicketHashes: Set<string>
  registryPrivateKey: Uint8Array
  registryPublicKey: Uint8Array
  revokedCommitments: Set<string>
  sequence: number
  signedBlindTicketHashes: string[]
}
