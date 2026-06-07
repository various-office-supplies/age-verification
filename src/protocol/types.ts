import type {
  AccumulatorParams,
  AccumulatorPublicKey,
  AccumulatorSecretKey,
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BBSPlusSignatureParamsG1,
  UniversalAccumulator
} from "@docknetwork/crypto-wasm-ts"

import type { InMemoryAccumulatorState } from "./anonymous-credential.js"

export type HexString = string

export type GovPublicKeys = {
  credentialPublicKeyHex: HexString
  revocationPublicKeyHex: HexString
}

export type PublicCredentialRequest = {
  blindedIndices: number[]
  commitmentHex: HexString
}

export type CredentialRequest = PublicCredentialRequest & {
  blindingHex: HexString
}

export type EncryptedPackage = {
  algorithm: "aes-256-gcm"
  ciphertextHex: HexString
  format: "csv" | "json"
  ivHex: HexString
  kind: string
  saltHex: HexString
  tagHex: HexString
  version: 1
}

export type IssuedCredential = {
  blindSignatureHex: HexString
  credentialIdHex: HexString
}

export type StoredCredential = {
  credentialIdHex: HexString
  signatureHex: HexString
  userSecretHex: HexString
}

export type WebsiteChallenge = {
  challengeId: string
  siteOrigin: string
}

export type WebsiteProof = {
  nullifierHex: HexString
  proofHex: HexString
  siteOrigin: string
}

export type InvalidIdAccumulator = {
  accumulatedHex: HexString
  issuedAt: string
  publicKeyHex: HexString
  sequence: number
}

export type ConvertibleInvalidIdAccumulator = InvalidIdAccumulator & {
  csv(): string
  json(): string
  save(file_path: string): Promise<void>
}

export type VerificationResult = {
  accepted: boolean
  reason: string
}

export type GovStatePackage = {
  accumulator: InvalidIdAccumulator
  invalidCredentialIds: HexString[]
  sequence: number
}

export type UserWalletPackage = {
  credential: StoredCredential | null
  credentialRequest: CredentialRequest | null
  revocationWitnessJson: string | null
}

export type WebsiteNullifierPackage = {
  nullifiers: HexString[]
  siteOrigin: string
}

export type GovKeyMaterial = {
  credentialParams: BBSPlusSignatureParamsG1
  credentialPublicKey: BBSPlusPublicKeyG2
  credentialSecretKey: BBSPlusSecretKey
  revocationAccumulator: UniversalAccumulator
  revocationParams: AccumulatorParams
  revocationPublicKey: AccumulatorPublicKey
  revocationSecretKey: AccumulatorSecretKey
  revocationState: InMemoryAccumulatorState
}

export type GovState = {
  invalidCredentialIds: Set<string>
  keyMaterial: GovKeyMaterial
  sequence: number
}

export type UserWallet = {
  credential: StoredCredential | null
  credentialRequest: CredentialRequest | null
  password: string
  revocationWitnessJson: string | null
}
