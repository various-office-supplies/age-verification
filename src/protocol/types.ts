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
  userSecretHex: HexString
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

export type VerificationResult =
  | { accepted: true; nullifierHex: HexString }
  | { accepted: false; reason: string }

export type GovExport = {
  invalidCredentialIds: HexString[]
  secret: string
  sequence: number
}

export type UserState = {
  credential: StoredCredential | null
  credentialRequest: CredentialRequest | null
  revocationWitnessJson: string | null
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
  secret: string
  sequence: number
}
