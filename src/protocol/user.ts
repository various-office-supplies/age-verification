import {
  complete_credential,
  create_credential_request,
  create_website_proof
} from "./anonymous-credential.js"
import {
  encrypt_package,
  encrypted_csv,
  encrypted_json,
  load_encrypted,
  save_encrypted,
  user_wallet_to_package
} from "./convert.js"
import type {
  EncryptedPackage,
  InvalidIdAccumulator,
  IssuedCredential,
  PublicCredentialRequest,
  UserWalletPackage,
  UserWallet,
  WebsiteChallenge,
  WebsiteProof
} from "./types.js"

export class User {
  private readonly wallet: UserWallet

  private constructor(wallet: UserWallet) {
    this.wallet = wallet
  }

  static create(password: string): User {
    return new User({
      credential: null,
      credentialRequest: null,
      password,
      revocationWitnessJson: null
    })
  }

  csv(): string {
    return encrypted_csv("user-wallet", this.wallet.password, this.unencrypted_wallet_package())
  }

  json(): string {
    return encrypted_json("user-wallet", this.wallet.password, this.unencrypted_wallet_package())
  }

  async load(source: string): Promise<void> {
    const wallet_package = await load_encrypted<UserWalletPackage>(
      source,
      "user-wallet",
      this.wallet.password
    )

    this.wallet.credential = wallet_package.credential
    this.wallet.credentialRequest = wallet_package.credentialRequest
    this.wallet.revocationWitnessJson = wallet_package.revocationWitnessJson
  }

  async save(file_path: string): Promise<void> {
    await save_encrypted(
      file_path,
      "user-wallet",
      this.wallet.password,
      this.unencrypted_wallet_package()
    )
  }

  wallet_package(): EncryptedPackage {
    return encrypt_package("user-wallet", this.wallet.password, this.unencrypted_wallet_package())
  }

  unencrypted_wallet_package(): UserWalletPackage {
    return user_wallet_to_package({
      credential: this.wallet.credential,
      credentialRequest: this.wallet.credentialRequest,
      revocationWitnessJson: this.wallet.revocationWitnessJson
    })
  }

  async begin_enrollment(): Promise<PublicCredentialRequest> {
    this.wallet.credentialRequest = await create_credential_request(this.wallet.password)
    return to_public_credential_request(this.wallet.credentialRequest)
  }

  complete_enrollment(issued_credential: IssuedCredential): void {
    if (!this.wallet.credentialRequest) {
      throw new Error("call begin_enrollment before complete_enrollment")
    }

    this.wallet.credential = complete_credential(
      this.wallet.password,
      this.wallet.credentialRequest,
      issued_credential
    )
    this.wallet.credentialRequest = null
  }

  set_revocation_witness(revocation_witness_json: string): void {
    this.wallet.revocationWitnessJson = revocation_witness_json
  }

  get_credential_id(): string {
    if (!this.wallet.credential) {
      throw new Error("complete enrollment before reading credential id")
    }

    return this.wallet.credential.credentialIdHex
  }

  create_proof(
    accumulator: InvalidIdAccumulator,
    challenge: WebsiteChallenge
  ): WebsiteProof {
    if (!this.wallet.credential || !this.wallet.revocationWitnessJson) {
      throw new Error("complete enrollment and set revocation witness before proving")
    }

    return create_website_proof(
      this.wallet.credential,
      challenge,
      accumulator,
      this.wallet.revocationWitnessJson
    )
  }
}

function to_public_credential_request(
  request: NonNullable<UserWallet["credentialRequest"]>
): PublicCredentialRequest {
  return {
    blindedIndices: request.blindedIndices,
    commitmentHex: request.commitmentHex
  }
}
