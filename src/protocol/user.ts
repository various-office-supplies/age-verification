import {
  complete_credential,
  create_credential_request,
  create_website_proof
} from "./anonymous-credential.js"
import type {
  CredentialRequest,
  InvalidIdAccumulator,
  IssuedCredential,
  PublicCredentialRequest,
  UserState,
  WebsiteChallenge,
  WebsiteProof
} from "./types.js"

export class User {
  private readonly state: UserState

  private constructor(state: UserState) {
    this.state = state
  }

  static create(): User {
    return new User({
      credential: null,
      credentialRequest: null,
      revocationWitnessJson: null
    })
  }

  static import(data: UserState): User {
    return new User({ ...data })
  }

  export(): UserState {
    return { ...this.state }
  }

  begin_enrollment(): PublicCredentialRequest {
    this.state.credentialRequest = create_credential_request()
    return to_public_credential_request(this.state.credentialRequest)
  }

  complete_enrollment(issued_credential: IssuedCredential): void {
    if (!this.state.credentialRequest) {
      throw new Error("call begin_enrollment before complete_enrollment")
    }

    this.state.credential = complete_credential(this.state.credentialRequest, issued_credential)
    this.state.credentialRequest = null
  }

  set_revocation_witness(revocation_witness_json: string): void {
    this.state.revocationWitnessJson = revocation_witness_json
  }

  get_credential_id(): string {
    if (!this.state.credential) {
      throw new Error("complete enrollment before reading credential id")
    }

    return this.state.credential.credentialIdHex
  }

  create_proof(
    accumulator: InvalidIdAccumulator,
    challenge: WebsiteChallenge
  ): WebsiteProof {
    if (!this.state.credential || !this.state.revocationWitnessJson) {
      throw new Error("complete enrollment and set revocation witness before proving")
    }

    return create_website_proof(
      this.state.credential,
      challenge,
      accumulator,
      this.state.revocationWitnessJson
    )
  }
}

function to_public_credential_request(request: CredentialRequest): PublicCredentialRequest {
  return {
    blindedIndices: request.blindedIndices,
    commitmentHex: request.commitmentHex
  }
}
