import { utf8ToBytes } from "@noble/hashes/utils.js"

import {
  add_invalid_credential_id,
  create_gov_key_material,
  create_invalid_id_accumulator,
  create_issued_credential,
  create_revocation_witness
} from "./anonymous-credential.js"
import { random_hex } from "./crypto.js"
import type {
  GovExport,
  GovPublicKeys,
  GovState,
  InvalidIdAccumulator,
  IssuedCredential,
  PublicCredentialRequest
} from "./types.js"

export class Gov {
  private readonly state: GovState

  private constructor(state: GovState) {
    this.state = state
  }

  // Pass your stored secret on every launch to keep the same keys across restarts.
  static async create(secret?: string): Promise<Gov> {
    return new Gov(await Gov.create_state(secret ?? random_hex(32)))
  }

  static async import(data: GovExport): Promise<Gov> {
    return new Gov(await Gov.create_state(data.secret, data))
  }

  export(): GovExport {
    return {
      invalidCredentialIds: Array.from(this.state.invalidCredentialIds),
      secret: this.state.secret,
      sequence: this.state.sequence
    }
  }

  get_public_keys(): GovPublicKeys {
    return {
      credentialPublicKeyHex: this.state.keyMaterial.credentialPublicKey.hex,
      revocationPublicKeyHex: this.state.keyMaterial.revocationPublicKey.hex
    }
  }

  issue_credential(request: PublicCredentialRequest): IssuedCredential {
    return create_issued_credential(request, this.state.keyMaterial)
  }

  async create_revocation_witness(credential_id_hex: string): Promise<string> {
    return create_revocation_witness(credential_id_hex, this.state.keyMaterial)
  }

  async nullify_credential(credential_id_hex: string): Promise<boolean> {
    if (this.state.invalidCredentialIds.has(credential_id_hex)) {
      return false
    }

    await add_invalid_credential_id(credential_id_hex, this.state.keyMaterial)
    this.state.invalidCredentialIds.add(credential_id_hex)
    return true
  }

  publish_invalid_id_accumulator(): InvalidIdAccumulator {
    this.state.sequence += 1
    return create_invalid_id_accumulator(this.state.keyMaterial, this.state.sequence)
  }

  private static async create_state(
    secret: string,
    data?: GovExport
  ): Promise<GovState> {
    const key_material = await create_gov_key_material(utf8ToBytes(secret))
    const invalid_credential_ids = new Set(data?.invalidCredentialIds ?? [])

    for (const credential_id_hex of invalid_credential_ids) {
      await add_invalid_credential_id(credential_id_hex, key_material)
    }

    return {
      invalidCredentialIds: invalid_credential_ids,
      keyMaterial: key_material,
      secret,
      sequence: data?.sequence ?? 0
    }
  }
}
