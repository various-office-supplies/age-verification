import {
  add_invalid_credential_id,
  create_gov_key_material,
  create_invalid_id_accumulator,
  create_issued_credential,
  create_revocation_witness,
  get_credential_public_key_hex,
  get_revocation_public_key_hex
} from "./anonymous-credential.js"
import {
  accumulator_with_conversions,
  encrypt_package,
  encrypted_csv,
  encrypted_json,
  gov_state_to_package,
  load_encrypted,
  save_encrypted
} from "./convert.js"
import type {
  ConvertibleInvalidIdAccumulator,
  EncryptedPackage,
  GovPublicKeys,
  GovStatePackage,
  GovState,
  IssuedCredential,
  PublicCredentialRequest
} from "./types.js"

export class Gov {
  private state: GovState
  private readonly password: string

  private constructor(state: GovState, password: string) {
    this.state = state
    this.password = password
  }

  static async create(password: string): Promise<Gov> {
    return new Gov(await Gov.create_state(password), password)
  }

  csv(): string {
    return encrypted_csv("gov-state", this.password, this.unencrypted_state_package())
  }

  json(): string {
    return encrypted_json("gov-state", this.password, this.unencrypted_state_package())
  }

  async load(source: string): Promise<void> {
    const state_package = await load_encrypted<GovStatePackage>(
      source,
      "gov-state",
      this.password
    )
    this.state = await Gov.create_state(this.password, state_package)
  }

  async save(file_path: string): Promise<void> {
    await save_encrypted(
      file_path,
      "gov-state",
      this.password,
      this.unencrypted_state_package()
    )
  }

  state_package(): EncryptedPackage {
    return encrypt_package("gov-state", this.password, this.unencrypted_state_package())
  }

  unencrypted_state_package(): GovStatePackage {
    return gov_state_to_package(
      Array.from(this.state.invalidCredentialIds),
      this.state.sequence,
      create_invalid_id_accumulator(this.state.keyMaterial, this.state.sequence)
    )
  }

  get_public_keys(): GovPublicKeys {
    return {
      credentialPublicKeyHex: get_credential_public_key_hex(this.state.keyMaterial),
      revocationPublicKeyHex: get_revocation_public_key_hex(this.state.keyMaterial)
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

  publish_invalid_id_accumulator(): ConvertibleInvalidIdAccumulator {
    this.state.sequence += 1
    return accumulator_with_conversions(
      create_invalid_id_accumulator(this.state.keyMaterial, this.state.sequence)
    )
  }

  private static async create_state(
    password: string,
    state_package?: GovStatePackage
  ): Promise<GovState> {
    const key_material = await create_gov_key_material(password)
    const invalid_credential_ids = new Set(state_package?.invalidCredentialIds ?? [])

    for (const credential_id_hex of invalid_credential_ids) {
      await add_invalid_credential_id(credential_id_hex, key_material)
    }

    return {
      invalidCredentialIds: invalid_credential_ids,
      keyMaterial: key_material,
      sequence: state_package?.sequence ?? 0
    }
  }
}
