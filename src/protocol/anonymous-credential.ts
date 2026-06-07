import {
  Accumulator,
  AccumulatorParams,
  AccumulatorPublicKey,
  AccumulatorSecretKey,
  BBSPlusBlindSignatureG1,
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BBSPlusSignatureG1,
  BBSPlusSignatureParamsG1,
  CompositeProof,
  initializeWasm,
  isWasmInitialized,
  MetaStatements,
  NonMembershipProvingKey,
  ProofSpec,
  Pseudonym,
  PseudonymBases,
  Statement,
  Statements,
  UniversalAccumulator,
  VBNonMembershipWitness,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from "@docknetwork/crypto-wasm-ts"
import { utf8ToBytes } from "@noble/hashes/utils.js"

import { domain_hash, from_hex, random_hex, to_hex } from "./crypto.js"
import type {
  CredentialRequest,
  GovKeyMaterial,
  InvalidIdAccumulator,
  IssuedCredential,
  PublicCredentialRequest,
  StoredCredential,
  WebsiteChallenge,
  WebsiteProof
} from "./types.js"

const CREDENTIAL_MESSAGE_COUNT = 2
const USER_SECRET_INDEX = 0
const CREDENTIAL_ID_INDEX = 1
const INVALID_ID_ACCUMULATOR_MAX_SIZE = 128

export class InMemoryAccumulatorState {
  private readonly members = new Map<string, Uint8Array>()

  async add(element: Uint8Array): Promise<void> {
    this.members.set(to_hex(element), element)
  }

  async remove(element: Uint8Array): Promise<void> {
    this.members.delete(to_hex(element))
  }

  async has(element: Uint8Array): Promise<boolean> {
    return this.members.has(to_hex(element))
  }

  async elements(): Promise<Iterable<Uint8Array>> {
    return this.members.values()
  }
}

export async function create_gov_key_material(password: string): Promise<GovKeyMaterial> {
  await ensure_anonymous_crypto_ready()

  const credential_params = get_credential_params()
  const revocation_params = get_revocation_params()
  const credential_secret_key = BBSPlusSecretKey.generate(seed("gov-credential-key", password))
  const revocation_secret_key = AccumulatorSecretKey.generate(seed("gov-revocation-key", password))
  const revocation_state = new InMemoryAccumulatorState()

  return {
    credentialParams: credential_params,
    credentialPublicKey: credential_secret_key.generatePublicKeyG2(credential_params),
    credentialSecretKey: credential_secret_key,
    revocationAccumulator: await UniversalAccumulator.initialize(
      INVALID_ID_ACCUMULATOR_MAX_SIZE,
      revocation_params,
      revocation_secret_key
    ),
    revocationParams: revocation_params,
    revocationPublicKey: revocation_secret_key.generatePublicKey(revocation_params),
    revocationSecretKey: revocation_secret_key,
    revocationState: revocation_state
  }
}

export async function create_credential_request(password: string): Promise<CredentialRequest> {
  await ensure_anonymous_crypto_ready()

  const hidden_messages = new Map([[USER_SECRET_INDEX, create_user_secret(password)]])
  const [blinding, request] = BBSPlusBlindSignatureG1.generateRequest(
    hidden_messages,
    get_credential_params(),
    false
  )

  return {
    blindedIndices: request.blindedIndices,
    blindingHex: to_hex(blinding),
    commitmentHex: to_hex(request.commitment)
  }
}

export function create_issued_credential(
  request: PublicCredentialRequest,
  key_material: GovKeyMaterial
): IssuedCredential {
  const credential_id_hex = random_hex()
  const credential_id = encode_credential_id(credential_id_hex)
  const revealed_messages = new Map([[CREDENTIAL_ID_INDEX, credential_id]])
  const blind_signature = BBSPlusBlindSignatureG1.generate(
    from_hex(request.commitmentHex),
    revealed_messages,
    key_material.credentialSecretKey,
    key_material.credentialParams,
    false
  )

  return {
    blindSignatureHex: blind_signature.hex,
    credentialIdHex: credential_id_hex
  }
}

export function complete_credential(
  password: string,
  request: CredentialRequest,
  issued: IssuedCredential
): StoredCredential {
  const blind_signature = new BBSPlusBlindSignatureG1(from_hex(issued.blindSignatureHex))
  const signature = blind_signature.unblind(from_hex(request.blindingHex))

  return {
    credentialIdHex: issued.credentialIdHex,
    signatureHex: signature.hex,
    userSecretHex: to_hex(create_user_secret(password))
  }
}

export async function add_invalid_credential_id(
  credential_id_hex: string,
  key_material: GovKeyMaterial
): Promise<void> {
  await key_material.revocationAccumulator.add(
    encode_credential_id(credential_id_hex),
    key_material.revocationSecretKey,
    key_material.revocationState
  )
}

export async function create_revocation_witness(
  credential_id_hex: string,
  key_material: GovKeyMaterial
): Promise<string> {
  const witness = await key_material.revocationAccumulator.nonMembershipWitness(
    encode_credential_id(credential_id_hex),
    key_material.revocationState,
    key_material.revocationSecretKey,
    key_material.revocationParams
  )

  return witness.toJSON()
}

export function create_invalid_id_accumulator(
  key_material: GovKeyMaterial,
  sequence: number
): InvalidIdAccumulator {
  return {
    accumulatedHex: to_hex(get_accumulated_bytes(key_material.revocationAccumulator)),
    issuedAt: new Date().toISOString(),
    publicKeyHex: key_material.revocationPublicKey.hex,
    sequence
  }
}

export function create_website_proof(
  credential: StoredCredential,
  challenge: WebsiteChallenge,
  accumulator: InvalidIdAccumulator,
  revocation_witness_json: string
): WebsiteProof {
  const nullifier = create_site_nullifier(challenge.siteOrigin, credential.userSecretHex)
  const nonce = create_proof_nonce(challenge)
  const proof = CompositeProof.generate(
    create_prover_spec(credential, challenge, accumulator),
    create_witnesses(credential, revocation_witness_json),
    nonce
  )

  return {
    nullifierHex: nullifier.hex,
    proofHex: proof.hex,
    siteOrigin: challenge.siteOrigin
  }
}

export function verify_website_proof(
  proof: WebsiteProof,
  challenge: WebsiteChallenge,
  accumulator: InvalidIdAccumulator,
  gov_public_key_hex: string
): boolean {
  const proof_object = new CompositeProof(from_hex(proof.proofHex))
  const result = proof_object.verify(
    create_verifier_spec(proof, challenge, accumulator, gov_public_key_hex),
    create_proof_nonce(challenge)
  )

  return result.verified
}

export function get_credential_public_key_hex(key_material: GovKeyMaterial): string {
  return key_material.credentialPublicKey.hex
}

export function get_revocation_public_key_hex(key_material: GovKeyMaterial): string {
  return key_material.revocationPublicKey.hex
}

function create_witnesses(
  credential: StoredCredential,
  revocation_witness_json: string
): Witnesses {
  const messages = create_credential_messages(credential)
  const witnesses = new Witnesses()

  witnesses.add(
    Witness.bbsPlusSignatureConstantTime(
      new BBSPlusSignatureG1(from_hex(credential.signatureHex)),
      messages,
      false
    )
  )
  witnesses.add(Witness.pseudonym(from_hex(credential.userSecretHex)))
  witnesses.add(
    Witness.vbAccumulatorNonMembership(
      encode_credential_id(credential.credentialIdHex),
      VBNonMembershipWitness.fromJSON(revocation_witness_json)
    )
  )

  return witnesses
}

function create_prover_spec(
  credential: StoredCredential,
  challenge: WebsiteChallenge,
  accumulator: InvalidIdAccumulator
): ProofSpec {
  return create_proof_spec(
    challenge,
    accumulator,
    Statement.bbsPlusSignatureProverConstantTime(get_credential_params(), new Map(), false),
    create_site_nullifier(challenge.siteOrigin, credential.userSecretHex)
  )
}

function create_verifier_spec(
  proof: WebsiteProof,
  challenge: WebsiteChallenge,
  accumulator: InvalidIdAccumulator,
  gov_public_key_hex: string
): ProofSpec {
  return create_proof_spec(
    challenge,
    accumulator,
    Statement.bbsPlusSignatureVerifierConstantTime(
      get_credential_params(),
      new BBSPlusPublicKeyG2(from_hex(gov_public_key_hex)),
      new Map(),
      false
    ),
    proof.nullifierHex
  )
}

function create_proof_spec(
  challenge: WebsiteChallenge,
  accumulator: InvalidIdAccumulator,
  signature_statement: Uint8Array,
  nullifier: Pseudonym | string
): ProofSpec {
  const statements = new Statements()
  const proof_context = create_proof_context(challenge.siteOrigin)

  statements.add(signature_statement)
  statements.add(create_pseudonym_statement(proof_context, nullifier))
  statements.add(create_accumulator_statement(accumulator))

  return new ProofSpec(statements, create_meta_statements(), [], proof_context.context)
}

function create_meta_statements(): MetaStatements {
  const meta_statements = new MetaStatements()
  const secret_equality = new WitnessEqualityMetaStatement()
  const credential_id_equality = new WitnessEqualityMetaStatement()

  secret_equality.addWitnessRef(0, USER_SECRET_INDEX)
  secret_equality.addWitnessRef(1, 0)
  credential_id_equality.addWitnessRef(0, CREDENTIAL_ID_INDEX)
  credential_id_equality.addWitnessRef(2, 0)
  meta_statements.addWitnessEquality(secret_equality)
  meta_statements.addWitnessEquality(credential_id_equality)

  return meta_statements
}

function create_pseudonym_statement(
  proof_context: ProofContext,
  nullifier: Pseudonym | string
): Uint8Array {
  if (typeof nullifier === "string") {
    return Statement.pseudonymVerifier(from_hex(nullifier), proof_context.base)
  }

  return Statement.pseudonym(nullifier, proof_context.base)
}

function create_accumulator_statement(accumulator: InvalidIdAccumulator): Uint8Array {
  return Statement.vbAccumulatorNonMembership(
    get_revocation_params(),
    new AccumulatorPublicKey(from_hex(accumulator.publicKeyHex)),
    get_non_membership_proving_key(),
    from_hex(accumulator.accumulatedHex)
  )
}

function create_credential_messages(credential: StoredCredential): Map<number, Uint8Array> {
  return new Map([
    [USER_SECRET_INDEX, from_hex(credential.userSecretHex)],
    [CREDENTIAL_ID_INDEX, encode_credential_id(credential.credentialIdHex)]
  ])
}

function create_user_secret(password: string): Uint8Array {
  return BBSPlusSignatureG1.encodeMessageForSigningConstantTime(
    domain_hash("user-credential-secret", utf8ToBytes(password))
  )
}

function encode_credential_id(credential_id_hex: string): Uint8Array {
  return Accumulator.encodeBytesAsAccumulatorMember(from_hex(credential_id_hex))
}

function create_proof_context(site_origin: string): ProofContext {
  const context = utf8ToBytes(`age-id:website-proof:${site_origin}`)
  const base = PseudonymBases.generateBaseForSecretKey(context)

  return { base, context }
}

function create_site_nullifier(site_origin: string, user_secret_hex: string): Pseudonym {
  return Pseudonym.new(create_proof_context(site_origin).base, from_hex(user_secret_hex))
}

function create_proof_nonce(challenge: WebsiteChallenge): Uint8Array {
  return domain_hash(
    "website-proof-nonce",
    utf8ToBytes(challenge.siteOrigin),
    utf8ToBytes(challenge.challengeId)
  )
}

function get_credential_params(): BBSPlusSignatureParamsG1 {
  return BBSPlusSignatureParamsG1.generate(
    CREDENTIAL_MESSAGE_COUNT,
    utf8ToBytes("age-id:credential-params:v1")
  )
}

function get_revocation_params(): AccumulatorParams {
  return AccumulatorParams.generate(utf8ToBytes("age-id:revocation-params:v1"))
}

function get_non_membership_proving_key(): NonMembershipProvingKey {
  return NonMembershipProvingKey.generate(utf8ToBytes("age-id:revocation-proof-key:v1"))
}

function get_accumulated_bytes(accumulator: UniversalAccumulator): Uint8Array {
  const accumulated = accumulator.accumulated as unknown

  if (ArrayBuffer.isView(accumulated)) {
    return new Uint8Array(accumulated.buffer, accumulated.byteOffset, accumulated.byteLength)
  }

  if (is_number_array(accumulated)) {
    return Uint8Array.from(accumulated)
  }

  if (is_accumulated_object(accumulated)) {
    return to_byte_array(accumulated.V)
  }

  throw new Error("invalid accumulator value")
}

function to_byte_array(value: ArrayBufferView | number[]): Uint8Array {
  if (is_number_array(value)) {
    return Uint8Array.from(value)
  }

  return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
}

function is_accumulated_object(value: unknown): value is { V: ArrayBufferView | number[] } {
  return typeof value === "object" && value !== null && "V" in value
}

function is_number_array(value: unknown): value is number[] {
  return Array.isArray(value) && value.every((item) => typeof item === "number")
}

function seed(domain: string, password: string): Uint8Array {
  return domain_hash(domain, utf8ToBytes(password)).slice(0, 32)
}

async function ensure_anonymous_crypto_ready(): Promise<void> {
  if (!isWasmInitialized()) {
    await initializeWasm()
  }
}

type ProofContext = {
  base: Uint8Array
  context: Uint8Array
}
