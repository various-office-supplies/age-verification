import { RSABSSA } from "@cloudflare/blindrsa-ts"
import { Group } from "@semaphore-protocol/group"
import * as ed25519 from "@noble/ed25519"
import { sha512 } from "@noble/hashes/sha2.js"
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8ToBytes
} from "@noble/hashes/utils.js"

import type { HexString, SignedRegistrySnapshot } from "./types.js"

const FIELD_SIZE =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n
const RSA_PUBLIC_EXPONENT = Uint8Array.from([1, 0, 1])
const RSA_MODULUS_BITS = 4096

export function random_hex(byte_length = 32): HexString {
  return bytesToHex(randomBytes(byte_length))
}

export function to_hex(bytes: Uint8Array): HexString {
  return bytesToHex(bytes)
}

export function from_hex(hex: HexString): Uint8Array {
  return hexToBytes(hex)
}

export function domain_hash(domain: string, ...parts: Uint8Array[]): Uint8Array {
  const label = utf8ToBytes(`age-id:${domain}:`)
  return sha512(concatBytes(label, ...parts))
}

export function hash_text_to_field(domain: string, value: string): bigint {
  return bytes_to_field(domain_hash(domain, utf8ToBytes(value)))
}

export function hash_bytes_to_hex(domain: string, bytes: Uint8Array): HexString {
  return bytesToHex(domain_hash(domain, bytes))
}

export async function create_enrollment_key_pair(): Promise<CryptoKeyPair> {
  return get_blind_suite().generateKey({
    modulusLength: RSA_MODULUS_BITS,
    publicExponent: RSA_PUBLIC_EXPONENT
  })
}

export async function create_registry_key_pair() {
  const private_key = ed25519.utils.randomSecretKey()
  const public_key = await ed25519.getPublicKeyAsync(private_key)
  return { private_key, public_key }
}

export async function sign_snapshot(snapshot: object, private_key: Uint8Array) {
  const message = encode_json(snapshot)
  return bytesToHex(await ed25519.signAsync(message, private_key))
}

export async function verify_registry_snapshot(
  signed_snapshot: SignedRegistrySnapshot,
  trusted_registry_public_key_hex: HexString
) {
  if (signed_snapshot.publicKeyHex !== trusted_registry_public_key_hex) {
    return false
  }

  const signature = hexToBytes(signed_snapshot.signatureHex)
  const public_key = hexToBytes(trusted_registry_public_key_hex)
  const signature_ok = await ed25519.verifyAsync(
    signature,
    encode_json(signed_snapshot.snapshot),
    public_key
  )
  const root_ok =
    compute_registry_root(signed_snapshot.snapshot.commitments) ===
    signed_snapshot.snapshot.registryRoot
  return signature_ok && root_ok
}

export function compute_registry_root(commitments: string[]): string {
  return new Group(commitments.map(BigInt)).root.toString()
}

export function get_blind_suite() {
  return RSABSSA.SHA384.PSS.Randomized()
}

export function encode_json(value: unknown): Uint8Array {
  return utf8ToBytes(stable_stringify(value))
}

export function short_hex(hex: HexString, visible = 12): string {
  return `${hex.slice(0, visible)}...`
}

function bytes_to_field(bytes: Uint8Array): bigint {
  return bytes_to_bigint(bytes) % FIELD_SIZE
}

function bytes_to_bigint(bytes: Uint8Array): bigint {
  let value = 0n

  for (const byte of bytes) {
    value = (value << 8n) + BigInt(byte)
  }

  return value
}

function stable_stringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stable_stringify).join(",")}]`
  }

  if (value && typeof value === "object") {
    return stringify_object(value as Record<string, unknown>)
  }

  return JSON.stringify(value)
}

function stringify_object(value: Record<string, unknown>): string {
  const keys = Object.keys(value).sort()
  const entries = keys.map((key) => `${JSON.stringify(key)}:${stable_stringify(value[key])}`)
  return `{${entries.join(",")}}`
}
