import { sha512 } from "@noble/hashes/sha2.js"
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8ToBytes
} from "@noble/hashes/utils.js"

import type { HexString } from "./types.js"

const FIELD_SIZE =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n
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
