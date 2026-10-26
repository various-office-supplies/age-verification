import { sha512 } from "@noble/hashes/sha2.js"
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8ToBytes
} from "@noble/hashes/utils.js"

import type { HexString } from "./types.js"

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
