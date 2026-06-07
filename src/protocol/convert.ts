import { access, readFile, writeFile } from "node:fs/promises"
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync
} from "node:crypto"

import type {
  ConvertibleInvalidIdAccumulator,
  EncryptedPackage,
  GovStatePackage,
  InvalidIdAccumulator,
  UserWalletPackage,
  WebsiteNullifierPackage
} from "./types.js"

type Format = "csv" | "json"
type CsvRecord = Record<string, string | number | null | undefined>

type EncryptedEnvelope = EncryptedPackage

export function accumulator_with_conversions(
  accumulator: InvalidIdAccumulator
): ConvertibleInvalidIdAccumulator {
  return {
    ...accumulator,
    csv: () => accumulator_to_csv(accumulator),
    json: () => JSON.stringify(accumulator, null, 2),
    save: (file_path: string) => save_public(file_path, accumulator, accumulator_to_csv)
  }
}

export function encrypt_package(kind: string, password: string, data: unknown): EncryptedPackage {
  return encrypt_text(kind, "json", password, JSON.stringify(data))
}

export function encrypted_json(kind: string, password: string, data: unknown): string {
  return JSON.stringify(encrypt_package(kind, password, data), null, 2)
}

export function encrypted_csv(kind: string, password: string, data: unknown): string {
  return envelope_to_csv(encrypt_text(kind, "json", password, JSON.stringify(data)))
}

export async function save_encrypted(
  file_path: string,
  kind: string,
  password: string,
  data: unknown
): Promise<void> {
  const text = detect_format(file_path) === "csv"
    ? encrypted_csv(kind, password, data)
    : encrypted_json(kind, password, data)
  await writeFile(file_path, text, "utf8")
}

export async function load_encrypted<T>(
  source: string,
  expected_kind: string,
  password: string
): Promise<T> {
  const { format, text } = await read_source(source)
  const envelope = format === "csv" ? envelope_from_csv(text) : JSON.parse(text)

  if (envelope.kind !== expected_kind) {
    throw new Error(`expected ${expected_kind} data`)
  }

  const plaintext = decrypt_text(envelope, password)
  return envelope.format === "csv"
    ? (unflatten_record(records_from_csv(plaintext)[0]) as T)
    : (JSON.parse(plaintext) as T)
}

export function website_json(data: WebsiteNullifierPackage): string {
  return JSON.stringify(data, null, 2)
}

export function website_csv(data: WebsiteNullifierPackage): string {
  return records_to_csv(
    data.nullifiers.map((nullifierHex) => ({
      nullifierHex,
      siteOrigin: data.siteOrigin
    }))
  )
}

export async function save_website(file_path: string, data: WebsiteNullifierPackage): Promise<void> {
  const text = detect_format(file_path) === "csv" ? website_csv(data) : website_json(data)
  await writeFile(file_path, text, "utf8")
}

export async function load_website(source: string): Promise<WebsiteNullifierPackage> {
  const { format, text } = await read_source(source)
  return format === "csv" ? website_from_csv(text) : JSON.parse(text)
}

export function gov_state_to_package(
  invalidCredentialIds: string[],
  sequence: number,
  accumulator: InvalidIdAccumulator
): GovStatePackage {
  return { accumulator, invalidCredentialIds, sequence }
}

export function user_wallet_to_package(wallet: UserWalletPackage): UserWalletPackage {
  return wallet
}

function encrypt_text(
  kind: string,
  format: Format,
  password: string,
  plaintext: string
): EncryptedEnvelope {
  assert_password(password, `${kind} password is required before saving, loading, or converting encrypted data`)

  const salt = randomBytes(16)
  const iv = randomBytes(12)
  const key = scryptSync(password, salt, 32)
  const cipher = createCipheriv("aes-256-gcm", key, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()])

  return {
    algorithm: "aes-256-gcm",
    ciphertextHex: ciphertext.toString("hex"),
    format,
    ivHex: iv.toString("hex"),
    kind,
    saltHex: salt.toString("hex"),
    tagHex: cipher.getAuthTag().toString("hex"),
    version: 1
  }
}

function decrypt_text(envelope: EncryptedEnvelope, password: string): string {
  assert_password(password, `${envelope.kind} password is required before saving, loading, or converting encrypted data`)

  const key = scryptSync(password, Buffer.from(envelope.saltHex, "hex"), 32)
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.ivHex, "hex"))
  decipher.setAuthTag(Buffer.from(envelope.tagHex, "hex"))

  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertextHex, "hex")),
    decipher.final()
  ]).toString("utf8")
}

async function save_public<T>(
  file_path: string,
  data: T,
  csv_converter: (data: T) => string
): Promise<void> {
  const text = detect_format(file_path) === "csv"
    ? csv_converter(data)
    : JSON.stringify(data, null, 2)
  await writeFile(file_path, text, "utf8")
}

async function read_source(source: string): Promise<{ format: Format; text: string }> {
  if (await file_exists(source)) {
    return {
      format: detect_format(source),
      text: await readFile(source, "utf8")
    }
  }

  return {
    format: detect_data_format(source),
    text: source
  }
}

async function file_exists(file_path: string): Promise<boolean> {
  try {
    await access(file_path)
    return true
  } catch {
    return false
  }
}

function detect_format(file_path: string): Format {
  return file_path.toLowerCase().endsWith(".csv") ? "csv" : "json"
}

function detect_data_format(text: string): Format {
  return text.trimStart().startsWith("{") ? "json" : "csv"
}

function assert_password(password: string, message: string): void {
  if (!password) {
    throw new Error(message)
  }
}

function accumulator_to_csv(accumulator: InvalidIdAccumulator): string {
  return records_to_csv([accumulator])
}

function website_from_csv(csv: string): WebsiteNullifierPackage {
  const records = records_from_csv(csv)
  return {
    nullifiers: records.map((record) => record.nullifierHex ?? ""),
    siteOrigin: records[0]?.siteOrigin ?? ""
  }
}

function envelope_to_csv(envelope: EncryptedEnvelope): string {
  return records_to_csv([envelope])
}

function envelope_from_csv(csv: string): EncryptedEnvelope {
  return records_from_csv(csv)[0] as unknown as EncryptedEnvelope
}

function records_to_csv(records: CsvRecord[]): string {
  if (records.length === 0) {
    return ""
  }

  const headers = Object.keys(records[0])
  const rows = records.map((record) => headers.map((header) => csv_escape(record[header])))
  return [headers.join(","), ...rows.map((row) => row.join(","))].join("\n")
}

function records_from_csv(csv: string): Record<string, string>[] {
  const lines = csv.trim().split(/\r?\n/).filter(Boolean)

  if (lines.length === 0) {
    return []
  }

  const headers = parse_csv_line(lines[0])
  return lines.slice(1).map((line) => {
    const values = parse_csv_line(line)
    return Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ""]))
  })
}

function csv_escape(value: string | number | null | undefined): string {
  const text = value === null || value === undefined ? "" : String(value)
  return /[",\n\r]/.test(text) ? `"${text.replaceAll("\"", "\"\"")}"` : text
}

function parse_csv_line(line: string): string[] {
  const values: string[] = []
  let currentValue = ""
  let inQuotes = false

  for (let index = 0; index < line.length; index += 1) {
    const character = line[index]
    const nextCharacter = line[index + 1]

    if (character === "\"" && inQuotes && nextCharacter === "\"") {
      currentValue += "\""
      index += 1
    } else if (character === "\"") {
      inQuotes = !inQuotes
    } else if (character === "," && !inQuotes) {
      values.push(currentValue)
      currentValue = ""
    } else {
      currentValue += character
    }
  }

  values.push(currentValue)
  return values
}

function flatten_record(value: unknown, prefix = ""): CsvRecord {
  if (!is_record(value)) {
    return { value: String(value ?? "") }
  }

  return Object.entries(value).reduce<CsvRecord>((flat, [key, entry]) => {
    const fullKey = prefix ? `${prefix}.${key}` : key

    if (is_record(entry)) {
      return { ...flat, ...flatten_record(entry, fullKey) }
    }

    flat[fullKey] = entry === null || entry === undefined ? "" : String(entry)
    return flat
  }, {})
}

function unflatten_record(record: Record<string, string>): unknown {
  const result: Record<string, unknown> = {}

  for (const [key, value] of Object.entries(record)) {
    assign_nested_value(result, key.split("."), csv_value_to_json_value(value))
  }

  return result
}

function assign_nested_value(target: Record<string, unknown>, path: string[], value: unknown): void {
  const [firstKey, ...remainingPath] = path

  if (remainingPath.length === 0) {
    target[firstKey] = value
    return
  }

  const current = target[firstKey]
  const next = is_record(current) ? current : {}
  target[firstKey] = next
  assign_nested_value(next, remainingPath, value)
}

function csv_value_to_json_value(value: string): unknown {
  if (value === "true") {
    return true
  }

  if (value === "false") {
    return false
  }

  if (/^\d+$/.test(value)) {
    return Number(value)
  }

  return value === "" ? null : value
}

function is_record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}
