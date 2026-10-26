// Browser shim, injected into the demo bundle with esbuild's --inject.
//
// The bundled crypto wasm loader decodes its base64-embedded wasm with
// `Buffer.from(base64, "base64")`, and `Buffer` only exists in Node. This
// provides just the surface the bundle touches, returning plain Uint8Arrays.
//
// ponytail: covers from/isBuffer/alloc/concat only. If a future dependency
// needs more of the Buffer API, extend this rather than pulling in a polyfill.
export const Buffer = {
  from(input, encoding) {
    if (typeof input !== "string") {
      return input instanceof ArrayBuffer ? new Uint8Array(input) : Uint8Array.from(input)
    }

    if (encoding === "base64") {
      const binary = atob(input)
      const bytes = new Uint8Array(binary.length)
      for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index)
      }
      return bytes
    }

    return new TextEncoder().encode(input)
  },
  isBuffer: (value) => value instanceof Uint8Array,
  alloc: (size) => new Uint8Array(size),
  concat: (list) => {
    const total = list.reduce((sum, item) => sum + item.length, 0)
    const out = new Uint8Array(total)
    let offset = 0
    for (const item of list) {
      out.set(item, offset)
      offset += item.length
    }
    return out
  }
}
