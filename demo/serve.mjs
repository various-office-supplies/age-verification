// Zero-dependency static server for the demo folder, so ES modules load over http.
import { createServer } from "node:http"
import { readFile } from "node:fs/promises"
import { extname, join, normalize } from "node:path"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL(".", import.meta.url))
const port = Number(process.env.PORT ?? 5173)
const content_types = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".wasm": "application/wasm"
}

createServer(async (request, response) => {
  const requested = (request.url ?? "/").split("?")[0]
  const relative = normalize(requested === "/" ? "index.html" : requested).replace(/^(\.\.[/\\])+/, "")
  const file = join(root, relative)

  if (!file.startsWith(root)) {
    response.writeHead(403).end("forbidden")
    return
  }

  try {
    const body = await readFile(file)
    response.writeHead(200, { "content-type": content_types[extname(file)] ?? "application/octet-stream" })
    response.end(body)
  } catch {
    response.writeHead(404).end("not found")
  }
}).listen(port, () => {
  console.log(`Demo running at http://localhost:${port}/  (Ctrl+C to stop)`)
})
