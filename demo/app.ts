// Presentation layer for the demo: one step at a time, centred, with a floating ID card.
// All cryptography lives in flow.ts; this file only renders and animates.

import { create_demo } from "./flow.js"
import type { VisitResult } from "./flow.js"

const GOV_SECRET = "demo-government-secret"
const FAKESOCIAL = "https://fakesocial.example"
const MORE_SITES = ["https://another-app.example", "https://news-reader.example", "https://forum.example"]
const FRESH_SITE = "https://brand-new.example"

const demo = create_demo(GOV_SECRET)

const stage = el<HTMLElement>("stage")
const status_bar = el<HTMLElement>("status-bar")
const dots_bar = el<HTMLElement>("dots")
const id_card = el<HTMLElement>("id-card")
const back_button = el<HTMLButtonElement>("back")
const next_button = el<HTMLButtonElement>("next")

type Level = "idle" | "ok" | "bad"
const status = {
  gov: { text: "no credentials issued", level: "idle" as Level },
  alice: { text: "no ID", level: "idle" as Level },
  site: { text: "not visited", level: "idle" as Level }
}

let enrolled = false
let revoked = false
let credential_id = ""
let site_results: VisitResult[] = []
let step_index = 0
let ready = false

type Step = {
  heading: string
  body: string
  action?: string
  content: () => string
  run?: () => Promise<void>
  done?: () => boolean
}

const steps: Step[] = [
  {
    heading: "Alice wants in — without giving herself away",
    body: "Websites keep asking for ID. Alice is 31, and she would rather not hand over her licence, her face, or her name to prove it. Three parties are involved.",
    content: () => `
      <div class="roles">
        <div class="role"><h3>Alice</h3><p class="muted small">Holds an ID she wants to keep private.</p></div>
        <div class="role"><h3>Government</h3><p class="muted small">Verifies her for real, then vouches anonymously.</p></div>
        <div class="role"><h3>Websites</h3><p class="muted small">Want proof of age, not an identity.</p></div>
      </div>`
  },
  {
    heading: "Alice verifies with the Government",
    body: "The Government checks her ID and face for real. Then it hands her a credential that proves she is an adult without carrying her identity.",
    action: "Send her ID to the Government",
    content: gov_content,
    run: run_gov,
    done: () => enrolled
  },
  {
    heading: "Alice visits FakeSocial",
    body: "FakeSocial asks her to prove she is over 18. She does — and the site learns only what it asked for.",
    action: "Prove her age at FakeSocial",
    content: site_content,
    run: run_site,
    done: () => site_results.some((result) => result.origin === FAKESOCIAL && result.status === "verified")
  },
  {
    heading: "A second account is refused",
    body: "Someone tries to reuse that credential — or a stranger uses Alice's stolen ID. FakeSocial recognises the same per-site ID and turns it away.",
    action: "Try to sign up again",
    content: impersonate_content,
    run: run_impersonate,
    done: () => site_results.some((result) => result.status === "duplicate")
  },
  {
    heading: "Every website gets its own ID",
    body: "Alice visits more sites. Each one gets a different pseudonym. The sites cannot compare them — and neither can the Government.",
    action: "Visit more sites",
    content: sites_content,
    run: run_more_sites,
    done: () => MORE_SITES.every((origin) => site_results.some((result) => result.origin === origin))
  },
  {
    heading: "The Government can revoke",
    body: "If a credential stops being valid, the Government revokes it. Every site refuses it afterwards — without any of them contacting the Government.",
    action: "Revoke Alice's credential",
    content: revoke_content,
    run: run_revoke,
    done: () => revoked
  }
]

// ---------- step content (state-aware, so Back/Next stay correct) ----------

function gov_content(): string {
  return `${exchange("Alice", "Government")}<div class="reveal">${enrolled ? gov_buckets() : ""}</div>`
}

function gov_buckets(): string {
  return buckets([
    ["Alice keeps private", ["Her secret", "Her credential"], "alice"],
    ["Shared, in the open", ["Blinded request", "Blind signature", "Government public key"], "shared"],
    ["Government keeps private", ["Its signing key"], "other"]
  ]) + `<p class="caption">The Government signed Alice's credential without ever seeing the secret that ties it to her. Alice never saw the Government's key.</p>`
}

function site_content(): string {
  const result = site_results.find((item) => item.origin === FAKESOCIAL && item.status === "verified")
  return `${exchange("Alice", "FakeSocial")}<div class="reveal">${result ? site_inspector(result) : ""}</div>
    ${result ? site_buckets() : ""}`
}

function site_inspector(result: VisitResult): string {
  return `
    <div class="inspector">
      <h4>What FakeSocial now has</h4>
      <dl>
        <dt>Age</dt><dd class="ok">Verified adult ✓</dd>
        <dt>Name, birth date, photo</dt><dd class="muted">never shared</dd>
        <dt>Alice's ID for this site</dt><dd class="mono">${shorten(result.pseudonymHex)}</dd>
      </dl>
    </div>
    <p class="caption">FakeSocial cannot tell who Alice is. It only knows that a unique verified adult signed up, and how to recognise her next time.</p>`
}

function site_buckets(): string {
  return buckets([
    ["Alice keeps private", ["Her credential", "Her secret", "Her IDs on other sites"], "alice"],
    ["Shared, in the open", ["The challenge", "The zero-knowledge proof"], "shared"],
    ["FakeSocial keeps private", ["Its list of seen IDs"], "other"]
  ])
}

function impersonate_content(): string {
  const duplicate = site_results.some((result) => result.status === "duplicate")
  return `${exchange("Alice", "FakeSocial")}
    <div class="reveal">${duplicate
      ? `<div class="notice bad">FakeSocial already holds this per-site ID. It refuses the second account: this ID was already used.</div>`
      : ""}</div>`
}

function sites_content(): string {
  return `<p class="caption">Each site receives a different pseudonym. Sites cannot compare them to find the same person — and the Government cannot work backwards from them to Alice.</p>
    <div class="reveal">${sites_table()}</div>`
}

function revoke_content(): string {
  const fresh = site_results.some((result) => result.origin === FRESH_SITE)
  return `${exchange("Government", "Alice")}
    <div class="reveal">${fresh
      ? `<div class="notice bad">A brand-new site refuses her credential — without ever asking the Government.</div>`
      : ""}</div>
    ${sites_table()}`
}

// ---------- step runs ----------

async function run_gov(): Promise<void> {
  await send_chip("Name · birth date · photo", "ltr")
  set_status("alice", "ID verified", "ok")
  await send_chip("Verified adult ✓", "rtl")

  await send_chip("Blinded request", "ltr")
  credential_id = await demo.enroll()
  enrolled = true
  await send_chip("Blind signature", "rtl")
  set_status("gov", "issued 1 credential", "ok")
  render_id_card()
}

async function run_site(): Promise<void> {
  await send_chip("Challenge", "rtl")
  await send_chip("Zero-knowledge proof", "ltr")
  site_results.push(demo.visit(FAKESOCIAL))
  set_status("site", "1 account", "ok")
}

async function run_impersonate(): Promise<void> {
  await send_chip("Zero-knowledge proof", "ltr")
  site_results.push(demo.visit(FAKESOCIAL))
  set_status("site", "refused a duplicate", "bad")
}

async function run_more_sites(): Promise<void> {
  for (const origin of MORE_SITES) {
    site_results.push(demo.visit(origin))
  }
  set_status("site", `${site_results.filter((r) => r.status === "verified").length} accounts`, "ok")
}

async function run_revoke(): Promise<void> {
  await demo.revoke()
  revoked = true
  await send_chip("Invalid-ID list", "ltr")
  set_status("gov", "revoked 1 credential", "bad")
  set_status("alice", "credential revoked", "bad")
  site_results.push(demo.visit(FRESH_SITE))
  set_status("site", "refused a revoked ID", "bad")
}

// ---------- rendering ----------

function render_stage(): void {
  const step = steps[step_index]
  stage.innerHTML = `<h2>${step.heading}</h2><p class="body">${step.body}</p>${step.content()}`
}

function render_status(): void {
  status_bar.innerHTML = ""
  const parties: [string, { text: string; level: Level }][] = [
    ["Government", status.gov],
    ["Alice", status.alice],
    ["Website", status.site]
  ]
  for (const [name, state] of parties) {
    const pill = document.createElement("span")
    pill.className = "pill"
    const dot = document.createElement("span")
    dot.className = `dot ${state.level === "idle" ? "" : state.level}`
    pill.append(dot, document.createTextNode(`${name} · ${state.text}`))
    status_bar.append(pill)
  }
}

function render_id_card(): void {
  if (!enrolled) return
  id_card.className = "id-card"
  id_card.innerHTML = `
    <span class="id-badge">Verified adult ✓</span>
    <p class="label">Issued by</p>
    <p>The Government</p>
    <p class="label">Credential</p>
    <p class="mono">${shorten(credential_id)}</p>
    <p class="label">Contains</p>
    <p class="muted small">No name · no birth date · no photo</p>`
}

function render_dots(): void {
  dots_bar.innerHTML = ""
  for (let index = 0; index < steps.length; index += 1) {
    const dot = document.createElement("i")
    if (index <= step_index) dot.className = "on"
    dots_bar.append(dot)
  }
}

function render_controls(): void {
  const step = steps[step_index]
  back_button.disabled = step_index === 0
  if (ready) {
    next_button.textContent = step_index === steps.length - 1 ? "Start over" : "Next"
  } else {
    next_button.textContent = step.action ?? "Next"
  }
  next_button.disabled = false
}

function enter_step(): void {
  const step = steps[step_index]
  ready = step.done ? step.done() : true
  render_stage()
  render_controls()
  render_dots()
}

// ---------- exchange helpers ----------

function exchange(left: string, right: string): string {
  return `
    <div class="exchange">
      <div class="sides">
        <article class="side"><h3>${left}</h3><ul class="inventory"></ul></article>
        <article class="side"><h3>${right}</h3><ul class="inventory"></ul></article>
      </div>
      <div class="wire"><div class="lane"></div></div>
    </div>`
}

async function send_chip(text: string, direction: "ltr" | "rtl"): Promise<void> {
  const lane = stage.querySelector<HTMLElement>(".lane")
  if (!lane) return

  const chip = document.createElement("span")
  chip.className = "chip"
  chip.textContent = text
  lane.append(chip)

  const travel = Math.max(lane.clientWidth - chip.offsetWidth - 16, 0)
  const start = direction === "ltr" ? "8px" : `${travel + 8}px`
  const end = direction === "ltr" ? `${travel + 8}px` : "8px"
  chip.style.left = start
  chip.style.opacity = "0"
  void chip.offsetWidth
  chip.style.transition = "left 820ms cubic-bezier(.4, 0, .2, 1), opacity 240ms ease"
  chip.style.opacity = "1"
  chip.style.left = end

  await sleep(860)
  chip.style.opacity = "0"
  await sleep(200)
  chip.remove()
}

function buckets(groups: [string, string[], string][]): string {
  const html = groups.map(([title, items, kind]) => `
    <div class="bucket ${kind}">
      <h4>${title}</h4>
      <ul>${items.map((item) => `<li>${item}</li>`).join("")}</ul>
    </div>`).join("")
  return `<div class="buckets">${html}</div>`
}

function sites_table(): string {
  if (site_results.length === 0) return `<p class="muted small">No sites visited yet.</p>`
  const rows = site_results.map((result) => `
    <tr>
      <td class="mono">${result.origin.replace("https://", "")}</td>
      <td class="mono">${shorten(result.pseudonymHex)}</td>
      <td class="${result.status === "verified" ? "ok" : "bad"}">${result_label(result)}</td>
    </tr>`).join("")
  return `<table><thead><tr><th>Site</th><th>Alice's ID there</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table>`
}

function result_label(result: VisitResult): string {
  if (result.status === "verified") return "Verified"
  if (result.status === "duplicate") return "Refused — ID already used"
  return "Refused — revoked"
}

function set_status(party: keyof typeof status, text: string, level: Level): void {
  status[party] = { text, level }
  render_status()
}

function shorten(hex: string): string {
  return hex.length > 14 ? `${hex.slice(0, 12)}…${hex.slice(-4)}` : hex
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function el<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id)
  if (!node) throw new Error(`missing element: #${id}`)
  return node as T
}

// ---------- wiring ----------

back_button.addEventListener("click", () => {
  if (step_index === 0) return
  step_index -= 1
  enter_step()
})

next_button.addEventListener("click", () => {
  void advance()
})

async function advance(): Promise<void> {
  const step = steps[step_index]

  if (ready) {
    if (step_index === steps.length - 1) {
      location.reload()
      return
    }
    step_index += 1
    enter_step()
    return
  }

  next_button.disabled = true
  try {
    await step.run?.()
    render_stage()
    ready = true
  } catch (error) {
    stage.insertAdjacentHTML("beforeend", `<div class="notice bad">Something went wrong: ${String(error)}</div>`)
    console.error(error)
  }
  render_controls()
  render_dots()
}

async function main(): Promise<void> {
  next_button.disabled = true
  await demo.boot()
  render_status()
  render_id_card()
  enter_step()
}

main().catch((error: unknown) => {
  stage.innerHTML = `<div class="notice bad">Could not start the demo: ${String(error)}</div>`
  console.error(error)
})
