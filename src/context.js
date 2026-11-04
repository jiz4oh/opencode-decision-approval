// Gathers bounded, read-only evidence for the Jev decision request.
// Everything here is best effort: any failure just omits a field. Never throws.
import { readFile, stat } from 'node:fs/promises'
import { isAbsolute, join, relative, resolve } from 'node:path'

export const LIMITS = Object.freeze({ fileBytes: 6000, totalBytes: 16000, metadataBytes: 2000, maxFiles: 4 })
const SECRET_LINE = /(api[_-]?key|secret|token|passw(or)?d|credential|private[_-]?key|authorization|bearer\s)/i
const SECRET_FILE = /(^|\/)(\.env(\..*)?|\.npmrc|\.netrc|id_[a-z0-9]+|.*\.pem|.*\.key|credentials.*)$/i

export function redact(text) {
  return text.split('\n').map((line) => (SECRET_LINE.test(line) ? '[redacted line]' : line)).join('\n')
}

function inside(cwd, path) {
  const rel = relative(cwd, path)
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel)
}

async function readBounded(cwd, rel, read) {
  if (!cwd || SECRET_FILE.test(rel)) return null
  const path = resolve(cwd, rel)
  if (!inside(cwd, path)) return null
  try {
    const info = await stat(path)
    if (!info.isFile()) return null
    const raw = String(await read(path, 'utf8'))
    const truncated = raw.length > LIMITS.fileBytes
    return { path: rel, truncated, content: redact(truncated ? raw.slice(0, LIMITS.fileBytes) : raw) }
  } catch { return null }
}

const tokens = (command) => command.split(/\s+/).filter(Boolean)
const PKG_RUNNERS = new Set(['npm', 'pnpm', 'yarn', 'bun'])
const PKG_BUILTINS = new Set(['install', 'i', 'add', 'remove', 'publish', 'exec', 'dlx', 'x', 'ci', 'update', 'link'])

// Returns the files/script bodies that the command will actually execute or read.
export async function relatedEvidence(command, cwd, read = readFile) {
  const files = []
  const scripts = []
  if (!cwd) return { files, scripts }
  const [bin, ...args] = tokens(command)
  // package.json scripts: npm test / npm run x / pnpm x / yarn x
  if (PKG_RUNNERS.has(bin)) {
    let name = args[0] === 'run' || args[0] === 'run-script' ? args[1] : args[0]
    if (bin === 'npm' && name && !['test', 't', 'start', 'run', 'run-script'].includes(args[0])) name = null
    if (name === 't') name = 'test'
    if (name && !PKG_BUILTINS.has(name)) {
      try {
        const pkg = JSON.parse(String(await read(resolve(cwd, 'package.json'), 'utf8')))
        const body = pkg?.scripts?.[name]
        scripts.push({ source: 'package.json', name, body: typeof body === 'string' ? redact(body) : null })
        for (const hook of ['pre' + name, 'post' + name]) {
          if (typeof pkg?.scripts?.[hook] === 'string') scripts.push({ source: 'package.json', name: hook, body: redact(pkg.scripts[hook]) })
        }
      } catch { scripts.push({ source: 'package.json', name, body: null }) }
    }
  }
  // make target: include Makefile excerpt
  if (bin === 'make') {
    for (const f of ['Makefile', 'makefile', 'GNUmakefile']) {
      const got = await readBounded(cwd, f, read)
      if (got) { files.push(got); break }
    }
  }
  if (['just'].includes(bin)) { const got = await readBounded(cwd, 'justfile', read); if (got) files.push(got) }
  // direct script execution or script-path arguments (./x.sh, scripts/run, bin/rails, foo.rb ...)
  for (const word of [bin, ...args]) {
    if (files.length >= LIMITS.maxFiles) break
    if (word.startsWith('-')) continue
    if (!/[\/.]/.test(word) || /^\d/.test(word)) continue
    if (!/^\.?\.?\/|\.(sh|bash|zsh|rb|py|js|mjs|cjs|ts|pl|lua|rake)$|^(bin|script|scripts)\//.test(word)) continue
    const got = await readBounded(cwd, word, read)
    if (got && !files.some((f) => f.path === got.path)) files.push(got)
  }
  // keep total payload bounded
  let budget = LIMITS.totalBytes
  const kept = []
  for (const f of files) {
    if (budget <= 0) break
    const content = f.content.slice(0, budget)
    budget -= content.length
    kept.push({ ...f, truncated: f.truncated || content.length < f.content.length, content })
  }
  return { files: kept, scripts }
}

export function sanitizeMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object') return null
  try {
    const text = redact(JSON.stringify(metadata))
    return text.length > LIMITS.metadataBytes ? { truncatedJson: text.slice(0, LIMITS.metadataBytes) } : JSON.parse(text)
  } catch { return null }
}

// Resolve the session working directory via the plugin SDK. Shape-tolerant; null on failure.
export async function sessionInfo(ctx, sessionID) {
  try {
    const get = ctx?.session?.get
    if (typeof get !== 'function' || !sessionID) return {}
    let s
    try { s = await get({ sessionID }) } catch { s = await get(sessionID) }
    s = s?.data ?? s
    const dir = s?.directory ?? s?.location?.directory ?? s?.path?.directory ?? null
    return { cwd: typeof dir === 'string' && isAbsolute(dir) ? dir : null, title: typeof s?.title === 'string' ? s.title.slice(0, 200) : null }
  } catch { return {} }
}

export async function gatherContext({ event, command, ctx, read = readFile }) {
  const info = await sessionInfo(ctx, event.sessionID)
  const meta = event.metadata && typeof event.metadata === 'object' ? event.metadata : {}
  const cwd = info.cwd ?? (typeof meta.cwd === 'string' && isAbsolute(meta.cwd) ? meta.cwd : null)
  const evidence = await relatedEvidence(command, cwd, read)
  const description = typeof meta.description === 'string' ? redact(meta.description).slice(0, 500) : null
  return {
    workingDirectory: cwd,
    sessionTitle: info.title ?? null,
    agentStatedPurpose: description,
    permissionMetadata: sanitizeMetadata(meta),
    toolSource: event.source ?? null,
    scripts: evidence.scripts,
    relatedFiles: evidence.files,
  }
}
