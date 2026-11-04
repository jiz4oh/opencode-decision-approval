import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { gatherContext, relatedEvidence, redact } from '../src/context.js'
import { evaluateJev } from '../src/decision.js'
import { createHandler } from '../src/runtime.js'
import { parseConfig } from '../src/config.js'

async function repo() {
  const dir = await mkdtemp(join(tmpdir(), 'oda-'))
  await writeFile(join(dir, 'package.json'), JSON.stringify({ scripts: { test: 'node --test', pretest: 'rm -rf dist', lint: 'eslint .' } }))
  await mkdir(join(dir, 'scripts'))
  await writeFile(join(dir, 'scripts/check.sh'), '#!/bin/sh\necho hi\nexport API_KEY=abc123\ncurl https://x\n')
  await writeFile(join(dir, '.env'), 'TOKEN=zzz')
  await writeFile(join(dir, 'Makefile'), 'build:\n\tgo build ./...\n')
  return dir
}
const ctx = (dir) => ({ session: { get: async () => ({ directory: dir, title: 'fix tests' }) } })
const output = (risk) => ({ answers: [{ name: 'risk', type: 'predicate', probability: risk }] })

test('npm test includes script body and pre/post hooks', async () => {
  const dir = await repo()
  const ev = await relatedEvidence('npm test', dir)
  assert.deepEqual(ev.scripts.map((s) => [s.name, s.body]), [['test', 'node --test'], ['pretest', 'rm -rf dist']])
  const p = await relatedEvidence('pnpm lint', dir)
  assert.equal(p.scripts[0].body, 'eslint .')
})

test('referenced script file content is included and secret lines redacted', async () => {
  const dir = await repo()
  const ev = await relatedEvidence('./scripts/check.sh', dir)
  assert.equal(ev.files[0].path, './scripts/check.sh')
  assert.match(ev.files[0].content, /curl https:\/\/x/)
  assert.doesNotMatch(ev.files[0].content, /abc123/)
  assert.equal(redact('ok\nTOKEN=1'), 'ok\n[redacted line]')
})

test('never reads secret files or paths outside cwd', async () => {
  const dir = await repo()
  assert.equal((await relatedEvidence('cat ./.env', dir)).files.length, 0)
  assert.equal((await relatedEvidence('cat ../../etc/passwd.sh', dir)).files.length, 0)
  assert.equal((await relatedEvidence('cat /etc/hosts.sh', dir)).files.length, 0)
})

test('make includes Makefile; gatherContext carries cwd, title, purpose', async () => {
  const dir = await repo()
  const c = await gatherContext({ event: { sessionID: 's', action: 'shell', metadata: { description: 'Build project' } }, command: 'make build', ctx: ctx(dir) })
  assert.equal(c.workingDirectory, dir)
  assert.equal(c.sessionTitle, 'fix tests')
  assert.equal(c.agentStatedPurpose, 'Build project')
  assert.match(c.relatedFiles[0].content, /go build/)
  const other = await gatherContext({ event: { sessionID: 's', action: 'read' }, command: 'make build', ctx: ctx(dir) })
  assert.deepEqual([other.relatedFiles, other.scripts, other.workingDirectory], [[], [], dir])
})

test('context failures degrade to no evidence, never throw', async () => {
  const c = await gatherContext({ event: { sessionID: 's' }, command: 'npm test', ctx: { session: { get: async () => { throw Error('x') } } } })
  assert.equal(c.workingDirectory, null)
  assert.deepEqual(c.scripts, [])
})

test('handler sends gathered context to Decision API; collector errors still evaluate', async () => {
  const dir = await repo()
  let seen
  const handle = createHandler({ config: parseConfig({ dryRun: false, riskThreshold: 0.15 }), generate: async (i) => { seen = i; return output(0.01) }, audit: async () => {},
    collect: (event, command) => gatherContext({ event, command, ctx: ctx(dir) }) })
  const ev = { sessionID: 's', action: 'shell', resources: ['npm test'], effect: 'ask' }
  await handle(ev)
  const v = seen.input[0].value
  assert.equal(v.command, 'npm test')
  assert.equal(v.workingDirectory, dir)
  assert.equal(v.scripts[0].body, 'node --test')
  assert.match(v.contextLimitation, /untrusted/)
  assert.equal(ev.effect, 'allow')
  const bad = createHandler({ config: parseConfig({ dryRun: false }), generate: async (i) => { seen = i; return output(0) }, audit: async () => {}, collect: async () => { throw Error('boom') } })
  await bad({ sessionID: 's', action: 'shell', resources: ['git status'], effect: 'ask' })
  assert.match(seen.input[0].value.contextLimitation, /Only this action and resource/)
})
