import test from 'node:test'
import assert from 'node:assert/strict'
import { parseConfig, loadConfig } from '../src/config.js'
import { evaluateJev } from '../src/decision.js'
import { createHandler } from '../src/runtime.js'

const event = (command = 'git status') => ({ sessionID: 'ses_1', action: 'shell', resources: [command], effect: 'ask' })
const output = (risk) => ({ answers: [{ name: 'risk', type: 'predicate', probability: risk }] })

test('native Decision API request contains predicate and typed evidence', async () => {
  let seen
  const result = await evaluateJev(async (input) => { seen = input; return output(0.005) }, event(), 'git status', parseConfig())
  assert.equal(result.action, 'allow')
  assert.deepEqual(seen.model, { providerID: 'opencode', id: 'jev-1.13' })
  assert.equal(seen.questions[0].type, 'predicate')
  assert.equal(seen.questions[0].name, 'risk')
  assert.equal(seen.input[0].type, 'json')
  assert.equal(seen.input[0].value.command, 'git status')
})

test('risk score threshold and missing answers fail to manual approval', async () => {
  const cfg = parseConfig()
  assert.equal((await evaluateJev(async () => output(0.01), event(), 'pwd', cfg)).action, 'allow')
  assert.equal((await evaluateJev(async () => output(0.01001), event(), 'pwd', cfg)).action, 'ask')
  assert.equal((await evaluateJev(async () => ({ answers: [] }), event(), 'pwd', cfg)).action, 'ask')
  assert.equal((await evaluateJev(async () => { throw Error('network') }, event(), 'pwd', cfg)).action, 'ask')
})

test('dry-run never mutates the permission event', async () => {
  const entries = []
  const handle = createHandler({ config: parseConfig(), generate: async () => output(0), audit: async (entry) => entries.push(entry) })
  const pending = event()
  await handle(pending)
  assert.equal(pending.effect, 'ask')
  assert.equal(entries[0].reason, 'dry_run')
  assert.equal(entries[0].effective, 'ask')
})

test('active mode automatically approves only eligible low-risk asks', async () => {
  let calls = 0
  const handle = createHandler({ config: parseConfig({ dryRun: false }), generate: async () => { calls++; return output(0.001) }, audit: async () => {} })
  const eligible = event()
  await handle(eligible)
  assert.equal(eligible.effect, 'allow')
  const blocked = event('git push')
  await handle(blocked)
  assert.equal(blocked.effect, 'ask')
  const originalAllow = { ...event(), effect: 'allow' }
  await handle(originalAllow)
  assert.equal(originalAllow.effect, 'allow')
  assert.equal(calls, 1)
})

test('audit persistence failures never auto-approve', async () => {
  const pending = event()
  const handle = createHandler({ config: parseConfig({ dryRun: false }), generate: async () => output(0), audit: async () => { throw Error('disk full') } })
  await handle(pending)
  assert.equal(pending.effect, 'ask')
})

test('missing config uses safe defaults, malformed config fails setup', async () => {
  const missing = Object.assign(new Error('missing'), { code: 'ENOENT' })
  const ready = await loadConfig({ configFile: '/tmp/decision.json' }, async () => { throw missing })
  assert.equal(ready.config.dryRun, true)
  await assert.rejects(loadConfig({ configFile: '/tmp/decision.json' }, async () => '{invalid'), /Invalid decision approval configuration/)
})

test('timeout and errors fail back to ask', async () => {
  const cfg = parseConfig({ timeoutMs: 1000 })
  const result = await evaluateJev(() => new Promise(() => {}), event(), 'pwd', cfg)
  assert.equal(result.action, 'ask')
  assert.equal(result.reason, 'decision_unavailable')
})
