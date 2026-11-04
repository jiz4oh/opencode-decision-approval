import test from 'node:test'
import assert from 'node:assert/strict'
import { parseConfig, loadConfig } from '../src/config.js'
import { evaluateJev } from '../src/decision.js'
import { createHandler, loadAgentRules, loadGlobalRules } from '../src/runtime.js'

const noGlobal = async () => []

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

test('candidatePrefixes skip Jev without calling Decision API', async () => {
  let calls = 0
  const entries = []
  const handle = createHandler({
    config: parseConfig({ dryRun: false, candidatePrefixes: ['git status'] }),
    generate: async () => { calls++; return output(0) },
    audit: async (entry) => entries.push(entry),
  })
  const pending = event('git status --short')
  await handle(pending)
  assert.equal(pending.effect, 'ask')
  assert.equal(calls, 0)
  assert.equal(entries[0].reason, 'skip_jev_prefix')
})

test('local skip reasons are audited without calling Decision API', async () => {
  let calls = 0
  const entries = []
  const handle = createHandler({ config: parseConfig({ dryRun: false }), generate: async () => { calls++; return output(0) }, audit: async (entry) => entries.push(entry) })
  for (const [command, reason] of [['git push', 'local_risk_filter'], ['pwd; rm -rf .', 'local_risk_filter'], ['npm test --config unsafe', 'unsafe_option']]) {
    entries.length = 0
    const pending = event(command)
    await handle(pending)
    assert.equal(pending.effect, 'ask', command)
    assert.equal(entries[0]?.reason, reason, command)
  }
  assert.equal(calls, 0)
})

test('compound commands get exactly one Jev call on the full string; one verdict for all', async () => {
  for (const [risk, effect] of [[0.001, 'allow'], [0.9, 'ask']]) {
    const seen = []
    const handle = createHandler({ config: parseConfig({ dryRun: false }), generate: async (input) => { seen.push(input); return output(risk) }, audit: async () => {} })
    const command = 'pwd; git status | cat\nfor f in a; do echo $f; done'
    const pending = event(command)
    await handle(pending)
    assert.equal(seen.length, 1)
    assert.equal(seen[0].input[0].value.command, command)
    assert.equal(seen[0].input[0].value.compoundSegments, undefined)
    assert.equal(pending.effect, effect)
  }
})

test('multi-resource shell: one Jev call per resource, any non-allow asks, all allow allows', async () => {
  for (const [risks, effect] of [[[0.001, 0.001], 'allow'], [[0.001, 0.9], 'ask']]) {
    const seen = []
    const entries = []
    const handle = createHandler({
      config: parseConfig({ dryRun: false }),
      generate: async (input) => { seen.push(input.input[0].value.command); return output(risks[seen.length - 1]) },
      audit: async (e) => entries.push(e),
      collect: async (_event, command) => ({ workingDirectory: '/w', sessionTitle: command }),
    })
    const pending = { sessionID: 'ses_1', action: 'shell', resources: ['pwd', 'echo compound-verify-ok'], effect: 'ask' }
    await handle(pending)
    assert.deepEqual(seen, ['pwd', 'echo compound-verify-ok'])
    assert.equal(pending.effect, effect)
    assert.equal(entries.length, 1)
    assert.deepEqual(entries[0].resources.map((r) => r.index), [0, 1])
    assert.equal(entries[0].effective, effect)
    assert.equal(JSON.stringify(entries[0]).includes('compound-verify-ok'), false)
  }
})

test('per-resource context comes from collect for each resource', async () => {
  const collected = []
  const handle = createHandler({ config: parseConfig({ dryRun: false }), generate: async () => output(0), audit: async () => {},
    collect: async (_e, command) => { collected.push(command); return null } })
  await handle({ sessionID: 's', action: 'shell', resources: ['pwd', 'git status'], effect: 'ask' })
  assert.deepEqual(collected.sort(), ['git status', 'pwd'])
})

test('OpenCode rules: any deny denies whole event without Jev; dry-run only records it', async () => {
  const rules = async () => [{ action: 'shell', resource: '*', effect: 'ask' }, { action: 'shell', resource: 'dd *', effect: 'deny' }]
  for (const [dryRun, effect] of [[false, 'deny'], [true, 'ask']]) {
    let calls = 0
    const entries = []
    const handle = createHandler({ config: parseConfig({ dryRun }), generate: async () => { calls++; return output(0) }, audit: async (e) => entries.push(e), rules })
    const pending = { sessionID: 's', action: 'shell', resources: ['pwd', 'dd if=x'], effect: 'ask' }
    await handle(pending)
    assert.equal(pending.effect, effect)
    assert.equal(calls, 0)
    assert.equal(entries[0].reason, 'rule_deny')
    assert.equal(entries[0].rules, 'agent')
  }
})

test('rule-allowed resources skip Jev; rule loading failure treats every resource as ask', async () => {
  const seen = []
  const ok = createHandler({ config: parseConfig({ dryRun: false }), generate: async (i) => { seen.push(i.input[0].value.command); return output(0) }, audit: async () => {},
    rules: async () => [{ action: 'shell', resource: '*', effect: 'ask' }, { action: 'shell', resource: 'ls *', effect: 'allow' }] })
  const ev = { sessionID: 's', action: 'shell', resources: ['ls -la', 'pwd'], effect: 'ask' }
  await ok(ev)
  assert.deepEqual(seen, ['pwd'])
  assert.equal(ev.effect, 'allow')
  seen.length = 0
  const entries = []
  const broken = createHandler({ config: parseConfig({ dryRun: false }), generate: async (i) => { seen.push(i.input[0].value.command); return output(0) }, audit: async (e) => entries.push(e),
    rules: async () => { throw Error('agent api down') } })
  await broken({ sessionID: 's', action: 'shell', resources: ['ls -la', 'pwd'], effect: 'ask' })
  assert.deepEqual(seen.sort(), ['ls -la', 'pwd'])
  assert.equal(entries[0].rules, 'unavailable')
})

test('non-shell actions stay ask and are audited', async () => {
  const entries = []
  const handle = createHandler({ config: parseConfig({ dryRun: false }), generate: async () => output(0), audit: async (e) => entries.push(e) })
  const ev = { sessionID: 's', action: 'edit', resources: ['a.js'], effect: 'ask' }
  await handle(ev)
  assert.equal(ev.effect, 'ask')
  assert.equal(entries[0].reason, 'unsupported_action')
  assert.equal(JSON.stringify(entries[0]).includes('a.js'), false)
})

test('timeout and errors fail back to ask', async () => {
  const cfg = parseConfig({ timeoutMs: 1000 })
  const result = await evaluateJev(() => new Promise(() => {}), event(), 'pwd', cfg)
  assert.equal(result.action, 'ask')
  assert.equal(result.reason, 'decision_unavailable')
})

test('loadAgentRules reads the agent ruleset via the SDK, falling back to the session agent', async () => {
  const perms = [{ action: 'shell', resource: '*', effect: 'ask' }]
  const asked = []
  const ctx = { agent: { get: async ({ agentID }) => { asked.push(agentID); return { data: { permissions: perms } } } }, session: { get: async () => ({ agent: 'build' }) } }
  assert.deepEqual(await loadAgentRules(ctx, { sessionID: 's', agent: 'plan' }, noGlobal), perms)
  assert.deepEqual(await loadAgentRules(ctx, { sessionID: 's' }, noGlobal), perms)
  assert.deepEqual(asked, ['plan', 'build'])
  assert.equal(await loadAgentRules({}, { sessionID: 's' }, noGlobal), null)
})

test('loadAgentRules appends non-t3 session rules and drops t3code overlay rules', async () => {
  const ctx = { agent: { get: async () => ({ data: { permissions: [{ action: '*', resource: '*', effect: 'allow' }] } }) },
    session: { get: async () => ({ agent: 'build', permission: [{ permission: 'bash', pattern: '*', action: 'ask' }, { permission: 'bash', pattern: 'dd *', action: 'deny' }] }) } }
  assert.deepEqual(await loadAgentRules(ctx, { sessionID: 's' }, noGlobal), [{ action: '*', resource: '*', effect: 'allow' }, { action: 'shell', resource: 'dd *', effect: 'deny' }])
})

test('t3code shell ask overlay over agent allow-all: pwd goes to Jev and can be allowed', async () => {
  const seen = []
  const handle = createHandler({ config: parseConfig({ dryRun: false }), generate: async (i) => { seen.push(i.input[0].value.command); return output(0) }, audit: async () => {},
    rules: async () => [{ action: '*', resource: '*', effect: 'allow' }] })
  const ev = { sessionID: 's', action: 'shell', resources: ['pwd'], effect: 'ask' }
  await handle(ev)
  assert.deepEqual(seen, ['pwd'])
  assert.equal(ev.effect, 'allow')
})

test('loadGlobalRules reads config permissions and tolerates missing/invalid files', async () => {
  const file = JSON.stringify({ permissions: [{ action: 'shell', resource: 'rtk git status *', effect: 'allow' }, { action: 'shell', resource: 'bad' }] })
  assert.deepEqual(await loadGlobalRules(async () => file, 'x'), [{ action: 'shell', resource: 'rtk git status *', effect: 'allow' }])
  assert.deepEqual(await loadGlobalRules(async () => { throw Error('ENOENT') }, 'x'), [])
  // Global rules are user policy: t3-looking external_directory allows are kept, `~/` expanded.
  const ext = JSON.stringify({ permissions: [{ action: 'external_directory', resource: '~/.agents/skills/*', effect: 'allow' }] })
  const [rule] = await loadGlobalRules(async () => ext, 'x')
  assert.equal(rule.action, 'external_directory')
  assert.ok(!rule.resource.startsWith('~') && rule.resource.endsWith('/.agents/skills/*'))
  assert.deepEqual(await loadGlobalRules(async () => '{ // jsonc', 'x'), [])
})

test('loadAgentRules merges agent defaults, then global config, then non-t3 session rules', async () => {
  const agent = [{ action: '*', resource: '*', effect: 'ask' }]
  const global = [{ action: 'shell', resource: 'rtk git status', effect: 'allow' }, { action: 'shell', resource: 'rtk git status *', effect: 'allow' }]
  const ctx = { agent: { get: async () => ({ data: { permissions: agent } }) },
    session: { get: async () => ({ agent: 'build', permission: [{ permission: 'bash', pattern: '*', action: 'ask' }, { permission: 'bash', pattern: 'dd *', action: 'deny' }] }) } }
  assert.deepEqual(await loadAgentRules(ctx, { sessionID: 's' }, async () => global), [...agent, ...global, { action: 'shell', resource: 'dd *', effect: 'deny' }])
  assert.deepEqual(await loadAgentRules({}, { sessionID: 's' }, async () => global), global)
})

test('rtk git status --short is allowed by a global rule without calling Jev', async () => {
  const ctx = { agent: { get: async () => ({ data: { permissions: [{ action: '*', resource: '*', effect: 'ask' }] } }) }, session: { get: async () => ({ agent: 'build' }) } }
  const global = [{ action: 'shell', resource: 'rtk git status', effect: 'allow' }, { action: 'shell', resource: 'rtk git status *', effect: 'allow' }]
  const seen = []; const entries = []
  const handle = createHandler({ config: parseConfig({ dryRun: false }), generate: async (i) => { seen.push(i.input[0].value.command); return output(0) },
    audit: async (e) => { entries.push(e) }, rules: (ev) => loadAgentRules(ctx, ev, async () => global) })
  const ev = { sessionID: 's', action: 'shell', resources: ['rtk git status --short', 'make build'], effect: 'ask' }
  await handle(ev)
  assert.deepEqual(seen, ['make build'])
  assert.equal(entries[0].resources.find((r) => r.index === 0).reason, 'rule_allow')
})

test('overlay: specific global allow stays rule_allow while allow-all-only resources go to Jev', async () => {
  const seen = []; const entries = []
  const rules = [{ action: '*', resource: '*', effect: 'allow' }, { action: 'shell', resource: 'rtk git status *', effect: 'allow' }]
  const handle = createHandler({ config: parseConfig({ dryRun: false }), generate: async (i) => { seen.push(i.input[0].value.command); return output(0) },
    audit: async (e) => { entries.push(e) }, rules: async () => rules })
  const ev = { sessionID: 's', action: 'shell', resources: ['rtk git status --short', 'pwd'], effect: 'ask' }
  await handle(ev)
  assert.deepEqual(seen, ['pwd'])
  assert.equal(entries[0].resources[0].reason, 'rule_allow')
  assert.equal(ev.effect, 'allow')
  seen.length = 0
  const solo = { sessionID: 's', action: 'shell', resources: ['rtk git status --short'], effect: 'ask' }
  await handle(solo)
  assert.deepEqual(seen, [])
  assert.equal(solo.effect, 'allow')
})
