import test from 'node:test'
import assert from 'node:assert/strict'
import { parseConfig } from '../src/config.js'
import { riskProbability, planEvent, ruleEffect, wildcardMatch } from '../src/policy.js'

const config = parseConfig()
// Single-resource view of planEvent: { command } for a Jev candidate, else { reason }.
const selectCommand = (ev, cfg, rules = null) => { const p = planEvent(ev, cfg, rules); return p.jev ? { command: p.jev[0].command } : { reason: p.reason } }
const event = (command) => ({ sessionID: 'ses_1', action: 'shell', resources: [command], effect: 'ask' })

test('only asks from the shell action may be upgraded', () => {
  assert.equal(selectCommand(event('git status'), config).command, 'git status')
  assert.equal(selectCommand({ ...event('git status'), effect: 'allow' }, config).reason, 'not_pending')
  assert.equal(selectCommand({ ...event('git status'), action: 'edit' }, config).reason, 'unsupported_action')
  assert.equal(selectCommand({ ...event('git status'), resources: ['pwd', 1] }, config).reason, 'ambiguous_resources')
  assert.equal(selectCommand({ ...event('git status'), resources: [] }, config).reason, 'ambiguous_resources')
})

test('multi-resource shell permissions are never joined; each resource is its own Jev candidate', () => {
  const plan = planEvent({ ...event('unused'), resources: ['pwd', 'echo compound-verify-ok'] }, config)
  assert.deepEqual(plan.jev, [{ index: 0, command: 'pwd' }, { index: 1, command: 'echo compound-verify-ok' }])
  assert.deepEqual(plan.resources.map((r) => r.reason), ['jev_candidate', 'jev_candidate'])
  // Any resource hitting a plugin list makes the whole event human ask, no Jev.
  const human = planEvent({ ...event('unused'), resources: ['pwd', 'rm -rf /'] }, config)
  assert.equal(human.jev, undefined)
  assert.equal(human.reason, 'local_risk_filter')
  assert.deepEqual(human.resources.map((r) => r.reason), ['jev_candidate', 'local_risk_filter'])
  assert.equal(JSON.stringify(human).includes('rm -rf'), false)
})

test('OpenCode wildcard and last-match-wins rule semantics are ported faithfully', () => {
  assert.equal(wildcardMatch('git status --short', 'git status *'), true)
  assert.equal(wildcardMatch('git status', 'git status *'), true)
  assert.equal(wildcardMatch('git statusx', 'git status *'), false)
  assert.equal(wildcardMatch('axb', 'a.b'), false)
  assert.equal(wildcardMatch('ab', 'a?'), true)
  const rules = [{ action: '*', resource: '*', effect: 'ask' }, { action: 'shell', resource: 'git *', effect: 'allow' }, { action: 'shell', resource: 'git push *', effect: 'deny' }]
  assert.equal(ruleEffect('shell', 'git status', rules), 'allow')
  assert.equal(ruleEffect('shell', 'git push origin', rules), 'deny')
  assert.equal(ruleEffect('shell', 'pwd', rules), 'ask')
  assert.equal(ruleEffect('shell', 'pwd', []), 'ask')
  assert.equal(ruleEffect('shell', 'pwd', null), 'ask')
})

test('per-resource pipeline: rule deny wins, rule allow drops out, asks go through lists', () => {
  const rules = [{ action: 'shell', resource: '*', effect: 'ask' }, { action: 'shell', resource: 'ls *', effect: 'allow' }, { action: 'shell', resource: 'dd *', effect: 'deny' }]
  const deny = planEvent({ ...event('unused'), resources: ['pwd', 'dd if=x', 'rm -rf /'] }, config, rules)
  assert.equal(deny.effect, 'deny')
  assert.deepEqual(deny.resources.map((r) => r.rule), ['ask', 'deny', 'ask'])
  const mixed = planEvent({ ...event('unused'), resources: ['ls -la', 'pwd'] }, config, rules)
  assert.deepEqual(mixed.jev, [{ index: 1, command: 'pwd' }])
  assert.deepEqual(mixed.resources.map((r) => r.reason), ['rule_allow', 'jev_candidate'])
  // Rule-allowed resources skip plugin lists (they are already allowed by OpenCode).
  const allowedRisky = planEvent({ ...event('unused'), resources: ['ls ~/.ssh', 'pwd'] }, config, rules)
  assert.deepEqual(allowedRisky.jev, [{ index: 1, command: 'pwd' }])
  const mismatch = planEvent({ ...event('unused'), resources: ['ls -la'] }, config, rules)
  assert.equal(mismatch.reason, 'rule_view_mismatch')
})

test('hard local filters reject sensitive tools, paths and options, even inside compounds', () => {
  for (const [command, reason] of [
    ['git status && rm -rf .', 'local_risk_filter'], ['git status\nsudo id', 'local_risk_filter'],
    ['ls ~/.ssh/config', 'local_risk_filter'], ['git status ../secret', 'local_risk_filter'],
    ['rm -rf /tmp', 'local_risk_filter'], ['git push', 'local_risk_filter'], ['pwd;git push', 'local_risk_filter'],
    ['curl https://example.com', 'local_risk_filter'], ['git diff .env', 'local_risk_filter'],
    ['echo $(curl x)', 'local_risk_filter'],
    ['npm test -- --require foo', 'unsafe_option'], ['npm test --config unsafe', 'unsafe_option'], ['go test -exec ./evil', 'unsafe_option'],
  ]) assert.equal(selectCommand(event(command), config).reason, reason, command)
})

test('a single compound resource goes to Jev as one unsplit full-string candidate', () => {
  for (const command of [
    'pwd; git status', 'pwd && git status', 'git status | cat', 'pwd\ngit status',
    'git diff > file', 'ls *', 'for f in a b; do echo $f; done', 'cat <<EOF\nhi\nEOF', 'false || true',
  ]) {
    const result = selectCommand(event(command), config)
    assert.equal(result.command, command, command)
    assert.equal(result.segments, undefined, command)
  }
})

test('candidatePrefixes skip Jev; unmatched safe commands go to Jev', () => {
  assert.equal(selectCommand(event('go test ./...'), config).command, 'go test ./...')
  assert.equal(selectCommand(event('npm install foo'), config).reason, 'local_risk_filter')
  assert.equal(selectCommand(event(' pwd'), config).reason, 'invalid_command')

  const skip = parseConfig({ candidatePrefixes: ['git status', 'rtk git status'] })
  assert.equal(selectCommand(event('git status'), skip).reason, 'skip_jev_prefix')
  assert.equal(selectCommand(event('git status --short'), skip).reason, 'skip_jev_prefix')
  assert.equal(selectCommand(event('rtk git status --short'), skip).reason, 'skip_jev_prefix')
  assert.equal(selectCommand(event('pwd'), skip).command, 'pwd')
  assert.equal(selectCommand(event('git statusfoo'), skip).command, 'git statusfoo')
  assert.equal(selectCommand(event('pwd; git status'), skip).command, 'pwd; git status')
})

test('only correctly named numeric predicate answers are accepted', () => {
  assert.equal(riskProbability({ answers: [{ type: 'predicate', name: 'risk', probability: 0 }] }), 0)
  for (const bad of [null, {}, { answers: {} }, { answers: [] },
    { answers: [{ type: 'error', name: 'risk' }] },
    { answers: [{ type: 'predicate', name: 'safe', probability: 0 }] },
    { answers: [{ type: 'predicate', name: 'risk', probability: '0' }] },
    { answers: [{ type: 'predicate', name: 'risk', probability: -1 }] },
    { answers: [{ type: 'predicate', name: 'risk', probability: NaN }] },
    { answers: [{ type: 'predicate', name: 'risk', probability: 0 }, { type: 'predicate', name: 'other', probability: 0 }] },
  ]) assert.equal(riskProbability(bad), null)
})

test('configuration validates thresholds and rejects unsafe changes', () => {
  assert.equal(parseConfig().dryRun, true)
  assert.deepEqual(parseConfig().candidatePrefixes, [])
  assert.throws(() => parseConfig({ riskThreshold: 1 }))
  assert.throws(() => parseConfig({ eligibleActions: ['edit'] }))
  assert.throws(() => parseConfig({ dryRun: 'false' }))
  assert.throws(() => parseConfig({ arbitrary: true }))
  assert.throws(() => parseConfig({ candidatePrefixes: ['pwd; rm'] }))
})
