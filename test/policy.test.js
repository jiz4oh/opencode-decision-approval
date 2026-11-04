import test from 'node:test'
import assert from 'node:assert/strict'
import { parseConfig } from '../src/config.js'
import { riskProbability, selectCommand } from '../src/policy.js'

const config = parseConfig()
const event = (command) => ({ sessionID: 'ses_1', action: 'shell', resources: [command], effect: 'ask' })

test('only asks from the shell action may be upgraded', () => {
  assert.equal(selectCommand(event('git status'), config).command, 'git status')
  assert.equal(selectCommand({ ...event('git status'), effect: 'allow' }, config).reason, 'not_pending')
  assert.equal(selectCommand({ ...event('git status'), action: 'edit' }, config).reason, 'unsupported_action')
  assert.equal(selectCommand({ ...event('git status'), resources: ['pwd', 'rm -rf /'] }, config).reason, 'ambiguous_resources')
})

test('rejects command chaining, sensitive commands and expansions', () => {
  for (const command of [
    'git status && rm -rf .', 'pwd; echo hello', 'git status | cat',
    'git status\nsudo id', 'git diff > file', 'pwd $(whoami)',
    'git status `whoami`', 'ls ~/.ssh/config', 'git status ../secret',
    'npm test -- --require foo', 'npm test --config unsafe',
    'go test -exec ./evil', 'ls *', 'rm -rf /tmp', 'git push',
    'curl https://example.com', 'git diff .env',
  ]) assert.equal(selectCommand(event(command), config).command, undefined, command)
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
