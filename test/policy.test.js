import test from 'node:test'
import assert from 'node:assert/strict'
import { parseConfig } from '../src/config.js'
import { isProjectEdit, riskProbability, planEvent, ruleEffect, wildcardMatch, isT3InjectedRule, stripT3Rules } from '../src/policy.js'

const config = parseConfig()
// Single-resource view of planEvent: { command } for a Jev candidate, else { reason }.
const selectCommand = (ev, cfg, rules = null) => { const p = planEvent(ev, cfg, rules); return p.jev ? { command: p.jev[0].command } : { reason: p.reason } }
const event = (command) => ({ sessionID: 'ses_1', action: 'shell', resources: [command], effect: 'ask' })

test('any action is planned; non-shell resources skip shell filters and go to Jev', () => {
  assert.equal(selectCommand(event('git status'), config).command, 'git status')
  assert.equal(selectCommand({ ...event('git status'), effect: 'allow' }, config).reason, 'not_pending')
  assert.equal(selectCommand({ ...event('git status'), action: 'edit' }, config).command, 'git status')
  const ext = { sessionID: 's', action: 'external_directory', resources: ['/Users/x/.t3/worktrees/repo/issue-2/*'], effect: 'ask' }
  assert.deepEqual(planEvent(ext, config).jev, [{ index: 0, command: ext.resources[0] }])
  assert.equal(selectCommand({ ...ext, action: 'some_new_action' }, config).command, ext.resources[0])
  assert.equal(selectCommand({ ...ext, resources: ['a\x00b'] }, config).reason, 'invalid_command')
  assert.equal(selectCommand(ext, parseConfig({ eligibleActions: ['shell'] })).reason, 'action_not_eligible')
  assert.equal(selectCommand(ext, parseConfig({ eligibleActions: ['shell', 'external_directory'] })).command, ext.resources[0])
  assert.equal(selectCommand(ext, parseConfig({ eligibleActions: ['*'] })).command, ext.resources[0])
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
  // All rule-allowed but OpenCode asked => invisible session overlay (t3code): ignored,
  // resources go through plugin lists + Jev instead of dead-ending.
  const overlay = planEvent({ ...event('unused'), resources: ['ls -la', 'ls ~/.ssh'] }, config, rules)
  assert.equal(overlay.reason, 'local_risk_filter')
  assert.deepEqual(overlay.resources.map((r) => r.overlay), ['session_ask_ignored', 'session_ask_ignored'])
  // Specific allow under the overlay: rule_allow, no Jev.
  const overlaySpecific = planEvent({ ...event('unused'), resources: ['ls -la'] }, config, rules)
  assert.deepEqual(overlaySpecific.jev, [])
  assert.deepEqual(overlaySpecific.resources.map((r) => r.reason), ['rule_allow'])
  // Allowed only by a bare `*` rule under the overlay: goes to Jev.
  const overlayJev = planEvent({ ...event('unused'), resources: ['ls -la'] }, config, [{ action: '*', resource: '*', effect: 'allow' }])
  assert.deepEqual(overlayJev.jev, [{ index: 0, command: 'ls -la' }])
})

test('t3code injected session rules are recognized and stripped; user rules survive', () => {
  for (const rule of [
    { permission: 'bash', pattern: '*', action: 'ask' }, { permission: '*', pattern: '*', action: 'ask' },
    { permission: '*', pattern: '*', action: 'deny' }, { permission: 'external_directory', pattern: '*', action: 'ask' },
    { permission: 'edit', pattern: '*', action: 'allow' }, { permission: 'read', pattern: '*.env', action: 'ask' },
    { permission: '*', pattern: '*', action: 'allow' }, { permission: 'external_directory', pattern: '/w/repo/*', action: 'allow' },
  ]) assert.equal(isT3InjectedRule(rule), true, JSON.stringify(rule))
  const user = [{ permission: 'bash', pattern: 'git push *', action: 'deny' }, { action: 'shell', resource: 'ls *', effect: 'allow' }]
  assert.deepEqual(stripT3Rules([{ permission: 'bash', pattern: '*', action: 'ask' }, ...user]),
    [{ action: 'shell', resource: 'git push *', effect: 'deny' }, { action: 'shell', resource: 'ls *', effect: 'allow' }])
  assert.deepEqual(stripT3Rules(undefined), [])
})

test('hard local filters reject sensitive tools, paths and options, even inside compounds', () => {
  for (const [command, reason] of [
    ['git status && rm -rf .', 'local_risk_filter'], ['git status\nsudo id', 'local_risk_filter'],
    ['ls ~/.ssh/config', 'local_risk_filter'], ['git status ../secret', 'local_risk_filter'],
    ['rm -rf /tmp', 'local_risk_filter'], ['git push', 'local_risk_filter'], ['pwd;git push', 'local_risk_filter'],
    ['curl https://example.com', 'local_risk_filter'], ['git diff .env', 'local_risk_filter'],
    ['echo $(curl x)', 'local_risk_filter'], ['sudo rm -rf /', 'local_risk_filter'],
    ['mise exec -- ruby -e "puts 1"', undefined], ['python -c \'print(1)\'', undefined], ['ruby -e \'\'', undefined],
    ['git status && mise exec -- ruby script.rb', undefined], ['find . -name x', undefined], ['bash -c "ls"', undefined],
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
  assert.equal(selectCommand(event('npm install foo'), config).command, 'npm install foo') // installs go to Jev; opencode allow rules short-circuit when present
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
  assert.equal(parseConfig({ riskThreshold: 0.6 }).riskThreshold, 0.6)
  assert.throws(() => parseConfig({ riskThreshold: -0.1 }))
  assert.deepEqual(parseConfig().eligibleActions, [])
  assert.deepEqual(parseConfig({ eligibleActions: ['shell', 'edit'] }).eligibleActions, ['shell', 'edit'])
  assert.throws(() => parseConfig({ eligibleActions: 'shell' }))
  assert.throws(() => parseConfig({ eligibleActions: ['bad action'] }))
  assert.throws(() => parseConfig({ dryRun: 'false' }))
  assert.throws(() => parseConfig({ arbitrary: true }))
  assert.throws(() => parseConfig({ candidatePrefixes: ['pwd; rm'] }))
})

test('edit inside session cwd is allowed locally; secrets, outside paths and globs are not', () => {
  const cwd = '/repo'
  for (const p of ['src/a.js', '/repo/app/views/x.erb', 'config/app.yml', '.env.example', 'test/token_helper_spec.rb'.replace('token_', '')]) assert.equal(isProjectEdit('edit', p, cwd), true, p)
  for (const p of ['../x.js', '/etc/hosts', '~/.zshrc', '.env', 'config/.env.local', '.ssh/config', 'certs/a.pem', '.git/config', 'src/*', 'config/credentials.yml', '/repo']) assert.equal(isProjectEdit('edit', p, cwd), false, p)
  assert.equal(isProjectEdit('edit', 'src/a.js', null), false)
  assert.equal(isProjectEdit('read', 'src/a.js', cwd), false)
  const plan = planEvent({ sessionID: 's', action: 'edit', resources: ['src/a.js', '/etc/hosts'], effect: 'ask' }, config, null, cwd)
  assert.deepEqual(plan.resources.map((r) => r.reason), ['project_edit_allow', 'jev_candidate'])
  assert.deepEqual(plan.jev, [{ index: 1, command: '/etc/hosts' }])
})
