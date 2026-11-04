// Conservative command gate adapted from the author's paseo-jev-approver.
// Per-resource pipeline (OpenCode may split one shell call into several resources;
// they are NEVER joined):
//   1. OpenCode permission rules (ported findLast + wildcard semantics) -> allow/deny/ask
//   2. any deny -> whole event deny; rule-allowed resources drop out; asks continue
//   3. plugin lists (candidatePrefixes / FORBIDDEN / HIGH_RISK / unsafe_option) -> human ask
//   4. any human ask -> whole event ask; else each remaining resource -> its own Jev call
//   5. any Jev non-allow -> ask; only all-allow -> allow (see runtime.js)
const FORBIDDEN = /(?:^|[\s;&|(`])(?:sudo|su|doas|rm|rmdir|shred|mkfs|dd|chmod|chown|mount|umount|reboot|shutdown|killall|curl|wget|ssh|scp|rsync|nc|ncat|socat|ftp|sftp|eval|exec|xargs|find|env|bash|sh|zsh|python|node|ruby|perl)(?=[\s;&|)`]|$)/i;
const HIGH_RISK = /(?:(?:^|[ \/])\.\.(?:\/|$)|~\/|\/etc\/|\/root\/|\/proc\/|\/dev\/|\.env\b|\.ssh\/|id_rsa|secret|token|password|credential|\b(?:git\s+(?:push|reset|clean|checkout|switch|restore|rebase|merge|commit|fetch|pull)|npm\s+(?:publish|install|uninstall)|pnpm\s+(?:publish|install|add|remove)|pip\s+install)\b)/i;
const UNSAFE_OPTION = /\s(?:--?(?:exec|preload|require|eval|config|output|out|write|delete|force|hard|upload)|-c)\b/i;

function matchesPrefix(command, prefixes) {
  return prefixes.some((prefix) => command === prefix || command.startsWith(prefix + ' '))
}

// Port of OpenCode 2.2.x Permission wildcard match (`*` any, `?` one char, trailing
// " *" also matches the bare command). Not a new rule language: same config rules.
export function wildcardMatch(value, pattern) {
  const subject = value.replaceAll('\\', '/')
  let source = pattern.replaceAll('\\', '/').replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')
  if (source.endsWith(' .*')) source = source.slice(0, -3) + '( .*)?'
  return new RegExp('^' + source + '$', 's').test(subject)
}

// Port of OpenCode rule evaluation: last matching rule wins, default ask.
export function ruleHit(action, resource, rules) {
  if (!Array.isArray(rules)) return null
  const hit = rules.findLast((rule) => rule && typeof rule.action === 'string' && typeof rule.resource === 'string' &&
    wildcardMatch(action, rule.action) && wildcardMatch(resource, rule.resource))
  return hit && ['allow', 'deny', 'ask'].includes(hit.effect) ? hit : null
}

export function ruleEffect(action, resource, rules) {
  return ruleHit(action, resource, rules)?.effect ?? 'ask'
}

// t3code (T3 Code Beta, OpencodeAdapter openCodePermissionRules) injects these session
// rules via session.create/update({ permission }). They are a UI approval overlay, not
// the user's policy, so they are stripped from any session ruleset the plugin can see.
const T3_RESTRICTED = ['bash', 'edit', 'webfetch', 'websearch', 'codesearch', 'external_directory', 'doom_loop']
const T3_ALWAYS_ALLOWED = ['question', 'read', 'glob', 'grep', 'lsp', 'todowrite', 'task', 'skill']
const T3_SIGNATURES = new Set([
  ...['*', ...T3_RESTRICTED].flatMap((p) => [`${p}|*|deny`, `${p}|*|ask`]),
  '*|*|allow', 'edit|*|allow', 'webfetch|*|allow', 'websearch|*|allow', 'codesearch|*|allow', 'external_directory|*|allow',
  ...T3_ALWAYS_ALLOWED.map((p) => `${p}|*|allow`),
  ...['ask', 'deny'].flatMap((a) => [`read|*.env|${a}`, `read|*.env.*|${a}`]), 'read|*.env.example|allow',
])

// Normalize a session rule ({permission,pattern,action} or {action,resource,effect}) to
// the V2 shape; null when malformed. `bash` is the legacy name of the `shell` action.
export function normalizeRule(rule) {
  if (!rule || typeof rule !== 'object') return null
  const action = rule.resource !== undefined ? rule.action : rule.permission
  const resource = rule.resource ?? rule.pattern
  const effect = rule.effect ?? (rule.resource === undefined ? rule.action : undefined)
  if (typeof action !== 'string' || typeof resource !== 'string' || !['allow', 'deny', 'ask'].includes(effect)) return null
  return { action, resource, effect }
}

export function isT3InjectedRule(rule) {
  const r = normalizeRule(rule)
  if (!r) return false
  if (r.resource.endsWith('/*') && r.action === 'external_directory' && r.effect === 'allow') return true // writableRoots
  return T3_SIGNATURES.has(`${r.action}|${r.resource}|${r.effect}`)
}

// Normalize without t3 stripping (for user-owned config rules). `home` expands a
// leading `~/` like OpenCode does for config permissions.
export function normalizeRules(rules, home = null) {
  if (!Array.isArray(rules)) return []
  return rules.map(normalizeRule).filter(Boolean)
    .map((r) => (r.action === 'bash' ? { ...r, action: 'shell' } : r))
    .map((r) => (home && r.resource.startsWith('~/') ? { ...r, resource: home + r.resource.slice(1) } : r))
}

export function stripT3Rules(rules) {
  if (!Array.isArray(rules)) return []
  return normalizeRules(rules.filter((rule) => !isT3InjectedRule(rule)))
}

const invalidResource = (value, config) => !value.trim() || value.length > config.maxCommandLength || value.includes('\x00')

// Step 3 for one resource: plugin lists decide human ask, otherwise Jev candidate.
// Only shell gets the command filters; other actions (paths, patterns, URLs) go to Jev.
export function classifyResource(command, config, action = 'shell') {
  if (action !== 'shell') return invalidResource(command, config) ? { reason: 'invalid_command' } : { command }
  if (!command.trim() || command.length > config.maxCommandLength || command.trim() !== command || command.includes('\x00')) {
    return { reason: 'invalid_command' }
  }
  if (matchesPrefix(command, config.candidatePrefixes)) return { reason: 'skip_jev_prefix' }
  if (FORBIDDEN.test(command) || HIGH_RISK.test(command)) return { reason: 'local_risk_filter' }
  if (UNSAFE_OPTION.test(command)) return { reason: 'unsafe_option' }
  return { command }
}

// Steps 1-4. Returns { reason } for event-level human ask, { effect: 'deny', ... },
// or { jev: [{ index, command }], resources } where resources is the audit path.
// `rules` null/undefined means rules unavailable: every resource is treated as ask.
export function planEvent(event, config, rules = null) {
  if (!event || event.effect !== 'ask') return { reason: 'not_pending' }
  if (typeof event.action !== 'string' || !event.action) return { reason: 'ambiguous_resources' }
  const eligible = config.eligibleActions ?? []
  if (eligible.length && !eligible.includes('*') && !eligible.includes(event.action)) return { reason: 'action_not_eligible' }
  const list = event.resources
  if (!Array.isArray(list) || list.length === 0 || !list.every((r) => typeof r === 'string')) {
    return { reason: 'ambiguous_resources' }
  }
  const resources = list.map((command, index) => {
    const hit = ruleHit(event.action, command, rules)
    // `broad`: allowed only by a bare `*` resource rule (e.g. an allow-all agent default).
    return { index, rule: hit?.effect ?? 'ask', broad: hit?.resource === '*', command }
  })
  if (resources.some((r) => r.rule === 'deny')) {
    return { effect: 'deny', reason: 'rule_deny', resources: resources.map(({ index, rule }) => ({ index, rule, reason: rule === 'deny' ? 'rule_deny' : null })) }
  }
  // OpenCode asked although every resource is allowed by the rules we can see: the ask
  // comes from session-level rules invisible to plugins (t3code's injected sessionRules
  // such as `bash * ask`). Ignore that overlay: resources allowed only by a bare `*` rule
  // go through steps 3-5; resources allowed by a specific rule (e.g. global
  // `rtk git status *`) stay rule_allow and never reach Jev.
  const overlay = resources.every((r) => r.rule === 'allow')
  const path = []
  const jev = []
  for (const r of resources) {
    if (r.rule === 'allow' && !overlay) { path.push({ index: r.index, rule: 'allow', reason: 'rule_allow' }); continue }
    const c = classifyResource(r.command, config, event.action)
    if (overlay && !r.broad) {
      // Specific allow under the overlay: no Jev, but the plugin's local risk filters still apply.
      const risky = c.reason === 'local_risk_filter' || c.reason === 'unsafe_option' || c.reason === 'invalid_command'
      path.push({ index: r.index, rule: 'allow', overlay: 'session_ask_ignored', reason: risky ? c.reason : 'rule_allow' })
      continue
    }
    const base = overlay ? { index: r.index, rule: 'allow', overlay: 'session_ask_ignored' } : { index: r.index, rule: 'ask' }
    if (c.reason) path.push({ ...base, reason: c.reason })
    else { path.push({ ...base, reason: 'jev_candidate' }); jev.push({ index: r.index, command: c.command }) }
  }
  const human = path.find((r) => r.reason !== 'rule_allow' && r.reason !== 'jev_candidate')
  if (human) return { reason: human.reason, resources: path }
  return { jev, resources: path }
}

export function riskProbability(result) {
  if (!result || !Array.isArray(result.answers) || result.answers.length !== 1) return null
  const answer = result.answers[0]
  if (answer?.type !== 'predicate' || answer.name !== 'risk') return null
  const score = answer.probability
  return typeof score === 'number' && Number.isFinite(score) && score >= 0 && score <= 1 ? score : null
}
