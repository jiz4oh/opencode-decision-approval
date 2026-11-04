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
export function ruleEffect(action, resource, rules) {
  if (!Array.isArray(rules)) return 'ask'
  const hit = rules.findLast((rule) => rule && typeof rule.action === 'string' && typeof rule.resource === 'string' &&
    wildcardMatch(action, rule.action) && wildcardMatch(resource, rule.resource))
  return hit && ['allow', 'deny', 'ask'].includes(hit.effect) ? hit.effect : 'ask'
}

// Step 3 for one resource: plugin lists decide human ask, otherwise Jev candidate.
export function classifyResource(command, config) {
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
  if (event.action !== 'shell') return { reason: 'unsupported_action' }
  const list = event.resources
  if (!Array.isArray(list) || list.length === 0 || !list.every((r) => typeof r === 'string')) {
    return { reason: 'ambiguous_resources' }
  }
  const resources = list.map((command, index) => ({ index, rule: Array.isArray(rules) ? ruleEffect(event.action, command, rules) : 'ask', command }))
  if (resources.some((r) => r.rule === 'deny')) {
    return { effect: 'deny', reason: 'rule_deny', resources: resources.map(({ index, rule }) => ({ index, rule, reason: rule === 'deny' ? 'rule_deny' : null })) }
  }
  const path = []
  const jev = []
  for (const r of resources) {
    if (r.rule === 'allow') { path.push({ index: r.index, rule: 'allow', reason: 'rule_allow' }); continue }
    const c = classifyResource(r.command, config)
    if (c.reason) path.push({ index: r.index, rule: 'ask', reason: c.reason })
    else { path.push({ index: r.index, rule: 'ask', reason: 'jev_candidate' }); jev.push({ index: r.index, command: c.command }) }
  }
  const human = path.find((r) => r.reason !== 'rule_allow' && r.reason !== 'jev_candidate')
  if (human) return { reason: human.reason, resources: path }
  // OpenCode said ask, yet every resource is rule-allowed by what we can see: keep ask.
  if (jev.length === 0) return { reason: 'rule_view_mismatch', resources: path }
  return { jev, resources: path }
}

export function riskProbability(result) {
  if (!result || !Array.isArray(result.answers) || result.answers.length !== 1) return null
  const answer = result.answers[0]
  if (answer?.type !== 'predicate' || answer.name !== 'risk') return null
  const score = answer.probability
  return typeof score === 'number' && Number.isFinite(score) && score >= 0 && score <= 1 ? score : null
}
