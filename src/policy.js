// Conservative command gate adapted from the author's paseo-jev-approver.
// No shell interpretation is attempted: ambiguous grammar always goes to a human.
const COMPOUND = /[\r\n;&|<>`]|\$\(|\$\{|\\|\x00/;
const FORBIDDEN = /(?:^|\s)(?:sudo|su|doas|rm|rmdir|shred|mkfs|dd|chmod|chown|mount|umount|reboot|shutdown|killall|curl|wget|ssh|scp|rsync|nc|ncat|socat|ftp|sftp|eval|exec|xargs|find|env|bash|sh|zsh|python|node|ruby|perl)(?:\s|$)/i;
const HIGH_RISK = /(?:(?:^|[ \/])\.\.(?:\/|$)|~\/|\/etc\/|\/root\/|\/proc\/|\/dev\/|\.env\b|\.ssh\/|id_rsa|secret|token|password|credential|\b(?:git\s+(?:push|reset|clean|checkout|switch|restore|rebase|merge|commit|fetch|pull)|npm\s+(?:publish|install|uninstall)|pnpm\s+(?:publish|install|add|remove)|pip\s+install)\b)/i;

function matchesPrefix(command, prefixes) {
  return prefixes.some((prefix) => command === prefix || command.startsWith(prefix + ' '))
}

export function selectCommand(event, config) {
  if (!event || event.effect !== 'ask') return { reason: 'not_pending' }
  if (event.action !== 'shell') return { reason: 'unsupported_action' }
  if (!Array.isArray(event.resources) || event.resources.length !== 1 || typeof event.resources[0] !== 'string') {
    return { reason: 'ambiguous_resources' }
  }
  const command = event.resources[0]
  if (!command.trim() || command.length > config.maxCommandLength || command.trim() !== command) {
    return { reason: 'invalid_command' }
  }
  // Matching candidatePrefixes skips Jev and leaves native human ask.
  if (matchesPrefix(command, config.candidatePrefixes)) {
    return { reason: 'skip_jev_prefix' }
  }
  if (COMPOUND.test(command) || FORBIDDEN.test(command) || HIGH_RISK.test(command)) {
    return { reason: 'local_risk_filter' }
  }
  // A prefix alone is insufficient when a second command could be hidden in the argument list.
  if (/\s(?:--?(?:exec|preload|require|eval|config|output|out|write|delete|force|hard|upload)|-c)\b/i.test(command)) {
    return { reason: 'unsafe_option' }
  }
  if (/\*|\?|\[|\]|\{|\}|\$/.test(command)) return { reason: 'shell_expansion' }
  return { command }
}

export function riskProbability(result) {
  if (!result || !Array.isArray(result.answers) || result.answers.length !== 1) return null
  const answer = result.answers[0]
  if (answer?.type !== 'predicate' || answer.name !== 'risk') return null
  const score = answer.probability
  return typeof score === 'number' && Number.isFinite(score) && score >= 0 && score <= 1 ? score : null
}
