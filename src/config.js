import { readFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'

export const DEFAULTS = Object.freeze({
  enabled: true,
  dryRun: true,
  mode: 'on-ask',
  model: { providerID: 'opencode', id: 'jev-1.13' },
  riskThreshold: 0.01,
  timeoutMs: 6500,
  maxCommandLength: 5000,
  eligibleActions: [], // [] or ['*'] = every action
  candidatePrefixes: [],
  audit: { enabled: true, path: null },
})

const object = (value) => value && typeof value === 'object' && !Array.isArray(value)
const keys = (item, allowed, name) => {
  if (!object(item)) throw new Error(`${name} must be an object`)
  for (const key of Object.keys(item)) {
    if (!allowed.includes(key)) throw new Error(`${name}: unknown option ${key}`)
  }
}

export function parseConfig(input = {}) {
  keys(input, Object.keys(DEFAULTS), 'config')
  const config = {
    ...DEFAULTS,
    ...input,
    model: { ...DEFAULTS.model, ...input.model },
    audit: { ...DEFAULTS.audit, ...input.audit },
    eligibleActions: input.eligibleActions ?? [...DEFAULTS.eligibleActions],
    candidatePrefixes: input.candidatePrefixes ?? [...DEFAULTS.candidatePrefixes],
  }
  for (const key of ['enabled', 'dryRun']) {
    if (typeof config[key] !== 'boolean') throw new Error(`${key} must be boolean`)
  }
  if (config.mode !== 'on-ask') throw new Error('Only mode=on-ask is supported')
  keys(config.model, ['providerID', 'id'], 'model')
  for (const field of ['providerID', 'id']) {
    if (typeof config.model[field] !== 'string' || !config.model[field].trim()) {
      throw new Error(`model.${field} must be a nonempty string`)
    }
  }
  if (!Number.isFinite(config.riskThreshold) || config.riskThreshold < 0 || config.riskThreshold >= 1) {
    throw new Error('riskThreshold must be >= 0 and < 1')
  }
  if (!Number.isInteger(config.timeoutMs) || config.timeoutMs < 1000 || config.timeoutMs > 15000) {
    throw new Error('timeoutMs must be an integer between 1000 and 15000')
  }
  if (!Number.isInteger(config.maxCommandLength) || config.maxCommandLength < 1 || config.maxCommandLength > 5000) {
    throw new Error('maxCommandLength must be an integer between 1 and 5000')
  }
  if (!Array.isArray(config.eligibleActions) || config.eligibleActions.length > 50 ||
      !config.eligibleActions.every((a) => typeof a === 'string' && /^(?:\*|[a-z_]{1,50})$/.test(a))) {
    throw new Error('eligibleActions must be a list of action names ([] or ["*"] = all)')
  }
  if (!Array.isArray(config.candidatePrefixes) || config.candidatePrefixes.length > 100 ||
      !config.candidatePrefixes.every((s) => typeof s === 'string' && s.length >= 2 && s.length <= 100 && s.trim() === s && /^[\w.\- ]+$/.test(s))) {
    throw new Error('candidatePrefixes must be a small list of simple command prefixes')
  }
  keys(config.audit, ['enabled', 'path'], 'audit')
  if (typeof config.audit.enabled !== 'boolean' || (config.audit.path !== null &&
      (typeof config.audit.path !== 'string' || !isAbsolute(config.audit.path)))) {
    throw new Error('audit.enabled must be boolean and audit.path must be null or absolute')
  }
  return config
}

export function defaultConfigPath() {
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), '.config')
  return join(base, 'opencode', 'decision-approval.json')
}

export async function loadConfig(options = {}, read = readFile) {
  if (!object(options)) throw new Error('Plugin options must be an object')
  const allowed = ['configFile']
  keys(options, allowed, 'plugin options')
  const choice = options.configFile ?? process.env.OPENCODE_DECISION_APPROVAL_CONFIG ?? defaultConfigPath()
  if (typeof choice !== 'string' || !isAbsolute(choice)) throw new Error('Config file path must be absolute')
  const path = resolve(choice)
  try {
    const data = JSON.parse(await read(path, 'utf8'))
    return { config: parseConfig(data), path }
  } catch (error) {
    if (error?.code === 'ENOENT') return { config: parseConfig(), path }
    throw new Error('Invalid decision approval configuration', { cause: error })
  }
}
