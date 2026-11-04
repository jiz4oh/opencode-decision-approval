import { loadConfig } from './config.js'
import { planEvent, stripT3Rules, normalizeRules } from './policy.js'
import { evaluateJev } from './decision.js'
import { createAudit } from './audit.js'
import { gatherContext } from './context.js'
import { readFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'

// Audit entries carry reason codes, rule effects and resource indexes only: never commands.
function entry(event, fields) {
  return { sessionID: event.sessionID, agent: event.agent ?? null, action: event.action, riskProbability: null, ...fields }
}

async function safeAudit(audit, record) {
  try { await audit(record); return true } catch { return false }
}

export function createHandler({ config, generate, audit, collect = null, rules = null }) {
  return async (event) => {
    if (!config.enabled || event.effect !== 'ask') return
    let ruleset = null
    if (rules) {
      try { ruleset = await rules(event) } catch { ruleset = null }
    }
    const plan = planEvent(event, config, ruleset)
    const rulesSource = Array.isArray(ruleset) ? 'agent' : 'unavailable'

    // Step 2: any rule deny denies the whole event (dry-run only records it).
    if (plan.effect === 'deny') {
      const next = config.dryRun ? 'ask' : 'deny'
      const ok = await safeAudit(audit, entry(event, { decision: 'deny', effective: next, reason: plan.reason, rules: rulesSource, resources: plan.resources }))
      if (ok && next === 'deny') event.effect = 'deny'
      return
    }
    // Steps 3-4 human ask (also event-level skips such as action_not_eligible).
    if (!plan.jev) {
      if (plan.reason) await safeAudit(audit, entry(event, { decision: 'ask', effective: 'ask', reason: plan.reason, rules: rulesSource, resources: plan.resources ?? null }))
      return
    }
    // Step 4: one Jev call per remaining resource, each with its own context.
    const verdicts = await Promise.all(plan.jev.map(async ({ index, command }) => {
      let context = null
      if (collect) {
        try { context = await collect(event, command) } catch { context = null }
      }
      const result = await evaluateJev(generate, event, command, config, context)
      return { index, ...result }
    }))
    const byIndex = new Map(verdicts.map((v) => [v.index, v]))
    const resources = plan.resources.map((r) => {
      const v = byIndex.get(r.index)
      return v ? { ...r, decision: v.action, reason: v.reason, riskProbability: v.riskProbability } : r
    })
    // Step 5: any non-allow -> ask; only all-allow -> allow.
    const failed = verdicts.find((v) => v.action !== 'allow')
    const decision = failed ? 'ask' : 'allow'
    const next = config.dryRun ? 'ask' : decision
    const scores = verdicts.map((v) => v.riskProbability).filter((p) => typeof p === 'number')
    const ok = await safeAudit(audit, entry(event, {
      decision,
      effective: next,
      reason: failed ? failed.reason : (config.dryRun ? 'dry_run' : 'jev_low_risk'),
      riskProbability: scores.length === verdicts.length ? Math.max(...scores) : null,
      rules: rulesSource,
      resources,
    }))
    // Audit failures must not produce unlogged automatic approvals.
    if (ok && next === 'allow') event.effect = 'allow'
  }
}

// Step 1 input: the resolved agent ruleset exposed by the plugin SDK (ctx.agent.get).
// Session-level runtime rules and saved "always" approvals are not exposed to plugins;
// missing rules degrade to "every resource is ask" (more review, never more allow).
// Global `permissions` from the managed OpenCode config (the plugin SDK exposes no config
// API). User-owned, so never t3-stripped; malformed entries dropped, `~/` expanded; [] on failure.
export function globalConfigPath() {
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'opencode', 'opencode.json')
}

export async function loadGlobalRules(read = readFile, path = globalConfigPath()) {
  try {
    const parsed = JSON.parse(await read(path, 'utf8'))
    const list = parsed?.permissions ?? parsed?.permission
    return Array.isArray(list) ? normalizeRules(list, homedir()) : []
  } catch { return [] }
}

// Step 1 ruleset, last match wins like OpenCode. OpenCode 2.2.5 builds an agent's rules as
// built-in agent defaults followed by the config `permissions` (agent.transform pushes them),
// then session rules. ctx.agent.get returns the pre-transform defaults (often ending in a
// catch-all ask), so the order here is agent defaults -> global config -> non-t3 session rules. Returns null only when nothing at all could be loaded.
export async function loadAgentRules(ctx, event, globalRules = () => loadGlobalRules()) {
  let agentID = typeof event.agent === 'string' && event.agent ? event.agent : null
  let sessionRules = []
  if (typeof ctx?.session?.get === 'function') {
    try {
      let s = await ctx.session.get({ sessionID: event.sessionID })
      s = s?.data ?? s
      if (!agentID && typeof s?.agent === 'string' && s.agent) agentID = s.agent
      // Session rules are not in the SDK type today; if exposed, drop t3code's overlay.
      sessionRules = stripT3Rules(s?.permission ?? s?.permissions)
    } catch { sessionRules = [] }
  }
  let global = []
  try { global = await globalRules() } catch { global = [] }
  let agent = null
  if (agentID && typeof ctx?.agent?.get === 'function') {
    try {
      const res = await ctx.agent.get({ agentID })
      const permissions = (res?.data ?? res)?.permissions
      if (Array.isArray(permissions)) agent = permissions
    } catch { agent = null }
  }
  if (agent === null && global.length === 0 && sessionRules.length === 0) return null
  return [...(agent ?? []), ...global, ...sessionRules]
}

export async function install(ctx) {
  const { config } = await loadConfig(ctx.options ?? {})
  if (!config.enabled) return
  const audit = createAudit(config)
  const handle = createHandler({
    config,
    generate: (input) => ctx.experimental.generate.decisions(input),
    audit,
    collect: (event, command) => gatherContext({ event, command, ctx }),
    rules: (event) => loadAgentRules(ctx, event),
  })
  const registration = await ctx.permission.hook('evaluate', handle)
  return () => registration.dispose()
}
