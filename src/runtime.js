import { loadConfig } from './config.js'
import { planEvent } from './policy.js'
import { evaluateJev } from './decision.js'
import { createAudit } from './audit.js'
import { gatherContext } from './context.js'

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
    if (rules && event.action === 'shell') {
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
    // Steps 3-4 human ask (also event-level skips such as unsupported_action).
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
export async function loadAgentRules(ctx, event) {
  let agentID = typeof event.agent === 'string' && event.agent ? event.agent : null
  if (!agentID && typeof ctx?.session?.get === 'function') {
    try {
      let s = await ctx.session.get({ sessionID: event.sessionID })
      s = s?.data ?? s
      if (typeof s?.agent === 'string' && s.agent) agentID = s.agent
    } catch { agentID = null }
  }
  if (!agentID || typeof ctx?.agent?.get !== 'function') return null
  const res = await ctx.agent.get({ agentID })
  const permissions = (res?.data ?? res)?.permissions
  return Array.isArray(permissions) ? permissions : null
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
