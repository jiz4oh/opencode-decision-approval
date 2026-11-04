import { loadConfig } from './config.js'
import { selectCommand } from './policy.js'
import { evaluateJev } from './decision.js'
import { createAudit } from './audit.js'

export function createHandler({ config, generate, audit }) {
  return async (event) => {
    if (!config.enabled || event.effect !== 'ask') return
    const candidate = selectCommand(event, config)
    if (!candidate.command) {
      if (candidate.reason === 'skip_jev_prefix') {
        try {
          await audit({
            sessionID: event.sessionID,
            agent: event.agent ?? null,
            action: event.action,
            decision: 'ask',
            effective: 'ask',
            reason: 'skip_jev_prefix',
            riskProbability: null,
          })
        } catch {
          // ignore audit failures when not auto-approving
        }
      }
      return
    }
    const result = await evaluateJev(generate, event, candidate.command, config)
    const next = config.dryRun ? 'ask' : result.action
    try {
      await audit({
        sessionID: event.sessionID,
        agent: event.agent ?? null,
        action: event.action,
        decision: result.action,
        effective: next,
        reason: config.dryRun && result.action === 'allow' ? 'dry_run' : result.reason,
        riskProbability: result.riskProbability,
      })
    } catch {
      // Audit failures must not produce unlogged automatic approvals.
      return
    }
    if (next === 'allow') {
      event.effect = 'allow'
      // Avoid attaching potentially sensitive model content to permission UI.
    }
  }
}

export async function install(ctx) {
  const { config } = await loadConfig(ctx.options ?? {})
  if (!config.enabled) return
  const audit = createAudit(config)
  const handle = createHandler({
    config,
    generate: (input) => ctx.experimental.generate.decisions(input),
    audit,
  })
  const registration = await ctx.permission.hook('evaluate', handle)
  return () => registration.dispose()
}
