import { appendFile, chmod, mkdir } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

export function defaultAuditPath() {
  const base = process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state')
  return join(base, 'opencode-decision-approval', 'decisions.jsonl')
}

export function createAudit(config) {
  if (!config.audit.enabled) return async () => {}
  const path = config.audit.path ?? defaultAuditPath()
  let queue = Promise.resolve()
  return (entry) => {
    // Entries contain reason codes and identifiers only, never raw commands or model inputs.
    const data = JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n'
    const next = queue.catch(() => {}).then(async () => {
      await mkdir(dirname(path), { recursive: true, mode: 0o700 })
      await appendFile(path, data, { encoding: 'utf8', mode: 0o600 })
      await chmod(path, 0o600)
    })
    queue = next
    return next
  }
}
