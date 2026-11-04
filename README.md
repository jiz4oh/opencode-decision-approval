# OpenCode Decision Approval

A **server-side OpenCode V2 plugin** that reduces permission prompts in T3 Code, OpenChamber, OpenCode TUI, and other OpenCode clients. It uses OpenCode's native `permission.hook("evaluate")` and **experimental Decision API** (`ctx.experimental.generate.decisions`) with Jev; it does **not** depend on Paseo or call the legacy System One HTTP endpoint directly.

Based on the policy approach in [jiz4oh/paseo-jev-approver](https://github.com/jiz4oh/paseo-jev-approver). The plugin uses no custom UI, approval endpoints, or separate API-key store. Your OpenCode server must already expose the configured decision model (the example uses `opencode/jev-1.13`).

## Setup

Requires **OpenCode V2 2.2.0+**, with Promise plugin APIs and experimental decision generation. Use a server version that exposes both APIs.

1. Clone this repository to a permanent location on the machine running **OpenCode Server**. The host needs normal access to the local files; T3 Code is only a client.
2. Add the absolute local directory to the **`plugins`** array of your global `opencode.json(c)`:

   ```jsonc
   {
     "plugins": ["/absolute/path/opencode-decision-approval"]
   }
   ```

   The directory has a `package.json` export and uses `@opencode/plugin` supplied by your OpenCode installation/plugin runtime. If the loader reports a missing module, install the compatible `@opencode/plugin` peer dependency in that plugin directory.

3. Copy [`examples/decision-approval.json`](examples/decision-approval.json) to `${XDG_CONFIG_HOME:-~/.config}/opencode/decision-approval.json` (JSON, not JSONC). Alternatively set `OPENCODE_DECISION_APPROVAL_CONFIG` to an absolute path or use the plugin entry object:

   ```jsonc
   {
     "plugins": [{
       "package": "/absolute/path/opencode-decision-approval",
       "options": { "configFile": "/absolute/path/decision-approval.json" }
     }]
   }
   ```

4. Ensure the OpenCode instance has credentials for the configured provider and model. These are handled by OpenCode, not this plugin.
5. Restart the OpenCode server after changing this configuration file. Observe the audit log while `dryRun` is `true`. After verifying the decision results, set `dryRun` to `false` and restart.

**Important:** The plugin only evaluates existing `ask` requests. If your OpenCode rules allow a command already, it stays allowed without Jev; if a configured rule explicitly denies it, the permission hook is not invoked. To subject commands to review, configure the native `shell` permission as `ask` in your OpenCode permissions (check the installed OpenCode version's permission schema).

## How it works

```text
OpenCode permission evaluation
   |-- explicit deny ------------------------> denied (plugin never sees it)
   |-- existing allow -----------------------> untouched
   `-- ask
        |-- non-shell / multiple resources --> native human approval
        |-- local risk or unknown command ---> native human approval
        `-- eligible command
              |-- Jev unsupported/error ------> native human approval
              |-- probability > threshold ---> native human approval
              `-- low risk + audit saved
                     |-- dryRun=true --------> native human approval
                     `-- dryRun=false -------> automatically allowed
```

Only the `shell` action is considered, and only commands beginning with a configured eligible prefix and passing a restrictive lexical filter are forwarded to Jev. The built-in rules reject command chaining, redirects, shell expansions, secret-like paths, common mutating tools, and known dangerous flags. This is **heuristic**, not a shell parser or a security boundary. A command such as `npm test` can execute arbitrary project scripts; use a narrow `candidatePrefixes` list on untrusted repositories.

Decision requests send **the raw command** to the configured Jev provider via OpenCode. This may disclose command text and task context embedded within it to that provider; the plugin does not send session history or file contents itself. Use your organization's approved model and provider before enabling automatic approval.

The model returns `answers: [{ type: "predicate", name: "risk", probability: number }]`. That probability represents the risk proposition being true, not approval confidence. A result at or below the configured `riskThreshold` is eligible for automatic approval. Errors, timeouts, mismatched answer types, malformed probabilities, or audit-write failures preserve native human approval.

## Configuration

See [`examples/decision-approval.json`](examples/decision-approval.json).

| Option | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Enable the hook |
| `dryRun` | `true` | Evaluate and audit, never auto-approve |
| `mode` | `on-ask` | Only review existing permission prompts |
| `model.providerID` / `model.id` | `opencode` / `jev-1.13` | OpenCode model reference, not an API endpoint |
| `riskThreshold` | `0.01` | Maximum probability of risk eligible for auto-approval (range 0–0.5) |
| `timeoutMs` | `6500` | Max wait before leaving approval to the user (1000–15000 ms) |
| `maxCommandLength` | `5000` | Maximum shell text inspected |
| `candidatePrefixes` | See example | Allowed candidate commands; **not** unconditional permissions |
| `eligibleActions` | `["shell"]` | Only shell is supported |
| `audit.enabled` | `true` | Persist audit log (recommended) |
| `audit.path` | `null` | Absolute JSONL path; default under XDG state directory |

The audit log defaults to `${XDG_STATE_HOME:-~/.local/state}/opencode-decision-approval/decisions.jsonl`. It includes session ID, action, decision, reason, probability and timestamps **but never raw commands or credentials**. A failed audit write prevents automatic approval. Logs are best-effort regarding external filesystem permissions; protect the state directory from other users.

## Tests

```sh
npm run check
```

Node 22+ is needed to run the tests. They use built-in `node:test` and no live Jev token. All model calls in the tests are mocked. **Integration testing against real OpenCode and T3 Code is still required before treating the plugin as production-ready.**

## Design notes

- Cross-client behavior comes from OpenCode Server's native Permission API, not from client-specific UI adapters.
- This plugin does not implement a custom `always allow` action, rewrite saved user rules, or grant approval to explicitly denied operations.
- It does not auto-deny risky actions: they continue to the client's permission dialog.
- There is no caching of model results, since a command that was safe once may not be safe after repository or environment changes.
- Risk probability thresholds are not calibrated safety guarantees.
