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
OpenCode permission evaluation (one event, possibly several shell resources)
   |-- any resource denied by rules ---------> denied (plugin never sees it)
   |-- every resource allowed ---------------> untouched
   `-- ask  -> plugin, per resource (never joined):
        0. non-string resources / action not in eligibleActions --> native human approval (audited)
        1. OpenCode rules (agent ruleset) ----> allow / deny / ask for EACH resource
        2. any resource deny ----------------> whole event deny (dryRun: ask, audited)
           rule-allowed resources drop out; ask resources continue
        3. plugin lists on each ask resource: candidatePrefixes, forbidden tool,
           risky path/subcommand, unsafe option, invalid -> "human ask"
        4. any human ask --------------------> whole event native human approval (audited)
           otherwise ONE Jev call PER remaining resource, each with its own context
        5. any Jev non-allow (risk > threshold, error, timeout, bad answer)
                                             -> whole event native human approval
           all Jev allow + audit saved
              |-- dryRun=true ---------------> native human approval
              `-- dryRun=false --------------> automatically allowed
```

Every permission action is considered (`shell`, `edit`, `read`, `external_directory`, `webfetch`, ...). Only `shell` resources go through the command filters (candidatePrefixes / FORBIDDEN / HIGH_RISK / unsafe option); other resources (paths, patterns, URLs) are only checked for empty/oversized/NUL and then sent to Jev with their action. OpenCode splits a compound shell call into several permission resources; the plugin evaluates each resource separately and aggregates with the strictest outcome (deny > ask > allow). It never joins resources into a synthetic string.

**Step 1 rules.** The plugin does not define its own rule language. It builds the ruleset the way OpenCode 2.2.5 does, in last-match-wins order: the agent's built-in permissions from the plugin SDK (`ctx.agent.get`, agent from the event or the session), then the global config `permissions` array (`$XDG_CONFIG_HOME/opencode/opencode.json`, default `~/.config/opencode/opencode.json`; OpenCode appends these to every agent, but `ctx.agent.get` returns the pre-config defaults and the plugin SDK has no config API), then non-t3code session rules. A missing or unparsable global file (including JSONC comments) contributes no rules. It evaluates the result with a port of OpenCode 2.2.x semantics: wildcard `*`/`?`, a trailing ` *` also matches the bare command, last matching rule wins, default `ask`. Session-level runtime rules and saved "always" approvals are not exposed to plugins; if the ruleset cannot be loaded, every resource is treated as `ask` (more review, never more allow). **t3code overlay.** T3 Code (OpencodeAdapter `openCodePermissionRules`) injects session rules via `session.create/update({ permission })`: `* * deny`, `<restricted> * deny`, then in approval modes `* * ask` and `<restricted> * ask` for `bash, edit, webfetch, websearch, codesearch, external_directory, doom_loop`, plus `* allow` for `question, read, glob, grep, lsp, todowrite, task, skill`, `read *.env`/`*.env.*` ask|deny, `read *.env.example` allow, mode-dependent `edit`/`webfetch`/`websearch`/`codesearch`/`external_directory` allows, writable-root `external_directory <root>/*` allow, and full-access `* * allow`. The plugin treats these as an approval UI overlay, not user policy: any of them seen in session rules are stripped (`stripT3Rules`), and other session rules are appended after the agent rules (`bash` normalized to `shell`). Because OpenCode 2.2.x does not expose session rules to plugins, the usual signal is indirect: if every resource is allowed by the visible rules but OpenCode still asked, the ask came from the overlay; it is ignored (audit `overlay: "session_ask_ignored"`) instead of dead-ending. Resources allowed by a specific rule (for example global `rtk git status *`) stay `rule_allow` and never reach Jev, though the local risk filter / unsafe-option checks still apply; resources allowed only by a bare `*` rule (an allow-all agent default) continue through steps 3-5.

**Single compound resources** (`;`, newlines, `&&`, `||`, `|`, loops, heredocs, redirects, expansions inside one resource) are sent to Jev as one full string. Hard local filters match anywhere in a resource. This is **heuristic**, not a security boundary. A command such as `npm test` can execute arbitrary project scripts; use a narrow `candidatePrefixes` list on untrusted repositories.

**Audit.** Each event writes one JSONL entry with the aggregate `decision`/`effective`/`reason`, `rules` (`agent` or `unavailable`), and a `resources` array of `{ index, rule, reason, decision?, riskProbability? }` per resource (reasons such as `rule_allow`, `rule_deny`, `skip_jev_prefix`, `local_risk_filter`, `unsafe_option`, `invalid_command`, `jev_low_risk`, `jev_risk_or_uncertainty`, `decision_unavailable`). Entries contain indexes and reason codes only, never command text.

Decision requests send **the raw command** to the configured Jev provider via OpenCode. This may disclose command text and task context embedded within it to that provider; the plugin also sends bounded, redacted context (cwd, session title, stated purpose, related script bodies/files inside the working tree) but never session history. Use your organization's approved model and provider before enabling automatic approval.

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
| `maxCommandLength` | `5000` | Maximum resource length inspected |
| `candidatePrefixes` | `[]` | Prefixes that **skip Jev** and stay as native human ask; unmatched safe commands go to Jev |
| `eligibleActions` | `[]` | Actions to evaluate; `[]` or `["*"]` = all |
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
